package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	adaptix "github.com/Adaptix-Framework/axc2/v2"
)

func base64Decode(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

func naxListenerLogInfo(format string, args ...any) { fmt.Printf("[NaxDarks-HTTP] [*] "+format+"\n", args...) }
func naxListenerLogOk(format string, args ...any)   { fmt.Printf("[NaxDarks-HTTP] [+] "+format+"\n", args...) }
func naxListenerLogErr(format string, args ...any)   { fmt.Printf("[NaxDarks-HTTP] [-] "+format+"\n", args...) }

// agentWatermark must match extender/config.yaml::agent_watermark.
// Adaptix uses the watermark to resolve which agent plugin to dispatch
// CreateAgent to when TsAgentCreate is called.
const agentWatermark = "deadbeef" // NAX Linux agent watermark

// httpServer is the listener's HTTP front-end. The profile-driven handler
// extracts client data via reverse transforms (decode/unmask/decrypt) and
// builds server responses via forward transforms (encrypt/mask/encode).
type httpServer struct {
	name       string
	host       string
	port       int
	ssl        bool
	sslCert    []byte
	sslKey     []byte
	uri        map[string]struct{} // bootstrap URIs (pre-profile)
	hbHeader   string              // legacy header name for beaconID fallback
	encryptKey []byte              // raw 16 bytes
	profileRaw string
	profile    *ProfileConfig

	pendingProfile sync.Map // key: beaconID, value: bool

	// Per-agent profile overrides for runtime profile updates.
	agentProfiles     sync.Map  // key: beaconID (string), value: *ProfileConfig
	agentPrevProfiles sync.Map  // key: beaconID (string), value: *ProfileConfig
	beaconIDHeaders   []string  // all known beacon ID header names (default + overrides)
	profileStoreCheck time.Time // last poll time (throttled to once per 5s)
	profileStoreRaw   sync.Map  // key: agentID, value: []byte (cached raw store data for change detection)

	ts Teamserver

	// agentIDMap maps the 16-hex-char beaconID (from X-Beacon-Id) to the
	// server-assigned AgentData.Id returned by TsAgentCreate.  Adaptix stores
	// the agent under AgentData.Id in its internal DB; subsequent calls to
	// TsAgentProcessData and TsAgentGetHostedAll must use that ID, NOT the
	// beaconID parameter we passed to TsAgentCreate.
	//
	// This mirrors the Kharon pattern:
	//   agentDataRes, _ := ts.TsAgentCreate(...)
	//   newAgentID := agentDataRes.Id   // server-assigned - use this
	//
	// See: out_source_projects/Kharon/listener_kharon_http/src_server/pl_http.go:737
	agentIDMap sync.Map // key: beaconID (string), value: adaptixID (int64)

	mu  sync.Mutex
	srv *http.Server
}

/* ========= [ Server constructor ] ========= */

func newHTTPServer(name, config string, ts Teamserver) (*httpServer, error) {
	var cfg map[string]any
	if err := json.Unmarshal([]byte(config), &cfg); err != nil {
		return nil, err
	}

	host, _ := cfg["host_bind"].(string)
	if host == "" {
		host = "0.0.0.0"
	}
	portFloat, _ := cfg["port_bind"].(float64)
	port := int(portFloat)
	if port < 1 || port > 65535 {
		return nil, errors.New("listener: invalid port_bind")
	}

	profile := parseProfileConfig(cfg)

	uriSet := map[string]struct{}{}
	uriSet["/api/v1/status"] = struct{}{}
	for _, u := range profile.Get.URIs {
		uriSet[u] = struct{}{}
	}
	for _, u := range profile.Post.URIs {
		uriSet[u] = struct{}{}
	}

	hbHeader := profile.BeaconIdHeader
	if hbHeader == "" {
		hbHeader = "X-Beacon-Id"
	}
	naxListenerLogInfo("beacon ID header: %s", hbHeader)

	keyHex, _ := cfg["encrypt_key"].(string)
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil || len(keyBytes) != 16 {
		return nil, errors.New("listener: encrypt_key must be 32 hex chars (16 bytes)")
	}

	// HTTPS is always enabled for this listener — ssl field not required in config
	sslEnabled := true
	var sslCert, sslKey []byte
	if sslEnabled {
		if raw, ok := cfg["ssl_cert"].(string); ok && raw != "" {
			if decoded, err := base64Decode(raw); err == nil {
				sslCert = decoded
			} else {
				sslCert = []byte(raw)
			}
		}
		if raw, ok := cfg["ssl_key"].(string); ok && raw != "" {
			if decoded, err := base64Decode(raw); err == nil {
				sslKey = decoded
			} else {
				sslKey = []byte(raw)
			}
		}
	}

	// Inject fields the agent builder needs: tcp_mode, c2_host, c2_port
	// The agent pl_main.go reads c2_host/c2_port but the HTTPS listener
	// stores them as host_bind/port_bind — alias them here.
	{
		if _, hasMode := cfg["tcp_mode"]; !hasMode {
			cfg["tcp_mode"] = "https (HTTPS → C2)"
		}
		if _, hasCH := cfg["c2_host"]; !hasCH {
			// Prefer callbacks_hosts (the actual C2 IP the agent connects to)
			// over host_bind (which can be 0.0.0.0).
			// callbacks_hosts entries are "host:port" — inject only the host part.
			if raw, ok := cfg["callbacks_hosts"].([]any); ok && len(raw) > 0 {
				if h, ok := raw[0].(string); ok && h != "" {
					if host, p, err2 := net.SplitHostPort(h); err2 == nil {
						cfg["c2_host"] = host
						if _, hasCP := cfg["c2_port"]; !hasCP && p != "" {
							if pn, err3 := strconv.Atoi(p); err3 == nil { cfg["c2_port"] = float64(pn) }
						}
					} else {
						cfg["c2_host"] = h
					}
				}
			} else if h, ok := cfg["host_bind"].(string); ok && h != "" && h != "0.0.0.0" {
				cfg["c2_host"] = h
			}
		}
		if _, hasCP := cfg["c2_port"]; !hasCP {
			if p, ok := cfg["port_bind"].(float64); ok && p > 0 {
				cfg["c2_port"] = p
			}
		}
		if enriched, err2 := json.Marshal(cfg); err2 == nil {
			config = string(enriched)
		}
	}

	s := &httpServer{
		name:       name,
		host:       host,
		port:       port,
		ssl:        sslEnabled,
		sslCert:    sslCert,
		sslKey:     sslKey,
		uri:        uriSet,
		hbHeader:   hbHeader,
		encryptKey: keyBytes,
		profileRaw: config,
		profile:    profile,
		ts:         ts,
	}
	// Always include X-Beacon-Id as the pre-profile bootstrap header.
	// The Linux agent sends REGISTER with X-Beacon-Id (profile not loaded yet),
	// then switches to the profile's beacon_id_hdr for subsequent GETs.
	if hbHeader != "X-Beacon-Id" {
		s.beaconIDHeaders = []string{hbHeader, "X-Beacon-Id"}
	} else {
		s.beaconIDHeaders = []string{hbHeader}
	}
	s.loadProfileOverrides()
	return s, nil
}

func (s *httpServer) bindHost() string             { return s.host }
func (s *httpServer) bindPort() int                { return s.port }
func (s *httpServer) profileJSON() ([]byte, error) { return []byte(s.profileRaw), nil }
func (s *httpServer) edit(config string) (adaptix.ListenerData, []byte, error) {
	return adaptix.ListenerData{}, nil, errors.New("listener edit is not available right now — use the per-agent profile command instead")
}

func (s *httpServer) start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.srv != nil {
		return errors.New("listener: already started")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.rootHandler)

	naxListenerLogInfo("start: URIs=%v  ssl=%v", s.uri, s.ssl)
	naxListenerLogInfo("start: beacon_id=%s  error=%d", s.hbHeader, s.profile.Error.Status)

	addr := net.JoinHostPort(s.host, strconv.Itoa(s.port))
	s.srv = &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 120 * time.Second}

	if s.ssl {
		certPath, keyPath, err := s.writeTLSFiles()
		if err != nil {
			s.srv = nil
			return fmt.Errorf("listener: TLS setup: %w", err)
		}
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			s.srv = nil
			return fmt.Errorf("listener: load certificate: %w", err)
		}
		s.srv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"http/1.1"},
		}
		go func() { _ = s.srv.ListenAndServeTLS("", "") }()
	} else {
		go func() { _ = s.srv.ListenAndServe() }()
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if s.ssl {
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 50 * time.Millisecond}, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
			if err == nil {
				_ = conn.Close()
				return nil
			}
		} else {
			conn, err := net.DialTimeout("tcp", addr, 20*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				return nil
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	return errors.New("listener: bind " + addr + " did not become ready in 500ms")
}

func (s *httpServer) writeTLSFiles() (certPath, keyPath string, err error) {
	dir := filepath.Join(ListenerDataDir, s.name)
	if _, statErr := os.Stat(dir); os.IsNotExist(statErr) {
		if err = os.MkdirAll(dir, os.ModePerm); err != nil {
			return "", "", fmt.Errorf("create listener dir: %w", err)
		}
	}
	certPath = filepath.Join(dir, "listener.crt")
	keyPath = filepath.Join(dir, "listener.key")
	if err = os.WriteFile(certPath, s.sslCert, 0600); err != nil {
		return "", "", fmt.Errorf("write cert: %w", err)
	}
	if err = os.WriteFile(keyPath, s.sslKey, 0600); err != nil {
		return "", "", fmt.Errorf("write key: %w", err)
	}
	return certPath, keyPath, nil
}

func (s *httpServer) stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := s.srv.Shutdown(ctx)
	s.srv = nil
	return err
}

func (s *httpServer) buildProfileFrame() []byte {
	body := EncodeProfileBodyV2(s.profile)
	return EncodeFrame(WireTypeProfile, body)
}

// beaconHandler - profile-driven handler with OutputConfig transforms.
//  1. Determine GET or POST.
//  2. Extract beaconID from the configured ClientMeta placement.
//  3. For GET: decode client data from ClientMeta (cookie/header/param).
//     For POST: extract data from ClientOutput placement.
//  4. Apply reverse transforms (strip prepend/append, decode, unmask, decrypt).
//  5. Route to agent create/process.
//  6. Build response with forward transforms.
//
// For backward compatibility with beacons that haven't received a v2 profile
// yet, the handler falls back to the legacy hbHeader extraction when the
// profile's ClientMeta is in the default "raw header" mode.
func (s *httpServer) rootHandler(w http.ResponseWriter, r *http.Request) {
	s.pollProfileStore()

	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		s.errorHandler(w, r)
		return
	}

	// Try to extract a valid beaconID from any known header.
	var beaconID string
	for _, hdr := range s.beaconIDHeaders {
		candidate := r.Header.Get(hdr)
		if isValidBeaconID(candidate) {
			beaconID = candidate
			break
		}
	}
	if beaconID == "" {
		s.forceReloadProfiles()
		for _, hdr := range s.beaconIDHeaders {
			candidate := r.Header.Get(hdr)
			if isValidBeaconID(candidate) {
				beaconID = candidate
				break
			}
		}
	}
	if beaconID == "" {
		s.errorHandler(w, r)
		return
	}

	s.beaconHandler(w, r, beaconID)
}

// tryDecodeWithProfile attempts to extract and decrypt client data using a
// specific profile's transaction config. Returns (plaintext, tx, error).
// For POST requests, rawBody must be pre-read since http.Request.Body is
// single-read; for GET requests rawBody is ignored.
func (s *httpServer) tryDecodeWithProfile(r *http.Request, isGet bool, profile *ProfileConfig, rawBody []byte) ([]byte, *HTTPTransaction, error) {
	var tx *HTTPTransaction
	if isGet {
		tx = &profile.Get
	} else {
		tx = &profile.Post
	}

	if isGet {
		rawMeta, err := extractMeta(&tx.ClientMeta, r)
		if err != nil || rawMeta == "" {
			return nil, nil, errors.New("meta extraction failed")
		}
		decoded, err := decodeClientInput(&tx.ClientMeta, []byte(rawMeta))
		if err != nil {
			return nil, nil, err
		}
		return decoded, tx, nil
	}

	clientOutput := tx.ClientOutput
	if clientOutput == nil {
		clientOutput = &OutputConfig{Format: "raw", Placement: "body"}
	}
	decoded, err := decodeClientInput(clientOutput, rawBody)
	if err != nil {
		if clientOutput.Format == "raw" || clientOutput.Format == "" {
			return nil, nil, err
		}
		return rawBody, tx, nil
	}
	return decoded, tx, nil
}

func (s *httpServer) beaconHandler(w http.ResponseWriter, r *http.Request, beaconID string) {
	isGet := r.Method == http.MethodGet

	// Pre-read POST body so we can retry with different profiles.
	var rawBody []byte
	if !isGet {
		body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, 32<<20))
		if err != nil {
			naxListenerLogErr("POST body read error beacon=%s: %v", beaconID, err)
			s.errorHandler(w, r)
			return
		}
		rawBody = body
	}

	// Build list of profiles to try: current override, previous override, then
	// agent hasn't applied it yet), the agent is still sending with the old
	// profile. Keeping the previous override ensures we can decode regardless
	// of which profile the agent is currently using.
	profilesToTry := []*ProfileConfig{s.profile}
	// v2: agentProfiles/agentPrevProfiles keyed by beaconID (string)
	if override, ok := s.agentProfiles.Load(beaconID); ok {
		profilesToTry = append([]*ProfileConfig{override.(*ProfileConfig)}, s.profile)
	} else if prev, ok := s.agentPrevProfiles.Load(beaconID); ok {
		profilesToTry = append([]*ProfileConfig{prev.(*ProfileConfig)}, s.profile)
	}

	var clientData []byte
	var tx *HTTPTransaction
	for i, prof := range profilesToTry {
		decoded, usedTx, err := s.tryDecodeWithProfile(r, isGet, prof, rawBody)
		if err == nil {
			clientData = decoded
			tx = usedTx
			break
		}
		_ = i // profile index unused without debug logging
	}
	if clientData == nil {
		naxListenerLogErr("beaconHandler: all profile decode attempts failed beacon=%s method=%s bodyLen=%d profiles=%d", beaconID, r.Method, len(rawBody), len(profilesToTry))
		s.errorHandler(w, r)
		return
	}

	// Step 3: Route the beacon using the server-assigned adaptixID, not the raw beaconID.
	// clientData is AES-encrypted; the server's Agent.ProcessData calls Extender.Decrypt.
	var adaptixID int64
	register := false

	if cachedID, ok := s.agentIDMap.Load(beaconID); ok {
		candidate := cachedID.(int64)
		if s.ts != nil && s.ts.TsAgentIsExists(candidate) {
			adaptixID = candidate
			_ = s.ts.TsAgentProcessData(adaptixID, clientData)
		} else {
			s.agentIDMap.Delete(beaconID)
			register = true
		}
	} else {
		register = true
	}

	if register && s.ts != nil {
		// v2: resolve by UID bytes — replaces TsAgentIsExists(string)
		if agentId, exists := s.ts.TsAgentIdByUID([]byte(beaconID)); exists {
			adaptixID = agentId
			s.agentIDMap.Store(beaconID, adaptixID)
			_ = s.ts.TsAgentProcessData(adaptixID, clientData)
		} else {
			remoteAddr, _, splitErr := net.SplitHostPort(r.RemoteAddr)
			if splitErr != nil {
				remoteAddr = r.RemoteAddr
			}
			beatWithId := make([]byte, 16+16+len(clientData))
			copy(beatWithId[:16], beaconID)
			copy(beatWithId[16:32], s.encryptKey)
			copy(beatWithId[32:], clientData)
			// v2: agentUid=[]byte(beaconID) separate; beat keeps beaconID prefix
			agentDataRes, err := s.ts.TsAgentCreate(agentWatermark, []byte(beaconID), beatWithId, s.name, remoteAddr, true)
			if err == nil {
				adaptixID = agentDataRes.Id
				s.agentIDMap.Store(beaconID, adaptixID)
				s.pendingProfile.Store(beaconID, true)
			}
		}
	}

	// Stamp LastTick
	if adaptixID != 0 && s.ts != nil {
		_ = s.ts.TsAgentSetTick(adaptixID, s.name)
	}

	// Step 4: Build and send response.
	// Use the same tx that successfully decoded the request - this ensures
	// the response is encoded in the format the agent currently expects.
	//
	// POST responses MUST NOT deliver tasks: the beacon only processes task
	// frames from the heartbeat GET response.  TsAgentGetHostedAll marks
	// tasks as dispatched, so including them in a POST response the beacon
	// ignores silently drops them.
	pending, _ := s.pendingProfile.LoadAndDelete(beaconID)
	if pending != nil && len(s.profile.Get.URIs) > 0 {
		s.writeProfileResponse(w, tx, beaconID)
	} else if isGet {
		s.writeResponseOrNoTasks(w, adaptixID, tx)
	} else {
		// POST response — send NO_TASKS (tasks are delivered via GET only)
		s.writeNoTasks(w, tx)
	}
}

// writeServerResponse encrypts payload, applies forward transforms per the
// transaction's ServerOutput, sets server headers, and writes the response.
func (s *httpServer) writeServerResponse(w http.ResponseWriter, tx *HTTPTransaction, payload []byte) {
	encoded, err := encodeServerOutput(&tx.ServerOutput, payload)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if tx.ServerHeaders != nil {
		for k, v := range tx.ServerHeaders {
			w.Header().Set(k, v)
		}
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	// Explicit Content-Length prevents chunked transfer encoding,
	// which confuses pre-profile agents that parse the response manually.
	w.Header().Set("Content-Length", strconv.Itoa(len(encoded)))
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(encoded)
}

func (s *httpServer) writeNoTasks(w http.ResponseWriter, tx *HTTPTransaction) {
	// If the profile defines an EmptyResp for the server output, use it.
	if tx.ServerOutput.EmptyResp != "" {
		body := []byte(tx.ServerOutput.EmptyResp)
		if tx.ServerHeaders != nil {
			for k, v := range tx.ServerHeaders {
				w.Header().Set(k, v)
			}
		} else {
			w.Header().Set("Content-Type", "application/octet-stream")
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
		return
	}

	// Default: locally-encrypted NO_TASKS frame (not routed through server PackData)
	frame := EncodeFrame(WireTypeNoTasks, nil)
	encrypted, err := EncryptCBCRandomIV(s.encryptKey, frame)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.writeServerResponse(w, tx, encrypted)
}

// writeResponseOrNoTasks checks whether the server has any pre-packed task
// bytes for this agent (via TsAgentGetHostedAll) and sends them encrypted.
// Falls back to a NO_TASKS frame when nothing is queued.
func (s *httpServer) writeResponseOrNoTasks(w http.ResponseWriter, agentId int64, tx *HTTPTransaction) {
	var payload []byte

	if s.ts != nil {
		hosted, _, err := s.ts.TsAgentGetHostedAll(agentId, 0x12c0000)
		if err == nil && len(hosted) > 0 {
			// TsAgentGetHostedAll returns data with a 4-byte LE length prefix
			// (same format as TCP transport lpWrite). Strip it before encoding
			// for HTTPS so the agent receives raw AES-CBC task frames.
			if len(hosted) >= 4 {
				dataLen := int(hosted[0]) | int(hosted[1])<<8 | int(hosted[2])<<16 | int(hosted[3])<<24
				if dataLen > 0 && dataLen+4 <= len(hosted) {
					hosted = hosted[4 : 4+dataLen]
				}
			}
			payload = hosted
		}
	}

	if len(payload) == 0 {
		s.writeNoTasks(w, tx)
		return
	}

	s.writeServerResponse(w, tx, payload)
}

func (s *httpServer) writeProfileResponse(w http.ResponseWriter, tx *HTTPTransaction, beaconID string) {
	var profileFrame []byte
	if override, ok := s.agentProfiles.Load(beaconID); ok {
		body := EncodeProfileBodyV2(override.(*ProfileConfig))
		profileFrame = EncodeFrame(WireTypeProfile, body)
	}
	if profileFrame == nil {
		profileFrame = s.buildProfileFrame()
	}
	encrypted, err := EncryptCBCRandomIV(s.encryptKey, profileFrame)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// The PROFILE response must be sent as raw bytes (no base64/mask encoding)
	// so that pre-profile agents (Linux) can decrypt it with plain AES-CBC.
	// Use a raw tx to bypass any ServerOutput transforms from the profile.
	rawTx := &HTTPTransaction{
		ServerOutput: OutputConfig{Format: "raw", Placement: "body"},
	}
	if tx != nil && tx.ServerHeaders != nil {
		rawTx.ServerHeaders = tx.ServerHeaders
	}
	s.writeServerResponse(w, rawTx, encrypted)
	naxListenerLogOk("PROFILE v2 frame sent")
}

func (s *httpServer) errorHandler(w http.ResponseWriter, _ *http.Request) {
	for k, v := range s.profile.Error.Headers {
		w.Header().Set(k, v)
	}
	w.WriteHeader(s.profile.Error.Status)
	_, _ = w.Write([]byte(s.profile.Error.Body))
}

// isValidBeaconID -- exactly 16 hex chars per docs/protocol/wire-v0.md.
func isValidBeaconID(s string) bool {
	if len(s) != 16 {
		return false
	}
	for _, c := range s {
		switch {
		case '0' <= c && c <= '9', 'a' <= c && c <= 'f', 'A' <= c && c <= 'F':
		default:
			return false
		}
	}
	return true
}
