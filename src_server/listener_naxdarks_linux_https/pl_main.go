package main

import (
	"fmt"
	"strings"

	adaptix "github.com/Adaptix-Framework/axc2/v2"
)

// Teamserver mirrors the adaptix.Teamserver interface methods used by this listener.
// Updated to match axc2 v3: TsAgentGetHostedAll now returns ([]byte, StatTasks, error).
type Teamserver interface {
	TsAgentIdByUID(uid []byte) (int64, bool)
	TsAgentIsExists(agentId int64) bool
	TsAgentCreate(agentCrc string, agentUid []byte, beat []byte,
		listenerName, ExternalIP string, Async bool) (adaptix.AgentData, error)
	TsAgentProcessData(agentId int64, bodyData []byte) error
	// Updated signature: now returns StatTasks as second value.
	TsAgentGetHostedAll(agentId int64, maxSize int) ([]byte, adaptix.StatTasks, error)
	TsAgentSetTick(agentId int64, listenerName string) error

	TsExtenderDataLoad(extenderName, key string) ([]byte, error)
	TsExtenderDataKeys(extenderName string) ([]string, error)
}

type PluginListener struct{}

type extenderListener struct {
	name string
	srv  *httpServer
}

var (
	Ts              Teamserver
	ModuleDir       string
	ListenerDataDir string
)

func InitPlugin(ts any, moduleDir string, listenerDir string) adaptix.PluginListener {
	ModuleDir = moduleDir
	ListenerDataDir = listenerDir
	if ts != nil {
		Ts, _ = ts.(Teamserver)
	}
	return &PluginListener{}
}

func (p *PluginListener) Call(operator string, listenerName string, function string, args string) {
}

func (p *PluginListener) Create(name, config string, customData []byte) (adaptix.ExtenderListener, adaptix.ListenerData, []byte, error) {
	srv, err := newHTTPServer(name, config, Ts)
	if err != nil {
		return nil, adaptix.ListenerData{}, nil, err
	}
	agentAddr := ""
	if len(srv.profile.Hosts) > 0 {
		agentAddr = strings.Join(srv.profile.Hosts, ", ")
	}
	proto := "http"
	if srv.ssl {
		proto = "https"
	}
	listenerData := adaptix.ListenerData{
		Name:      name,
		BindHost:  srv.bindHost(),
		BindPort:  fmt.Sprintf("%d", srv.bindPort()),
		AgentAddr: agentAddr,
		Protocol:  proto,
		Type:      "external",
		Status:    "stopped",
	}
	return &extenderListener{name: name, srv: srv}, listenerData, []byte(config), nil
}

func (a *extenderListener) Start() error {
	return a.srv.start()
}

func (a *extenderListener) Stop() error {
	return a.srv.stop()
}

func (a *extenderListener) Edit(config string) (adaptix.ListenerData, []byte, error) {
	return a.srv.edit(config)
}

func (a *extenderListener) GetProfile() ([]byte, error) {
	return a.srv.profileJSON()
}

func (a *extenderListener) InternalHandler(data []byte) (int64, error) {
	naxListenerLogInfo("InternalHandler: data len=%d", len(data))
	if len(data) < 17 {
		return 0, fmt.Errorf("InternalHandler: data too short (%d)", len(data))
	}
	beaconID := string(data[:16])
	ciphertext := data[16:]
	naxListenerLogInfo("InternalHandler: beaconID=%s ciphertextLen=%d keyPrefix=%x", beaconID, len(ciphertext), a.srv.encryptKey[:4])

	beatWithId := make([]byte, 16+16+len(ciphertext))
	copy(beatWithId[:16], beaconID)
	copy(beatWithId[16:32], a.srv.encryptKey)
	copy(beatWithId[32:], ciphertext)

	agentData, err := a.srv.ts.TsAgentCreate(agentWatermark, []byte(beaconID), beatWithId, a.name, "0.0.0.0", false)
	if err != nil {
		naxListenerLogErr("InternalHandler: TsAgentCreate failed: %v", err)
		return 0, fmt.Errorf("InternalHandler: TsAgentCreate: %w", err)
	}
	naxListenerLogInfo("InternalHandler: child agent created id=%d", agentData.Id)
	a.srv.agentIDMap.Store(beaconID, agentData.Id)
	return agentData.Id, nil
}

func main() {}
