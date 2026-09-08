package main

import (
	"encoding/json"
	"errors"
	"fmt"

	adaptix "github.com/Adaptix-Framework/axc2/v2"
)

type cachedAgentIdentity struct {
	Computer   string
	Username   string
	Pid        string
	Tid        string
	Arch       string
	Sleep      uint
	InternalIP string
	Domain     string
	Process    string
	Elevated   bool
	OsDesc     string
}

func loadCacheFromStore() {
	if Ts == nil {
		return
	}
	keys, err := Ts.TsExtenderDataKeys(extenderNameAgents)
	if err != nil || len(keys) == 0 {
		return
	}
	count := 0
	for _, key := range keys {
		raw, err := Ts.TsExtenderDataLoad(extenderNameAgents, key)
		if err != nil || len(raw) == 0 {
			continue
		}
		var e cachedAgentIdentity
		if err := json.Unmarshal(raw, &e); err != nil {
			continue
		}
		ad := adaptix.AgentData{
			Computer: e.Computer, Username: e.Username, Pid: e.Pid,
			Tid: e.Tid, Arch: e.Arch, Sleep: e.Sleep,
			InternalIP: e.InternalIP, Domain: e.Domain,
			Process: e.Process, Elevated: e.Elevated,
			OsDesc: e.OsDesc,
		}
		agentIdentityCache.Store(key, ad)
		count++
	}
	naxLogInfo("loadCacheFromStore: loaded %d linux agent(s)", count)
}

func saveCacheEntry(beaconID string, ad adaptix.AgentData) {
	if Ts == nil {
		return
	}
	e := cachedAgentIdentity{
		Computer: ad.Computer, Username: ad.Username, Pid: ad.Pid,
		Tid: ad.Tid, Arch: ad.Arch, Sleep: ad.Sleep,
		InternalIP: ad.InternalIP, Domain: ad.Domain,
		Process: ad.Process, Elevated: ad.Elevated,
		OsDesc: ad.OsDesc,
	}
	data, err := json.Marshal(e)
	if err != nil {
		naxLogErr("saveCacheEntry: %v", err)
		return
	}
	if err := Ts.TsExtenderDataSave(extenderNameAgents, beaconID, data); err != nil {
		naxLogErr("saveCacheEntry: save error: %v", err)
	}
}

func registerCleanupHooks() {
	if Ts == nil {
		return
	}
	// Cleanup cache and extender store when agent is terminated or removed
	Ts.TsEventHookRegister("agent.terminate", "nax_linux_cleanup", 1, 0, func(data any) error {
		agentId, ok := data.(int64)
		if !ok {
			return nil
		}
		agentIdentityCache.Delete(agentId)
		key := fmt.Sprintf("%d", agentId)
		_ = Ts.TsExtenderDataDelete(extenderNameAgents, key)
		_ = Ts.TsExtenderDataDelete(extenderNameProfiles, key)
		naxLogInfo("agent.terminate cleanup: linux agent %d", agentId)
		return nil
	})
	// Auto-create or update target when a new linux agent registers
	Ts.TsEventHookRegister("agent.create", "nax_linux_target", 1, 0, func(data any) error {
		agentData, ok := data.(adaptix.AgentData)
		if !ok {
			return nil
		}
		if agentData.Os != adaptix.OS_LINUX {
			return nil
		}
		if _, err := Ts.TsTargetsCreateAlive(agentData); err != nil {
			naxLogErr("agent.create: TsTargetsCreateAlive: %v", err)
		}
		return nil
	})
}

//   [beaconID(16)][aesKey(16)][encrypted_frame]
func (p *PluginAgent) CreateAgent(beat []byte) (adaptix.AgentData, adaptix.AgentFunctions, error) {
	if len(beat) < 32 {
		return adaptix.AgentData{}, adaptix.AgentFunctions{},
			errors.New("linux agent: CreateAgent: beat too short")
	}

	beaconID := string(beat[:16])
	aesKey   := make([]byte, 16)
	copy(aesKey, beat[16:32])
	frameData := beat[32:]

	ad := adaptix.AgentData{
		UID:        []byte(beaconID),
		Name:       beaconID,
		Os:         adaptix.OS_LINUX,
		SessionKey: aesKey,
	}

	naxLogInfo("CreateAgent (linux): beaconID=%s keyPrefix=%x frameDataLen=%d",
		beaconID, aesKey[:4], len(frameData))

	decrypted, err := DecryptCBC(aesKey, frameData)
	if err != nil {
		naxLogErr("CreateAgent (linux): decrypt failed beaconID=%s: %v", beaconID, err)
		return ad, p.AgentRestore(ad), nil
	}

	msgType, _, body, err := DecodeFrame(decrypted)
	if err != nil {
		naxLogErr("CreateAgent (linux): DecodeFrame failed: %v", err)
		return ad, p.AgentRestore(ad), nil
	}

	naxLogInfo("CreateAgent (linux): frame type=0x%02x bodyLen=%d", msgType, len(body))

	if msgType != WireTypeRegister {
		if cached, ok := agentIdentityCache.Load(beaconID); ok {
			cachedAd := cached.(adaptix.AgentData)
			ad.Computer   = cachedAd.Computer
			ad.Username   = cachedAd.Username
			ad.Pid        = cachedAd.Pid
			ad.Tid        = cachedAd.Tid
			ad.Arch       = cachedAd.Arch
			ad.Sleep      = cachedAd.Sleep
			ad.InternalIP = cachedAd.InternalIP
			ad.Domain     = cachedAd.Domain
			ad.Process    = cachedAd.Process
			ad.Elevated   = cachedAd.Elevated
			ad.OsDesc     = cachedAd.OsDesc
		}
		return ad, p.AgentRestore(ad), nil
	}

	reg, err := DecodeRegister(body)
	if err != nil {
		return adaptix.AgentData{}, adaptix.AgentFunctions{},
			fmt.Errorf("linux agent: DecodeRegister: %w", err)
	}

	arch := archString(reg.Arch)

	ad.Computer   = reg.Hostname
	ad.Username   = reg.Username
	ad.Pid        = fmt.Sprintf("%d", reg.Pid)
	ad.Tid        = fmt.Sprintf("%d", reg.Tid)
	ad.Arch       = arch
	ad.Sleep      = uint(reg.SleepMs / 1000)
	ad.InternalIP = reg.Ip
	ad.Domain     = reg.Domain
	ad.Process    = reg.ProcessName
	ad.Elevated   = reg.Elevated != 0
	ad.OsDesc     = linuxOsDesc(reg.OsMajor, reg.OsMinor, reg.OsBuild, arch)

	naxLogOk("CreateAgent (linux): beaconID=%s host=%s user=%s pid=%s arch=%s ip=%s elevated=%v os=%s",
		beaconID, ad.Computer, ad.Username, ad.Pid, ad.Arch, ad.InternalIP, ad.Elevated, ad.OsDesc)

	agentIdentityCache.Store(beaconID, ad)
	saveCacheEntry(beaconID, ad)

	return ad, p.AgentRestore(ad), nil
}
