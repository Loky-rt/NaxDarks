package main

import (
	"encoding/json"
	"fmt"
)

const extenderNameProfiles = "nax_profiles"

func saveProfileToStore(agentId string, profile *ProfileConfig) error {
	if Ts == nil {
		return fmt.Errorf("teamserver not available")
	}
	data, err := json.Marshal(map[string]any{
		"beacon_id_header": profile.BeaconIdHeader,
		"profile":          profile,
	})
	if err != nil {
		return err
	}
	return Ts.TsExtenderDataSave(extenderNameProfiles, agentId, data)
}

func removeProfileFromStore(agentId string) {
	if Ts == nil {
		return
	}
	if err := Ts.TsExtenderDataDelete(extenderNameProfiles, agentId); err != nil {
		naxLogErr("removeProfileFromStore: %v", err)
	}
}
