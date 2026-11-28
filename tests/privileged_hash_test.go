package tests

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivilegedSettingsHashVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "testdata", "privileged-settings-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Booleans                 [5]byte `json:"booleans"`
		Mode                     uint32  `json:"required_privilege_mode"`
		RootExecutionAllowed     bool    `json:"root_execution_allowed"`
		TrafficMonitoringEnabled bool    `json:"traffic_monitoring_enabled"`
		Hash                     string  `json:"sha256"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	sawRoot := false
	for _, v := range vectors {
		payload := append([]byte("komari.privileged-settings.v1\x00"), v.Booleans[:]...)
		payload = binary.BigEndian.AppendUint32(payload, v.Mode)
		if v.RootExecutionAllowed {
			sawRoot = true
			payload = append(payload, "\x00root_execution_allowed\x01"...)
		}
		if v.TrafficMonitoringEnabled {
			payload = append(payload, "\x00traffic_monitoring_enabled\x01"...)
		}
		hash := sha256.Sum256(payload)
		if got := hex.EncodeToString(hash[:]); got != v.Hash {
			t.Errorf("mode %d, root execution %t: hash %s, want %s", v.Mode, v.RootExecutionAllowed, got, v.Hash)
		}
	}
	if !sawRoot {
		t.Fatal("missing root-execution hash vector")
	}
}
