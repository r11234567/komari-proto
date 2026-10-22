package tests

import (
	"testing"

	deploymentv1 "github.com/r11234567/komari-proto/gen/go/komari/deployment/v1"
	reportv1 "github.com/r11234567/komari-proto/gen/go/komari/report/v1"
	"google.golang.org/protobuf/proto"
)

func TestInstallationObservationPreservesUnknownAndExplicitFalse(t *testing.T) {
	no := false
	observation := &reportv1.InstallationObservation{OperatingSystem: "windows", Executable: `C:\Program Files\Komari\komari-agent.exe`, IgnoreUnsafeCertificate: &no}
	wire, err := proto.Marshal(&deploymentv1.GetDeploymentResponse{Installation: observation})
	if err != nil {
		t.Fatal(err)
	}
	var decoded deploymentv1.GetDeploymentResponse
	if err := proto.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	got := decoded.GetInstallation()
	if got == nil || got.IgnoreUnsafeCertificate == nil || *got.IgnoreUnsafeCertificate || got.DisableAutoUpdate != nil || got.GetExecutable() != observation.Executable {
		t.Fatal("installation observation lost explicit false, unknown, or Windows path")
	}
	if (&deploymentv1.GetDeploymentResponse{}).GetInstallation() != nil || (&reportv1.AgentMetadata{}).GetInstallation() != nil {
		t.Fatal("old peers must have no fabricated installation observation")
	}
}
