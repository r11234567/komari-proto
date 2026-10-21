package tests

import (
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	hostv1 "github.com/r11234567/komari-proto/gen/go/komari/host/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"testing"
)

func TestPrivilegedV2PreservesLegacyWire(t *testing.T) {
	// Field numbers are from the released v1 message, not generated v2 code.
	b := protowire.AppendTag(nil, 1, protowire.BytesType)
	b = protowire.AppendString(b, "node")
	b = protowire.AppendTag(b, 2, protowire.VarintType)
	b = protowire.AppendVarint(b, 7)
	b = protowire.AppendTag(b, 5, protowire.VarintType)
	b = protowire.AppendVarint(b, 2)
	var r configv1.PrivilegedRevision
	if err := proto.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	if r.AgentId != "node" || r.Revision != 7 || r.State != configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_NEEDS_MANUAL_AUTHORIZATION {
		t.Fatalf("legacy interpretation changed: %v", &r)
	}
	if r.ProtocolVersion != 0 || r.Authorization != nil {
		t.Fatal("legacy message fabricated v2 approval")
	}
}
func TestPrivilegedV2RoundTripApprovalAndSequence(t *testing.T) {
	r := &configv1.PrivilegedRevision{AgentId: "node", Revision: 1, UpdateSequence: 9, ApprovalGeneration: 2, ProtocolVersion: 2, Authorization: &hostv1.HostAuthorization{AgentId: "node", Revision: 1, ServiceId: "custom.service", ApprovalGeneration: 2, Actions: []hostv1.HostAction{hostv1.HostAction_HOST_ACTION_INSTALL_RESCUE_HELPER}}}
	b, err := proto.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var out configv1.PrivilegedRevision
	if err := proto.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(r, &out) {
		t.Fatal("approval binding was lost")
	}
	if int32(configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_FAILED) != 5 {
		t.Fatal("legacy enum renumbered")
	}
}
