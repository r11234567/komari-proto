package tests

import (
	"testing"
	"time"

	execv1 "github.com/r11234567/komari-proto/gen/go/komari/exec/v1"
	metricsv1 "github.com/r11234567/komari-proto/gen/go/komari/metrics/v1"
	reportv1 "github.com/r11234567/komari-proto/gen/go/komari/report/v1"
	rescuev1 "github.com/r11234567/komari-proto/gen/go/komari/rescue/v1"
	securityv1 "github.com/r11234567/komari-proto/gen/go/komari/security/v1"
	websshv1 "github.com/r11234567/komari-proto/gen/go/komari/webssh/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestExecutionAssignment_WireCompatibility(t *testing.T) {
	// 1. Verify field numbers via descriptor reflection
	msgDesc := (&execv1.ExecutionAssignment{}).ProtoReflect().Descriptor()
	specField := msgDesc.Fields().ByName("spec")
	if specField == nil {
		t.Fatal("expected ExecutionAssignment to contain field 'spec'")
	}
	if specField.Number() != 4 {
		t.Fatalf("expected 'spec' field to have wire tag 4, got %d", specField.Number())
	}
	fieldOpts, ok := specField.Options().(*descriptorpb.FieldOptions)
	if !ok || !fieldOpts.GetDeprecated() {
		t.Fatal("expected 'spec' field to be marked deprecated in ExecutionAssignment")
	}

	envelopeField := msgDesc.Fields().ByName("envelope")
	if envelopeField == nil {
		t.Fatal("expected ExecutionAssignment to contain field 'envelope'")
	}
	if envelopeField.Number() != 5 {
		t.Fatalf("expected 'envelope' field to have wire tag 5, got %d", envelopeField.Number())
	}

	// 2. Wire compatibility: serialize with legacy spec (tag 4) and ensure deserialization works
	legacySpec := &execv1.ExecutionSpec{
		Command:          "echo",
		Arguments:        []string{"legacy wire compatibility"},
		WorkingDirectory: "/tmp",
		Timeout:          durationpb.New(10 * time.Second),
		MaxOutputBytes:   4096,
	}

	legacyAssignment := &execv1.ExecutionAssignment{
		AssignmentId:   "legacy-assign-01",
		LeaseExpiresAt: timestamppb.Now(),
		Spec:           legacySpec,
	}

	data, err := proto.Marshal(legacyAssignment)
	if err != nil {
		t.Fatalf("failed to marshal legacy assignment: %v", err)
	}

	var decoded execv1.ExecutionAssignment
	if err := proto.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal assignment with field 4: %v", err)
	}
	if decoded.GetSpec() == nil {
		t.Fatal("expected decoded spec to be non-nil")
	}
	if decoded.GetSpec().GetCommand() != "echo" {
		t.Fatalf("expected command 'echo', got %q", decoded.GetSpec().GetCommand())
	}

	// 3. Serialize with new envelope (tag 5)
	envelope := &securityv1.SignedEnvelope{
		Payload: []byte("payload-data"),
		Signatures: []*securityv1.Signature{
			{
				KeyId:     "key-1",
				Algorithm: securityv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519,
				Value:     []byte("sig-data"),
			},
		},
	}
	newAssignment := &execv1.ExecutionAssignment{
		AssignmentId: "new-assign-01",
		Spec:         legacySpec,
		Envelope:     envelope,
	}

	newData, err := proto.Marshal(newAssignment)
	if err != nil {
		t.Fatalf("failed to marshal assignment with both spec and envelope: %v", err)
	}

	var decodedBoth execv1.ExecutionAssignment
	if err := proto.Unmarshal(newData, &decodedBoth); err != nil {
		t.Fatalf("failed to unmarshal dual assignment: %v", err)
	}
	if decodedBoth.GetSpec() == nil || decodedBoth.GetSpec().GetCommand() != "echo" {
		t.Fatalf("spec field 4 corrupted in dual assignment")
	}
	if decodedBoth.GetEnvelope() == nil || string(decodedBoth.GetEnvelope().GetPayload()) != "payload-data" {
		t.Fatalf("envelope field 5 corrupted in dual assignment")
	}
}

func TestRescueAssignment_WireCompatibility(t *testing.T) {
	msgDesc := (&rescuev1.RescueAssignment{}).ProtoReflect().Descriptor()
	sessionField := msgDesc.Fields().ByName("session")
	if sessionField == nil {
		t.Fatal("expected RescueAssignment to contain field 'session'")
	}
	if sessionField.Number() != 2 {
		t.Fatalf("expected 'session' field to have wire tag 2, got %d", sessionField.Number())
	}
	sessionOpts, ok := sessionField.Options().(*descriptorpb.FieldOptions)
	if !ok || !sessionOpts.GetDeprecated() {
		t.Fatal("expected 'session' field to be marked deprecated in RescueAssignment")
	}

	envelopeField := msgDesc.Fields().ByName("envelope")
	if envelopeField == nil {
		t.Fatal("expected RescueAssignment to contain field 'envelope'")
	}
	if envelopeField.Number() != 4 {
		t.Fatalf("expected 'envelope' field to have wire tag 4, got %d", envelopeField.Number())
	}
}

func TestDeprecatedRPCs_Enforcement(t *testing.T) {
	// 1. ReportService.SubmitReport must be deprecated
	reportServiceDesc := reportv1.File_komari_report_v1_report_proto.Services().ByName("AgentReportService")
	if reportServiceDesc == nil {
		t.Fatal("expected AgentReportService in report.proto")
	}
	submitMethod := reportServiceDesc.Methods().ByName("SubmitReport")
	if submitMethod == nil {
		t.Fatal("expected SubmitReport method in AgentReportService")
	}
	methodOpts, ok := submitMethod.Options().(*descriptorpb.MethodOptions)
	if !ok || !methodOpts.GetDeprecated() {
		t.Fatal("expected SubmitReport method to be marked deprecated")
	}

	// 2. WebSSHService legacy polling methods must be deprecated
	websshServiceDesc := websshv1.File_komari_webssh_v1_webssh_proto.Services().ByName("WebSSHService")
	if websshServiceDesc == nil {
		t.Fatal("expected WebSSHService in webssh.proto")
	}
	legacyMethods := []string{
		"CreateSession",
		"SendSessionCommand",
		"WatchSession",
		"AcknowledgeSessionEvents",
		"CloseSession",
	}
	for _, methodName := range legacyMethods {
		m := websshServiceDesc.Methods().ByName(protoreflect.Name(methodName))
		if m == nil {
			t.Fatalf("expected method %s in WebSSHService", methodName)
		}
		opts, ok := m.Options().(*descriptorpb.MethodOptions)
		if !ok || !opts.GetDeprecated() {
			t.Fatalf("expected method %s to be marked deprecated", methodName)
		}
	}

	// Active methods must NOT be deprecated
	activeMethods := []string{
		"OpenSession",
		"LeaseSessions",
		"AttachSession",
	}
	for _, methodName := range activeMethods {
		m := websshServiceDesc.Methods().ByName(protoreflect.Name(methodName))
		if m == nil {
			t.Fatalf("expected active method %s in WebSSHService", methodName)
		}
		opts, ok := m.Options().(*descriptorpb.MethodOptions)
		if ok && opts.GetDeprecated() {
			t.Fatalf("expected active method %s NOT to be marked deprecated", methodName)
		}
	}

	// 3. MetricsService UploadMetrics and StreamMetrics
	metricsServiceDesc := metricsv1.File_komari_metrics_v1_metrics_proto.Services().ByName("MetricsService")
	if metricsServiceDesc == nil {
		t.Fatal("expected MetricsService in metrics.proto")
	}
	for _, methodName := range []string{"UploadMetrics", "StreamMetrics"} {
		m := metricsServiceDesc.Methods().ByName(protoreflect.Name(methodName))
		if m == nil {
			t.Fatalf("expected method %s in MetricsService", methodName)
		}
		opts, ok := m.Options().(*descriptorpb.MethodOptions)
		if !ok || !opts.GetDeprecated() {
			t.Fatalf("expected method %s to be marked deprecated", methodName)
		}
	}
}
