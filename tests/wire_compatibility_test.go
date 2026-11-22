package tests

import (
	"testing"
	"time"

	browserv1 "github.com/r11234567/komari-proto/gen/go/komari/browser/v1"
	execv1 "github.com/r11234567/komari-proto/gen/go/komari/exec/v1"
	filev1 "github.com/r11234567/komari-proto/gen/go/komari/file/v1"
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

	// 2. WebSSHService browser RPCs and agent streams are active; OpenSession is removed.
	websshServiceDesc := websshv1.File_komari_webssh_v1_webssh_proto.Services().ByName("WebSSHService")
	if websshServiceDesc == nil {
		t.Fatal("expected WebSSHService in webssh.proto")
	}
	if m := websshServiceDesc.Methods().ByName("OpenSession"); m != nil {
		t.Fatal("expected OpenSession method to be removed from WebSSHService")
	}
	activeMethods := []string{
		"CreateSession",
		"SendSessionCommand",
		"WatchSession",
		"AcknowledgeSessionEvents",
		"CloseSession",
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

func TestP3CProtocolCleanup_Descriptors(t *testing.T) {
	// 1. FileAssignment keeps arguments deprecated and defines typed payload oneof.
	assignDesc := (&filev1.FileAssignment{}).ProtoReflect().Descriptor()
	argsField := assignDesc.Fields().ByName("arguments")
	if argsField == nil || argsField.Number() != 18 {
		t.Fatal("expected FileAssignment.arguments field at tag 18")
	}
	if opts, ok := argsField.Options().(*descriptorpb.FieldOptions); !ok || !opts.GetDeprecated() {
		t.Fatal("expected FileAssignment.arguments to be marked deprecated")
	}
	payloadOneof := assignDesc.Oneofs().ByName("payload")
	if payloadOneof == nil || payloadOneof.Fields().Len() != 15 {
		t.Fatalf("expected FileAssignment.payload oneof with 15 typed branches, got %v", payloadOneof)
	}
	leaseRespDesc := (&filev1.LeaseFileOperationsResponse{}).ProtoReflect().Descriptor()
	if hb := leaseRespDesc.Fields().ByName("heartbeat"); hb == nil || hb.Kind() != protoreflect.BoolKind {
		t.Fatal("expected LeaseFileOperationsResponse.heartbeat bool field")
	}

	// 2. Read-only browser GET RPCs declare NO_SIDE_EFFECTS.
	browserSvc := browserv1.File_komari_browser_v1_browser_proto.Services().ByName("BrowserService")
	if browserSvc == nil {
		t.Fatal("expected BrowserService descriptor")
	}
	getPublicInfo := browserSvc.Methods().ByName("GetPublicInfo")
	if getPublicInfo == nil {
		t.Fatal("expected BrowserService.GetPublicInfo descriptor")
	}
	mOpts, _ := getPublicInfo.Options().(*descriptorpb.MethodOptions)
	if mOpts.GetIdempotencyLevel() != descriptorpb.MethodOptions_NO_SIDE_EFFECTS {
		t.Fatalf("expected GetPublicInfo NO_SIDE_EFFECTS, got %v", mOpts.GetIdempotencyLevel())
	}

	// 3. SignatureAlgorithm only exposes Ed25519 and reserves 2..5.
	sigAlgDesc := securityv1.File_komari_security_v1_security_proto.Enums().ByName("SignatureAlgorithm")
	if sigAlgDesc == nil {
		t.Fatal("expected SignatureAlgorithm enum descriptor")
	}
	if sigAlgDesc.Values().Len() != 2 {
		t.Fatalf("expected 2 SignatureAlgorithm enum values (UNSPECIFIED, ED25519), got %d", sigAlgDesc.Values().Len())
	}
	for _, tag := range []protoreflect.EnumNumber{2, 3, 4, 5} {
		if !sigAlgDesc.ReservedRanges().Has(tag) {
			t.Fatalf("expected SignatureAlgorithm enum tag %d to be reserved", tag)
		}
	}

	// 4. WebSSH File fields removed and reserved.
	for _, check := range []struct {
		desc protoreflect.MessageDescriptor
		tag  protoreflect.FieldNumber
	}{
		{(&websshv1.SendSessionCommandRequest{}).ProtoReflect().Descriptor(), 5},
		{(&websshv1.SessionEvent{}).ProtoReflect().Descriptor(), 5},
		{(&websshv1.AgentSessionEvent{}).ProtoReflect().Descriptor(), 4},
		{(&websshv1.AttachSessionResponse{}).ProtoReflect().Descriptor(), 4},
	} {
		if check.desc.Fields().ByName("file") != nil {
			t.Fatalf("expected %s.file to be removed", check.desc.FullName())
		}
		if !check.desc.ReservedRanges().Has(check.tag) || !check.desc.ReservedNames().Has("file") {
			t.Fatalf("expected %s tag %d and name 'file' to be reserved", check.desc.FullName(), check.tag)
		}
	}
}
