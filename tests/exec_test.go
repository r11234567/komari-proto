package tests

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	commonv1 "github.com/r11234567/komari-proto/gen/go/komari/common/v1"
	execv1 "github.com/r11234567/komari-proto/gen/go/komari/exec/v1"
	"github.com/r11234567/komari-proto/gen/go/komari/exec/v1/execv1connect"
	securityv1 "github.com/r11234567/komari-proto/gen/go/komari/security/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type mockExecutionServer struct {
	execv1connect.UnimplementedExecutionServiceHandler
	controlPlanePrivKey ed25519.PrivateKey
	controlPlanePubKey  ed25519.PublicKey
	storedExecution     *execv1.Execution
}

func (s *mockExecutionServer) CreateExecution(
	_ context.Context,
	req *connect.Request[execv1.CreateExecutionRequest],
) (*connect.Response[execv1.CreateExecutionResponse], error) {
	if req.Msg.GetCommand() == "" && len(req.Msg.GetAgentIds()) == 0 && req.Msg.GetAgentId() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("command and agent_id required"))
	}
	exec := &execv1.Execution{
		ExecutionId: "exec-test-12345",
		AgentId:     req.Msg.GetAgentId(),
		State:       commonv1.OperationState_OPERATION_STATE_QUEUED,
		CreatedAt:   timestamppb.Now(),
	}
	s.storedExecution = exec
	return connect.NewResponse(&execv1.CreateExecutionResponse{
		Execution: exec,
	}), nil
}

func (s *mockExecutionServer) GetExecution(
	_ context.Context,
	req *connect.Request[execv1.GetExecutionRequest],
) (*connect.Response[execv1.GetExecutionResponse], error) {
	if s.storedExecution == nil || s.storedExecution.ExecutionId != req.Msg.GetExecutionId() {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("execution not found"))
	}
	return connect.NewResponse(&execv1.GetExecutionResponse{
		Execution: s.storedExecution,
	}), nil
}

func (s *mockExecutionServer) CancelExecution(
	_ context.Context,
	req *connect.Request[execv1.CancelExecutionRequest],
) (*connect.Response[execv1.CancelExecutionResponse], error) {
	if s.storedExecution == nil || s.storedExecution.ExecutionId != req.Msg.GetExecutionId() {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("execution not found"))
	}
	s.storedExecution.State = commonv1.OperationState_OPERATION_STATE_CANCELLED
	s.storedExecution.FinishedAt = timestamppb.Now()
	return connect.NewResponse(&execv1.CancelExecutionResponse{
		Execution: s.storedExecution,
	}), nil
}

func (s *mockExecutionServer) WatchExecution(
	ctx context.Context,
	req *connect.Request[execv1.WatchExecutionRequest],
	stream *connect.ServerStream[execv1.WatchExecutionResponse],
) error {
	events := []*execv1.ExecutionEvent{
		{
			ExecutionId: req.Msg.GetExecutionId(),
			Sequence:    1,
			OccurredAt:  timestamppb.Now(),
			State:       commonv1.OperationState_OPERATION_STATE_RUNNING,
			Stream:      execv1.OutputStream_OUTPUT_STREAM_STDOUT,
			Output:      []byte("Starting task execution...\n"),
		},
		{
			ExecutionId: req.Msg.GetExecutionId(),
			Sequence:    2,
			OccurredAt:  timestamppb.Now(),
			State:       commonv1.OperationState_OPERATION_STATE_SUCCEEDED,
			Stream:      execv1.OutputStream_OUTPUT_STREAM_STDOUT,
			Output:      []byte("Task completed successfully.\n"),
			ExitCode:    proto.Int32(0),
		},
	}

	for _, ev := range events {
		if err := stream.Send(&execv1.WatchExecutionResponse{Event: ev}); err != nil {
			return err
		}
	}
	return nil
}

func (s *mockExecutionServer) LeaseExecution(
	ctx context.Context,
	req *connect.Request[execv1.LeaseExecutionRequest],
	stream *connect.ServerStream[execv1.LeaseExecutionResponse],
) error {
	// Construct the internal ExecutionSpec (only exists inside signed envelope payload)
	rawSpec := &execv1.ExecutionSpec{
		Command:          "uname",
		Arguments:        []string{"-a"},
		WorkingDirectory: "/root",
		Timeout:          durationpb.New(30 * time.Second),
		MaxOutputBytes:   1024 * 1024,
	}
	specBytes, err := proto.Marshal(rawSpec)
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}

	// Wrap in SignedInstruction
	instruction := &securityv1.SignedInstruction{
		AgentId:         req.Msg.GetAgentId(),
		Nonce:           "single-use-nonce-12345",
		IssuedAt:        timestamppb.Now(),
		ExpiresAt:       timestamppb.New(time.Now().Add(5 * time.Minute)),
		InstructionType: "exec:v1",
		Body:            specBytes,
	}
	payloadBytes, err := proto.Marshal(instruction)
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}

	// Sign payload with control plane Ed25519 private key
	sigValue := ed25519.Sign(s.controlPlanePrivKey, payloadBytes)
	envelope := &securityv1.SignedEnvelope{
		Payload: payloadBytes,
		Signatures: []*securityv1.Signature{
			{
				Algorithm: securityv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519,
				Value:     sigValue,
				KeyId:     "master-key-2026",
			},
		},
	}

	assignment := &execv1.ExecutionAssignment{
		AssignmentId:   "assignment-001",
		Execution:      s.storedExecution,
		LeaseExpiresAt: timestamppb.New(time.Now().Add(2 * time.Minute)),
		Envelope:       envelope, // Using the new SignedEnvelope field
	}

	return stream.Send(&execv1.LeaseExecutionResponse{
		Assignment: assignment,
	})
}

func (s *mockExecutionServer) ReportExecutionEvent(
	_ context.Context,
	req *connect.Request[execv1.ReportExecutionEventRequest],
) (*connect.Response[execv1.ReportExecutionEventResponse], error) {
	if req.Msg.GetEvent() == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("event required"))
	}
	return connect.NewResponse(&execv1.ReportExecutionEventResponse{
		AcceptedSequence: req.Msg.GetEvent().GetSequence(),
	}), nil
}

func setupExecutionTestServer(t *testing.T) (*mockExecutionServer, *httptest.Server, execv1connect.ExecutionServiceClient) {
	t.Helper()
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 keys: %v", err)
	}

	srv := &mockExecutionServer{
		controlPlanePrivKey: privKey,
		controlPlanePubKey:  pubKey,
	}

	mux := http.NewServeMux()
	path, handler := execv1connect.NewExecutionServiceHandler(srv)
	mux.Handle(path, handler)

	httpServer := httptest.NewServer(mux)
	client := execv1connect.NewExecutionServiceClient(httpServer.Client(), httpServer.URL)

	return srv, httpServer, client
}

func TestExecutionService_FullLifecycle(t *testing.T) {
	ctx := context.Background()
	_, httpServer, client := setupExecutionTestServer(t)
	defer httpServer.Close()

	// 1. CreateExecution
	createResp, err := client.CreateExecution(ctx, connect.NewRequest(&execv1.CreateExecutionRequest{
		AgentId: "agent-node-001",
		Command: "uptime",
		Timeout: durationpb.New(10 * time.Second),
		TwoFactor: &commonv1.TwoFactorProof{
			Code:        "123456",
			ChallengeId: "challenge-uuid",
		},
	}))
	if err != nil {
		t.Fatalf("CreateExecution failed: %v", err)
	}
	execID := createResp.Msg.GetExecution().GetExecutionId()
	if execID != "exec-test-12345" {
		t.Fatalf("unexpected execution ID: %q", execID)
	}
	if createResp.Msg.GetExecution().GetState() != commonv1.OperationState_OPERATION_STATE_QUEUED {
		t.Fatalf("unexpected state: %v", createResp.Msg.GetExecution().GetState())
	}

	// 2. GetExecution
	getResp, err := client.GetExecution(ctx, connect.NewRequest(&execv1.GetExecutionRequest{
		ExecutionId: execID,
	}))
	if err != nil {
		t.Fatalf("GetExecution failed: %v", err)
	}
	if getResp.Msg.GetExecution().GetAgentId() != "agent-node-001" {
		t.Fatalf("unexpected agent ID: %v", getResp.Msg.GetExecution().GetAgentId())
	}

	// 3. WatchExecution (Server Streaming)
	watchStream, err := client.WatchExecution(ctx, connect.NewRequest(&execv1.WatchExecutionRequest{
		ExecutionId: execID,
	}))
	if err != nil {
		t.Fatalf("WatchExecution failed: %v", err)
	}
	var receivedEvents []*execv1.ExecutionEvent
	for watchStream.Receive() {
		receivedEvents = append(receivedEvents, watchStream.Msg().GetEvent())
	}
	if err := watchStream.Err(); err != nil {
		t.Fatalf("WatchExecution stream error: %v", err)
	}
	if len(receivedEvents) != 2 {
		t.Fatalf("expected 2 execution events, got %d", len(receivedEvents))
	}
	if receivedEvents[0].GetSequence() != 1 || string(receivedEvents[0].GetOutput()) != "Starting task execution...\n" {
		t.Fatalf("event 1 mismatch: %+v", receivedEvents[0])
	}
	if receivedEvents[1].GetSequence() != 2 || receivedEvents[1].GetExitCode() != 0 {
		t.Fatalf("event 2 mismatch: %+v", receivedEvents[1])
	}

	// 4. ReportExecutionEvent
	reportResp, err := client.ReportExecutionEvent(ctx, connect.NewRequest(&execv1.ReportExecutionEventRequest{
		AgentId: "agent-node-001",
		Event:   receivedEvents[1],
	}))
	if err != nil {
		t.Fatalf("ReportExecutionEvent failed: %v", err)
	}
	if reportResp.Msg.GetAcceptedSequence() != 2 {
		t.Fatalf("expected accepted sequence 2, got %d", reportResp.Msg.GetAcceptedSequence())
	}

	// 5. CancelExecution
	cancelResp, err := client.CancelExecution(ctx, connect.NewRequest(&execv1.CancelExecutionRequest{
		ExecutionId: execID,
		Reason:      "manual operator termination",
	}))
	if err != nil {
		t.Fatalf("CancelExecution failed: %v", err)
	}
	if cancelResp.Msg.GetExecution().GetState() != commonv1.OperationState_OPERATION_STATE_CANCELLED {
		t.Fatalf("expected state CANCELLED, got %v", cancelResp.Msg.GetExecution().GetState())
	}
}

func TestExecutionService_SignedEnvelopeUnpackAndVerification(t *testing.T) {
	ctx := context.Background()
	srv, httpServer, client := setupExecutionTestServer(t)
	defer httpServer.Close()

	// Create task first
	_, err := client.CreateExecution(ctx, connect.NewRequest(&execv1.CreateExecutionRequest{
		AgentId: "agent-node-001",
		Command: "uname -a",
	}))
	if err != nil {
		t.Fatalf("CreateExecution failed: %v", err)
	}

	// Lease execution to receive SignedEnvelope
	leaseStream, err := client.LeaseExecution(ctx, connect.NewRequest(&execv1.LeaseExecutionRequest{
		AgentId: "agent-node-001",
	}))
	if err != nil {
		t.Fatalf("LeaseExecution failed: %v", err)
	}

	if !leaseStream.Receive() {
		t.Fatalf("expected assignment in stream, but stream ended: %v", leaseStream.Err())
	}

	assignment := leaseStream.Msg().GetAssignment()
	if assignment == nil {
		t.Fatal("assignment is nil")
	}

	envelope := assignment.GetEnvelope()
	if envelope == nil {
		t.Fatal("envelope is nil in ExecutionAssignment! Spec was not properly converted to SignedEnvelope")
	}

	// 1. Verify Ed25519 signature
	if len(envelope.GetSignatures()) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(envelope.GetSignatures()))
	}
	sig := envelope.GetSignatures()[0]
	if sig.GetAlgorithm() != securityv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519 {
		t.Fatalf("unexpected signature algorithm: %v", sig.GetAlgorithm())
	}

	verified := ed25519.Verify(srv.controlPlanePubKey, envelope.GetPayload(), sig.GetValue())
	if !verified {
		t.Fatal("Ed25519 signature verification FAILED on valid payload!")
	}

	// 2. Unpack SignedInstruction
	var instruction securityv1.SignedInstruction
	if err := proto.Unmarshal(envelope.GetPayload(), &instruction); err != nil {
		t.Fatalf("failed to unmarshal SignedInstruction from envelope payload: %v", err)
	}
	if instruction.GetAgentId() != "agent-node-001" {
		t.Fatalf("unexpected agent ID in instruction: %q", instruction.GetAgentId())
	}
	if instruction.GetInstructionType() != "exec:v1" {
		t.Fatalf("unexpected instruction type: %q", instruction.GetInstructionType())
	}

	// 3. Unpack ExecutionSpec from verified instruction body
	var spec execv1.ExecutionSpec
	if err := proto.Unmarshal(instruction.GetBody(), &spec); err != nil {
		t.Fatalf("failed to unmarshal ExecutionSpec from instruction body: %v", err)
	}
	if spec.GetCommand() != "uname" {
		t.Fatalf("expected command 'uname', got %q", spec.GetCommand())
	}
	if len(spec.GetArguments()) != 1 || spec.GetArguments()[0] != "-a" {
		t.Fatalf("unexpected arguments: %v", spec.GetArguments())
	}
	if spec.GetWorkingDirectory() != "/root" {
		t.Fatalf("unexpected working directory: %q", spec.GetWorkingDirectory())
	}

	// 4. Test Tampering Detection (Adversary MITM modifies 1 byte in payload)
	tamperedPayload := make([]byte, len(envelope.GetPayload()))
	copy(tamperedPayload, envelope.GetPayload())
	tamperedPayload[len(tamperedPayload)-1] ^= 0xFF // Flip bits of last byte

	tamperedVerified := ed25519.Verify(srv.controlPlanePubKey, tamperedPayload, sig.GetValue())
	if tamperedVerified {
		t.Fatal("Security critical failure: Tampered payload verified successfully! Expected verification failure.")
	}
}
