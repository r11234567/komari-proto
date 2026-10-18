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
	rescuev1 "github.com/r11234567/komari-proto/gen/go/komari/rescue/v1"
	"github.com/r11234567/komari-proto/gen/go/komari/rescue/v1/rescuev1connect"
	securityv1 "github.com/r11234567/komari-proto/gen/go/komari/security/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type mockRescueServer struct {
	rescuev1connect.UnimplementedRescueServiceHandler
	controlPlanePrivKey ed25519.PrivateKey
	controlPlanePubKey  ed25519.PublicKey
	storedSession       *rescuev1.RescueSession
}

func (s *mockRescueServer) GetRescueStatus(
	_ context.Context,
	req *connect.Request[rescuev1.GetRescueStatusRequest],
) (*connect.Response[rescuev1.GetRescueStatusResponse], error) {
	return connect.NewResponse(&rescuev1.GetRescueStatusResponse{
		Status: &rescuev1.RescueHelperStatus{
			Requested:        true,
			Installed:        true,
			GuardianRunning:  true,
			HelperRunning:    true,
			Version:          "1.0.0-rescue",
			HelperInstanceId: "helper-inst-999",
			ObservedAt:       timestamppb.Now(),
			NetworkIsolation: rescuev1.NetworkIsolationMode_NETWORK_ISOLATION_MODE_NONE,
		},
	}), nil
}

func (s *mockRescueServer) CreateRescueSession(
	_ context.Context,
	req *connect.Request[rescuev1.CreateRescueSessionRequest],
) (*connect.Response[rescuev1.CreateRescueSessionResponse], error) {
	if req.Msg.GetAgentId() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("agent_id required"))
	}
	sess := &rescuev1.RescueSession{
		SessionId: "rescue-sess-12345",
		AgentId:   req.Msg.GetAgentId(),
		Action:    req.Msg.GetAction(),
		State:     commonv1.OperationState_OPERATION_STATE_QUEUED,
		CreatedAt: timestamppb.Now(),
		SshPort:   req.Msg.SshPort,
	}
	s.storedSession = sess
	return connect.NewResponse(&rescuev1.CreateRescueSessionResponse{
		Session: sess,
	}), nil
}

func (s *mockRescueServer) LeaseRescueSessions(
	ctx context.Context,
	req *connect.Request[rescuev1.LeaseRescueSessionsRequest],
	stream *connect.ServerStream[rescuev1.LeaseRescueSessionsResponse],
) error {
	// Sign instruction for rescue assignment
	instruction := &securityv1.SignedInstruction{
		AgentId:         req.Msg.GetAgentId(),
		Nonce:           "rescue-nonce-98765",
		IssuedAt:        timestamppb.Now(),
		ExpiresAt:       timestamppb.New(time.Now().Add(15 * time.Minute)),
		InstructionType: "rescue:v1",
		Body:            []byte("ALLOW_PORT_2222_FOR_900S"),
	}
	payloadBytes, err := proto.Marshal(instruction)
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}

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

	assignment := &rescuev1.RescueAssignment{
		AssignmentId:   "rescue-assign-001",
		Session:        s.storedSession,
		LeaseExpiresAt: timestamppb.New(time.Now().Add(15 * time.Minute)),
		Envelope:       envelope, // Using the new SignedEnvelope in rescue assignment
	}

	return stream.Send(&rescuev1.LeaseRescueSessionsResponse{
		Assignment: assignment,
	})
}

func (s *mockRescueServer) CancelRescueSession(
	_ context.Context,
	req *connect.Request[rescuev1.CancelRescueSessionRequest],
) (*connect.Response[rescuev1.CancelRescueSessionResponse], error) {
	if s.storedSession == nil || s.storedSession.SessionId != req.Msg.GetSessionId() {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("rescue session not found"))
	}
	s.storedSession.State = commonv1.OperationState_OPERATION_STATE_CANCELLED
	s.storedSession.FinishedAt = timestamppb.Now()
	return connect.NewResponse(&rescuev1.CancelRescueSessionResponse{
		Session: s.storedSession,
	}), nil
}

func (s *mockRescueServer) ReportRescueStatus(
	_ context.Context,
	req *connect.Request[rescuev1.ReportRescueStatusRequest],
) (*connect.Response[rescuev1.ReportRescueStatusResponse], error) {
	return connect.NewResponse(&rescuev1.ReportRescueStatusResponse{
		Accepted: true,
	}), nil
}

func (s *mockRescueServer) ReportRescueEvent(
	_ context.Context,
	req *connect.Request[rescuev1.ReportRescueEventRequest],
) (*connect.Response[rescuev1.ReportRescueEventResponse], error) {
	return connect.NewResponse(&rescuev1.ReportRescueEventResponse{
		AcceptedSequence: req.Msg.GetEvent().GetSequence(),
	}), nil
}

func setupRescueTestServer(t *testing.T) (*mockRescueServer, *httptest.Server, rescuev1connect.RescueServiceClient) {
	t.Helper()
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 keys: %v", err)
	}

	srv := &mockRescueServer{
		controlPlanePrivKey: privKey,
		controlPlanePubKey:  pubKey,
	}

	mux := http.NewServeMux()
	path, handler := rescuev1connect.NewRescueServiceHandler(srv)
	mux.Handle(path, handler)

	httpServer := httptest.NewServer(mux)
	client := rescuev1connect.NewRescueServiceClient(httpServer.Client(), httpServer.URL)

	return srv, httpServer, client
}

func TestRescueService_FullLifecycle(t *testing.T) {
	ctx := context.Background()
	_, httpServer, client := setupRescueTestServer(t)
	defer httpServer.Close()

	// 1. GetRescueStatus
	statusResp, err := client.GetRescueStatus(ctx, connect.NewRequest(&rescuev1.GetRescueStatusRequest{
		AgentId: "agent-node-002",
	}))
	if err != nil {
		t.Fatalf("GetRescueStatus failed: %v", err)
	}
	if !statusResp.Msg.GetStatus().GetGuardianRunning() || !statusResp.Msg.GetStatus().GetHelperRunning() {
		t.Fatalf("expected guardian and helper running, got: %+v", statusResp.Msg.GetStatus())
	}

	// 2. CreateRescueSession
	createResp, err := client.CreateRescueSession(ctx, connect.NewRequest(&rescuev1.CreateRescueSessionRequest{
		AgentId: "agent-node-002",
		Action:  rescuev1.RescueAction_RESCUE_ACTION_TEMPORARY_SSH_ACCESS,
		Timeout: durationpb.New(15 * time.Minute),
		SshPort: proto.Uint32(2222),
		TwoFactor: &commonv1.TwoFactorProof{
			Code:        "654321",
			ChallengeId: "challenge-sess-002",
		},
	}))
	if err != nil {
		t.Fatalf("CreateRescueSession failed: %v", err)
	}
	sessID := createResp.Msg.GetSession().GetSessionId()
	if sessID != "rescue-sess-12345" {
		t.Fatalf("unexpected session ID: %q", sessID)
	}
	if createResp.Msg.GetSession().GetSshPort() != 2222 {
		t.Fatalf("expected SSH port 2222, got %d", createResp.Msg.GetSession().GetSshPort())
	}

	// 3. ReportRescueStatus
	reportStatusResp, err := client.ReportRescueStatus(ctx, connect.NewRequest(&rescuev1.ReportRescueStatusRequest{
		AgentId: "agent-node-002",
		Status: &rescuev1.RescueHelperStatus{
			HelperRunning:   true,
			GuardianRunning: true,
		},
	}))
	if err != nil || !reportStatusResp.Msg.GetAccepted() {
		t.Fatalf("ReportRescueStatus failed: %v", err)
	}

	// 4. ReportRescueEvent
	reportEventResp, err := client.ReportRescueEvent(ctx, connect.NewRequest(&rescuev1.ReportRescueEventRequest{
		AgentId:          "agent-node-002",
		HelperInstanceId: "helper-inst-999",
		Event: &rescuev1.RescueEvent{
			SessionId: sessID,
			Sequence:  1,
			State:     commonv1.OperationState_OPERATION_STATE_RUNNING,
			SshAccess: &rescuev1.TemporarySSHAccess{
				Port:            2222,
				Granted:         true,
				ExpiryMechanism: rescuev1.ExpiryMechanism_EXPIRY_MECHANISM_NFTABLES_TIMEOUT,
			},
		},
	}))
	if err != nil || reportEventResp.Msg.GetAcceptedSequence() != 1 {
		t.Fatalf("ReportRescueEvent failed: %v", err)
	}

	// 5. CancelRescueSession
	cancelResp, err := client.CancelRescueSession(ctx, connect.NewRequest(&rescuev1.CancelRescueSessionRequest{
		SessionId: sessID,
		Reason:    "maintenance completed ahead of schedule",
	}))
	if err != nil {
		t.Fatalf("CancelRescueSession failed: %v", err)
	}
	if cancelResp.Msg.GetSession().GetState() != commonv1.OperationState_OPERATION_STATE_CANCELLED {
		t.Fatalf("expected state CANCELLED, got %v", cancelResp.Msg.GetSession().GetState())
	}
}

func TestRescueService_SignedEnvelopeVerification(t *testing.T) {
	ctx := context.Background()
	srv, httpServer, client := setupRescueTestServer(t)
	defer httpServer.Close()

	// Create rescue session first
	_, err := client.CreateRescueSession(ctx, connect.NewRequest(&rescuev1.CreateRescueSessionRequest{
		AgentId: "agent-node-002",
		Action:  rescuev1.RescueAction_RESCUE_ACTION_TEMPORARY_SSH_ACCESS,
		SshPort: proto.Uint32(2222),
	}))
	if err != nil {
		t.Fatalf("CreateRescueSession failed: %v", err)
	}

	// Lease rescue sessions to receive SignedEnvelope
	leaseStream, err := client.LeaseRescueSessions(ctx, connect.NewRequest(&rescuev1.LeaseRescueSessionsRequest{
		AgentId: "agent-node-002",
	}))
	if err != nil {
		t.Fatalf("LeaseRescueSessions failed: %v", err)
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
		t.Fatal("envelope is nil in RescueAssignment! SignedEnvelope was not added properly")
	}

	// 1. Verify Ed25519 signature
	if len(envelope.GetSignatures()) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(envelope.GetSignatures()))
	}
	sig := envelope.GetSignatures()[0]
	verified := ed25519.Verify(srv.controlPlanePubKey, envelope.GetPayload(), sig.GetValue())
	if !verified {
		t.Fatal("Ed25519 signature verification FAILED on RescueAssignment envelope payload!")
	}

	// 2. Unpack SignedInstruction
	var instruction securityv1.SignedInstruction
	if err := proto.Unmarshal(envelope.GetPayload(), &instruction); err != nil {
		t.Fatalf("failed to unmarshal SignedInstruction: %v", err)
	}
	if instruction.GetAgentId() != "agent-node-002" {
		t.Fatalf("unexpected agent ID: %q", instruction.GetAgentId())
	}
	if instruction.GetInstructionType() != "rescue:v1" {
		t.Fatalf("unexpected instruction type: %q", instruction.GetInstructionType())
	}
	if string(instruction.GetBody()) != "ALLOW_PORT_2222_FOR_900S" {
		t.Fatalf("unexpected instruction body: %q", string(instruction.GetBody()))
	}
}
