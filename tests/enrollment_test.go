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
	enrollmentv1 "github.com/r11234567/komari-proto/gen/go/komari/enrollment/v1"
	"github.com/r11234567/komari-proto/gen/go/komari/enrollment/v1/enrollmentv1connect"
	securityv1 "github.com/r11234567/komari-proto/gen/go/komari/security/v1"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type mockEnrollmentServer struct {
	enrollmentv1connect.UnimplementedEnrollmentServiceHandler
	enrollmentv1connect.UnimplementedEnrollmentAdminServiceHandler
	controlPlanePrivKey ed25519.PrivateKey
	controlPlanePubKey  ed25519.PublicKey
	agentPrivKey        ed25519.PrivateKey
	agentPubKey         ed25519.PublicKey

	approved bool
	consumed bool
}

func (s *mockEnrollmentServer) BeginEnrollment(
	_ context.Context,
	req *connect.Request[enrollmentv1.BeginEnrollmentRequest],
) (*connect.Response[enrollmentv1.BeginEnrollmentResponse], error) {
	if req.Msg.GetDevice() == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("device profile required"))
	}
	return connect.NewResponse(&enrollmentv1.BeginEnrollmentResponse{
		DeviceCode:              "dev-code-abcdef",
		UserCode:                "ABCD-1234",
		VerificationUri:         "https://panel.example.com/enroll",
		VerificationUriComplete: "https://panel.example.com/enroll?code=ABCD-1234",
		ExpiresAt:               timestamppb.New(time.Now().Add(10 * time.Minute)),
		PollInterval:            durationpb.New(5 * time.Second),
	}), nil
}

func (s *mockEnrollmentServer) PollEnrollment(
	_ context.Context,
	req *connect.Request[enrollmentv1.PollEnrollmentRequest],
) (*connect.Response[enrollmentv1.PollEnrollmentResponse], error) {
	if req.Msg.GetDeviceCode() != "dev-code-abcdef" {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("invalid device code"))
	}
	if s.consumed {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("device code already consumed"))
	}
	if !s.approved {
		return connect.NewResponse(&enrollmentv1.PollEnrollmentResponse{
			State: enrollmentv1.EnrollmentState_ENROLLMENT_STATE_PENDING,
		}), nil
	}

	// Once approved and polled, consume it atomically
	s.consumed = true
	return connect.NewResponse(&enrollmentv1.PollEnrollmentResponse{
		State: enrollmentv1.EnrollmentState_ENROLLMENT_STATE_APPROVED,
		Credentials: &enrollmentv1.AgentCredentials{
			AgentId:              "agent-enrolled-123",
			AccessToken:          "at-token-xyz-123",
			AccessTokenExpiresAt: timestamppb.New(time.Now().Add(24 * time.Hour)),
			RefreshToken:         "rt-token-uvw-456",
			RefreshTokenExpiresAt: timestamppb.New(time.Now().Add(180 * 24 * time.Hour)),
		},
	}), nil
}

func (s *mockEnrollmentServer) RefreshCredentials(
	_ context.Context,
	req *connect.Request[enrollmentv1.RefreshCredentialsRequest],
) (*connect.Response[enrollmentv1.RefreshCredentialsResponse], error) {
	if req.Msg.GetRefreshToken() != "rt-token-uvw-456" {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid refresh token"))
	}

	proof := req.Msg.GetProof()
	if proof == nil || len(proof.GetSignatures()) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("proof signature required"))
	}

	// Verify agent's signature on proof
	sig := proof.GetSignatures()[0]
	if !ed25519.Verify(s.agentPubKey, proof.GetPayload(), sig.GetValue()) {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid proof signature"))
	}

	return connect.NewResponse(&enrollmentv1.RefreshCredentialsResponse{
		Credentials: &enrollmentv1.AgentCredentials{
			AgentId:               "agent-enrolled-123",
			AccessToken:           "at-token-new-789",
			AccessTokenExpiresAt:  timestamppb.New(time.Now().Add(24 * time.Hour)),
			RefreshToken:          "rt-token-uvw-456",
			RefreshTokenExpiresAt: timestamppb.New(time.Now().Add(180 * 24 * time.Hour)),
		},
	}), nil
}

func (s *mockEnrollmentServer) ApproveEnrollment(
	_ context.Context,
	req *connect.Request[enrollmentv1.ApproveEnrollmentRequest],
) (*connect.Response[enrollmentv1.ApproveEnrollmentResponse], error) {
	if req.Msg.GetUserCode() != "ABCD-1234" {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("invalid user code"))
	}
	s.approved = true
	return connect.NewResponse(&enrollmentv1.ApproveEnrollmentResponse{
		AgentId: "agent-enrolled-123",
	}), nil
}

func setupEnrollmentTestServer(t *testing.T) (
	*mockEnrollmentServer,
	*httptest.Server,
	enrollmentv1connect.EnrollmentServiceClient,
	enrollmentv1connect.EnrollmentAdminServiceClient,
) {
	t.Helper()
	cpPub, cpPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate control plane keys: %v", err)
	}
	agPub, agPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate agent keys: %v", err)
	}

	srv := &mockEnrollmentServer{
		controlPlanePrivKey: cpPriv,
		controlPlanePubKey:  cpPub,
		agentPrivKey:        agPriv,
		agentPubKey:         agPub,
	}

	mux := http.NewServeMux()
	path1, handler1 := enrollmentv1connect.NewEnrollmentServiceHandler(srv)
	path2, handler2 := enrollmentv1connect.NewEnrollmentAdminServiceHandler(srv)
	mux.Handle(path1, handler1)
	mux.Handle(path2, handler2)

	httpServer := httptest.NewServer(mux)
	client := enrollmentv1connect.NewEnrollmentServiceClient(httpServer.Client(), httpServer.URL)
	adminClient := enrollmentv1connect.NewEnrollmentAdminServiceClient(httpServer.Client(), httpServer.URL)

	return srv, httpServer, client, adminClient
}

func TestEnrollmentService_FullLifecycle(t *testing.T) {
	ctx := context.Background()
	srv, httpServer, client, adminClient := setupEnrollmentTestServer(t)
	defer httpServer.Close()

	// 1. BeginEnrollment
	beginResp, err := client.BeginEnrollment(ctx, connect.NewRequest(&enrollmentv1.BeginEnrollmentRequest{
		Device: &enrollmentv1.DeviceIdentity{
			Hostname:        "debian-vps-node",
			OperatingSystem: "linux",
			Architecture:    "x86_64",
		},
		AgentPublicKey: &securityv1.PublicKey{
			Algorithm: securityv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519,
			Value:     srv.agentPubKey,
			KeyId:     "agent-key-01",
		},
	}))
	if err != nil {
		t.Fatalf("BeginEnrollment failed: %v", err)
	}
	if beginResp.Msg.GetUserCode() != "ABCD-1234" {
		t.Fatalf("unexpected user code: %q", beginResp.Msg.GetUserCode())
	}
	devCode := beginResp.Msg.GetDeviceCode()

	// 2. PollEnrollment while PENDING
	pollPendingResp, err := client.PollEnrollment(ctx, connect.NewRequest(&enrollmentv1.PollEnrollmentRequest{
		DeviceCode: devCode,
	}))
	if err != nil {
		t.Fatalf("PollEnrollment failed: %v", err)
	}
	if pollPendingResp.Msg.GetState() != enrollmentv1.EnrollmentState_ENROLLMENT_STATE_PENDING {
		t.Fatalf("expected PENDING state, got: %v", pollPendingResp.Msg.GetState())
	}

	// 3. Admin approves enrollment
	_, err = adminClient.ApproveEnrollment(ctx, connect.NewRequest(&enrollmentv1.ApproveEnrollmentRequest{
		UserCode: "ABCD-1234",
	}))
	if err != nil {
		t.Fatalf("ApproveEnrollment failed: %v", err)
	}

	// 4. PollEnrollment after approval -> delivers credentials and consumes device code
	pollApprovedResp, err := client.PollEnrollment(ctx, connect.NewRequest(&enrollmentv1.PollEnrollmentRequest{
		DeviceCode: devCode,
	}))
	if err != nil {
		t.Fatalf("PollEnrollment approved failed: %v", err)
	}
	if pollApprovedResp.Msg.GetState() != enrollmentv1.EnrollmentState_ENROLLMENT_STATE_APPROVED {
		t.Fatalf("expected APPROVED state, got: %v", pollApprovedResp.Msg.GetState())
	}
	creds := pollApprovedResp.Msg.GetCredentials()
	if creds.GetAccessToken() != "at-token-xyz-123" || creds.GetRefreshToken() != "rt-token-uvw-456" {
		t.Fatalf("unexpected credentials: %+v", creds)
	}

	// 5. Subsequent poll fails because code was consumed atomically
	_, err = client.PollEnrollment(ctx, connect.NewRequest(&enrollmentv1.PollEnrollmentRequest{
		DeviceCode: devCode,
	}))
	if err == nil {
		t.Fatal("expected error on polling already-consumed device code, got success")
	}

	// 6. RefreshCredentials using Ed25519 signed proof
	proofPayload := []byte("komari-refresh-challenge-payload")
	sig := ed25519.Sign(srv.agentPrivKey, proofPayload)
	proof := &securityv1.SignedEnvelope{
		Payload: proofPayload,
		Signatures: []*securityv1.Signature{
			{
				Algorithm: securityv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519,
				Value:     sig,
				KeyId:     "agent-key-01",
			},
		},
	}

	refreshResp, err := client.RefreshCredentials(ctx, connect.NewRequest(&enrollmentv1.RefreshCredentialsRequest{
		RefreshToken: creds.GetRefreshToken(),
		Proof:        proof,
	}))
	if err != nil {
		t.Fatalf("RefreshCredentials failed: %v", err)
	}
	if refreshResp.Msg.GetCredentials().GetAccessToken() != "at-token-new-789" {
		t.Fatalf("expected new AT 'at-token-new-789', got %q", refreshResp.Msg.GetCredentials().GetAccessToken())
	}
}
