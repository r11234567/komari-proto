package tests

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	metricsv1 "github.com/r11234567/komari-proto/gen/go/komari/metrics/v1"
	"github.com/r11234567/komari-proto/gen/go/komari/metrics/v1/metricsv1connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type mockMetricsServer struct {
	metricsv1connect.UnimplementedMetricsServiceHandler
	storedPoints []*metricsv1.MetricsPoint
}

func (s *mockMetricsServer) SubmitMetrics(
	_ context.Context,
	req *connect.Request[metricsv1.SubmitMetricsRequest],
) (*connect.Response[metricsv1.SubmitMetricsResponse], error) {
	if req.Msg.GetAgentId() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("agent_id required"))
	}
	s.storedPoints = append(s.storedPoints, req.Msg.GetPoints()...)
	return connect.NewResponse(&metricsv1.SubmitMetricsResponse{
		AcceptedSequence: req.Msg.GetSequence(),
		AcceptedPoints:   uint32(len(req.Msg.GetPoints())),
	}), nil
}

func (s *mockMetricsServer) QueryMetrics(
	_ context.Context,
	req *connect.Request[metricsv1.QueryMetricsRequest],
) (*connect.Response[metricsv1.QueryMetricsResponse], error) {
	var matchedPoints []*metricsv1.MetricsPoint
	for _, pt := range s.storedPoints {
		for _, m := range req.Msg.GetMetrics() {
			if pt.GetMetric() == m {
				matchedPoints = append(matchedPoints, pt)
			}
		}
	}
	return connect.NewResponse(&metricsv1.QueryMetricsResponse{
		Series: []*metricsv1.MetricsSeries{
			{
				AgentId: req.Msg.GetAgentIds()[0],
				Metric:  req.Msg.GetMetrics()[0],
				Points:  matchedPoints,
			},
		},
	}), nil
}

func (s *mockMetricsServer) ListMetricDefinitions(
	_ context.Context,
	_ *connect.Request[metricsv1.ListMetricDefinitionsRequest],
) (*connect.Response[metricsv1.ListMetricDefinitionsResponse], error) {
	return connect.NewResponse(&metricsv1.ListMetricDefinitionsResponse{
		Definitions: []*metricsv1.MetricDefinition{
			{
				Name:          "cpu_usage",
				Type:          "gauge",
				Unit:          "percent",
				RetentionDays: 30,
			},
			{
				Name:          "memory_used",
				Type:          "gauge",
				Unit:          "bytes",
				RetentionDays: 30,
			},
		},
	}), nil
}

func (s *mockMetricsServer) ListPingTasks(
	_ context.Context,
	_ *connect.Request[metricsv1.ListPingTasksRequest],
) (*connect.Response[metricsv1.ListPingTasksResponse], error) {
	return connect.NewResponse(&metricsv1.ListPingTasksResponse{
		Tasks: []*metricsv1.PingTask{
			{
				TaskId:   1,
				Name:     "Cloudflare DNS Ping",
				Type:     "icmp",
				Interval: durationpb.New(10 * time.Second),
			},
		},
	}), nil
}

func (s *mockMetricsServer) GetPingStats(
	_ context.Context,
	req *connect.Request[metricsv1.GetPingStatsRequest],
) (*connect.Response[metricsv1.GetPingStatsResponse], error) {
	return connect.NewResponse(&metricsv1.GetPingStatsResponse{
		Stats: []*metricsv1.PingStat{
			{
				AgentId:       req.Msg.GetAgentIds()[0],
				TaskId:        req.Msg.GetTaskIds()[0],
				Name:          "Cloudflare DNS Ping",
				Total:         100,
				Valid:         99,
				LossPercent:   1.0,
				Average:       proto.Float64(12.5),
				ProbeInterval: durationpb.New(10 * time.Second),
			},
		},
	}), nil
}

func setupMetricsTestServer(t *testing.T) (*mockMetricsServer, *httptest.Server, metricsv1connect.MetricsServiceClient) {
	t.Helper()
	srv := &mockMetricsServer{}
	mux := http.NewServeMux()
	path, handler := metricsv1connect.NewMetricsServiceHandler(srv)
	mux.Handle(path, handler)

	httpServer := httptest.NewServer(mux)
	client := metricsv1connect.NewMetricsServiceClient(httpServer.Client(), httpServer.URL)

	return srv, httpServer, client
}

func TestMetricsService_FullLifecycle(t *testing.T) {
	ctx := context.Background()
	_, httpServer, client := setupMetricsTestServer(t)
	defer httpServer.Close()

	now := timestamppb.Now()

	// 1. SubmitMetrics (Unary Ingestion)
	submitResp, err := client.SubmitMetrics(ctx, connect.NewRequest(&metricsv1.SubmitMetricsRequest{
		AgentId:  "agent-node-003",
		Sequence: 101,
		Points: []*metricsv1.MetricsPoint{
			{
				Metric:     "cpu_usage",
				Value:      45.5,
				ObservedAt: now,
				Labels:     map[string]string{"core": "0"},
			},
			{
				Metric:     "memory_used",
				Value:      4294967296, // 4GB
				ObservedAt: now,
				Labels:     map[string]string{"type": "ram"},
			},
		},
	}))
	if err != nil {
		t.Fatalf("SubmitMetrics failed: %v", err)
	}
	if submitResp.Msg.GetAcceptedSequence() != 101 || submitResp.Msg.GetAcceptedPoints() != 2 {
		t.Fatalf("unexpected submit response: %+v", submitResp.Msg)
	}

	// 2. QueryMetrics
	queryResp, err := client.QueryMetrics(ctx, connect.NewRequest(&metricsv1.QueryMetricsRequest{
		AgentIds: []string{"agent-node-003"},
		Metrics:  []string{"cpu_usage"},
	}))
	if err != nil {
		t.Fatalf("QueryMetrics failed: %v", err)
	}
	if len(queryResp.Msg.GetSeries()) != 1 || len(queryResp.Msg.GetSeries()[0].GetPoints()) != 1 {
		t.Fatalf("unexpected series: %+v", queryResp.Msg.GetSeries())
	}
	if queryResp.Msg.GetSeries()[0].GetPoints()[0].GetValue() != 45.5 {
		t.Fatalf("expected value 45.5, got %v", queryResp.Msg.GetSeries()[0].GetPoints()[0].GetValue())
	}

	// 3. ListMetricDefinitions
	defsResp, err := client.ListMetricDefinitions(ctx, connect.NewRequest(&metricsv1.ListMetricDefinitionsRequest{}))
	if err != nil {
		t.Fatalf("ListMetricDefinitions failed: %v", err)
	}
	if len(defsResp.Msg.GetDefinitions()) != 2 {
		t.Fatalf("expected 2 definitions, got %d", len(defsResp.Msg.GetDefinitions()))
	}

	// 4. ListPingTasks & GetPingStats
	tasksResp, err := client.ListPingTasks(ctx, connect.NewRequest(&metricsv1.ListPingTasksRequest{}))
	if err != nil {
		t.Fatalf("ListPingTasks failed: %v", err)
	}
	if len(tasksResp.Msg.GetTasks()) != 1 {
		t.Fatalf("expected 1 ping task, got %d", len(tasksResp.Msg.GetTasks()))
	}

	statsResp, err := client.GetPingStats(ctx, connect.NewRequest(&metricsv1.GetPingStatsRequest{
		AgentIds: []string{"agent-node-003"},
		TaskIds:  []uint64{1},
	}))
	if err != nil {
		t.Fatalf("GetPingStats failed: %v", err)
	}
	if len(statsResp.Msg.GetStats()) != 1 || statsResp.Msg.GetStats()[0].GetAverage() != 12.5 {
		t.Fatalf("unexpected ping stats: %+v", statsResp.Msg.GetStats())
	}
}
