# Komari Proto

Canonical Connect-RPC and Protocol Buffers contracts shared by Komari Backend,
Frontend, and Agent. Legacy JSON-RPC2, Agent v1/v2, and Nezha protocols are
compatibility adapters and must not receive new product features.

## Service boundaries

| Service | Lifecycle | Purpose |
| --- | --- | --- |
| `AgentReportService` | unary | Basic system and capability reports |
| `MetricsService` | unary, client stream, server stream | Metric ingest, query, and live samples |
| `ConfigService` | unary, server stream | Desired runtime config and revision ACK |
| `ExecutionService` | unary, server stream | Bounded execution, output, and cancellation |
| `WebSSHService` | bidi, unary cleanup | Interactive terminal sessions only |
| `AgentEventService` | unary, server stream | Lifecycle notifications and replay ACK |
| `DeploymentService` | unary | Install profiles and config delivery state |
| `BrowserService` | unary, server stream | Typed browser read models and theme contract |

Only WebSSH uses a bidirectional stream. Metrics, configuration, execution,
agent events, and reports have independent cancellation, deadline, replay, and
error lifecycles.

## Compatibility rules

- Consumers pin one Git tag or commit from this repository.
- Deleted fields are reserved and field numbers are never reused.
- Times and durations use `google.protobuf.Timestamp` and
  `google.protobuf.Duration`.
- Long-running work must end in an observable operation state after transport
  cancellation or deadline expiry.
- Authentication, authorization, 2FA, validation, revision conflicts, and
  application errors never trigger a legacy fallback.
- Generated files are CI artifacts and must not be edited manually.

## Local checks

```bash
buf format --diff --exit-code
buf lint
buf generate
git diff --exit-code
```

Breaking checks compare against the latest release tag:

```bash
buf breaking --against '.git#tag=v0.1.0'
```

## Generated artifacts

`buf generate` writes committed Go and TypeScript sources beneath `gen/`.
Consumers import those files from a fixed tag or commit. CI regenerates them,
requires a clean diff, and also packages
`komari-proto-generated-<commit>.tar.gz` for snapshot builds.
