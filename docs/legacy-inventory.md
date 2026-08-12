# Legacy protocol inventory

This inventory is a migration oracle, not an API design source. New fields and
features are added only to the Connect services.

## Browser JSON-RPC2

| Legacy namespace | Required role | Connect owner | Fallback |
| --- | --- | --- | --- |
| `common:*` | guest | `BrowserService` | transport unavailable only |
| `public:*` | guest | `BrowserService` | transport unavailable only |
| `admin:*` | admin | Browser, Metrics, Deployment, Execution | transport unavailable only |
| `client:*` | agent | Report, Metrics, Config, AgentEvent | old Agent only |

Known methods at the baseline include public info/version, node list/recent
status, dashboard/charts/alerts, clients, deployment profiles, metrics,
settings, ping/route/task, terminal, and remote execution. Method names,
parameter JSON, numeric error codes, ACL role, and sensitive-operation marking
remain frozen in the Backend golden tests.

## Agent protocols

| Legacy path | Purpose | Connect replacement |
| --- | --- | --- |
| v1 HTTP report | basic/report upload | `AgentReportService.SubmitReport` |
| v2 JSON-RPC/WebSocket report | report, task, config, ACK | split Report/Metrics/Config/Execution/Event services |
| Nezha gRPC | compatible report/monitoring | Report/Metrics adapters |

The adapters preserve ACK, replay, coalescing, TTL, revision, and idempotency
behavior. They do not gain online config fields, capability fields, execution
features, or other new behavior.

## Error and fallback policy

Fallback is permitted only for endpoint/transport unavailability or an older
server that does not expose Connect. Unauthenticated, permission denied,
failed precondition, invalid argument, revision conflict, cancelled, deadline
exceeded, and 2FA failures are final and must be surfaced to the caller.
