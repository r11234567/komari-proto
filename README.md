# Komari Proto

Canonical Connect and Protocol Buffers contracts for this fork's panel, Agent and Web. [Documentation](docs/README.md) · [Compatibility](docs/contracts/compatibility.md) · [Validation and baselines](docs/development/testing.md).

Consumers pin a Git commit via submodule and import the generated Go and TypeScript clients under `gen/`. Initialize recursively before building. To change a contract, edit the source under [komari](komari), then run Buf 1.57.0 format, lint, both breaking checks and generate; commit the generated changes with the source change. Do not edit generated files manually.

WebSSH and MetricsService.StreamMetrics support bidirectional streaming. Each service defines its own cancellation, deadlines, acknowledgments and error lifecycle. Removed fields reserve their original names/numbers, and transport compatibility cannot bypass authorization or application errors.
