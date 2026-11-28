# 协议验证

[工作流](../../.github/workflows/protocol.yml)固定 Buf 1.57.0，并保留两层 breaking：评审过的兼容基线 `d89e88d8ae3e416563e4345fd653a10f67d89053`，以及 PR 的 base 或 push 的 before（有值且不同才执行）。旧 tag `v0.1.0` 是历史标记，不是现行 CI 基线。

本地与 CI 都运行 [契约检查脚本](../../scripts/ci/check-contracts.sh)：`bash scripts/ci/check-contracts.sh <base-sha>`。脚本按 [.buf-version](../../.buf-version) 校验 Buf 版本，运行格式、lint、breaking 和生成零差异检查，包括新生成的未跟踪文件。用 `go test ./...`、`npm ci && npm test`（Node 22 和 24）及 `npm pack --dry-run` 验证两个语言的消费契约。
