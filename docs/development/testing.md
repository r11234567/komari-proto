# 协议验证

[工作流](../../.github/workflows/protocol.yml)固定 Buf 1.57.0，并保留两层 breaking：评审过的兼容基线 `d89e88d8ae3e416563e4345fd653a10f67d89053`，以及 PR 的 base 或 push 的 before（有值且不同才执行）。旧 tag `v0.1.0` 是历史标记，不是现行 CI 基线。

运行 `buf format --diff --exit-code`、`buf lint`、`buf breaking --against '.git#ref=d89e88d8ae3e416563e4345fd653a10f67d89053'`，再以本次基线额外检查。生成后 `git diff --exit-code -- gen`，同时检查新生成的未跟踪文件。用 `go test ./...`、TypeScript 编译、Node 22 和 24 的哈希向量，以及 `npm pack --dry-run` 验证两个语言的消费契约。
