# 当前接口与兼容边界

新功能使用 Connect 服务；存在于 schema 或带有 deprecated 标记不代表当前调用已经退役。

| 入口 | 当前状态 | 说明 |
| --- | --- | --- |
| Browser、Metrics、Config、Execution、WebSSH、AgentEvent 等 Connect 服务 | 使用中 | protobuf 中每个 RPC 的流向为准。WebSSH 和 `MetricsService.StreamMetrics` 都有双向流。 |
| `AgentReportService.SubmitReport` | 仍有现行调用 | 标记 deprecated，Agent 目前仍提交必要报告。 |
| 面板公开 `/api/rpc2` | 只读主题兼容 | 维护的允许名单与心跳；内部 RPC Bind 或旧方法名不等于对外放行。 |
| Agent v1 HTTP | 遗留兼容 | 由面板单独注册并保护，与 Browser RPC2 无关。 |
| Agent v2 WebSocket JSON-RPC | 已退役 | 现行功能通过分开的 Connect 服务实现。 |
| 哪吒 Agent gRPC | 已退役 | 同名的主题迁移与 Agent 协议无关。 |

只允许经明确设计的旧端点或传输兼容。鉴权、权限、2FA、冲突、验证失败等应用错误不触发降级。字段和 enum 不重用旧号码；不以文档整理删除 wire 或生成输入。

[面板的 RPC 边界](https://github.com/r11234567/komari/blob/main/docs/architecture/security/rpc-compatibility.md)。
