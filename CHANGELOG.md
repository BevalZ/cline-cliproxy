# Changelog

## [v1.0.0] - 2026-09-15

首个发布：Cline 免费模型 → CLIProxyAPI 动态插件。

### 新增
- WorkOS 设备授权流登录（浏览器授权即凭证，无需手工提取 token）
- 上游模型动态同步（`/v1/models`，30 分钟刷新）+ 内置回退表
- 多账号 UID 隔离（邮箱 hash 独立凭证文件）+ 429/空响应冷却切号轮换
- 免费通道适配：非流式强制流式聚合、全局 800ms 串行间隔、空内容检测重试
- `Bearer workos:` 鉴权 + Cline 客户端指纹头（UA/X-CLIENT-TYPE/HTTP-Referer 等）

### 修复
- 上游 `{data:{...}}` 包装解包；tool_calls 流式分片按 index 合并
- refreshToken 轮换回写持久化（Cline 每次刷新都会换 refreshToken）

### 变更
- 模型策略：仅暴露免费模型，屏蔽 `cline-pass/*` 订阅付费与 `zai/glm-5.2` 按次付费
