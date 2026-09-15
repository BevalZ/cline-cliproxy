# cline-cliproxy

把 **Cline**（https://cline.bot）的免费模型能力封装成 [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)（CPA）
动态插件：任何支持 OpenAI 协议的客户端（Claude Code、Cursor、Cline、Kelivo、SDK……）都能直接调用
Cline 上游的免费模型。

协议逆向自 [pingmike2/cline2api-workers](https://github.com/pingmike2/cline2api-workers)（MIT）。

## 功能特性

| 能力 | 说明 |
|---|---|
| 登录方式 | WorkOS 设备授权流（浏览器打开链接 → Google/GitHub/邮箱登录 → 自动完成，无需手工粘 token） |
| 模型策略 | **仅免费模型**（`:free` 后缀 + `deepseek/deepseek-v4-flash` 白名单）；`cline-pass/*` 订阅付费、`zai/glm-5.2` 按次付费全部屏蔽 |
| 模型同步 | 动态拉取上游 `/v1/models`（30 分钟刷新）+ 内置回退表 |
| 账号隔离 | 每个账号按邮箱 hash 独立凭证文件（`cline-<hash>.json`），多账号互不覆盖 |
| 额度轮换 | 429 / 空响应自动解析冷却时长（如 `Try again in 2h 51m`，上限 6h）并切号重试 |
| 免费通道适配 | 非流式请求强制上游流式再聚合；全局串行 + 800ms 间隔防并发空响应 |
| 代理 | 上游全走 `http://127.0.0.1:7890`（api.workos.com / api.cline.bot 境外） |

## 构建

```bash
cd cline-cliproxy
export PATH=$HOME/.local/go/bin:$PATH GOPROXY=https://goproxy.cn,direct
go build -buildmode=c-shared -o cline.so .
```

## 部署（3 步）

1. 复制插件并校验（btrfs 环境用 dd）：
   ```bash
   dd if=cline.so of=~/CLIProxyAPI/plugins/cline.so bs=1M && sync && md5sum cline.so ~/CLIProxyAPI/plugins/cline.so
   ```
2. `~/CLIProxyAPI/config.yaml` 的 `plugins.configs` 显式启用（新插件必须加，否则不加载）：
   ```yaml
   plugins:
     enabled: true
     dir: plugins
     configs:
       cline:
         enabled: true
         priority: 100
   ```
3. `systemctl --user restart cliproxyapi`，日志出现 `plugin registered plugin_id=cline` 即成功。

## 添加账号（登录即凭证）

管理面板（http://127.0.0.1:8317/management.html）→ cline provider → 添加账号 →
浏览器打开 WorkOS 授权链接登录 → 凭证自动落盘 `~/.cli-proxy-api/cline-<hash>.json`。
多账号各自独立文件，429 冷却自动切换。

## 可用模型（免费）

- `deepseek/deepseek-v4-flash`（默认，每日免费额度，用完 429 提示冷却时间）
- `poolside/laguna-s-2.1:free`
- 上游 `/v1/models` 中所有 `:free` 后缀模型（动态同步自动收录）

## 关联项目

- [BevalZ/workbuddy-proxy](https://github.com/BevalZ/workbuddy-proxy) — 同一插件框架下的
  腾讯 CodeBuddy + WorkBuddy International 插件
- 部署/排障经验见本机 Hermes 技能 `cliproxy-gateway/references/cline-cliproxy-plugin.md`

## 许可

MIT © 2026 BevalZ
