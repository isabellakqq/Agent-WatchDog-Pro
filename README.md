# AgentWatchdogPro

**EN:** Open-source app-layer + runtime firewall for AI agents.  
**中文：** 面向 AI Agent 的开源应用层 + 运行时防火墙。

---

## What is AgentWatchdogPro? | 这是什么

**EN:** AgentWatchdogPro sits between your agent and tools. It intercepts tool calls before execution, scores risk, and returns `allow` / `block` with reason + matched rule.  
**中文：** AgentWatchdogPro 位于 Agent 与工具之间，在执行前拦截请求、进行风险评分，并返回 `allow` / `block`（包含原因和命中规则）。

---

## Architecture Diagram | 架构图

```text
┌───────────────────────────┐
│ Agent / Workflow Engine   │
└─────────────┬─────────────┘
              │ tool call
              ▼
      ┌───────────────────┐
      │ /v1/intercept API │  (App-layer Firewall)
      └─────────┬─────────┘
                ▼
      ┌───────────────────┐
      │ Risk + Policy     │
      │ - prompt injection│
      │ - SQLi patterns   │
      │ - secret access   │
      │ - exfil patterns  │
      └───────┬─────┬─────┘
              │     │
         allow▼     ▼block
      ┌──────────┐  ┌────────────────────┐
      │ Tool Exec│  │ Block + Reason/Rule│
      └──────────┘  └────────────────────┘
              \        /
               \      /
                ▼    ▼
            ┌──────────────┐
            │ Audit Store  │
            └──────┬───────┘
                   ▼
            ┌──────────────┐
            │ Dashboard    │
            └──────────────┘
```

---

## Core Features | 核心能力

- **EN:** Pre-execution policy enforcement for agent tool calls  
  **中文：** 工具执行前的策略拦截
- **EN:** Real-time decision: `allow` / `block` + reason + matched rule  
  **中文：** 实时决策：`allow` / `block` + 原因 + 命中规则
- **EN:** Audit trail for replay/compliance/debugging  
  **中文：** 审计轨迹（回放/合规/排障）
- **EN:** Reliability controls (heartbeat, failure report, fallback)  
  **中文：** 稳定性控制（心跳、失败上报、fallback）
- **EN:** Optional Linux runtime monitoring (eBPF mode)  
  **中文：** 可选 Linux 运行时监控（eBPF 模式）

---

## Browser Guard Extension | 浏览器防护扩展

**EN:** Added `browser-extension/` (Chrome Manifest V3) to block browser AI access and AI action-taking by default.
**中文：** 新增 `browser-extension/`（Chrome MV3 扩展），默认阻断浏览器 AI 访问与 AI 代操作。

### Browser Guard quick start | 浏览器扩展快速使用

```bash
# 1) Open Chrome extensions page
chrome://extensions

# 2) Enable Developer mode
# 3) Load unpacked -> select Agent-WatchDog-Pro/browser-extension
```

**Modes / 模式**
- `block-all`: block all AI access/action-taking（全部阻断）
- `policy-check`: call WatchDog `POST /v1/intercept`（调用策略引擎判定）
- `allow-all`: allow all（全部放行）

## SDK Status | SDK 现状

**EN:** Current repo includes a **Python SDK** (`sdk/python/agent_firewall.py`) for app-layer integration.  
**中文：** 当前仓库已提供 **Python SDK**（`sdk/python/agent_firewall.py`）用于应用层接入。

**EN:** Node/other SDKs are planned.  
**中文：** Node 等其他 SDK 在路线图中。

---

## Quick Start (Local) | 本地快速开始

### 1) Clone | 克隆仓库

```bash
git clone https://github.com/isabellakqq/Agent-WatchDog-Pro.git
cd Agent-WatchDog-Pro
```

### 2) Build backend | 编译后端

```bash
cargo build -p agent-watchdog --release
```

### 3) Start app-layer firewall | 启动应用层防火墙

```bash
./target/release/agent-watchdog --proxy-only
```

**EN:** Default endpoint: `http://localhost:3001`  
**中文：** 默认地址：`http://localhost:3001`

### 4) Example intercept request | 拦截请求示例

```bash
curl -s -X POST http://localhost:3001/v1/intercept \
  -H "content-type: application/json" \
  -d '{
    "agent_id":"demo-agent",
    "user_id":"demo-user",
    "tool":"file_read",
    "args":{"path":"/etc/shadow"}
  }'
```

---

## Key APIs | 关键接口

- `POST /v1/intercept`
- `POST /v1/agent/heartbeat`
- `POST /v1/reliability/report`
- `GET /v1/reliability/status`
- `POST /v1/reliability/fallback/activate`
- `POST /v1/reliability/fallback/deactivate`

---

## Docs | 文档

- Roadmap: [`ROADMAP.md`](./ROADMAP.md)
- Contributing: [`CONTRIBUTING.md`](./CONTRIBUTING.md)

---

## License

MIT
