# AgentWatchdogPro

<p align="center">
  <b>Open-source Runtime + App-Layer Firewall for AI Agents</b><br/>
  在 Agent 执行工具前，实时判断并阻断高风险动作（Prompt Injection / SQLi / Secret Exfiltration）
</p>

<p align="center">
  <a href="https://github.com/isabellakqq/Agent-WatchDog-Pro/releases/tag/v0.1.0-open-source">Latest Release</a>
  ·
  <a href="./ROADMAP.md">Roadmap</a>
  ·
  <a href="./CONTRIBUTING.md">Contributing</a>
</p>

---

## Why AgentWatchdogPro

AI Agent 的风险不再只是“回答错误”，而是**执行错误动作**。  
AgentWatchdogPro 提供一个可插拔的安全闸层：

- 在工具调用前做风险评估
- 返回 `allow / block`（含理由与命中规则）
- 全量审计决策轨迹
- 支持可靠性 fallback（自动/手动）

---

## What it protects

- Prompt injection 驱动的危险工具调用
- SQL injection 模式
- 敏感文件读取（`/etc/shadow` / SSH keys / `.env` / cloud creds）
- 数据外泄行为模式（webhook/paste/ngrok 等）
- 危险 shell 指令模式

---

## Architecture Diagram

```mermaid
flowchart LR
    A[Agent / Workflow Engine] --> B[/v1/intercept]
    B --> C[Risk Scoring Engine]
    C --> D[Policy Matcher]
    D -->|allow| E[Tool Execution]
    D -->|block| F[Blocked + Reason]
    D --> G[Audit Store]
    G --> H[Dashboard /demo-live]
    I[Heartbeat + Reliability Report] --> J[Reliability Control Plane]
    J --> K[Auto Fallback / Manual Fallback]
```

---

## Quick Start (Local, app-layer mode)

> 这是最推荐的安装方式：不依赖 Linux eBPF，Mac/Windows/Linux 都可先跑通。

### 1) Clone

```bash
git clone https://github.com/isabellakqq/Agent-WatchDog-Pro.git
cd Agent-WatchDog-Pro
```

### 2) Build backend

```bash
cargo build -p agent-watchdog --release
```

### 3) Start firewall proxy (proxy-only)

```bash
./target/release/agent-watchdog --proxy-only
```

默认监听：`http://localhost:3001`

### 4) Run attack simulation

```bash
python3 tests/attack_simulation.py --host localhost --port 3001 --skip-bench
```

### 5) Open visual live demo dashboard (optional)

```bash
cd dashboard
npm install
npm run dev -- --host 0.0.0.0 --port 3000
```

浏览器打开：`http://localhost:3000/demo-live`

---

## API (Core)

### Intercept

`POST /v1/intercept`

```json
{
  "agent_id": "demo-agent",
  "user_id": "demo-user",
  "tool": "file_read",
  "args": { "path": "/etc/shadow" }
}
```

Response:

```json
{
  "decision": "block",
  "allowed": false,
  "risk_score": 60.0,
  "reason": "Blocked by policy",
  "matched_rule": "block-shadow-access"
}
```

### Reliability

- `POST /v1/agent/heartbeat`
- `POST /v1/reliability/report`
- `GET /v1/reliability/status`
- `POST /v1/reliability/fallback/activate`
- `POST /v1/reliability/fallback/deactivate`

---

## Product Modes

### Mode A — App-layer Firewall (default)
- 跨平台（Mac / Windows / Linux / Cloud）
- 通过 API / SDK 拦截工具调用

### Mode B — Linux Runtime Firewall (advanced)
- 基于 eBPF 的运行时监控
- 适合 Linux 生产环境深度防护

---

## Demo Assets

- Live demo page: `dashboard/src/app/pages/LiveDemo.tsx`
- Attack simulation: `tests/attack_simulation.py`
- Reliability demo: `tests/demo_reliability.py`

---

## Open-source Plan

- GTM plan: `docs/OPEN_SOURCE-GTM-PLAN.md`
- Social launch posts: `docs/SOCIAL-POSTS-LAUNCH-ZH-EN.md`
- 7-day launch calendar: `docs/LAUNCH-WEEK-CALENDAR.md`

---

## Contributing

欢迎贡献：规则引擎、误报优化、SDK、文档、样例。  
详见：[`CONTRIBUTING.md`](./CONTRIBUTING.md)

## License

MIT
