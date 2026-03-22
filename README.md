# AgentWatchdogPro

**Open-source runtime + app-layer firewall for AI agents.**

AgentWatchdogPro blocks unsafe agent actions in real time (prompt injection, SQLi patterns, secret-file access, data exfil attempts), with audit trails and reliability fallback controls.

---

## Why this exists

AI agents are now taking real actions in production.
The failure mode is not just “bad answer” — it is **unsafe execution**.

AgentWatchdogPro gives you a guardrail layer between agent intent and tool execution.

---

## What it does

- **App-layer firewall (cross-platform)**
  - Intercepts agent tool calls via `/v1/intercept`
  - Scores risk + matches policy rules
  - Returns `allow` / `block` with reason and rule
- **Runtime monitoring (Linux mode)**
  - eBPF-based file access detection for sensitive paths
- **Audit trail**
  - Structured decision logs for replay, debugging, and compliance
- **Reliability control plane**
  - Heartbeats, failure counters, auto fallback, manual fallback toggle
- **Dashboard**
  - Real-time events + reliability panel + live attack demo page

---

## Threats covered (default)

- Prompt-injection-style unsafe action requests
- SQL injection patterns in query/tool payloads
- Secret-file reads (`/etc/shadow`, SSH keys, `.env`, cloud creds)
- Data exfil channels (pastebin/webhook/ngrok-style patterns)
- Dangerous shell command patterns

---

## Architecture (high-level)

1. Agent/tool call enters firewall proxy (`/v1/intercept`)
2. Risk engine scores payload + policy matcher evaluates rules
3. Decision returned (`allow` or `block`) before tool execution
4. Decision persisted to audit store
5. Reliability layer tracks failures and can auto-switch fallback mode

---

## Quickstart (app-layer mode)

### 1) Build backend

```bash
cargo build -p agent-watchdog --release
```

### 2) Start firewall proxy only (no eBPF required)

```bash
./target/release/agent-watchdog --proxy-only
```

### 3) Send a test intercept request

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

Expected result: `block` with matched rule.

### 4) Run attack simulation

```bash
python3 tests/attack_simulation.py --host localhost --port 3001 --skip-bench
```

---

## Live Demo UI

Dashboard includes a visual live demo page:

- **Path:** `/demo-live`
- Trigger attacks via buttons (SQLi / secret file / prompt injection)
- See real-time `ALLOW/BLOCK`, risk score, matched rule, and latency

---

## Reliability API

- `POST /v1/agent/heartbeat`
- `GET /v1/reliability/status`
- `POST /v1/reliability/report`
- `POST /v1/reliability/fallback/activate`
- `POST /v1/reliability/fallback/deactivate`

---

## Product modes

- **Mode A: App-layer firewall (recommended default)**
  - Works for macOS / Windows / Linux / cloud agents
- **Mode B: Linux runtime firewall (advanced hardening)**
  - Adds eBPF-based runtime visibility and blocking workflows

---

## Roadmap

See [`ROADMAP.md`](./ROADMAP.md) for public milestones.

---

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md).

If you want to help, a great place to start is:
- policy rules
- false-positive reduction
- language SDK integrations
- attack replay datasets

---

## License

MIT
