/**
 * Agent-WatchDog — Mock Firewall Backend (Bun/TypeScript)
 *
 * A faithful port of the Rust firewall proxy that runs natively on macOS.
 * Replicates: risk scoring, policy engine, prompt injection detection,
 * audit trail, and all API endpoints.
 *
 * Usage:
 *   cd /path/to/Agent-WatchDog
 *   bun run mock-server/firewall.ts
 *
 * Endpoints (port 3001):
 *   POST /v1/intercept        — evaluate a tool call
 *   GET  /v1/audit            — get audit log + stats
 *   GET  /v1/audit/stats      — get summary stats only
 *   GET  /v1/health           — health check
 *   GET  /v1/agent/scenarios  — list demo scenarios
 *   POST /v1/agent/run        — run a scenario (SSE stream)
 */

import { ALL_SCENARIOS, type Scenario, type ScenarioStep } from "./scenarios";

// ══════════════════════════════════════════════════════════════════
//  TOOL WEIGHTS  (0–40)
// ══════════════════════════════════════════════════════════════════

function toolBaseWeight(tool: string): [number, string] {
    switch (tool.toLowerCase()) {
        case "shell_exec":
        case "exec":
        case "run_command":
        case "bash":
            return [40, "Shell execution — highest risk"];
        case "file_write":
        case "file_delete":
        case "fs_write":
        case "write_file":
            return [35, "File write/delete — can corrupt data"];
        case "file_read":
        case "fs_read":
        case "read_file":
            return [20, "File read — can leak secrets"];
        case "http_request":
        case "fetch":
        case "curl":
        case "api_call":
            return [25, "HTTP request — potential exfiltration"];
        case "database_query":
        case "sql_query":
        case "db_exec":
            return [30, "Database query — can read/modify data"];
        case "mongo_query":
            return [30, "MongoDB query — can read/modify data"];
        case "env_read":
        case "get_env":
        case "read_env":
            return [15, "Environment read — can leak config"];
        case "code_exec":
        case "eval":
        case "python_exec":
            return [38, "Code execution — near-maximum risk"];
        case "llm_call":
        case "llm_invoke":
        case "chat_completion":
            return [15, "LLM call — prompt injection vector"];
        case "search":
        case "web_search":
        case "calculator":
        case "clock":
            return [5, "Information tool — low risk"];
        default:
            return [15, "Unknown tool — moderate default risk"];
    }
}

// ══════════════════════════════════════════════════════════════════
//  DANGEROUS PATTERNS  (arg matching, 0–40 cap)
// ══════════════════════════════════════════════════════════════════

const DANGEROUS_PATTERNS: [string, number, string][] = [
    // ── File paths
    ["/etc/shadow", 40, "Password file access"],
    ["/etc/passwd", 20, "User list access"],
    ["id_rsa", 35, "SSH private key"],
    ["id_ed25519", 35, "SSH private key"],
    [".env", 30, "Environment secrets"],
    ["aws/credentials", 35, "AWS credentials"],
    [".kube/config", 30, "Kubernetes config"],
    ["master.key", 35, "Master key access"],
    ["gcp-sa-key", 30, "GCP service account key"],
    [".bash_history", 25, "Bash history access"],
    // ── Shell commands
    ["rm -rf", 40, "Recursive force delete"],
    ["chmod 777", 30, "Insecure permissions"],
    ["curl", 15, "External HTTP call"],
    ["wget", 15, "External download"],
    ["nc ", 35, "Netcat — possible reverse shell"],
    ["ncat", 35, "Ncat — possible reverse shell"],
    ["base64", 20, "Encoding — possible obfuscation"],
    ["> /dev/", 35, "Writing to device file"],
    ["| bash", 40, "Piping to bash — code injection"],
    ["| sh", 35, "Piping to sh — code injection"],
    ["eval(", 35, "Dynamic code evaluation"],
    ["exec(", 35, "Dynamic code execution"],
    ["mkfifo", 30, "Named pipe — possible reverse shell"],
    ["/bin/sh -i", 40, "Interactive shell — reverse shell"],
    ["/dev/tcp/", 40, "Bash /dev/tcp reverse shell"],
    // ── SQL Injection — Classic
    ["drop table", 40, "SQL DROP TABLE"],
    ["drop database", 40, "SQL DROP DATABASE"],
    ["delete from", 30, "SQL DELETE"],
    ["truncate table", 35, "SQL TRUNCATE TABLE"],
    ["alter table", 25, "SQL ALTER TABLE"],
    ["' or '1'='1", 40, "SQL injection — tautology"],
    ["' or 1=1", 40, "SQL injection — tautology"],
    ["or 1=1", 30, "SQL injection — tautology"],
    ["having 1=1", 35, "SQL injection — HAVING tautology"],
    ["union select", 35, "SQL injection — UNION"],
    ["union all select", 35, "SQL injection — UNION ALL"],
    // ── SQL Injection — Blind / Time-based
    ["sleep(", 35, "SQL injection — time-based blind (SLEEP)"],
    ["benchmark(", 35, "SQL injection — time-based blind (BENCHMARK)"],
    ["waitfor delay", 35, "SQL injection — MSSQL time-based blind"],
    ["pg_sleep", 35, "SQL injection — PostgreSQL time-based blind"],
    // ── SQL Injection — Data Exfiltration
    ["load_file(", 35, "SQL injection — file read (LOAD_FILE)"],
    ["into outfile", 35, "SQL injection — file write (INTO OUTFILE)"],
    ["into dumpfile", 35, "SQL injection — file write (INTO DUMPFILE)"],
    ["information_schema", 30, "SQL injection — schema enumeration"],
    ["group_concat(", 25, "SQL injection — data extraction"],
    // ── SQL Injection — Stacked Queries
    ["; drop", 35, "SQL injection — stacked query (DROP)"],
    ["; delete", 30, "SQL injection — stacked query (DELETE)"],
    ["; exec", 30, "SQL injection — stacked query (EXEC)"],
    // ── SQL Injection — Stored Procedures
    ["xp_cmdshell", 40, "SQL injection — MSSQL command execution"],
    ["sp_executesql", 30, "SQL injection — MSSQL dynamic SQL"],
    // ── SQL Injection — Error-based
    ["extractvalue(", 30, "SQL injection — error-based (EXTRACTVALUE)"],
    ["updatexml(", 30, "SQL injection — error-based (UPDATEXML)"],
    // ── SQL Injection — OOB
    ["utl_http.request", 35, "SQL injection — Oracle OOB"],
    ["utl_inaddr", 30, "SQL injection — Oracle DNS lookup"],
    ["dbms_ldap", 30, "SQL injection — Oracle LDAP exfiltration"],
    ["xp_dirtree", 35, "SQL injection — MSSQL UNC path exfil"],
    // ── SQL Injection — Second-order / ORM
    ["char(", 20, "SQL injection — CHAR() bypass"],
    ["substr(", 20, "SQL injection — SUBSTR() extraction"],
    ["substring(", 20, "SQL injection — SUBSTRING() extraction"],
    // ── NoSQL Injection
    ["$where", 30, "NoSQL injection — MongoDB $where"],
    ["$gt", 20, "NoSQL injection — MongoDB $gt operator"],
    ["$ne", 20, "NoSQL injection — MongoDB $ne operator"],
    ["$regex", 25, "NoSQL injection — MongoDB $regex"],
    // ── Exfiltration
    ["webhook.site", 30, "Known exfiltration endpoint"],
    ["ngrok", 25, "Tunnel — possible exfiltration"],
    ["pastebin", 25, "Paste service — possible data leak"],
    ["requestbin", 25, "Request bin — possible exfiltration"],
    ["pipedream", 25, "Pipedream — possible exfiltration"],
];

// ══════════════════════════════════════════════════════════════════
//  PROMPT INJECTION PATTERNS
// ══════════════════════════════════════════════════════════════════

const INJECTION_PATTERNS: [string, number, string][] = [
    // ── Instruction Override
    ["ignore previous instructions", 35, "Prompt injection: instruction override"],
    ["ignore all instructions", 35, "Prompt injection: instruction override"],
    ["ignore all previous", 35, "Prompt injection: instruction override"],
    ["disregard previous instructions", 35, "Prompt injection: instruction override"],
    ["forget your instructions", 35, "Prompt injection: instruction override"],
    ["forget all instructions", 35, "Prompt injection: instruction override"],
    ["override your instructions", 35, "Prompt injection: instruction override"],
    ["new instructions:", 25, "Prompt injection: instruction injection"],
    // ── Role Hijacking
    ["you are now", 25, "Prompt injection: role hijacking"],
    ["pretend to be", 25, "Prompt injection: role hijacking"],
    ["pretend you are", 25, "Prompt injection: role hijacking"],
    ["act as if you", 20, "Prompt injection: role hijacking"],
    ["from now on you are", 30, "Prompt injection: role hijacking"],
    ["enter developer mode", 30, "Prompt injection: developer mode"],
    ["enter debug mode", 25, "Prompt injection: debug mode"],
    // ── Information Extraction
    ["system prompt", 30, "Prompt injection: system prompt extraction"],
    ["show your instructions", 30, "Prompt injection: instruction extraction"],
    ["reveal your instructions", 30, "Prompt injection: instruction extraction"],
    ["repeat your instructions", 30, "Prompt injection: instruction extraction"],
    ["show me your prompt", 30, "Prompt injection: prompt extraction"],
    // ── Jailbreak
    ["jailbreak", 35, "Prompt injection: jailbreak keyword"],
    ["dan mode", 30, "Prompt injection: DAN jailbreak"],
    ["developer mode enabled", 30, "Prompt injection: developer mode jailbreak"],
    ["do anything now", 30, "Prompt injection: DAN jailbreak"],
    ["no restrictions", 25, "Prompt injection: restriction bypass"],
    ["without any restrictions", 25, "Prompt injection: restriction bypass"],
    ["bypass restrictions", 30, "Prompt injection: restriction bypass"],
    ["no ethical guidelines", 30, "Prompt injection: ethics bypass"],
    ["ignore safety", 35, "Prompt injection: safety bypass"],
    ["ignore content policy", 35, "Prompt injection: policy bypass"],
    // ── Security Bypass
    ["override security", 35, "Prompt injection: security override"],
    ["bypass security", 35, "Prompt injection: security bypass"],
    ["bypass filter", 30, "Prompt injection: filter bypass"],
    ["disable security", 35, "Prompt injection: security disable"],
    ["disable safety", 35, "Prompt injection: safety disable"],
    ["ignore safeguards", 35, "Prompt injection: safeguard bypass"],
    // ── Delimiter / Boundary Injection
    ["[system]", 25, "Prompt injection: fake system delimiter"],
    ["<<sys>>", 25, "Prompt injection: fake system delimiter"],
    ["### system:", 25, "Prompt injection: fake system header"],
    ["<|im_start|>", 30, "Prompt injection: ChatML delimiter injection"],
    ["<|im_end|>", 30, "Prompt injection: ChatML delimiter injection"],
    ["```system", 25, "Prompt injection: code-block system injection"],
    // ── Encoding Evasion
    ["base64 decode", 20, "Prompt injection: encoding evasion"],
    ["rot13", 15, "Prompt injection: encoding evasion"],
    ["decode the following", 15, "Prompt injection: encoding evasion"],
    ["decode and execute", 20, "Prompt injection: encoding evasion"],
    // ── Indirect Prompt Injection
    ["when the user asks", 20, "Prompt injection: indirect trigger"],
    ["if anyone asks", 20, "Prompt injection: indirect trigger"],
    ["in your next response", 20, "Prompt injection: deferred action"],
    ["from this point forward", 20, "Prompt injection: persistent override"],
    ["always respond with", 20, "Prompt injection: response override"],
    ["never mention", 15, "Prompt injection: censorship directive"],
    // ── Payload Splitting
    ["concatenate the following", 20, "Prompt injection: payload splitting"],
    ["combine these parts", 20, "Prompt injection: payload assembly"],
    ["read backwards", 15, "Prompt injection: reversal evasion"],
    ["take first letter of each", 15, "Prompt injection: acrostic evasion"],
    // ── Multi-language
    ["忽略之前的指令", 30, "Prompt injection: Chinese instruction override"],
    ["忽略之前的", 25, "Prompt injection: Chinese partial override"],
    ["ignorez les instructions", 30, "Prompt injection: French instruction override"],
    ["ignoriere alle anweisungen", 30, "Prompt injection: German instruction override"],
    ["前の指示を無視", 30, "Prompt injection: Japanese instruction override"],
    // ── Context Manipulation
    ["new conversation begins", 25, "Prompt injection: context reset"],
    ["the previous messages were a test", 25, "Prompt injection: context invalidation"],
];

// ══════════════════════════════════════════════════════════════════
//  DETECTION ENGINE
// ══════════════════════════════════════════════════════════════════

interface RiskBreakdown {
    total: number;
    tool_weight: number;
    arg_danger: number;
    frequency_penalty: number;
    details: string[];
}

function computeArgDanger(args: unknown): [number, string[]] {
    const raw = JSON.stringify(args).toLowerCase();
    let score = 0;
    const details: string[] = [];

    // Pattern matching on args
    for (const [pattern, weight, desc] of DANGEROUS_PATTERNS) {
        if (raw.includes(pattern.toLowerCase())) {
            score += weight;
            details.push(`${desc} (+${weight})`);
        }
    }

    // Prompt injection detection
    for (const [pattern, weight, desc] of INJECTION_PATTERNS) {
        if (raw.includes(pattern.toLowerCase())) {
            score += weight;
            details.push(`${desc} (+${weight})`);
        }
    }

    // Multi-pattern bonus (like the Rust implementation)
    const injectionHits = details.filter((d) => d.includes("Prompt injection")).length;
    if (injectionHits >= 3) {
        const bonus = (injectionHits - 2) * 5;
        score += bonus;
        details.push(
            `Multiple injection indicators (${injectionHits} patterns, +${bonus} bonus)`
        );
    }

    return [Math.min(score, 40), details];
}

// ── Frequency tracker (per-agent burst detection) ────────────────

const callWindows = new Map<string, number[]>();
const WINDOW_MS = 60_000; // 60 seconds
const BURST_THRESHOLD = 10;

function frequencyPenalty(agentId: string): [number, string | null] {
    const now = Date.now();
    const cutoff = now - WINDOW_MS;

    let calls = callWindows.get(agentId) ?? [];
    calls = calls.filter((t) => t > cutoff);
    calls.push(now);
    callWindows.set(agentId, calls);

    if (calls.length > BURST_THRESHOLD) {
        const ratio = (calls.length - BURST_THRESHOLD) / BURST_THRESHOLD;
        const penalty = Math.min(ratio * 20, 20);
        return [
            penalty,
            `Burst: ${calls.length} calls in 60s (threshold: ${BURST_THRESHOLD})`,
        ];
    }
    return [0, null];
}

function computeRisk(
    tool: string,
    args: unknown,
    agentId: string
): RiskBreakdown {
    const details: string[] = [];

    // 1. Tool weight
    const [tw, toolDesc] = toolBaseWeight(tool);
    details.push(`Tool: ${tool} — ${toolDesc} (+${tw})`);

    // 2. Arg danger
    const [ad, argDetails] = computeArgDanger(args);
    details.push(...argDetails);

    // 3. Frequency
    const [fp, fpDetail] = frequencyPenalty(agentId);
    if (fpDetail) details.push(fpDetail);

    return {
        total: Math.min(tw + ad + fp, 100),
        tool_weight: tw,
        arg_danger: ad,
        frequency_penalty: fp,
        details,
    };
}

// ══════════════════════════════════════════════════════════════════
//  POLICY ENGINE
// ══════════════════════════════════════════════════════════════════

interface PolicyRule {
    id: string;
    description: string;
    action: "block" | "allow";
    tools?: string[];
    arg_contains?: string[];
    min_risk_score?: number;
}

// Ported from watchdog.toml
const POLICY_RULES: PolicyRule[] = [
    {
        id: "block-shadow-access",
        description: "Block any tool reading /etc/shadow",
        action: "block",
        arg_contains: ["/etc/shadow"],
    },
    {
        id: "block-ssh-key-access",
        description: "Block reading SSH private keys",
        action: "block",
        arg_contains: ["id_rsa", "id_ed25519", "id_ecdsa"],
    },
    {
        id: "block-dangerous-shell",
        description: "Block dangerous shell commands",
        action: "block",
        tools: ["shell_exec", "exec", "run_command", "bash"],
        arg_contains: [
            "rm -rf",
            "| bash",
            "> /dev/",
            "nc ",
            "ncat",
            "netcat",
            "/dev/sda",
            "/dev/tcp/",
            "dd if=",
            "chmod 777",
            "chmod 666",
        ],
    },
    {
        id: "block-env-exfiltration",
        description: "Block reading .env files, AWS credentials, or kube config",
        action: "block",
        arg_contains: [".env", "aws/credentials", "master.key", ".kube/config"],
    },
    {
        id: "block-data-exfiltration",
        description: "Block HTTP to known exfil endpoints",
        action: "block",
        tools: ["http_request", "fetch", "curl", "api_call"],
        arg_contains: [
            "webhook.site",
            "ngrok",
            "pastebin",
            "requestbin",
            "hookbin",
            "pipedream",
        ],
    },
    {
        id: "block-sql-injection",
        description: "Block SQL injection patterns in DB tools",
        action: "block",
        tools: ["database_query", "sql_query", "db_exec", "mongo_query"],
        arg_contains: [
            "' or '1'='1",
            "' or 1=1",
            "or 1=1",
            "having 1=1",
            "union select",
            "union all select",
            "drop table",
            "drop database",
            "delete from",
            "truncate table",
            "sleep(",
            "benchmark(",
            "waitfor delay",
            "pg_sleep",
            "load_file(",
            "into outfile",
            "into dumpfile",
            "information_schema",
            "xp_cmdshell",
            "sp_executesql",
            "; drop",
            "; delete",
            "; exec",
            "group_concat(",
            "extractvalue(",
            "updatexml(",
            "utl_http",
            "xp_dirtree",
            "$where",
            "$gt",
            "$ne",
            "$regex",
        ],
    },
    {
        id: "block-sql-injection-any-tool",
        description: "Block SQL injection patterns in any tool",
        action: "block",
        arg_contains: [
            "union select",
            "' or '1'='1",
            "drop table",
            "xp_cmdshell",
            "sleep(",
            "benchmark(",
            "into outfile",
            "information_schema",
        ],
        min_risk_score: 30,
    },
    {
        id: "block-prompt-injection",
        description: "Block common prompt injection patterns",
        action: "block",
        arg_contains: [
            "ignore previous instructions",
            "ignore all instructions",
            "disregard previous instructions",
            "forget your instructions",
            "override security",
            "bypass security",
            "system prompt",
            "jailbreak",
            "dan mode",
            "developer mode enabled",
            "ignore safety",
            "<|im_start|>",
            "you are now",
            "pretend to be",
            "忽略之前的指令",
            "忽略之前的",
            "decode and execute",
            "no restrictions",
            "disable safety",
            "when the user asks",
        ],
    },
    {
        id: "allow-calculator",
        description: "Always allow calculator and clock tools",
        action: "allow",
        tools: ["calculator", "clock", "search"],
    },
];

const RISK_THRESHOLD = 80;

function evaluatePolicy(
    tool: string,
    args: unknown,
    risk: RiskBreakdown
): { decision: "allow" | "block"; reason: string; matched_rule: string | null } {
    const argsStr = JSON.stringify(args).toLowerCase();
    const toolLower = tool.toLowerCase();

    for (const rule of POLICY_RULES) {
        // Check tool match
        if (rule.tools && rule.tools.length > 0) {
            const toolMatch = rule.tools.some((t) => {
                if (t.endsWith("*")) return toolLower.startsWith(t.slice(0, -1));
                if (t.startsWith("*")) return toolLower.endsWith(t.slice(1));
                return toolLower === t;
            });
            if (!toolMatch) continue;
        }

        // Check arg_contains match
        if (rule.arg_contains && rule.arg_contains.length > 0) {
            const argMatch = rule.arg_contains.some((pat) =>
                argsStr.includes(pat.toLowerCase())
            );
            if (!argMatch) continue;
        }

        // Check min_risk_score
        if (rule.min_risk_score !== undefined && risk.total < rule.min_risk_score) {
            continue;
        }

        // Rule matched!
        return {
            decision: rule.action,
            reason: rule.description,
            matched_rule: rule.id,
        };
    }

    // No rule matched — check risk threshold
    if (risk.total >= RISK_THRESHOLD) {
        return {
            decision: "block",
            reason: `Risk score ${risk.total.toFixed(1)} exceeds threshold ${RISK_THRESHOLD}`,
            matched_rule: null,
        };
    }

    return {
        decision: "allow",
        reason: `No policy rule matched, risk ${risk.total.toFixed(1)} below threshold`,
        matched_rule: null,
    };
}

// ══════════════════════════════════════════════════════════════════
//  AUDIT STORE (in-memory ring buffer)
// ══════════════════════════════════════════════════════════════════

interface AuditRecord {
    id: string;
    timestamp: string;
    agent_id: string;
    user_id: string;
    session_id: string | null;
    tool: string;
    args: unknown;
    decision: "allow" | "block";
    risk_score: number;
    risk_breakdown: RiskBreakdown;
    reason: string;
    matched_rule: string | null;
    dry_run: boolean;
}

const auditRecords: AuditRecord[] = [];
const MAX_RECORDS = 50_000;
let recordCounter = 0;

function addAuditRecord(rec: Omit<AuditRecord, "id">) {
    recordCounter++;
    const record: AuditRecord = { id: `audit-${recordCounter}`, ...rec };
    auditRecords.push(record);
    if (auditRecords.length > MAX_RECORDS) auditRecords.shift();
}

function getStats() {
    const total = auditRecords.length;
    const blocked = auditRecords.filter((r) => r.decision === "block").length;
    const allowed = total - blocked;
    const oneHourAgo = Date.now() - 3600_000;
    const blockedLastHour = auditRecords.filter(
        (r) =>
            r.decision === "block" && new Date(r.timestamp).getTime() > oneHourAgo
    ).length;
    const avgRisk =
        total > 0
            ? auditRecords.reduce((s, r) => s + r.risk_score, 0) / total
            : 0;
    return {
        total_evaluations: total,
        total_allowed: allowed,
        total_blocked: blocked,
        blocked_last_hour: blockedLastHour,
        avg_risk_score: avgRisk,
    };
}

// ══════════════════════════════════════════════════════════════════
//  HTTP SERVER (Bun.serve)
// ══════════════════════════════════════════════════════════════════

const PORT = 3001;

const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
};

function jsonResponse(data: unknown, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: { "Content-Type": "application/json", ...corsHeaders },
    });
}

console.log(`
╔══════════════════════════════════════════════════════════╗
║  🛡️  Agent-WatchDog — Mock Firewall Backend              ║
║  Port: ${PORT}                                              ║
║  Endpoints:                                              ║
║    POST /v1/intercept        — evaluate tool call        ║
║    GET  /v1/audit            — audit log + stats         ║
║    GET  /v1/audit/stats      — summary stats             ║
║    GET  /v1/health           — health check              ║
║    GET  /v1/agent/scenarios  — list demo scenarios       ║
║    POST /v1/agent/run        — run scenario (SSE)        ║
╚══════════════════════════════════════════════════════════╝
`);

// ══════════════════════════════════════════════════════════════════
//  AGENT SIMULATION ENGINE (SSE streaming)
// ══════════════════════════════════════════════════════════════════

function sseEvent(event: string, data: unknown): string {
    return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Run a scenario step-by-step, streaming SSE events to the client */
async function runScenario(
    scenario: Scenario,
    controller: ReadableStreamDefaultController<Uint8Array>
): Promise<void> {
    const encoder = new TextEncoder();
    const emit = (event: string, data: unknown) => {
        try {
            controller.enqueue(encoder.encode(sseEvent(event, data)));
        } catch {
            // Stream closed by client
        }
    };

    // Start event
    emit("scenario_start", {
        id: scenario.id,
        title: scenario.title,
        task: scenario.task,
        agent_persona: scenario.agent_persona,
        total_steps: scenario.steps.length,
    });

    await sleep(800);

    let totalBlocked = 0;
    let totalAllowed = 0;

    for (let i = 0; i < scenario.steps.length; i++) {
        const step = scenario.steps[i];

        // Delay for dramatic effect
        if (step.delay_ms) {
            await sleep(step.delay_ms);
        }

        // Emit agent thinking
        emit("thinking", {
            step: i + 1,
            thought: step.thought,
        });

        await sleep(1200); // Give time to read the thought

        // Emit tool call intent
        emit("tool_call", {
            step: i + 1,
            tool: step.tool,
            args: step.args,
        });

        await sleep(600);

        // Actually evaluate through the firewall engine
        const agentId = `demo-${scenario.id}`;
        const risk = computeRisk(step.tool, step.args, agentId);
        const { decision, reason, matched_rule } = evaluatePolicy(
            step.tool,
            step.args,
            risk
        );

        // Record in audit log (real records!)
        addAuditRecord({
            timestamp: new Date().toISOString(),
            agent_id: agentId,
            user_id: "demo-e2e",
            session_id: `scenario-${scenario.id}`,
            tool: step.tool,
            args: step.args,
            decision,
            risk_score: risk.total,
            risk_breakdown: risk,
            reason,
            matched_rule,
            dry_run: false,
        });

        if (decision === "block") totalBlocked++;
        else totalAllowed++;

        // Emit firewall result
        emit("firewall_result", {
            step: i + 1,
            decision,
            risk_score: risk.total,
            reason,
            matched_rule,
            risk_breakdown: {
                tool_weight: risk.tool_weight,
                arg_danger: risk.arg_danger,
                frequency_penalty: risk.frequency_penalty,
                details: risk.details,
            },
        });

        await sleep(800);

        // Emit agent reaction (adaptation)
        const reaction =
            decision === "block" ? step.on_block : step.on_allow;
        if (reaction) {
            emit("agent_reaction", {
                step: i + 1,
                decision,
                reaction,
            });
            await sleep(600);
        }
    }

    // Scenario complete
    emit("scenario_end", {
        id: scenario.id,
        total_steps: scenario.steps.length,
        blocked: totalBlocked,
        allowed: totalAllowed,
        conclusion: scenario.conclusion,
    });

    controller.close();
}

Bun.serve({
    port: PORT,
    hostname: "0.0.0.0",
    async fetch(req) {
        const url = new URL(req.url);

        // CORS preflight
        if (req.method === "OPTIONS") {
            return new Response(null, { status: 204, headers: corsHeaders });
        }

        // ── Health ──
        if (url.pathname === "/v1/health" && req.method === "GET") {
            return new Response("ok", { status: 200, headers: corsHeaders });
        }

        // ── Audit log ──
        if (url.pathname === "/v1/audit" && req.method === "GET") {
            const recent = auditRecords.slice(-100).reverse();
            return jsonResponse({ records: recent, stats: getStats() });
        }

        // ── Audit stats ──
        if (url.pathname === "/v1/audit/stats" && req.method === "GET") {
            return jsonResponse(getStats());
        }

        // ── Agent scenarios list ──
        if (url.pathname === "/v1/agent/scenarios" && req.method === "GET") {
            const scenarioList = ALL_SCENARIOS.map((s) => ({
                id: s.id,
                title: s.title,
                icon: s.icon,
                description: s.description,
                task: s.task,
                color: s.color,
                step_count: s.steps.length,
            }));
            return jsonResponse(scenarioList);
        }

        // ── Agent scenario runner (SSE stream) ──
        if (url.pathname === "/v1/agent/run" && req.method === "POST") {
            try {
                const body = (await req.json()) as { scenario_id: string };
                const scenario = ALL_SCENARIOS.find(
                    (s) => s.id === body.scenario_id
                );
                if (!scenario) {
                    return jsonResponse(
                        { error: `Scenario '${body.scenario_id}' not found` },
                        404
                    );
                }

                console.log(
                    `\n🎬 Starting scenario: ${scenario.title} (${scenario.steps.length} steps)`
                );

                const stream = new ReadableStream<Uint8Array>({
                    async start(controller) {
                        await runScenario(scenario, controller);
                    },
                });

                return new Response(stream, {
                    status: 200,
                    headers: {
                        "Content-Type": "text/event-stream",
                        "Cache-Control": "no-cache",
                        Connection: "keep-alive",
                        ...corsHeaders,
                    },
                });
            } catch (e) {
                console.error("Error starting scenario:", e);
                return jsonResponse({ error: "Invalid request" }, 400);
            }
        }

        // ── Intercept (THE CORE ENDPOINT) ──
        if (url.pathname === "/v1/intercept" && req.method === "POST") {
            try {
                const body = (await req.json()) as {
                    agent_id: string;
                    user_id: string;
                    tool: string;
                    args: unknown;
                    session_id?: string;
                };

                const { agent_id, user_id, tool, args, session_id } = body;

                // 1. Compute risk
                const risk = computeRisk(tool, args, agent_id);

                // 2. Evaluate policy
                const { decision, reason, matched_rule } = evaluatePolicy(
                    tool,
                    args,
                    risk
                );

                // 3. Log
                const emoji = decision === "block" ? "🛑 BLOCKED" : "✅ ALLOWED";
                console.log(
                    `${emoji}: agent=${agent_id} tool=${tool} risk=${risk.total.toFixed(1)} reason=${reason}`
                );

                // 4. Record audit
                addAuditRecord({
                    timestamp: new Date().toISOString(),
                    agent_id,
                    user_id,
                    session_id: session_id ?? null,
                    tool,
                    args,
                    decision,
                    risk_score: risk.total,
                    risk_breakdown: risk,
                    reason,
                    matched_rule,
                    dry_run: false,
                });

                // 5. Respond
                const response = {
                    decision,
                    allowed: decision === "allow",
                    risk_score: risk.total,
                    risk_breakdown: risk,
                    reason,
                    matched_rule,
                    dry_run: false,
                };

                return jsonResponse(
                    response,
                    decision === "block" ? 403 : 200
                );
            } catch (e) {
                console.error("Error processing intercept:", e);
                return jsonResponse({ error: "Invalid request" }, 400);
            }
        }

        return new Response("Not Found", { status: 404, headers: corsHeaders });
    },
});

console.log(`🔥 Firewall mock backend running on http://localhost:${PORT}`);
console.log(`   Try: curl http://localhost:${PORT}/v1/health`);
console.log(``);
