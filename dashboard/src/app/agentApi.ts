/**
 * Firewall API — Agent simulation endpoints
 */

// Re-export everything from firewallApi so pages can import from either
export { checkFirewallHealth } from "./firewallApi";

const BASE =
    typeof window !== "undefined" && window.location.port === "5173"
        ? "http://localhost:3001"
        : "";

// ── Types ────────────────────────────────────────────────────

export interface ScenarioInfo {
    id: string;
    title: string;
    icon: string;
    description: string;
    task: string;
    color: "red" | "orange" | "purple" | "green" | "blue";
    step_count: number;
}

export interface SSEScenarioStart {
    id: string;
    title: string;
    task: string;
    agent_persona: string;
    total_steps: number;
}

export interface SSEThinking {
    step: number;
    thought: string;
}

export interface SSEToolCall {
    step: number;
    tool: string;
    args: Record<string, unknown>;
}

export interface SSEFirewallResult {
    step: number;
    decision: "allow" | "block";
    risk_score: number;
    reason: string;
    matched_rule: string | null;
    risk_breakdown: {
        tool_weight: number;
        arg_danger: number;
        frequency_penalty: number;
        details: string[];
    };
}

export interface SSEAgentReaction {
    step: number;
    decision: "allow" | "block";
    reaction: string;
}

export interface SSEScenarioEnd {
    id: string;
    total_steps: number;
    blocked: number;
    allowed: number;
    conclusion: string;
}

export type SSEEvent =
    | { type: "scenario_start"; data: SSEScenarioStart }
    | { type: "thinking"; data: SSEThinking }
    | { type: "tool_call"; data: SSEToolCall }
    | { type: "firewall_result"; data: SSEFirewallResult }
    | { type: "agent_reaction"; data: SSEAgentReaction }
    | { type: "scenario_end"; data: SSEScenarioEnd };

// ── API ──────────────────────────────────────────────────────

export async function fetchScenarios(): Promise<ScenarioInfo[]> {
    const res = await fetch(`${BASE}/v1/agent/scenarios`);
    if (!res.ok) throw new Error(`GET /v1/agent/scenarios failed: ${res.status}`);
    return res.json();
}

/**
 * Start a scenario and return an async iterator of SSE events.
 * Uses fetch + ReadableStream (no EventSource needed for POST).
 */
export async function* runScenarioStream(
    scenarioId: string
): AsyncGenerator<SSEEvent> {
    const res = await fetch(`${BASE}/v1/agent/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scenario_id: scenarioId }),
    });

    if (!res.ok) {
        const err = await res.text();
        throw new Error(`POST /v1/agent/run failed: ${res.status} — ${err}`);
    }

    const reader = res.body?.getReader();
    if (!reader) throw new Error("No response body");

    const decoder = new TextDecoder();
    let buffer = "";

    while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });

        // Parse SSE lines
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? ""; // Keep incomplete line in buffer

        let currentEvent = "";
        for (const line of lines) {
            if (line.startsWith("event: ")) {
                currentEvent = line.slice(7).trim();
            } else if (line.startsWith("data: ") && currentEvent) {
                try {
                    const data = JSON.parse(line.slice(6));
                    yield { type: currentEvent, data } as SSEEvent;
                } catch {
                    // skip malformed
                }
                currentEvent = "";
            }
        }
    }
}
