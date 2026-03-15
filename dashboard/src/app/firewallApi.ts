/**
 * Firewall API client — communicates with the Agent-WatchDog
 * interceptor proxy on :3001 (proxied through Vite in dev).
 *
 * This connects the Dashboard to the firewall's real-time
 * interception data (POST /v1/intercept audit trail).
 */

// ── Types ────────────────────────────────────────────────────────

export interface FirewallAuditRecord {
  id: string;
  timestamp: string;
  agent_id: string;
  user_id: string;
  session_id: string | null;
  tool: string;
  args: unknown;
  decision: "allow" | "block";
  risk_score: number;
  risk_breakdown: {
    total: number;
    tool_weight: number;
    arg_danger: number;
    frequency_penalty: number;
    details: string[];
  };
  reason: string;
  matched_rule: string | null;
  dry_run: boolean;
}

export interface FirewallAuditStats {
  total_evaluations: number;
  total_allowed: number;
  total_blocked: number;
  blocked_last_hour: number;
  avg_risk_score: number;
}

export interface FirewallAuditResponse {
  records: FirewallAuditRecord[];
  stats: FirewallAuditStats;
}

export interface InterceptRequest {
  agent_id: string;
  user_id: string;
  tool: string;
  args: Record<string, unknown>;
  session_id?: string;
}

export interface InterceptResponse {
  decision: "allow" | "block";
  allowed: boolean;
  risk_score: number;
  risk_breakdown: {
    total: number;
    tool_weight: number;
    arg_danger: number;
    frequency_penalty: number;
    details: string[];
  };
  reason: string;
  matched_rule: string | null;
  dry_run: boolean;
}

// ── REST API ─────────────────────────────────────────────────────

export async function fetchFirewallAudit(): Promise<FirewallAuditResponse> {
  const res = await fetch("/v1/audit");
  if (!res.ok) throw new Error(`GET /v1/audit failed: ${res.status}`);
  return res.json();
}

export async function fetchFirewallStats(): Promise<FirewallAuditStats> {
  const res = await fetch("/v1/audit/stats");
  if (!res.ok) throw new Error(`GET /v1/audit/stats failed: ${res.status}`);
  return res.json();
}

export async function sendInterceptRequest(
  req: InterceptRequest
): Promise<InterceptResponse> {
  const res = await fetch("/v1/intercept", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
  });
  // 403 is expected for blocked requests — still parse the body
  if (!res.ok && res.status !== 403) {
    throw new Error(`POST /v1/intercept failed: ${res.status}`);
  }
  return res.json();
}

export async function checkFirewallHealth(): Promise<boolean> {
  try {
    const res = await fetch("/v1/health");
    return res.ok;
  } catch {
    return false;
  }
}
