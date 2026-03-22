# Launch Posts (X / LinkedIn / Reddit)

## X Post #1 (Launch)
We just open-sourced **AgentWatchdogPro**: a runtime + app-layer firewall for AI agents.

It blocks unsafe agent actions in real time:
- prompt-injection driven tool abuse
- secret-file access
- SQLi-style payloads
- exfil patterns

Includes audit trail + reliability fallback controls.

If you build agent systems, I’d love your feedback.

#AI #AIAgents #Security #OpenSource

---

## X Post #2 (Demo angle)
Most “AI safety” stops at policy docs.

We built something executable:
**AgentWatchdogPro** intercepts tool calls at runtime and returns ALLOW/BLOCK with reason + matched rule.

Now open source.

---

## LinkedIn Post (Founder narrative)
AI agents are moving from copilots to operators.
That means mistakes are no longer just bad text outputs — they can become unsafe actions.

We open-sourced **AgentWatchdogPro**, a runtime + app-layer firewall for agent systems.

What it does:
- Intercepts tool calls before execution
- Scores risk and enforces policy decisions
- Blocks risky actions in real time
- Logs audit trails for post-incident review
- Supports reliability fallback for degraded conditions

If you’re building agent products and want to test this in real workflows, DM me.

---

## Reddit Post (value-first)
Title: We open-sourced an app-layer firewall for AI agent tool calls (looking for feedback)

Body:
We’ve been seeing the same problem repeatedly in agent systems: model quality is improving, but execution safety is still fragile.

So we open-sourced **AgentWatchdogPro**:
- policy-based intercept on `/v1/intercept`
- real-time allow/block decisions
- audit logging + reliability fallback controls
- live demo page to simulate attacks and safe requests

Would appreciate feedback on:
1) false-positive handling
2) policy pack design (strict/balanced)
3) SDK ergonomics

Happy to share a quickstart and benchmark details in comments.
