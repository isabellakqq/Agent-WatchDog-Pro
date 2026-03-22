# Launch Posts (CN + EN)

## 1) X 首发（中文）
我们刚刚开源了 **AgentWatchdogPro**：面向 AI Agent 的 runtime + 应用层防火墙。

它可以在工具执行前实时拦截高风险请求：
- Prompt Injection 驱动的危险操作
- 敏感文件访问（如 /etc/shadow、.env、密钥）
- SQL 注入模式
- 数据外泄模式

并提供审计轨迹与可靠性 fallback 控制。

如果你在做 AI Agent 系统，欢迎试用和提建议。

#AI #AIAgent #Security #OpenSource

---

## 2) X Launch (English)
We just open-sourced **AgentWatchdogPro** — a runtime + app-layer firewall for AI agents.

It blocks unsafe actions before tool execution:
- prompt-injection-driven tool abuse
- secret file access
- SQLi patterns
- exfiltration patterns

Includes audit trails + reliability fallback controls.

If you’re building agent systems, I’d love your feedback.

#AI #AIAgents #Security #OpenSource

---

## 3) LinkedIn（中文）
AI Agent 正在从“回答问题”走向“执行任务”。
风险也从“答错”变成“做错”。

我们开源了 **AgentWatchdogPro**，做的是 Agent 执行层的安全闸门：
- 工具调用前拦截
- 风险评分与规则匹配
- 实时 allow / block
- 审计回放与可靠性 fallback

欢迎正在做 Agent 产品的团队一起测试与共建。

---

## 4) LinkedIn (English)
AI agents are moving from copilots to operators.
That changes the risk profile from “wrong answer” to “unsafe action.”

We open-sourced **AgentWatchdogPro** to add a guardrail layer between agent intent and tool execution:
- pre-execution intercept
- risk scoring + policy matching
- real-time allow/block decision
- auditability + reliability fallback

If you’re building agent workflows, happy to collaborate.

---

## 5) Reddit（中文简版）
标题：我们开源了一个 AI Agent 应用层防火墙，想听听大家对误报和策略包的建议

正文：
我们把 AgentWatchdogPro 开源了，核心是工具执行前的 `/v1/intercept`，根据风险评分和规则进行 allow/block。
目前重点在：prompt injection、敏感文件访问、SQLi 和外泄模式。
想请教社区三个问题：
1) 误报控制最好怎么做分层？
2) 默认策略包该如何平衡安全与可用性？
3) SDK 接入体验你更偏好哪种？

---

## 6) Reddit (English)
Title: We open-sourced an app-layer firewall for AI agents — looking for feedback

Body:
We open-sourced AgentWatchdogPro to enforce runtime safety for agent tool calls.

Core flow:
- intercept on `/v1/intercept`
- risk scoring + rule matching
- real-time allow/block before execution
- audit trail + reliability fallback controls

Would love feedback on:
1) false-positive strategy,
2) policy pack design,
3) SDK ergonomics.
