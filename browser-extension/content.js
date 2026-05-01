(async function initWatchDogContent() {
  const pageUrl = window.location.href;

  async function getPolicy(context) {
    try {
      const res = await chrome.runtime.sendMessage({
        type: "GET_EFFECTIVE_POLICY",
        url: pageUrl,
        context
      });
      if (res?.ok) return res;
      return { policy: "block", reason: "Policy check failed, blocked by default" };
    } catch {
      return { policy: "block", reason: "Runtime unavailable, blocked by default" };
    }
  }

  const aiPolicy = await getPolicy("ai_access");
  const actionPolicy = await getPolicy("action_taking");

  const blockAi = aiPolicy.policy !== "allow";
  const blockActions = actionPolicy.policy !== "allow";

  const style = document.createElement("link");
  style.rel = "stylesheet";
  style.href = chrome.runtime.getURL("styles.css");
  (document.head || document.documentElement).appendChild(style);

  const script = document.createElement("script");
  script.src = chrome.runtime.getURL("page-hook.js");
  script.dataset.awdBlockAi = String(blockAi);
  script.dataset.awdBlockActions = String(blockActions);
  script.dataset.awdAiReason = aiPolicy.reason || "Blocked by policy";
  script.dataset.awdActionReason = actionPolicy.reason || "Blocked by policy";
  script.dataset.awdMode = `${aiPolicy.mode || "unknown"}/${actionPolicy.mode || "unknown"}`;
  (document.documentElement || document.head).appendChild(script);
  script.remove();

  window.addEventListener("message", async (event) => {
    if (event.source !== window) return;
    if (!event.data || event.data.type !== "AWD_BLOCKED_EVENT") return;

    const payload = event.data.payload || {};
    await chrome.runtime.sendMessage({
      type: "LOG_BLOCKED_EVENT",
      eventType: payload.eventType || "action",
      url: pageUrl,
      reason: payload.reason || "Blocked by Agent WatchDog browser firewall",
      source: "content"
    });
  });
})();
