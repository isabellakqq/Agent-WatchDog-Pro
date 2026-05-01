let currentHost = "";

async function getCurrentHost() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url) return "";
  try {
    return new URL(tab.url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function renderEvents(events) {
  const root = document.getElementById("events");
  if (!events?.length) {
    root.innerHTML = '<div class="awd-muted">No blocked events / 暂无拦截记录</div>';
    return;
  }

  root.innerHTML = events.slice(0, 12).map((e) => {
    const time = new Date(e.ts).toLocaleTimeString();
    return `
      <div class="awd-event">
        <div class="awd-event-top">
          <span>${e.type || "event"}</span>
          <span class="awd-muted">${time}</span>
        </div>
        <div class="awd-event-reason">${(e.reason || "blocked").slice(0, 120)}</div>
        <div class="awd-muted awd-mono">${e.host || ""}</div>
      </div>
    `;
  }).join("");
}

async function refresh() {
  const hostEl = document.getElementById("currentHost");
  const globalPolicyEl = document.getElementById("globalPolicy");
  const sitePolicyEl = document.getElementById("sitePolicy");
  const backendStatusEl = document.getElementById("backendStatus");

  currentHost = await getCurrentHost();
  hostEl.textContent = currentHost || "-";

  const state = await chrome.runtime.sendMessage({ type: "GET_STATE" });
  if (!state?.ok) return;

  const { settings, backendReachable } = state;
  globalPolicyEl.value = settings.globalPolicy || "policy-check";
  sitePolicyEl.value = currentHost ? (settings.siteRules?.[currentHost] || "inherit") : "inherit";

  backendStatusEl.textContent = backendReachable ? "online" : "offline";
  backendStatusEl.className = `awd-badge ${backendReachable ? "awd-ok" : "awd-bad"}`;

  renderEvents(settings.blockedEvents || []);
}

async function main() {
  await refresh();

  document.getElementById("globalPolicy").addEventListener("change", async (e) => {
    await chrome.runtime.sendMessage({
      type: "SET_GLOBAL_POLICY",
      value: e.target.value
    });
    await refresh();
  });

  document.getElementById("saveSiteRule").addEventListener("click", async () => {
    const value = document.getElementById("sitePolicy").value;
    await chrome.runtime.sendMessage({
      type: "SET_SITE_RULE",
      host: currentHost,
      value
    });
    await refresh();
  });

  document.getElementById("clearEvents").addEventListener("click", async () => {
    await chrome.runtime.sendMessage({ type: "CLEAR_BLOCKED_EVENTS" });
    await refresh();
  });
}

main();
