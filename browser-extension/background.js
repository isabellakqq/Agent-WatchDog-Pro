const DEFAULT_SETTINGS = {
  backendUrl: "http://localhost:3001",
  globalPolicy: "policy-check", // block-all | policy-check | allow-all
  siteRules: {},
  blockedEvents: []
};

const AI_DOMAIN_FILTERS = [
  "||generativelanguage.googleapis.com^",
  "||gemini.google.com^",
  "||aistudio.google.com^",
  "||api.openai.com^",
  "||api.anthropic.com^",
  "||chatgpt.com^",
  "||claude.ai^",
  "||copilot.microsoft.com^"
];

const DYNAMIC_RULE_ID_START = 10000;
const DYNAMIC_RULE_ID_END = 14000;

async function getSettings() {
  const data = await chrome.storage.local.get(Object.keys(DEFAULT_SETTINGS));
  return {
    ...DEFAULT_SETTINGS,
    ...data,
    siteRules: data.siteRules || {},
    blockedEvents: data.blockedEvents || []
  };
}

async function saveSettings(patch) {
  await chrome.storage.local.set(patch);
}

function hostFromUrl(inputUrl) {
  try {
    return new URL(inputUrl).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function policyForHost(host, settings) {
  if (!host) return settings.globalPolicy;
  if (settings.siteRules[host]) return settings.siteRules[host];

  // fallback: support wildcard-ish parent domain inheritance
  const parts = host.split(".");
  for (let i = 1; i < parts.length - 1; i++) {
    const parent = parts.slice(i).join(".");
    if (settings.siteRules[parent]) return settings.siteRules[parent];
  }

  return settings.globalPolicy;
}

async function pushBlockedEvent(event) {
  const settings = await getSettings();
  const next = [
    {
      id: crypto.randomUUID(),
      ts: Date.now(),
      ...event
    },
    ...settings.blockedEvents
  ].slice(0, 120);

  await saveSettings({ blockedEvents: next });
}

async function pingBackend(backendUrl) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 1800);
  try {
    const res = await fetch(`${backendUrl.replace(/\/$/, "")}/v1/health`, {
      method: "GET",
      signal: controller.signal
    });
    clearTimeout(timeout);
    return res.ok;
  } catch {
    clearTimeout(timeout);
    return false;
  }
}

async function watchdogIntercept(tool, args, settings) {
  const backendUrl = settings.backendUrl.replace(/\/$/, "");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 2500);

  try {
    const res = await fetch(`${backendUrl}/v1/intercept`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      signal: controller.signal,
      body: JSON.stringify({
        agent_id: "browser-extension",
        user_id: "local-user",
        tool,
        args,
        session_id: "chrome"
      })
    });

    clearTimeout(timeout);

    if (!res.ok) {
      return {
        reachable: true,
        allowed: false,
        reason: `WatchDog denied (${res.status})`
      };
    }

    const data = await res.json();
    return {
      reachable: true,
      allowed: !!data.allowed,
      reason: data.reason || (data.allowed ? "Allowed by WatchDog" : "Blocked by WatchDog")
    };
  } catch {
    clearTimeout(timeout);
    return {
      reachable: false,
      allowed: false,
      reason: "WatchDog unreachable, blocked by default"
    };
  }
}

async function evaluateAccess(url, context = "ai_access") {
  const settings = await getSettings();
  const host = hostFromUrl(url);
  const mode = policyForHost(host, settings);

  if (mode === "allow-all") {
    return { policy: "allow", mode, reason: "Global/site policy allow-all" };
  }

  if (mode === "block-all") {
    const reason = "Global/site policy block-all";
    await pushBlockedEvent({ type: context, url, host, reason, source: "extension" });
    return { policy: "block", mode, reason };
  }

  const verdict = await watchdogIntercept(
    context === "action_taking" ? "browser_action_taking" : "browser_ai_access",
    { url, host, context },
    settings
  );

  if (verdict.allowed) {
    return { policy: "allow", mode, reason: verdict.reason };
  }

  await pushBlockedEvent({
    type: context,
    url,
    host,
    reason: verdict.reason,
    source: verdict.reachable ? "watchdog" : "extension"
  });

  return {
    policy: "block",
    mode,
    reason: verdict.reason
  };
}

async function syncDeclarativeRules() {
  const settings = await getSettings();

  // Enable/disable static block ruleset by global mode.
  await chrome.declarativeNetRequest.updateEnabledRulesets({
    enableRulesetIds: settings.globalPolicy === "allow-all" ? [] : ["ai_block_rules"],
    disableRulesetIds: settings.globalPolicy === "allow-all" ? ["ai_block_rules"] : []
  });

  // Rebuild dynamic allow rules for site allowlist entries.
  const dynamic = await chrome.declarativeNetRequest.getDynamicRules();
  const toRemove = dynamic
    .map(r => r.id)
    .filter(id => id >= DYNAMIC_RULE_ID_START && id <= DYNAMIC_RULE_ID_END);

  const allowHosts = Object.entries(settings.siteRules)
    .filter(([, mode]) => mode === "allow-all")
    .map(([host]) => host);

  const addRules = [];
  let id = DYNAMIC_RULE_ID_START;
  for (const host of allowHosts) {
    for (const filter of AI_DOMAIN_FILTERS) {
      if (id > DYNAMIC_RULE_ID_END) break;
      addRules.push({
        id,
        priority: 10,
        action: { type: "allow" },
        condition: {
          urlFilter: filter,
          initiatorDomains: [host],
          resourceTypes: ["main_frame", "sub_frame", "script", "xmlhttprequest"]
        }
      });
      id += 1;
    }
  }

  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: toRemove,
    addRules
  });
}

chrome.runtime.onInstalled.addListener(async () => {
  const settings = await getSettings();
  await saveSettings(settings);
  await syncDeclarativeRules();
});

chrome.runtime.onStartup.addListener(async () => {
  await syncDeclarativeRules();
});

chrome.declarativeNetRequest.onRuleMatchedDebug.addListener(async (info) => {
  await pushBlockedEvent({
    type: "network",
    url: info.request?.url || "",
    host: hostFromUrl(info.request?.url || ""),
    reason: `DNR blocked by rule ${info.rule?.ruleId}`,
    source: "dnr"
  });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    if (message?.type === "GET_EFFECTIVE_POLICY") {
      const result = await evaluateAccess(message.url, message.context || "ai_access");
      sendResponse({ ok: true, ...result });
      return;
    }

    if (message?.type === "LOG_BLOCKED_EVENT") {
      await pushBlockedEvent({
        type: message.eventType || "action",
        url: message.url || sender?.tab?.url || "",
        host: hostFromUrl(message.url || sender?.tab?.url || ""),
        reason: message.reason || "Blocked by browser firewall",
        source: message.source || "content"
      });
      sendResponse({ ok: true });
      return;
    }

    if (message?.type === "GET_STATE") {
      const settings = await getSettings();
      const backendReachable = await pingBackend(settings.backendUrl);
      sendResponse({ ok: true, settings, backendReachable });
      return;
    }

    if (message?.type === "SET_GLOBAL_POLICY") {
      await saveSettings({ globalPolicy: message.value });
      await syncDeclarativeRules();
      sendResponse({ ok: true });
      return;
    }

    if (message?.type === "SET_SITE_RULE") {
      const settings = await getSettings();
      const siteRules = { ...settings.siteRules };
      if (!message.host || message.value === "inherit") {
        delete siteRules[message.host];
      } else {
        siteRules[message.host] = message.value;
      }
      await saveSettings({ siteRules });
      await syncDeclarativeRules();
      sendResponse({ ok: true, siteRules });
      return;
    }

    if (message?.type === "CLEAR_BLOCKED_EVENTS") {
      await saveSettings({ blockedEvents: [] });
      sendResponse({ ok: true });
      return;
    }

    if (message?.type === "SAVE_SETTINGS_PATCH") {
      await saveSettings(message.patch || {});
      await syncDeclarativeRules();
      sendResponse({ ok: true });
      return;
    }

    if (message?.type === "PING_BACKEND") {
      const settings = await getSettings();
      const ok = await pingBackend(settings.backendUrl);
      sendResponse({ ok });
      return;
    }

    sendResponse({ ok: false, error: "unknown_message" });
  })();

  return true;
});
