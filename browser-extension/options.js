function setStatus(msg, isError = false) {
  const el = document.getElementById("status");
  el.textContent = msg;
  el.style.color = isError ? "#f87171" : "#94a3b8";
}

async function loadState() {
  const state = await chrome.runtime.sendMessage({ type: "GET_STATE" });
  if (!state?.ok) {
    setStatus("Failed to load settings / 读取配置失败", true);
    return;
  }

  const settings = state.settings;
  document.getElementById("backendUrl").value = settings.backendUrl || "http://localhost:3001";
  document.getElementById("globalPolicy").value = settings.globalPolicy || "policy-check";
  document.getElementById("siteRules").value = JSON.stringify(settings.siteRules || {}, null, 2);
}

async function saveState() {
  const backendUrl = document.getElementById("backendUrl").value.trim();
  const globalPolicy = document.getElementById("globalPolicy").value;
  const siteRulesRaw = document.getElementById("siteRules").value.trim();

  let siteRules = {};
  if (siteRulesRaw) {
    try {
      siteRules = JSON.parse(siteRulesRaw);
    } catch (e) {
      setStatus(`Invalid JSON: ${e.message}`, true);
      return;
    }
  }

  await chrome.runtime.sendMessage({
    type: "SAVE_SETTINGS_PATCH",
    patch: { backendUrl, globalPolicy, siteRules }
  });

  setStatus("Saved / 已保存");
}

function exportSettings() {
  const payload = {
    backendUrl: document.getElementById("backendUrl").value.trim(),
    globalPolicy: document.getElementById("globalPolicy").value,
    siteRules: JSON.parse(document.getElementById("siteRules").value || "{}")
  };

  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "agent-watchdog-browser-policy.json";
  a.click();
  URL.revokeObjectURL(url);
}

function bindImport() {
  const input = document.getElementById("importFile");
  input.addEventListener("change", async () => {
    const file = input.files?.[0];
    if (!file) return;

    try {
      const text = await file.text();
      const data = JSON.parse(text);

      if (typeof data !== "object" || !data) {
        throw new Error("Invalid JSON object");
      }

      document.getElementById("backendUrl").value = data.backendUrl || "http://localhost:3001";
      document.getElementById("globalPolicy").value = data.globalPolicy || "policy-check";
      document.getElementById("siteRules").value = JSON.stringify(data.siteRules || {}, null, 2);
      setStatus("Imported. Click Save to apply / 已导入，点击保存生效");
    } catch (e) {
      setStatus(`Import failed: ${e.message}`, true);
    }

    input.value = "";
  });
}

document.getElementById("save").addEventListener("click", saveState);
document.getElementById("export").addEventListener("click", exportSettings);

bindImport();
loadState();
