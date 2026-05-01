(() => {
  const currentScript = document.currentScript;
  const blockAi = currentScript?.dataset?.awdBlockAi === "true";
  const blockActions = currentScript?.dataset?.awdBlockActions === "true";
  const aiReason = currentScript?.dataset?.awdAiReason || "Blocked by policy";
  const actionReason = currentScript?.dataset?.awdActionReason || "Blocked by policy";
  const mode = currentScript?.dataset?.awdMode || "unknown";

  if (!blockAi && !blockActions) return;

  const KEYWORDS = /(gemini|google\s*ai|copilot|openai|anthropic|assistant|prompt\s*api|window\.ai|chrome\.ai)/i;
  const STACK_HINT = /(gemini|copilot|openai|anthropic|assistant|playwright|puppeteer|selenium|robot|autofill|automate)/i;

  let blockedCount = 0;
  let lastUserGestureAt = Date.now();

  const emitBlocked = (eventType, reason, details = {}) => {
    blockedCount += 1;
    updateBadge();

    window.postMessage({
      type: "AWD_BLOCKED_EVENT",
      payload: {
        eventType,
        reason,
        details,
        mode,
        blockedCount
      }
    }, "*");
  };

  const isRecentUserGesture = () => Date.now() - lastUserGestureAt < 1200;

  const likelyAutomatedCall = () => {
    const stack = (new Error().stack || "").toLowerCase();
    return STACK_HINT.test(stack) || !isRecentUserGesture();
  };

  const userEvents = ["pointerdown", "mousedown", "keydown", "touchstart", "submit", "click"];
  userEvents.forEach((evt) => {
    window.addEventListener(evt, () => {
      lastUserGestureAt = Date.now();
    }, { capture: true, passive: true });
  });

  // Small floating indicator
  const panel = document.createElement("div");
  panel.className = "awd-indicator";
  panel.innerHTML = `
    <div class="awd-title">Agent WatchDog</div>
    <div class="awd-sub">AI Firewall Active</div>
    <div class="awd-meta">Mode: ${mode}</div>
    <div class="awd-meta" id="awd-count">Blocked: 0</div>
  `;
  document.documentElement.appendChild(panel);

  const updateBadge = () => {
    const count = panel.querySelector("#awd-count");
    if (count) count.textContent = `Blocked: ${blockedCount}`;
  };

  setTimeout(() => {
    panel.style.opacity = "0.6";
  }, 3500);

  if (blockAi) {
    const blockApiRead = (name, reason) => {
      try {
        Object.defineProperty(window, name, {
          configurable: false,
          enumerable: false,
          get() {
            emitBlocked("ai_access", reason, { api: name });
            throw new Error(`Agent WatchDog blocked ${name}: ${reason}`);
          },
          set() {
            emitBlocked("ai_access", `Write attempt on ${name}`, { api: name });
            return true;
          }
        });
      } catch {
        // ignore defineProperty failures
      }
    };

    blockApiRead("ai", aiReason);

    if (window.chrome && typeof window.chrome === "object") {
      try {
        Object.defineProperty(window.chrome, "aiOriginTrial", {
          configurable: false,
          get() {
            emitBlocked("ai_access", aiReason, { api: "chrome.aiOriginTrial" });
            throw new Error(`Agent WatchDog blocked chrome.aiOriginTrial: ${aiReason}`);
          },
          set() {
            emitBlocked("ai_access", "Write attempt on chrome.aiOriginTrial", { api: "chrome.aiOriginTrial" });
            return true;
          }
        });
      } catch {
        // ignore
      }
    }

    const originalPostMessage = window.postMessage;
    window.postMessage = function patchedPostMessage(message, targetOrigin, transfer) {
      const text = JSON.stringify(message || {});
      if (KEYWORDS.test(text)) {
        emitBlocked("postMessage", "Blocked suspicious AI postMessage payload", { preview: text.slice(0, 180) });
        return;
      }
      return originalPostMessage.call(this, message, targetOrigin, transfer);
    };

    const observer = new MutationObserver((mutations) => {
      for (const m of mutations) {
        for (const node of m.addedNodes) {
          if (!(node instanceof Element)) continue;

          const attrs = [
            node.getAttribute("src") || "",
            node.getAttribute("href") || "",
            node.getAttribute("data-source") || "",
            node.id || "",
            node.className || ""
          ].join(" ");

          if (KEYWORDS.test(attrs)) {
            emitBlocked("dom_mutation", "Blocked AI-related injected node", { tag: node.tagName, attrs: attrs.slice(0, 200) });
            node.remove();
            continue;
          }

          if (node.tagName === "SCRIPT" && KEYWORDS.test(node.textContent || "")) {
            emitBlocked("script_injection", "Blocked suspicious AI script", { tag: node.tagName });
            node.remove();
          }
        }
      }
    });

    observer.observe(document.documentElement || document, {
      childList: true,
      subtree: true
    });
  }

  if (blockActions) {
    const originalClick = HTMLElement.prototype.click;
    HTMLElement.prototype.click = function patchedClick(...args) {
      if (likelyAutomatedCall()) {
        emitBlocked("action_taking", actionReason, { action: "element.click", tag: this.tagName });
        return;
      }
      return originalClick.apply(this, args);
    };

    const originalSubmit = HTMLFormElement.prototype.submit;
    HTMLFormElement.prototype.submit = function patchedSubmit(...args) {
      if (likelyAutomatedCall()) {
        emitBlocked("action_taking", actionReason, { action: "form.submit" });
        return;
      }
      return originalSubmit.apply(this, args);
    };

    const originalOpen = window.open;
    window.open = function patchedOpen(...args) {
      if (likelyAutomatedCall()) {
        emitBlocked("action_taking", actionReason, { action: "window.open", url: String(args?.[0] || "") });
        return null;
      }
      return originalOpen.apply(this, args);
    };

    const locationAssign = Location.prototype.assign;
    Location.prototype.assign = function patchedAssign(...args) {
      if (likelyAutomatedCall()) {
        emitBlocked("action_taking", actionReason, { action: "location.assign", url: String(args?.[0] || "") });
        return;
      }
      return locationAssign.apply(this, args);
    };

    const locationReplace = Location.prototype.replace;
    Location.prototype.replace = function patchedReplace(...args) {
      if (likelyAutomatedCall()) {
        emitBlocked("action_taking", actionReason, { action: "location.replace", url: String(args?.[0] || "") });
        return;
      }
      return locationReplace.apply(this, args);
    };

    const pushState = history.pushState;
    history.pushState = function patchedPushState(...args) {
      if (likelyAutomatedCall()) {
        emitBlocked("action_taking", actionReason, { action: "history.pushState" });
        return;
      }
      return pushState.apply(this, args);
    };

    const replaceState = history.replaceState;
    history.replaceState = function patchedReplaceState(...args) {
      if (likelyAutomatedCall()) {
        emitBlocked("action_taking", actionReason, { action: "history.replaceState" });
        return;
      }
      return replaceState.apply(this, args);
    };
  }

  emitBlocked("startup", "Browser AI firewall initialized", {
    blockAi,
    blockActions,
    mode
  });
})();
