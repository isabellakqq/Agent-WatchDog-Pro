#!/usr/bin/env python3
"""
Agent-WatchDog reliability demo

Demo flow:
1) Send heartbeat (agent online)
2) Report 3 consecutive failures -> auto fallback should activate
3) Report success -> failure counter resets (mode keeps fallback until manual deactivate)
4) Deactivate fallback manually

Usage:
  python3 tests/demo_reliability.py

Optional env:
  WATCHDOG_BASE_URL=http://localhost:3001
"""

import json
import os
import sys
from urllib import request
from urllib.error import HTTPError, URLError

BASE_URL = os.getenv("WATCHDOG_BASE_URL", "http://localhost:3001")


def color(text, c):
    codes = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "bold": "\033[1m",
        "end": "\033[0m",
    }
    return f"{codes.get(c, '')}{text}{codes['end']}"


def post(path, payload):
    data = json.dumps(payload).encode("utf-8")
    req = request.Request(
        BASE_URL + path,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        return e.code, {"error": body}
    except URLError as e:
        return 0, {"error": str(e)}


def get(path):
    req = request.Request(BASE_URL + path, method="GET")
    try:
        with request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        return e.code, {"error": body}
    except URLError as e:
        return 0, {"error": str(e)}


def show_status(label):
    code, data = get("/v1/reliability/status")
    if code != 200:
        print(color(f"[FAIL] {label}: GET status failed => {code} {data}", "red"))
        return None

    mode = data.get("mode")
    failures = data.get("consecutive_failures")
    retries = data.get("retry_total")
    fallback_count = data.get("fallback_activations")
    online = data.get("online_agents")

    mode_color = "green" if mode == "normal" else "yellow"
    print(
        f"{color('[STATUS]', 'blue')} {label}: "
        f"mode={color(mode, mode_color)}, "
        f"failures={failures}, retries={retries}, "
        f"fallback_activations={fallback_count}, online_agents={online}"
    )
    return data


def main():
    print(color("\n=== Agent-WatchDog Reliability Demo ===", "bold"))
    print(f"Base URL: {BASE_URL}\n")

    # 1) Heartbeat
    print(color("Step 1) Send heartbeat", "blue"))
    code, data = post(
        "/v1/agent/heartbeat",
        {
            "agent_id": "demo-agent-1",
            "session_id": "demo-session-1",
            "model": "claude-opus",
        },
    )
    if code != 200:
        print(color(f"Heartbeat failed: {code} {data}", "red"))
        sys.exit(1)
    print(color("Heartbeat OK", "green"))
    show_status("after heartbeat")

    # 2) Trigger auto fallback by 3 failures
    print(color("\nStep 2) Report 3 consecutive failures (auto fallback expected)", "blue"))
    for i in range(1, 4):
        code, data = post(
            "/v1/reliability/report",
            {
                "agent_id": "demo-agent-1",
                "status": "failure",
                "error": f"demo failure #{i}",
            },
        )
        if code != 200:
            print(color(f"Failure report #{i} failed: {code} {data}", "red"))
            sys.exit(1)
        print(color(f"reported failure #{i}", "yellow"))

    s = show_status("after 3 failures")
    if s and s.get("mode") == "fallback":
        print(color("Auto fallback activated ✅", "green"))
    else:
        print(color("Auto fallback NOT activated ❌", "red"))

    # 3) Report success (counter reset)
    print(color("\nStep 3) Report success (failure counter reset)", "blue"))
    code, _ = post(
        "/v1/reliability/report",
        {
            "agent_id": "demo-agent-1",
            "status": "success",
        },
    )
    if code != 200:
        print(color(f"Success report failed: {code}", "red"))
        sys.exit(1)

    s = show_status("after success")
    if s and s.get("consecutive_failures") == 0:
        print(color("Consecutive failures reset ✅", "green"))
    else:
        print(color("Consecutive failures did not reset ❌", "red"))

    # 4) Deactivate fallback manually
    print(color("\nStep 4) Deactivate fallback manually", "blue"))
    code, _ = post("/v1/reliability/fallback/deactivate", {})
    if code != 200:
        print(color(f"Deactivate fallback failed: {code}", "red"))
        sys.exit(1)

    s = show_status("after manual deactivate")
    if s and s.get("mode") == "normal":
        print(color("Fallback deactivated, back to normal ✅", "green"))
    else:
        print(color("Fallback still active ❌", "red"))

    print(color("\nDemo complete.", "bold"))


if __name__ == "__main__":
    main()
