#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
#  Agent-WatchDog — One-click Local Demo Launcher
#
#  Starts the mock firewall backend + dashboard for interactive demos.
#  Works on macOS without Rust/Linux — uses Bun mock backend.
#
#  Usage:
#    ./start-demo.sh           # Start both servers
#    ./start-demo.sh --stop    # Stop all servers
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
MOCK_LOG="/tmp/watchdog-mock.log"
VITE_LOG="/tmp/watchdog-vite.log"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

stop_servers() {
    echo -e "${CYAN}Stopping servers...${RESET}"
    lsof -ti:3001 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -ti:5173 2>/dev/null | xargs kill -9 2>/dev/null || true
    echo -e "${GREEN}✓ All servers stopped${RESET}"
}

if [[ "${1:-}" == "--stop" ]]; then
    stop_servers
    exit 0
fi

echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  🛡️  Agent-WatchDog — Local Demo Launcher                ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${RESET}"

# ── Pre-flight checks ─────────────────────────────────────────────
if ! command -v bun &>/dev/null; then
    echo -e "${RED}✗ bun not found. Install: curl -fsSL https://bun.sh/install | bash${RESET}"
    exit 1
fi

# ── Kill stale processes ──────────────────────────────────────────
stop_servers 2>/dev/null

# ── Install dashboard deps (if needed) ───────────────────────────
if [ ! -d "$DIR/dashboard/node_modules" ]; then
    echo -e "${CYAN}Installing dashboard dependencies...${RESET}"
    cd "$DIR/dashboard" && bun install
fi

# ── Start mock firewall backend ──────────────────────────────────
echo -e "${CYAN}Starting mock firewall backend on :3001...${RESET}"
cd "$DIR"
nohup bun run mock-server/firewall.ts > "$MOCK_LOG" 2>&1 &
MOCK_PID=$!
sleep 2

if curl -sf http://localhost:3001/v1/health > /dev/null 2>&1; then
    echo -e "  ${GREEN}✓ Firewall backend running (PID $MOCK_PID)${RESET}"
else
    echo -e "  ${RED}✗ Backend failed to start. Check $MOCK_LOG${RESET}"
    exit 1
fi

# ── Start Vite dashboard ─────────────────────────────────────────
echo -e "${CYAN}Starting dashboard on :5173...${RESET}"
cd "$DIR/dashboard"
nohup npx vite --port 5173 > "$VITE_LOG" 2>&1 &
VITE_PID=$!
sleep 3

if lsof -ti:5173 > /dev/null 2>&1; then
    echo -e "  ${GREEN}✓ Dashboard running (PID $VITE_PID)${RESET}"
else
    echo -e "  ${RED}✗ Dashboard failed to start. Check $VITE_LOG${RESET}"
    exit 1
fi

# ── Done ──────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}✅ All systems go!${RESET}"
echo ""
echo -e "  ${BOLD}Agent 对抗演示:${RESET} http://localhost:5173/agent-demo"
echo -e "  ${BOLD}防火墙面板:${RESET}   http://localhost:5173/firewall"
echo -e "  ${BOLD}Backend API:${RESET}  http://localhost:3001/v1/health"
echo ""
echo -e "  ${CYAN}推荐: 打开 Agent 对抗演示页面，选择场景，点击开始！${RESET}"
echo -e "  ${CYAN}Or run: ./demo/run_demo.sh${RESET}"
echo ""
echo -e "  Stop with: ${BOLD}./start-demo.sh --stop${RESET}"
