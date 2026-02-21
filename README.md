# Agent-WatchDog

<p align="center">
  <strong>AI Agent 运行时安全监控系统</strong><br>
  基于 Rust + eBPF 的敏感文件访问实时检测与阻断工具
</p>

---

## ✨ 功能特性

- 🔍 **内核级监控** — 通过 eBPF tracepoint (`sys_enter_openat`) 捕获所有文件打开操作，零侵入、低开销
- 🚨 **实时告警** — 敏感文件访问立即触发高危告警，通过 WebSocket 推送到前端
- 🛡️ **进程阻断** — 一键终止恶意进程（发送 SIGKILL）
- 📊 **可视化仪表盘** — React 前端展示实时告警、统计数据、事件历史
- 🔌 **REST + WebSocket API** — 后端暴露完整 API，支持第三方集成

## 🏗️ 架构

```
┌──────────────────────────────────────────────────┐
│                  Linux Kernel                    │
│  ┌────────────────────────────────────────────┐  │
│  │  eBPF Program (sys_enter_openat tracepoint)│  │
│  │  捕获所有 open() 系统调用                    │  │
│  └──────────────┬─────────────────────────────┘  │
│                 │ PerfEventArray                  │
├─────────────────┼────────────────────────────────┤
│   User Space    │                                │
│  ┌──────────────▼─────────────────────────────┐  │
│  │  Rust Daemon (Tokio + Aya)                 │  │
│  │  ├── 敏感关键词匹配                          │  │
│  │  ├── 事件存储 (内存环形缓冲区)                │  │
│  │  └── Axum HTTP/WS API Server (:3000)       │  │
│  └──────────────┬─────────────────────────────┘  │
└─────────────────┼────────────────────────────────┘
                  │ REST API + WebSocket
┌─────────────────▼────────────────────────────────┐
│  React Dashboard (Vite + Tailwind + shadcn/ui)   │
│  实时告警 · 事件历史 · 进程监控 · 配置管理         │
└──────────────────────────────────────────────────┘
```

## 📁 项目结构

```
Agent-WatchDog/
├── agent-watchdog-common/   # 共享类型 (内核 + 用户空间), #[repr(C)], no_std
├── agent-watchdog-ebpf/     # eBPF 内核态程序 (bpfel-unknown-none 目标)
├── agent-watchdog/          # 用户态守护进程 (Tokio + Aya + Axum)
│   └── src/
│       ├── main.rs          # 入口: eBPF 加载 + 事件循环
│       ├── api.rs           # HTTP/WebSocket API 路由
│       └── event_store.rs   # 内存事件存储
├── dashboard/               # React 前端仪表盘
│   └── src/app/
│       ├── api.ts           # API 客户端 (REST + WebSocket)
│       └── pages/           # Dashboard, Events, Processes, Configuration
└── xtask/                   # 构建辅助工具 (交叉编译 eBPF)
```

## 🔑 监控的敏感文件

| 关键词 | 说明 |
|-------|------|
| `.env` | 环境变量/密钥文件 |
| `id_rsa` / `id_ed25519` / `id_ecdsa` | SSH 私钥 |
| `shadow` | 系统密码文件 |
| `aws/credentials` | AWS 密钥 |
| `.kube/config` | Kubernetes 配置 |
| `.docker/config.json` | Docker 凭证 |
| `secrets.yaml` / `secrets.yml` | 密钥配置文件 |
| `master.key` | Rails 主密钥 |
| `.pgpass` | PostgreSQL 密码 |
| `.netrc` | FTP/HTTP 凭证 |
| `gcp/application_default_credentials.json` | GCP 凭证 |

## 📋 环境要求

### 后端 (Linux 服务器)
- **Linux 内核 ≥ 5.4**，需支持 BTF (`ls /sys/kernel/btf/vmlinux`)
- **Root 权限** — 加载 eBPF 程序需要
- x86_64 架构

### 编译环境 (macOS / Linux)
- **Rust stable + nightly** 工具链
  ```bash
  rustup toolchain install nightly --component rust-src
  ```
- **bpf-linker**
  ```bash
  cargo install bpf-linker
  ```
- **交叉编译器** (macOS 编译 Linux 目标时)
  ```bash
  brew install x86_64-unknown-linux-gnu  # macOS
  rustup target add x86_64-unknown-linux-gnu
  ```

### 前端
- **Bun ≥ 1.0** 或 **Node.js ≥ 18**

---

## 🚀 快速开始

### 1. 编译 eBPF 程序

```bash
# 方式一：使用 xtask（适用于本机是 x86_64 Linux）
cargo xtask build-ebpf

# 方式二：手动编译（macOS 交叉编译时推荐）
cd agent-watchdog-ebpf
CARGO_ENCODED_RUSTFLAGS='--cfg=bpf_target_arch="x86_64"' \
  cargo +nightly build \
  --target=bpfel-unknown-none \
  -Z build-std=core \
  --release
```

### 2. 编译用户态守护进程

```bash
# 本机 Linux
cargo build --release

# macOS 交叉编译到 Linux
cargo build --release --target x86_64-unknown-linux-gnu
```

### 3. 部署到服务器

```bash
# 上传二进制文件
scp target/x86_64-unknown-linux-gnu/release/agent-watchdog user@server:~/agent-watchdog/
scp agent-watchdog-ebpf/target/bpfel-unknown-none/release/agent-watchdog \
    user@server:~/agent-watchdog/target/bpfel-unknown-none/release/agent-watchdog
```

### 4. 启动后端

在目标 Linux 服务器上：

```bash
cd ~/agent-watchdog

# 前台运行（调试用）
RUST_LOG=info sudo -E ./agent-watchdog

# 后台运行（生产环境）
nohup sudo -E env RUST_LOG=info ./agent-watchdog --port 3000 > /tmp/watchdog.log 2>&1 &
```

启动后会看到：
```
🌐  API server listening on http://0.0.0.0:3000
📡  Starting eBPF event reader on 8 CPUs...
```

### 5. 启动前端仪表盘

```bash
cd dashboard

# 安装依赖
bun install        # 或 npm install

# 修改 vite.config.ts 中的后端地址
# 将 proxy target 改为你的服务器 IP
#   '/api': { target: 'http://YOUR_SERVER_IP:3000' }
#   '/ws':  { target: 'ws://YOUR_SERVER_IP:3000' }

# 启动开发服务器
bun run dev        # 或 npm run dev
```

打开浏览器访问 `http://localhost:5173`。

### 6. 测试告警

在服务器上触发敏感文件访问：

```bash
cat /etc/shadow
cat ~/.ssh/id_rsa
cat ~/.aws/credentials
cat ~/.kube/config
touch /tmp/test.env && cat /tmp/test.env
```

你应该能在仪表盘上实时看到高危告警 🚨

---

## 🔌 API 接口

后端默认运行在 `http://SERVER_IP:3000`。

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/health` | 健康检查 |
| `GET` | `/api/stats` | 仪表盘统计数据 |
| `GET` | `/api/events` | 所有事件列表 |
| `GET` | `/api/alerts` | 活跃告警列表 |
| `POST` | `/api/events/{id}/block` | 阻断进程 (SIGKILL) |
| `POST` | `/api/events/{id}/ignore` | 标记为误报 |
| `GET` | `/ws/events` | WebSocket 实时事件流 |

### 示例

```bash
# 健康检查
curl http://localhost:3000/api/health
# => "ok"

# 获取统计
curl http://localhost:3000/api/stats
# => {"today_alerts":7,"active_alerts":5,"blocked_count":1,"ignored_count":1,"total_events":7}

# 获取活跃告警
curl http://localhost:3000/api/alerts
# => [{"id":"...","timestamp":"...","pid":1234,"comm":"cat","filename":"/etc/shadow","severity":"high","status":"active"}]

# 阻断进程
curl -X POST http://localhost:3000/api/events/{event_id}/block
# => {"success":true,"message":"Process 1234 killed"}
```

---

## �️ 开发指南

### 添加新的敏感关键词

编辑 `agent-watchdog/src/main.rs` 中的 `SENSITIVE_KEYWORDS` 数组：

```rust
const SENSITIVE_KEYWORDS: &[&str] = &[
    ".env",
    "id_rsa",
    // 添加新关键词（小写）
    "my_secret_file",
];
```

重新编译并部署即可生效。

### 添加新的事件字段

1. 更新 `agent-watchdog-common/src/lib.rs` 中的 `FileOpenEvent`（必须 `#[repr(C)]`，固定大小）
2. 在 `agent-watchdog-ebpf/src/main.rs` 中填充字段（注意 512 字节栈限制）
3. 在 `agent-watchdog/src/main.rs` 事件处理循环中读取字段
4. 更新 `dashboard/src/app/api.ts` 中的字段映射

---

## ⚠️ 注意事项

- eBPF 程序 **必须以 `--release` 编译**，debug 构建会被内核验证器拒绝
- eBPF 栈限制 512 字节，大结构体需使用 `PerCpuArray` 作为 scratch buffer
- 用户态指针 **禁止直接解引用**，必须使用 `bpf_probe_read_user_str_bytes`
- macOS 无法运行 eBPF 程序，仅用于交叉编译
- 阻断进程操作 (block) 会发送 **SIGKILL**，请谨慎使用

## 📄 License

MIT
