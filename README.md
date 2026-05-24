# Vigilo

> *Latin: "I watch. I am vigilant."*

Vigilo is an open-source endpoint security daemon for crypto infrastructure. It runs on the server where your hot wallet, signing service, bridge validator, or exchange integration lives — and watches for attack patterns at the OS level **before they reach the chain**.

---

## Why OS-level, not on-chain?

By the time a transaction hits the chain, the private key is already gone. Every crypto hack follows the same sequence on the server first:

```
1. Attacker gets foothold (RCE, supply chain, compromised dep)
2. Process reads keystore / .env / private key file   ← Vigilo sees this
3. Shell spawned or outbound connection made           ← Vigilo sees this
4. Key exfiltrated to attacker infrastructure         ← Vigilo sees this
5. On-chain transaction                               (too late)
```

Vigilo catches steps 2–4. Chain monitoring catches step 5. You want 2–4.

---

## Architecture

```
Your Server (crypto infra)
┌─────────────────────────────────────────────┐
│  vigilo daemon (Go binary)                  │
│                                             │
│  FileWatcher  — inotify on sensitive paths  │
│  ProcessWatch — /proc, detects shell spawn  │
│  NetWatch     — /proc/net/tcp, new conns    │
│                                             │
│  SQLite buffer (24h retention)              │
│  MCP server   — exposes query tools         │
└──────────────────┬──────────────────────────┘
                   │ MCP (stdio or SSE)
                   ▼
┌─────────────────────────────────────────────┐
│  vigilo-agent (TypeScript)                  │
│                                             │
│  Pulls events every 5 min via MCP           │
│  Claude claude-opus-4-7 analyst             │
│  Correlates sequences → signals             │
│  Alerts: Slack                              │
└─────────────────────────────────────────────┘
```

**Two deployment modes:**

| Mode | When to use |
|---|---|
| **Standalone** | Daemon + agent on the same server. Only external call is the Anthropic API. |
| **Hub/spoke** | Daemon on each client server, agent runs centrally (your Cloud Run / VPS). One agent, many daemons. |

---

## What Vigilo detects

| Pattern | Signal |
|---|---|
| Shell (`bash`/`sh`) spawned from `node`, `python`, `java` | RCE / code injection |
| Keystore, `.pem`, `wallet.json`, `.env` read by unexpected process | Credential theft / key exfiltration |
| Outbound connection to port 4444, 1337, 31337 after file access | Active exfiltration |
| `curl`/`wget` spawned from app process | Data exfiltration |
| New connection to previously-unseen IP | Lateral movement / C2 |
| Package install (`npm`, `pip`) from unexpected process | Supply chain persistence |
| Privilege escalation (`sudo` by app process) | Attacker expanding access |

Vigilo uses Claude to **correlate sequences** — a single file read might be `info`, but file read + network connection to a new IP = `critical`. No rules to write.

---

## Quick start

### 1. Install the daemon

**From source** (requires Go 1.23+):

```bash
git clone https://github.com/voltagebots/vigilo
cd vigilo
go build -o vigilo ./cmd/vigilo
sudo mv vigilo /usr/local/bin/
```

**Verify:**

```bash
vigilo --help
```

### 2. Configure

```bash
sudo mkdir -p /etc/vigilo
sudo cp config.example.yaml /etc/vigilo/config.yaml
sudo $EDITOR /etc/vigilo/config.yaml
```

Key settings:

```yaml
watch_paths:
  - $HOME/.ethereum        # Ethereum keystore
  - $HOME/.bitcoin         # Bitcoin wallet
  - /app/.env              # App secrets
  - /app/keystore          # Custom keystore path

poll_interval: 5s          # /proc poll frequency
buffer_retention_hours: 24 # How long to keep events
mcp_transport: stdio       # stdio (local) or http (remote agent)
```

### 3. Run the daemon

**Standalone (daemon + agent on same host):**

```bash
sudo mkdir -p /var/lib/vigilo
vigilo -config /etc/vigilo/config.yaml -db /var/lib/vigilo/events.db
```

**As a systemd service:**

```ini
# /etc/systemd/system/vigilo.service
[Unit]
Description=Vigilo security daemon
After=network.target

[Service]
ExecStart=/usr/local/bin/vigilo -config /etc/vigilo/config.yaml -db /var/lib/vigilo/events.db
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now vigilo
```

### 4. Run the agent

```bash
cd agent
cp .env.example .env
$EDITOR .env   # add ANTHROPIC_API_KEY, SLACK_BOT_TOKEN, VIGILO_ALERT_CHANNEL
npm install
npm run dev
```

The agent connects to the daemon via MCP (stdio by default), pulls events every 5 minutes, and posts Slack alerts when Claude detects a threat.

---

## Configuration reference

### Daemon (`config.yaml`)

| Field | Default | Description |
|---|---|---|
| `watch_paths` | See example | Directories/files to watch for access. Supports `$HOME`. |
| `exclude_paths` | `$HOME/.npm`, `$HOME/.cache`, `/tmp` | Never watch these. |
| `poll_interval` | `5s` | How often to poll `/proc` and `/proc/net/tcp`. |
| `buffer_retention_hours` | `24` | Events older than this are auto-purged from SQLite. |
| `mcp_transport` | `stdio` | `stdio` for local agent, `http` for remote agent (SSE). |
| `mcp_addr` | `:7070` | Bind address — only used when `mcp_transport: http`. |

### Agent (`.env`)

| Variable | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | Yes | Claude API key |
| `SLACK_BOT_TOKEN` | Yes | Slack bot token (`xoxb-...`) |
| `VIGILO_ALERT_CHANNEL` | Yes | Slack channel ID for alerts |
| `SCAN_CRON` | No | Cron schedule (default: `*/5 * * * *`) |
| `LOOKBACK_MINUTES` | No | Event window per scan (default: `6`) |
| `VIGILO_MCP_URL` | No | Set to connect to a remote daemon via SSE (e.g. `http://10.0.0.5:7070`) |
| `VIGILO_DAEMON_BIN` | No | Path to vigilo binary for stdio mode (default: `vigilo`) |
| `VIGILO_CONFIG` | No | Config path passed to daemon in stdio mode (default: `/etc/vigilo/config.yaml`) |

---

## MCP tools

The daemon exposes these tools over the MCP protocol. The agent calls them automatically; you can also connect any MCP-compatible client (e.g. Claude Desktop) directly to the daemon for ad-hoc investigation.

| Tool | Description |
|---|---|
| `get_file_access_events` | File reads/writes to sensitive paths, filterable by severity |
| `get_process_events` | Suspicious child process spawns |
| `get_network_events` | Outbound connections to unexpected destinations |
| `get_all_events` | All sources — used by agent for correlation analysis |
| `get_critical_events` | High + critical events only — for rapid triage |

All tools accept a `since` (ISO8601) parameter and return JSON arrays.

**Connect Claude Desktop directly to the daemon:**

```json
{
  "mcpServers": {
    "vigilo": {
      "command": "vigilo",
      "args": ["-config", "/etc/vigilo/config.yaml", "-db", "/var/lib/vigilo/events.db"]
    }
  }
}
```

---

## Signal categories

When the agent detects a threat pattern, it classifies it into one of:

| Category | Description |
|---|---|
| `key_exfiltration` | Private key or keystore accessed then sent externally |
| `rce` | Remote code execution — shell spawned from app process |
| `credential_theft` | Env vars or secret files harvested |
| `supply_chain` | Unexpected package install or dependency modification |
| `privilege_escalation` | App process gained elevated permissions |
| `lateral_movement` | Connection to internal hosts or new external infrastructure |
| `reconnaissance` | Systematic probing without clear exfiltration yet |

---

## Roadmap

- [ ] `auditd` integration — kernel-level privilege escalation events
- [ ] Signal deduplication — suppress repeat alerts for same open issue
- [ ] Suppression rules — per-path / per-process allowlist in config
- [ ] GitHub Actions CI — build + test on push
- [ ] Dockerfile — single container for easy client-side deploy
- [ ] Hub/spoke dashboard — central view across multiple daemons
- [ ] eBPF collectors (Phase 3) — sub-millisecond detection latency

---

## License

MIT
