# 🛡️ SSH Honeypot

> A realistic SSH honeypot written in Rust — captures attacker behaviour, analyses it with AI, and alerts in real time.

**Author:** Mohamed KADA — ESGI Cybersécurité 2025-2026

---

## What it does

When an attacker connects via SSH, they land inside a fully simulated Linux shell. Every keystroke is recorded. When the session ends, Claude AI analyses the commands against the MITRE ATT&CK framework and scores the threat from 0 to 10. If the score exceeds a configurable threshold, an alert is sent to Discord, Slack, or any webhook endpoint.

**Key features**

- Accepts any SSH credentials (password & public key) and logs them all
- Realistic interactive shell with ~40 built-in commands and a virtual filesystem
- Three machine personas: web server, database server, developer workstation
- AI fallback (Claude Haiku) for unrecognised commands — stays in character
- Async MITRE ATT&CK scoring after each session (tactics, techniques, score 0–10)
- SQLite persistence — sessions, credentials, commands, alerts
- Self-contained HTML report generated on demand
- Discord / Slack / generic webhook alerts with AI summary

---

## Prerequisites

- [Rust](https://rustup.rs/) 1.75 or later
- An [Anthropic API key](https://console.anthropic.com/) *(optional — enables AI features)*

---

## Installation

```bash
git clone https://github.com/MohamedKada/Honeypot.git
cd Honeypot
cargo build --release
```

---

## Configuration

Create a `.env` file at the project root:

```env
ANTHROPIC_API_KEY=sk-ant-...        # Claude Haiku fallback + MITRE scoring
HONEYPOT_WEBHOOK_URL=https://...    # Discord / Slack / generic webhook (optional)
```

Both values can also be passed as CLI flags (see below).

---

## Usage

### Start the honeypot

```bash
# Interactive persona selection
cargo run --release

# Pick a persona directly
cargo run --release -- --persona web-server

# Custom port and alert threshold
cargo run --release -- --persona database --port 2222 --seuil-alerte 6
```

Connect from another terminal:

```bash
ssh -p 2222 admin@localhost   # any username / any password
```

### List available personas

```bash
cargo run --release -- --liste
```

| ID | Description |
|----|-------------|
| `web-server` | Ubuntu 22.04 — Nginx + PHP + WordPress |
| `database` | Ubuntu 20.04 — PostgreSQL 15 + pgAdmin |
| `dev-machine` | Debian 12 — Docker, Node.js, Python |

### Generate an HTML report

```bash
cargo run --release -- --rapport report.html
```

Opens `report.html` in any browser — no server required.

### All options

| Flag | Default | Description |
|------|---------|-------------|
| `--persona <ID>` | menu | Persona to use |
| `--port <N>` | `2222` | Listening port |
| `--seuil-alerte <N>` | `7` | MITRE score threshold for alerts (0–10) |
| `--webhook-url <URL>` | — | Webhook endpoint (or `HONEYPOT_WEBHOOK_URL`) |
| `--api-key <KEY>` | — | Anthropic key (or `ANTHROPIC_API_KEY`) |
| `--rapport <FILE>` | — | Generate HTML report and exit |
| `--liste` | — | List personas and exit |

---

## Project structure

```
src/
├── main.rs       CLI entry point, persona selection, server startup
├── server.rs     SSH protocol handler (russh 0.44)
├── shell.rs      Session state, input processing, command dispatch
├── commands.rs   ~40 built-in command implementations
├── vfs.rs        In-memory virtual filesystem
├── persona.rs    TOML persona loader
├── ai.rs         Claude Haiku fallback + async MITRE ATT&CK scoring
├── db.rs         SQLite persistence (sqlx 0.7, WAL mode)
├── report.rs     Self-contained HTML dashboard generator
└── webhook.rs    Discord / Slack / generic HTTP alerts
personas/
├── web-server.toml
├── database.toml
└── dev-machine.toml
```

---

## ⚠️ Responsible use

This tool is built for **defensive** security research and education only.

- Deploy exclusively on infrastructure you own or have explicit written permission to monitor.
- All captured credentials, commands, and IP addresses are sensitive data — handle them accordingly and comply with applicable privacy laws (GDPR, etc.).
- Do **not** use this honeypot to deceive, entrap, or collect data on individuals without their knowledge in contexts where doing so is illegal.
- The authors accept no liability for misuse of this software.
