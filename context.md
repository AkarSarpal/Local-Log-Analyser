# LLM_Analyst — Project Context

_Last updated: 2026-06-19_

---

## What This Is

A fully local SIEM (Security Information and Event Management) log analyser. Ingests logs from various sources, sends them to a local Ollama LLM, and saves structured security reports. **No cloud. No API keys. No data leaves the machine.**

Core privacy argument: security logs contain sensitive data (IPs, usernames, internal hostnames, incident details). A local LLM solves the privacy problem completely.

---

## Hardware

- **Machine:** Mac Mini 2025, Apple Silicon M4
- **RAM:** 24GB Unified (≈17.8GB available to Ollama after macOS reservation — normal)
- **Ollama version:** 0.30.10, Metal compute (Apple M4 iGPU)
- **Ollama endpoint:** `http://localhost:11434`

---

## Tech Stack

```
Log Sources (firewall, auth, system, custom)
        ↓
analyser.py — collector + chunker
        ↓
Ollama — mistral:7b or llama3.1:13b (local inference)
        ↓
Reports: .md / .html saved to ./reports/
        ↓
(Optional) Open WebUI — chat interface at localhost:3000
```

| Layer | Detail |
|---|---|
| Language | Python 3.11+ |
| LLM runtime | Ollama |
| Default model | `mistral:7b` |
| Better model | `llama3.1:13b` (recommended for deeper analysis) |
| Key deps | `requests`, `pyyaml`, `watchdog` |
| Chat UI | Open WebUI (Docker, `localhost:3000`) |

### Model selection guide (for this hardware)

| Model | VRAM | Use |
|---|---|---|
| `mistral:7b` | 5GB | Fast triage, structured markdown output |
| `llama3.1:8b` | 8GB | Best balance — pattern recognition, structured reports |
| `llama3.1:13b` | 10GB | Deep analysis, multi-stage attack correlation |
| `llama3.1:70b` | 48GB+ | Won't fit in 24GB |

---

## Files

```
LLM_Analyst/
├── analyser.py                  # all logic (~400 lines, single-file)
├── config.yaml                  # all settings (sources, schedule, model, prompt)
├── requirements.txt             # requests, pyyaml, watchdog
├── README.md
├── context.md                   # this file
└── siem-local-llm-journey.md    # project journal / original dev conversation
```

Runtime directories (auto-created):
```
sources/drop/         # drop .log files here
reports/              # output: .md + optional .html per run + daily digest
```

---

## Architecture

```
CLI args
  └─► load_config()
        └─► run_all() / run_scheduled()
              └─► run_source()
                    ├─► COLLECTORS[type]()    # collect raw log text
                    ├─► analyse_logs()        # POST to Ollama /api/chat
                    ├─► save_markdown()
                    ├─► save_html()           # optional
                    ├─► notify_macos()        # desktop alert on CRITICAL/HIGH
                    └─► append_to_digest()    # daily rollup
```

### Source types & collectors

| Type | Collector | Notes |
|---|---|---|
| `folder` | `collect_folder()` | Globs `*.log` in a watched directory |
| `macos_system` | `collect_macos_system()` | Calls macOS `log` CLI, pulls last N minutes |
| `ssh_auth` | `collect_file()` | `tail -n 1000` of `/var/log/auth.log` |
| `web_server` | `collect_file()` | `tail -n 1000` of nginx access log |
| `syslog` | `collect_file()` | `tail -n 1000` of `/var/log/syslog` |

### Schedule modes

| Mode | Behaviour |
|---|---|
| `watch` | `watchdog` Observer — triggers instantly on new file in drop folder |
| `hourly` | `time.sleep(3600)` loop |
| `daily` | Polls every 30s, fires at configured `daily_time` |
| `manual` | No-op; use `--run-now` flag |

### Report outputs

- Markdown always written; HTML optional (toggle in `config.yaml`)
- Severity extracted by scanning report text for `CRITICAL / HIGH / MEDIUM / LOW`
- macOS `osascript` notification on CRITICAL or HIGH
- Daily digest appended to `reports/digest_YYYY-MM-DD.md`

---

## The LLM Refusal Problem (solved)

Out of the box `mistral:7b` refused to analyse logs:
> *"As a text-based AI model, I don't have the ability to analyze real log data…"*

**Fix:** a strong system prompt that explicitly instructs the model to treat logs as text and never refuse. This prompt is baked into `config.yaml` under the `prompt:` key. `llama3.1:8b` is also less prone to this behaviour if refusals recur.

---

## CLI Usage

```bash
python analyser.py                          # follows schedule.mode from config
python analyser.py --run-now               # immediate run, all enabled sources
python analyser.py --source "Drop Folder"  # run one source by name
python analyser.py --model llama3.1:13b    # override model
python analyser.py --format html           # override report format
python analyser.py --config /path/to/x.yaml
```

---

## Open WebUI (Interactive Chat)

For ad-hoc / interactive analysis alongside the automation pipeline:

```bash
docker run -d \
  -p 3000:8080 \
  --add-host=host.docker.internal:host-gateway \
  -v open-webui:/app/backend/data \
  --name open-webui \
  ghcr.io/open-webui/open-webui:main
```

Open `http://localhost:3000`. Auto-detects Ollama on `host.docker.internal:11434`.
Apply the system prompt from `config.yaml → prompt:` in WebUI → Settings → System Prompt.

---

## Azure AI Foundry — Considered & Deferred

Considered for access to GPT-4o / o3 and native Sentinel integration but deferred because it eliminates the privacy advantage (logs leave the machine). 

**Hybrid architecture (future):** local Ollama does fast triage on everything → only sanitised summaries of Critical/High events are sent to Azure for deep analysis. Not started yet.

---

## Known Bugs

| Bug | Location | Detail |
|---|---|---|
| Config path mismatch | `load_config()` L46 | Default is `config/config.yaml` but file lives at `./config.yaml`. Bare `python analyser.py` fails. |
| 8k char truncation | `analyse_logs()` L114 | Log content silently capped at 8 000 chars — large files are truncated without warning. |
| Digest header never written | `append_to_digest()` L228-230 | `digest_path.exists()` checked after opening for append — header is never written on first creation. |
| No run-state tracking | — | Same file re-analysed on every run; no deduplication. |

---

## Next Steps (from project journal)

### High impact
- [ ] Test automation script with real log files
- [ ] Enable macOS system log source (`macos_system` in config)
- [ ] Connect SSH auth logs from `/var/log/auth.log`
- [ ] Fix config path default (`config/config.yaml` → `config.yaml`)
- [ ] Fix digest header bug

### Model
- [ ] Switch to `llama3.1:13b` as default for deeper analysis
- [ ] Tune system prompt per model (mistral vs llama behave differently)

### Real log sources
- [ ] pfSense / firewall syslog
- [ ] Web server access logs
- [ ] Custom application logs

### Better reporting
- [ ] HTML dashboard with threat trends over time
- [ ] Weekly summary digest
- [ ] Chunking / sliding-window for logs beyond 8k chars

### Share publicly
- [ ] Package as Docker Compose (one-command setup)
- [ ] Publish as GitHub repo
- [ ] Follow-up LinkedIn post with automation demo

---

## Test Log Scenarios

Three ready-made test cases in `siem-local-llm-journey.md` (section 7):

| Test | Kill chain | Expected severity |
|---|---|---|
| Brute force + root compromise | SSH brute force → root login → malware download → C2 callback | CRITICAL |
| Lateral movement + privesc | File recon → failed privesc → rogue admin → RDP lateral move | HIGH/CRITICAL |
| Data exfiltration | Escalating uploads to filebin/wetransfer/mega + DNS tunnelling + 380MB file access | HIGH/CRITICAL |
