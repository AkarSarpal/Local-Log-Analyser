# SIEM Local Analyser

A fully local SIEM log analyser powered by [Ollama](https://ollama.com). Drop in log files, get structured threat reports — no cloud, no data leaves your machine.

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Features

- Analyses log files locally using Ollama LLMs (llama3.1, mistral, etc.)
- Supports folder drops, macOS system logs, SSH auth, nginx, syslog
- Outputs structured Markdown (and optional HTML) reports with severity ratings
- Watch mode reacts to new files instantly; scheduled or manual modes also available
- macOS desktop notifications on Critical findings
- Daily digest report that rolls up all runs

---

## Requirements

- macOS or Linux
- Python 3.11+
- [Ollama](https://ollama.com) running locally

---

## Setup

### 1. Install Ollama and pull a model

```bash
# Install Ollama (macOS)
brew install ollama

# Start the Ollama server (keep this running in a terminal)
ollama serve

# Pull a model — pick one:
ollama pull llama3.1:8b    # recommended (good quality, ~5 GB)
ollama pull mistral:7b     # faster triage (~4.4 GB)
```

### 2. Clone the repo

```bash
git clone https://github.com/YOUR_USERNAME/LLM_Analyst.git
cd LLM_Analyst
```

### 3. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 4. Verify it works

```bash
python analyser.py --help
```

You should see the usage output. If Ollama is running, you're ready.

---

## Quick Start

```bash
# Drop a log file into sources/drop/ then run immediately
cp /path/to/some.log sources/drop/
python analyser.py --run-now

# Watch sources/drop/ continuously — reacts the moment a file appears
python analyser.py

# Analyse a specific configured source by name
python analyser.py --source "SSH Auth Logs"

# Override the model on the fly
python analyser.py --run-now --model mistral:7b

# Get an HTML report instead of (or in addition to) Markdown
python analyser.py --run-now --format html

# Analyse a specific file within a source folder
python analyser.py --source "Drop Folder" --file dns.log
```

Reports are saved to `./reports/`.

---

## Configuration

All settings live in `config.yaml` — no code changes needed.

### Switch model

```yaml
ollama:
  model: "llama3.1:8b"   # swap to mistral:7b, llama3.1:70b, etc.
```

### Change schedule

```yaml
schedule:
  mode: "watch"      # watch | hourly | daily | manual
  daily_time: "02:00"
```

### Add a log source

```yaml
sources:
  - name: "My App Logs"
    type: folder
    enabled: true
    path: "/var/log/myapp"
    pattern: "*.log"
```

Source types: `folder` | `macos_system` | `ssh_auth` | `web_server` | `syslog`

Set `enabled: false` to temporarily disable without deleting.

### Enable HTML reports

```yaml
reports:
  formats:
    - markdown
    - html        # add this line
```

### Optional: add a log header hint

If your logs use a non-standard format (e.g. Zeek TSV), add a `header:` key so the LLM knows the column layout:

```yaml
  - name: "Zeek DNS Logs"
    type: folder
    enabled: true
    path: "/path/to/zeek/dns"
    pattern: "*.log"
    header: "Columns: timestamp, uid, src_ip, src_port, dst_ip, dst_port, proto, query, answers"
```

---

## Project Structure

```
LLM_Analyst/
├── analyser.py        # main script — all logic lives here
├── config.yaml        # all settings (model, sources, schedule, prompt)
├── requirements.txt
├── sources/
│   └── drop/          # drop log files here for quick analysis
└── reports/           # generated reports saved here (gitignored)
```

---

## Report Format

Each report contains five sections:

| Section | What it contains |
|---|---|
| Executive Summary | One-paragraph overview |
| Threat Indicators | Suspicious IPs/domains/users, each tagged `Severity: Critical/High/Medium/Low` |
| Event Timeline | Chronological notable events |
| Anomalies Detected | Statistical or behavioural outliers |
| Recommendations | Numbered remediation steps |

---

## Troubleshooting

**`ConnectionRefusedError` or no response from Ollama**
Ollama isn't running. Start it: `ollama serve`

**Model not found**
Pull it first: `ollama pull llama3.1:8b`

**Analysis times out**
Increase `timeout` in `config.yaml`, or switch to a smaller model.

**No logs found**
Check `path` and `pattern` in your source config. Use `--run-now` with debug prints to trace.

---

## License

MIT
