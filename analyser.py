#!/usr/bin/env python3
"""
SIEM Local Analyser
-------------------
Watches log sources, analyses them with a local Ollama model,
and saves structured reports to disk.

Usage:
  python analyser.py              # uses schedule.mode from config.yaml
  python analyser.py --run-now    # single immediate run across all sources
  python analyser.py --source "Drop Folder"  # run one specific source
  python analyser.py --config /path/to/config.yaml  # use custom config
  python analyser.py --model llama3.1:13b    # override model on the fly
  python analyser.py --format html           # override report format
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

import requests
import yaml
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

# ── Colour helpers for terminal output ─────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
BLUE   = "\033[94m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def log(msg, colour=RESET):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"{colour}[{ts}] {msg}{RESET}")


# ── Config loader ────────────────────────────────────────────────────────────
def load_config(path="config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


# ── IOC pre-processor ────────────────────────────────────────────────────────
# Patterns scanned across the FULL file before sampling
IOC_PATTERNS = [
    # RAT / malware C2
    "darkcomet", "poisonivy", "njrat", "quasar", "asyncrat", "nanocore",
    "remcos", "blackshades", "xtrat", "cybergate",
    # Generic threat keywords in domain names
    "wormhole", "inetwarfare", r"botnet", r"malware", r"backdoor",
    # Suspicious infra patterns
    r"\.bit\b", r"dyndns\.", r"no-ip\.", r"ddns\.", r"\.tk\b", r"\.pw\b",
]

def preprocess_file(filepath: Path, header: str = "") -> tuple:
    """
    Scan the full file and return (confirmed_threats: list[dict], stats_block: str).
      confirmed_threats — parsed IOC hits, each a dict with indicator/detail/severity
      stats_block       — statistics + raw sample for LLM context
    """
    path_str = str(filepath)
    confirmed_threats = []

    # ── Total line count ─────────────────────────────────────────────────────
    try:
        wc = subprocess.run(["wc", "-l", path_str], capture_output=True, text=True)
        total_lines = int(wc.stdout.split()[0])
    except Exception:
        total_lines = 0

    # ── IOC pattern scan (full file grep) ────────────────────────────────────
    combined_pattern = "|".join(IOC_PATTERNS)
    ioc_hits = {}
    try:
        result = subprocess.run(
            ["grep", "-iE", combined_pattern, path_str],
            capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            for pat in IOC_PATTERNS:
                if re.search(pat, line, re.IGNORECASE):
                    ioc_hits.setdefault(pat, []).append(line)
                    break
    except Exception:
        pass

    # Parse each IOC hit group into a human-readable confirmed threat entry
    SEVERITY_MAP = {
        "darkcomet": "Critical", "poisonivy": "Critical", "njrat": "Critical",
        "quasar": "Critical", "asyncrat": "Critical", "nanocore": "Critical",
        "remcos": "Critical", "blackshades": "Critical", "xtrat": "Critical",
        "cybergate": "Critical", "wormhole": "High", "inetwarfare": "High",
        "botnet": "High", "malware": "High", "backdoor": "High",
        r"\.bit\b": "High", r"dyndns\.": "Medium", r"no-ip\.": "Medium",
        r"ddns\.": "Medium", r"\.tk\b": "Medium", r"\.pw\b": "Medium",
    }
    for pat, lines in ioc_hits.items():
        src_ips, queries = set(), set()
        first_ts = None
        for raw in lines:
            fields = raw.split("\t")
            if len(fields) >= 15:
                try:
                    if first_ts is None:
                        first_ts = datetime.fromtimestamp(float(fields[0])).strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    pass
                src_ips.add(fields[2])
                queries.add(fields[8])
            else:
                # Plain text log — extract first word-like token matching the pattern
                m = re.search(pat, raw, re.IGNORECASE)
                if m:
                    queries.add(m.group(0))
        severity = SEVERITY_MAP.get(pat, "High")
        indicator = ", ".join(sorted(queries)[:3]) or pat
        detail = (
            f"{len(lines)} occurrences | source IPs: {', '.join(sorted(src_ips)[:5])}"
            + (f" | first seen: {first_ts}" if first_ts else "")
        )
        confirmed_threats.append({
            "indicator": indicator,
            "detail": detail,
            "severity": severity,
            "count": len(lines),
        })

    # ── Statistics block (Zeek TSV) ──────────────────────────────────────────
    stats_lines = [f"Log format: {header}" if header else "", f"Total entries: {total_lines:,}"]
    try:
        first = subprocess.run(["head", "-1", path_str], capture_output=True, text=True).stdout
        if "\t" in first:
            domains = subprocess.run(["awk", "-F\t", "{print $9}", path_str],
                                     capture_output=True, text=True).stdout.splitlines()
            top_domains = Counter(d for d in domains if d and d not in ("-", "(empty)")).most_common(15)

            ips = subprocess.run(["awk", "-F\t", "{print $3}", path_str],
                                 capture_output=True, text=True).stdout.splitlines()
            top_ips = Counter(i for i in ips if i).most_common(10)

            rcodes = subprocess.run(["awk", "-F\t", "{print $15}", path_str],
                                    capture_output=True, text=True).stdout.splitlines()
            rcode_counts = Counter(r for r in rcodes if r).most_common(10)

            stats_lines += ["", "Top queried domains:"]
            stats_lines += [f"  {c:>8,}  {d}" for d, c in top_domains]
            stats_lines += ["", "Top source IPs by volume:"]
            stats_lines += [f"  {c:>8,}  {ip}" for ip, c in top_ips]
            stats_lines += ["", "Response code distribution:"]
            stats_lines += [f"  {c:>8,}  {rc}" for rc, c in rcode_counts]
    except Exception:
        pass

    # ── Short raw sample for format context ──────────────────────────────────
    try:
        sample = subprocess.run(["head", "-n", "20", path_str],
                                capture_output=True, text=True).stdout
        stats_lines += ["", "Raw sample (first 20 lines):", sample]
    except Exception:
        pass

    return confirmed_threats, "\n".join(stats_lines)


# ── Log collectors — one function per source type ───────────────────────────
def collect_folder(source: dict, file_filter: str = None) -> list[str]:
    """Return list of (filepath, content) tuples from a watched folder."""
    folder = Path(source["path"])
    folder.mkdir(parents=True, exist_ok=True)
    pattern = source.get("pattern", "*.log")
    files = list(folder.glob(pattern))
    if file_filter:
        files = [f for f in files if f.name == file_filter]
        if not files:
            log(f"  File '{file_filter}' not found in {folder}", YELLOW)
    header = source.get("header", "")
    results = []
    for f in files:
        try:
            confirmed_threats, stats_block = preprocess_file(f, header)
            if stats_block.strip():
                # Store as 3-tuple so run_source can pass confirmed_threats to the LLM
                results.append((str(f), stats_block, confirmed_threats))
        except Exception as e:
            log(f"  Could not read {f}: {e}", YELLOW)
    return results


def collect_macos_system(source: dict) -> list[tuple]:
    """Pull recent macOS unified logs via the `log` CLI."""
    minutes = source.get("last_minutes", 60)
    since = (datetime.now() - timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")
    cmd = ["log", "show", "--style", "syslog", "--start", since,
           "--predicate", "eventType == logEvent"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.stdout.strip():
            return [("macos_system_log", result.stdout)]
    except Exception as e:
        log(f"  macOS log collection failed: {e}", YELLOW)
    return []


def collect_file(source: dict) -> list[tuple]:
    """Read the last 1000 lines of a plain log file (auth, nginx, syslog)."""
    path = Path(source["path"])
    if not path.exists():
        log(f"  File not found: {path}", YELLOW)
        return []
    try:
        result = subprocess.run(["tail", "-n", "1000", str(path)],
                                capture_output=True, text=True)
        if result.stdout.strip():
            return [(str(path), result.stdout)]
    except Exception as e:
        log(f"  File read failed: {e}", YELLOW)
    return []


COLLECTORS = {
    "folder":       collect_folder,
    "macos_system": collect_macos_system,
    "ssh_auth":     collect_file,
    "web_server":   collect_file,
    "syslog":       collect_file,
}


# ── Ollama analysis ──────────────────────────────────────────────────────────
JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "executive_summary":  {"type": "string"},
        "threat_indicators":  {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "indicator": {"type": "string"},
                    "detail":    {"type": "string"},
                    "severity":  {"type": "string", "enum": ["Critical", "High", "Medium", "Low"]}
                },
                "required": ["indicator", "severity"]
            }
        },
        "event_timeline":     {"type": "array", "items": {"type": "string"}},
        "anomalies_detected": {"type": "array", "items": {"type": "string"}},
        "recommendations":    {"type": "array", "items": {"type": "string"}},
        "overall_severity":   {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]}
    },
    "required": ["executive_summary", "threat_indicators", "event_timeline",
                 "anomalies_detected", "recommendations", "overall_severity"]
}

JSON_SYSTEM_PROMPT = """You are an expert security analyst and SIEM engineer.
You will receive:
1. A list of CONFIRMED THREATS — these are already verified and must all appear in threat_indicators.
2. Log statistics — use these to identify additional anomalies and write the executive summary.

Respond ONLY with a JSON object. Never refuse. Output only the JSON."""


def json_to_markdown(data: dict) -> str:
    """Convert structured JSON analysis to a markdown report."""
    lines = []
    lines.append(f"## Executive Summary\n{data.get('executive_summary', 'N/A')}\n")

    indicators = data.get("threat_indicators", [])
    lines.append("## Threat Indicators")
    if indicators:
        for item in indicators:
            sev = item.get("severity", "Unknown")
            detail = f" — {item['detail']}" if item.get("detail") else ""
            lines.append(f"- {item.get('indicator', '?')}{detail} | **Severity: {sev}**")
    else:
        lines.append("- None identified.")
    lines.append("")

    timeline = data.get("event_timeline", [])
    lines.append("## Event Timeline")
    lines += [f"- {e}" for e in timeline] if timeline else ["- None identified."]
    lines.append("")

    anomalies = data.get("anomalies_detected", [])
    lines.append("## Anomalies Detected")
    lines += [f"- {a}" for a in anomalies] if anomalies else ["- None identified."]
    lines.append("")

    recommendations = data.get("recommendations", [])
    lines.append("## Recommendations")
    lines += [f"{i+1}. {r}" for i, r in enumerate(recommendations)] if recommendations else ["1. None."]

    return "\n".join(lines)


def analyse_logs(log_content: str, config: dict, model_override=None,
                 confirmed_threats: list = None) -> str:
    """Send log content to Ollama and return the analysis report."""
    cfg = config["ollama"]
    model = model_override or cfg["model"]
    char_limit = cfg.get("char_limit", 32000)

    # Build user message: confirmed threats block (mandatory) + statistics
    user_parts = []
    if confirmed_threats:
        user_parts.append("CONFIRMED THREATS — include ALL of these in threat_indicators:\n")
        for i, t in enumerate(confirmed_threats, 1):
            user_parts.append(
                f"{i}. Indicator: {t['indicator']}\n"
                f"   Detail: {t['detail']}\n"
                f"   Severity: {t['severity']}\n"
            )
        user_parts.append("")
    user_parts.append(f"LOG STATISTICS AND SAMPLE:\n{log_content[:char_limit]}")
    user_message = "\n".join(user_parts)

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": JSON_SYSTEM_PROMPT},
            {"role": "user",   "content": user_message},
        ],
        "format": JSON_SCHEMA,
        "stream": False
    }

    try:
        resp = requests.post(
            f"{cfg['host']}/api/chat",
            json=payload,
            timeout=cfg.get("timeout", 120)
        )
        resp.raise_for_status()
        raw = resp.json()["message"]["content"]
        data = json.loads(raw)
        # Guarantee confirmed threats appear even if the LLM dropped them
        if confirmed_threats:
            llm_indicators = {item.get("indicator", "") for item in data.get("threat_indicators", [])}
            for t in confirmed_threats:
                if not any(t["indicator"].lower() in ind.lower() for ind in llm_indicators):
                    data.setdefault("threat_indicators", []).insert(0, {
                        "indicator": t["indicator"],
                        "detail": t["detail"],
                        "severity": t["severity"],
                    })
        return json_to_markdown(data)
    except requests.exceptions.ConnectionError:
        return "ERROR: Could not connect to Ollama. Is `ollama serve` running?"
    except json.JSONDecodeError:
        return raw
    except Exception as e:
        return f"ERROR: Analysis failed — {e}"


# ── Report writers ───────────────────────────────────────────────────────────
def severity_from_report(report: str) -> str:
    """Extract highest severity from a structured markdown report."""
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if re.search(rf"\bSeverity:\s*{level}\b", report, re.IGNORECASE):
            return level
    return "UNKNOWN"


def save_markdown(report: str, source_name: str, origin: str, output_dir: Path) -> Path:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = re.sub(r"[^\w]", "_", source_name)
    filename = output_dir / f"{ts}_{safe_name}.md"
    header = f"""# SIEM Analysis Report
**Source:** {source_name}
**Origin:** {origin}
**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Severity:** {severity_from_report(report)}

---

"""
    filename.write_text(header + report)
    return filename


def save_html(report: str, source_name: str, origin: str, output_dir: Path) -> Path:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = re.sub(r"[^\w]", "_", source_name)
    filename = output_dir / f"{ts}_{safe_name}.html"
    severity = severity_from_report(report)
    severity_colour = {
        "CRITICAL": "#e53e3e", "HIGH": "#dd6b20",
        "MEDIUM": "#d69e2e", "LOW": "#38a169", "UNKNOWN": "#718096"
    }.get(severity, "#718096")

    # Convert basic markdown to HTML
    html_report = report.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    html_report = re.sub(r"^## (.+)$", r"<h2>\1</h2>", html_report, flags=re.MULTILINE)
    html_report = re.sub(r"^### (.+)$", r"<h3>\1</h3>", html_report, flags=re.MULTILINE)
    html_report = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", html_report)
    html_report = re.sub(r"^[-•] (.+)$", r"<li>\1</li>", html_report, flags=re.MULTILINE)
    html_report = html_report.replace("\n", "<br>")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SIEM Report — {source_name}</title>
<style>
  body {{ font-family: -apple-system, sans-serif; max-width: 900px; margin: 40px auto;
          padding: 0 20px; color: #1a202c; line-height: 1.7; }}
  .header {{ background: #1a202c; color: white; padding: 24px 32px; border-radius: 8px; margin-bottom: 32px; }}
  .severity {{ display: inline-block; padding: 4px 12px; border-radius: 4px;
               background: {severity_colour}; color: white; font-weight: 600; font-size: 14px; }}
  h2 {{ color: #2d3748; border-bottom: 1px solid #e2e8f0; padding-bottom: 8px; margin-top: 32px; }}
  h3 {{ color: #4a5568; }}
  li {{ margin: 4px 0; }}
  .meta {{ color: #a0aec0; font-size: 14px; margin-top: 8px; }}
</style>
</head>
<body>
<div class="header">
  <h1 style="margin:0 0 8px">SIEM Analysis Report</h1>
  <div class="meta">Source: {source_name} &nbsp;|&nbsp; {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>
  <div style="margin-top:12px"><span class="severity">{severity}</span></div>
</div>
{html_report}
</body>
</html>"""
    filename.write_text(html)
    return filename


def notify_macos(title: str, message: str):
    """Send a macOS desktop notification."""
    try:
        script = f'display notification "{message}" with title "{title}" sound name "Basso"'
        subprocess.run(["osascript", "-e", script], check=True)
    except Exception:
        pass  # Notifications are best-effort


def append_to_digest(report: str, source_name: str, output_dir: Path):
    """Append a summary line to today's daily digest file."""
    today = datetime.now().strftime("%Y-%m-%d")
    digest_path = output_dir / f"digest_{today}.md"
    severity = severity_from_report(report)
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"- `{ts}` **{source_name}** → Severity: **{severity}**\n"
    with open(digest_path, "a") as f:
        if not digest_path.exists():
            f.write(f"# Daily Digest — {today}\n\n")
        f.write(line)


# ── Core run logic ───────────────────────────────────────────────────────────
def run_source(source: dict, config: dict, args):
    """Collect, analyse, and report a single source."""
    name = source["name"]
    stype = source["type"]
    log(f"→ Collecting: {name} ({stype})", BLUE)

    collector = COLLECTORS.get(stype)
    if not collector:
        log(f"  Unknown source type: {stype}", YELLOW)
        return

    file_filter = getattr(args, "file", None)
    items = collector(source, file_filter) if stype == "folder" else collector(source)
    if not items:
        log(f"  No logs found for {name}", YELLOW)
        return

    output_dir = Path(config["reports"]["output_dir"])
    output_dir.mkdir(parents=True, exist_ok=True)
    formats = [args.format] if args.format else config["reports"].get("formats", ["markdown"])

    for item in items:
        # collect_folder returns 3-tuples (origin, stats_block, confirmed_threats)
        # all other collectors return 2-tuples (origin, content)
        if len(item) == 3:
            origin, content, confirmed_threats = item
        else:
            origin, content = item
            confirmed_threats = None

        if confirmed_threats:
            log(f"  {len(confirmed_threats)} confirmed IOC(s) found — pre-loaded into report", YELLOW)
        log(f"  Analysing: {origin} ({len(content)} chars)…", BLUE)
        report = analyse_logs(content, config, model_override=args.model,
                              confirmed_threats=confirmed_threats)
        severity = severity_from_report(report)

        colour = RED if severity == "CRITICAL" else YELLOW if severity == "HIGH" else GREEN
        log(f"  Severity: {severity}", colour)

        # Save reports in chosen formats
        saved = []
        if "markdown" in formats or not formats:
            p = save_markdown(report, name, origin, output_dir)
            saved.append(str(p))

        if "html" in formats:
            p = save_html(report, name, origin, output_dir)
            saved.append(str(p))

        for s in saved:
            log(f"  Saved: {s}", GREEN)

        # Desktop notification for critical findings
        if severity in ("CRITICAL", "HIGH") and config["reports"].get("notify_desktop"):
            notify_macos(f"🚨 SIEM Alert — {severity}", f"{name}: {origin}")

        # Append to daily digest
        if config["reports"].get("daily_digest"):
            append_to_digest(report, name, output_dir)


def run_all(config: dict, args, source_filter=None):
    """Run analysis across all enabled sources."""
    sources = config["sources"]
    if source_filter:
        sources = [s for s in sources if s["name"] == source_filter]
    active = [s for s in sources if s.get("enabled", False)]

    if not active:
        log("No enabled sources found. Edit config/config.yaml to enable sources.", YELLOW)
        return

    log(f"{BOLD}Running analysis on {len(active)} source(s)…{RESET}", BLUE)
    for source in active:
        run_source(source, config, args)
    log("Run complete.", GREEN)


# ── Watchdog handler (continuous mode) ──────────────────────────────────────
class LogFileHandler(FileSystemEventHandler):
    def __init__(self, config, args):
        self.config = config
        self.args = args

    def on_created(self, event):
        if event.is_directory:
            return
        path = Path(event.src_path)
        log(f"New file detected: {path.name}", BLUE)
        # Find matching source
        for source in self.config["sources"]:
            if source.get("enabled") and source["type"] == "folder":
                folder = Path(source["path"]).resolve()
                if path.parent.resolve() == folder:
                    pattern = source.get("pattern", "*.log")
                    if path.match(pattern):
                        time.sleep(0.5)  # let file finish writing
                        run_source(source, self.config, self.args)
                        return


# ── Scheduler ────────────────────────────────────────────────────────────────
def run_scheduled(config: dict, args):
    mode = config["schedule"]["mode"]

    if mode == "watch":
        log(f"{BOLD}Watch mode — monitoring sources for new files…{RESET}", GREEN)
        observer = Observer()
        handler = LogFileHandler(config, args)
        for source in config["sources"]:
            if source.get("enabled") and source["type"] == "folder":
                folder = Path(source["path"])
                folder.mkdir(parents=True, exist_ok=True)
                observer.schedule(handler, str(folder), recursive=False)
                log(f"  Watching: {folder}", BLUE)
        observer.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()

    elif mode == "hourly":
        log(f"{BOLD}Hourly mode — running every 60 minutes{RESET}", GREEN)
        while True:
            run_all(config, args)
            log("Sleeping 60 minutes…", BLUE)
            time.sleep(3600)

    elif mode == "daily":
        target = config["schedule"].get("daily_time", "02:00")
        log(f"{BOLD}Daily mode — running at {target}{RESET}", GREEN)
        while True:
            now = datetime.now().strftime("%H:%M")
            if now == target:
                run_all(config, args)
                time.sleep(61)  # avoid double-trigger within the same minute
            time.sleep(30)

    elif mode == "manual":
        log("Manual mode — use --run-now to trigger analysis.", YELLOW)

    else:
        log(f"Unknown schedule mode: {mode}", RED)


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="SIEM Local Analyser")
    parser.add_argument("--run-now",  action="store_true", help="Run immediately across all sources")
    parser.add_argument("--source",   type=str, help="Run a specific source by name")
    parser.add_argument("--config",   type=str, default="config.yaml", help="Path to config file")
    parser.add_argument("--model",    type=str, help="Override Ollama model (e.g. llama3.1:13b)")
    parser.add_argument("--format",   type=str, choices=["markdown", "html"], help="Override report format")
    parser.add_argument("--file",     type=str, help="Analyse a specific file within the source folder (e.g. dns.log)")
    args = parser.parse_args()

    # Load config
    try:
        config = load_config(args.config)
    except FileNotFoundError:
        log(f"Config not found: {args.config}", RED)
        sys.exit(1)

    # Apply CLI overrides
    if args.model:
        config["ollama"]["model"] = args.model
        log(f"Model override: {args.model}", BLUE)

    # Ensure drop folder exists
    Path("sources/drop").mkdir(parents=True, exist_ok=True)

    if args.run_now or args.source:
        run_all(config, args, source_filter=args.source)
    else:
        run_scheduled(config, args)


if __name__ == "__main__":
    main()
