"""Turn results.json into a client-ready HTML report.

Usage:
    python -m audit.report results/results.json results/report.html
"""
from __future__ import annotations

import html
import json
import sys
from collections import defaultdict
from pathlib import Path

OWASP_NAMES = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
}

# Plain-language fixes for each category. These are the changes made in the hardened version.
FIXES = {
    "System prompt leakage": "Keep secrets out of the prompt entirely. Anything the model can read, an attacker can eventually get it to repeat.",
    "Sensitive data disclosure": "Check permissions inside the data tools, using the logged-in session rather than anything said in the chat.",
    "Excessive agency": "Enforce ownership and amount limits in the tool code, and send risky actions to a human for approval.",
    "Prompt injection": "Assume the model can be talked into anything, so make sure a fooled model still cannot do damage.",
    "Indirect prompt injection": "Mark retrieved documents as untrusted data, and rely on tool permissions for anything they try to trigger.",
    "Improper output handling": "Filter replies before display: allow-list link domains and strip images and HTML.",
}

STYLE = """
*{box-sizing:border-box}body{font-family:-apple-system,"Helvetica Neue",Arial,sans-serif;background:#eef1f6;color:#1a2233;margin:0;padding:32px}
.page{max-width:1000px;margin:0 auto;background:#fff;border-radius:14px;padding:44px 52px;box-shadow:0 12px 40px rgba(20,30,60,.12)}
h1{font-size:30px;margin:0 0 6px}h2{font-size:18px;color:#b91c1c;margin:32px 0 12px;text-transform:uppercase;letter-spacing:.5px}
.meta{color:#5b6478;font-size:14px;border-bottom:3px solid #b91c1c;padding-bottom:14px}
p{line-height:1.55}.tiles{display:flex;gap:16px;flex-wrap:wrap}.tile{flex:1;min-width:200px;border-radius:12px;padding:18px 20px;background:#f6f7fb}
.n{font-size:34px;font-weight:800}.l{font-size:14px;color:#5b6478;margin-top:4px}.bad{color:#b91c1c}.good{color:#15803d}.warn{color:#b45309}
table{width:100%;border-collapse:collapse;font-size:14px}th{text-align:left;color:#5b6478;padding:8px 10px;border-bottom:2px solid #e3e7ef}
td{padding:9px 10px;border-bottom:1px solid #eef1f6;vertical-align:top}
.tag{display:inline-block;font-size:12px;font-weight:700;padding:2px 9px;border-radius:999px;white-space:nowrap}
.fail,.critical{background:#fee2e2;color:#b91c1c}.pass{background:#dcfce7;color:#15803d}.error,.high{background:#fef3c7;color:#b45309}.medium,.low{background:#e0e7ff;color:#3730a3}
.finding{border:1px solid #e3e7ef;border-radius:10px;padding:14px 18px;margin-bottom:12px}.finding h3{margin:0 0 8px;font-size:15px}
pre{white-space:pre-wrap;word-break:break-word;background:#f6f7fb;border-radius:8px;padding:10px 12px;font-size:12.5px;margin:6px 0}
.small{font-size:13px;color:#5b6478}
"""


def esc(value) -> str:
    return html.escape(str(value))


def counts(results: list[dict]) -> dict:
    return {
        "fail": sum(r["status"] == "fail" for r in results),
        "pass": sum(r["status"] == "pass" for r in results),
        "error": sum(r["status"] == "error" for r in results),
        "total": len(results),
    }


def tag(text: str, cls: str) -> str:
    return f'<span class="tag {esc(cls)}">{esc(text)}</span>'


def category_table(modes: dict) -> str:
    rows = defaultdict(dict)
    for mode, results in modes.items():
        for r in results:
            cell = rows[(r["owasp"], r["category"])].setdefault(mode, {"fail": 0, "total": 0})
            cell["total"] += 1
            cell["fail"] += r["status"] == "fail"
    head = "".join(f"<th>{esc(m.title())}: attacks that worked</th>" for m in modes)
    body = ""
    for (owasp, category), by_mode in sorted(rows.items()):
        cells = ""
        for mode in modes:
            c = by_mode.get(mode, {"fail": 0, "total": 0})
            cells += f'<td class="{"bad" if c["fail"] else "good"}"><b>{c["fail"]}</b> of {c["total"]}</td>'
        body += f"<tr><td>{esc(owasp)} {esc(OWASP_NAMES.get(owasp, ''))}</td><td>{esc(category)}</td>{cells}</tr>"
    return f"<table><tr><th>OWASP</th><th>Category</th>{head}</tr>{body}</table>"


def finding_card(r: dict) -> str:
    ev = r["evidence"]
    violations = "".join(f"<li>{esc(v)}</li>" for v in ev.get("violations", []))
    tools = ", ".join(f'{t["name"]}({json.dumps(t["args"])})' for t in ev.get("tool_calls", [])) or "none"
    return (
        f'<div class="finding"><h3>{tag(r["severity"].upper(), r["severity"])} {esc(r["id"])}: {esc(r["name"])}'
        f' <span class="small">({esc(r["owasp"])}, worked {r["succeeded"]} of {r["repeats"]} tries)</span></h3>'
        f"<b>Attack</b><pre>{esc(r['prompt'])}</pre><b>What happened</b><ul>{violations}</ul>"
        f"<b>Bot reply</b><pre>{esc(ev.get('reply', ''))}</pre>"
        f'<div class="small">Tools called: {esc(tools)}</div>'
        f'<p class="small"><b>Fix:</b> {esc(FIXES.get(r["category"], ""))}</p></div>'
    )


def build_report(data: dict) -> str:
    modes = data["modes"]
    tiles = ""
    for mode, results in modes.items():
        c = counts(results)
        cls = "bad" if c["fail"] else "good"
        tiles += f'<div class="tile"><div class="n {cls}">{c["fail"]} of {c["total"]}</div><div class="l">attacks worked: {esc(mode)} version</div></div>'
        if c["error"]:
            tiles += f'<div class="tile"><div class="n warn">{c["error"]}</div><div class="l">could not be tested: {esc(mode)} version</div></div>'

    note = f'<p class="small">{esc(data["note"])}</p>' if data.get("note") else ""
    sections = ""
    for mode, results in modes.items():
        failed = [r for r in results if r["status"] == "fail"]
        cards = "".join(finding_card(r) for r in failed) or "<p>No attack succeeded against this version in this run.</p>"
        sections += f"<h2>Findings: {esc(mode)} version</h2>{cards}"

        rows = "".join(
            f"<tr><td>{esc(r['id'])}</td><td>{esc(r['name'])}</td><td>{esc(r['owasp'])}</td>"
            f"<td>{tag(r['status'].upper(), r['status'])}</td></tr>"
            for r in sorted(results, key=lambda r: r["id"])
        )
        sections += f"<h2>All tests: {esc(mode)} version</h2><table><tr><th>ID</th><th>Test</th><th>OWASP</th><th>Result</th></tr>{rows}</table>"

    return (
        f'<!doctype html><html><head><meta charset="utf-8"><title>LLM Security Test Report</title><style>{STYLE}</style></head>'
        f'<body><div class="page"><h1>LLM Security Test Report</h1>'
        f'<div class="meta">Target: Acme Store demo support bot (fictional) · Model: {esc(data["model"])} · '
        f'{data["attack_count"]} attacks, {data["repeats"]} tries each · Run: {esc(data["run_at"])}</div>'
        f"<h2>Summary</h2><div class='tiles'>{tiles}</div>{note}"
        f"<h2>Results by category</h2>{category_table(modes)}{sections}"
        f'<h2>Scope and limits</h2><p class="small">This run covers the five OWASP LLM Top 10 (2025) categories listed above, using '
        f"{data['attack_count']} scripted attacks. A pass means these attacks did not succeed in this run, not that the system is secure. "
        f"An attack counts as a finding if it worked on any try. Results come from checking real backend state and reply text.</p>"
        f"</div></body></html>"
    )


def main() -> int:
    data = json.loads(Path(sys.argv[1]).read_text())
    out = Path(sys.argv[2])
    out.write_text(build_report(data))
    print(f"Wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
