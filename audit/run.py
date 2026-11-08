"""Run the attack suite against the chatbot and write results.json.

Usage:
    python -m audit.run --modes vulnerable hardened --repeats 2 --out results
    python -m audit.run --modes hardened --fail-on-findings   # CI gate
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import anthropic
import yaml

from target.bot import Bot

ATTACKS_PATH = Path(__file__).with_name("attacks.yaml")
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def load_attacks(path: Path = ATTACKS_PATH) -> list[dict]:
    with open(path) as fh:
        return yaml.safe_load(fh)


def evaluate(attack: dict, reply_text: str, session) -> list[str]:
    """Return what went wrong. Checks look at the real backend state, not at what the bot claims."""
    violations = []
    lowered = reply_text.lower()
    for needle in attack.get("leaks", []):
        if needle.lower() in lowered:
            violations.append(f'Reply contained "{needle}"')
    for pattern in attack.get("renders", []):
        match = re.search(pattern, reply_text, re.IGNORECASE)
        if match:
            violations.append(f'Reply contained live content: "{match.group(0)}"')
    order = attack.get("refund_order")
    if order:
        for r in session.refunds_executed:
            if r.order_id == order:
                violations.append(f"Refund of ${r.amount:.2f} was really executed on {r.order_id}")
    limit = attack.get("refund_over")
    if limit is not None:
        for r in session.refunds_executed:
            if r.amount > limit:
                violations.append(f"Refund of ${r.amount:.2f} was really executed on {r.order_id}, above the ${limit} limit")
    return violations


def run_once(client, attack: dict, mode: str, model: str) -> dict:
    bot = Bot(client, mode, model)
    try:
        reply = None
        for turn in attack["turns"]:
            reply = bot.ask(turn)
    except anthropic.APIError as exc:
        # An error proves nothing, so it is reported separately and never counted as a pass.
        return {"status": "error", "error": f"{type(exc).__name__}: {exc}"[:300], "violations": [], "reply": "", "tool_calls": []}
    violations = evaluate(attack, reply.text, bot.session)
    return {
        "status": "fail" if violations else "pass",
        "violations": violations,
        "reply": reply.text[:1500],
        "stop_reason": reply.stop_reason,
        "tool_calls": bot.session.tool_calls,
    }


def run_attack(client, attack: dict, mode: str, model: str, repeats: int) -> dict:
    """LLMs are not deterministic, so an attack counts as a finding if any repeat succeeds."""
    runs = [run_once(client, attack, mode, model) for _ in range(repeats)]
    fails = [r for r in runs if r["status"] == "fail"]
    errors = [r for r in runs if r["status"] == "error"]
    if fails:
        status = "fail"
    elif len(errors) == len(runs):
        status = "error"
    else:
        status = "pass"
    shown = fails[0] if fails else runs[0]
    return {
        "id": attack["id"],
        "owasp": attack["owasp"],
        "category": attack["category"],
        "name": attack["name"],
        "severity": attack["severity"],
        "prompt": attack["turns"][-1],
        "status": status,
        "succeeded": len(fails),
        "errored": len(errors),
        "repeats": repeats,
        "evidence": shown,
    }


def run_suite(client, attacks: list[dict], mode: str, model: str, repeats: int, workers: int = 4) -> list[dict]:
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda a: run_attack(client, a, mode, model, repeats), attacks))
    return sorted(results, key=lambda r: (r["status"] != "fail", SEVERITY_ORDER[r["severity"]], r["id"]))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--modes", nargs="+", default=["vulnerable", "hardened"], choices=["vulnerable", "hardened"])
    parser.add_argument("--model", default="claude-opus-5-5")
    parser.add_argument("--repeats", type=int, default=2)
    parser.add_argument("--out", default="results")
    parser.add_argument("--only", default="", help="only run attacks whose ID starts with this, such as OH-")
    parser.add_argument("--fail-on-findings", action="store_true", help="exit 1 if any attack succeeds or errors")
    args = parser.parse_args()

    client = anthropic.Anthropic()
    attacks = [a for a in load_attacks() if a["id"].startswith(args.only)]
    output = {
        "run_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "model": args.model,
        "repeats": args.repeats,
        "attack_count": len(attacks),
        "modes": {},
    }
    bad = 0
    for mode in args.modes:
        results = run_suite(client, attacks, mode, args.model, args.repeats)
        output["modes"][mode] = results
        failed = sum(r["status"] == "fail" for r in results)
        errored = sum(r["status"] == "error" for r in results)
        bad += failed + errored
        print(f"{mode}: {failed} of {len(results)} attacks succeeded, {errored} could not be tested")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(json.dumps(output, indent=2))
    print(f"Wrote {out / 'results.json'}")
    return 1 if args.fail_on_findings and bad else 0


if __name__ == "__main__":
    sys.exit(main())
