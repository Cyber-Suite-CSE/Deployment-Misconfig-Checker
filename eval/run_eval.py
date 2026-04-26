"""V1 vs V2 evaluation harness.

Usage:
    python -m eval.run_eval [--runs N] [--versions v1,v2]
                            [--prompt "..."] [--out-dir eval/results]

The default settings reproduce the paper's Table 1: 3 runs each of V1 and V2
against the DVWP target on localhost:31337, paper-verbatim prompt.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv

from eval.metrics import collect_metrics
from eval.recorder import record_tool_calls
from eval.report import write_summary


PAPER_PROMPT = (
    "Perform reconnaissance, web vulnerability scanning, and exploit lookup "
    "against localhost:31337."
)


def run_v1(prompt: str) -> dict[str, Any]:
    """Run V1: single agent, GPT-4o, all tools."""
    from v1.single_agent import SingleSecurityAgent

    agent = SingleSecurityAgent()
    with record_tool_calls() as calls:
        out = agent.process_request(prompt)
    return {
        **out,
        "tool_calls": calls,
        "version": "v1",
        "config": {
            "model": agent.model,
            "temperature": agent.temperature,
            "recursion_limit": agent.recursion_limit,
        },
    }


def run_v2(prompt: str) -> dict[str, Any]:
    """Run V2: orchestrator (gpt-4o) + sub-agents (gpt-4o-mini), all tools.

    Forces LLM_PROVIDER=openai for the duration of the run so the comparison
    matches the paper's stated configuration.
    """
    prior_provider = os.environ.get("LLM_PROVIDER")
    os.environ["LLM_PROVIDER"] = "openai"
    try:
        from agents.orchestrator_agent import OrchestratorAgent

        orch = OrchestratorAgent(
            orchestrator_model="gpt-4o",
            sub_agent_model="gpt-4o-mini",
            temperature=0.0,
        )
        start = time.perf_counter()
        with record_tool_calls() as calls:
            report = orch.process_user_request(prompt)
        elapsed = time.perf_counter() - start
        return {
            "final_message": report,
            "all_messages": [],  # V2's orchestrator doesn't expose a single message log
            "wall_clock_seconds": elapsed,
            "tool_calls": calls,
            "version": "v2",
            "config": {
                "orchestrator_model": "gpt-4o",
                "sub_agent_model": "gpt-4o-mini",
                "temperature": 0.0,
            },
        }
    finally:
        if prior_provider is None:
            os.environ.pop("LLM_PROVIDER", None)
        else:
            os.environ["LLM_PROVIDER"] = prior_provider


VERSION_RUNNERS: dict[str, Callable[[str], dict[str, Any]]] = {
    "v1": run_v1,
    "v2": run_v2,
}


def _save_run(run: dict, metrics: dict, out_dir: Path, version: str, run_idx: int) -> Path:
    path = out_dir / f"{version}_run_{run_idx}.json"
    payload = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "metrics": metrics,
        **run,
    }
    path.write_text(json.dumps(payload, default=str, indent=2))
    return path


def main() -> None:
    load_dotenv()

    parser = argparse.ArgumentParser(description="V1/V2 evaluation harness")
    parser.add_argument("--runs", type=int, default=3, help="Runs per version (default 3)")
    parser.add_argument(
        "--versions",
        type=str,
        default="v1,v2",
        help="Comma-separated versions to run (default v1,v2)",
    )
    parser.add_argument(
        "--prompt",
        type=str,
        default=PAPER_PROMPT,
        help="Natural-language prompt to send to each version",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "results",
        help="Directory for per-run JSON + summary outputs",
    )
    args = parser.parse_args()

    versions = [v.strip() for v in args.versions.split(",") if v.strip()]
    for v in versions:
        if v not in VERSION_RUNNERS:
            raise SystemExit(f"Unknown version: {v}. Choose from {list(VERSION_RUNNERS)}")

    if not os.getenv("OPENAI_API_KEY"):
        raise SystemExit("OPENAI_API_KEY required (eval pins both V1 and V2 to OpenAI per paper).")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    print(f"[eval] prompt: {args.prompt}")
    print(f"[eval] versions: {versions}, runs each: {args.runs}")
    print(f"[eval] output dir: {args.out_dir}")

    all_metrics: dict[str, list[dict]] = {v: [] for v in versions}
    for version in versions:
        runner = VERSION_RUNNERS[version]
        for i in range(1, args.runs + 1):
            print(f"\n=== [{version}] run {i}/{args.runs} ===")
            try:
                run = runner(args.prompt)
            except Exception as exc:  # noqa: BLE001 — record then continue
                print(f"[{version}] run {i} FAILED: {exc}")
                traceback.print_exc()
                run = {
                    "version": version,
                    "final_message": "",
                    "tool_calls": [],
                    "wall_clock_seconds": 0.0,
                    "all_messages": [],
                    "error": f"{type(exc).__name__}: {exc}",
                }
            metrics = collect_metrics(run)
            print(f"[{version}] metrics: {metrics}")
            _save_run(run, metrics, args.out_dir, version, i)
            all_metrics[version].append(metrics)

    write_summary(all_metrics, args.out_dir)
    print(f"\n[eval] wrote summary.json/md/tex to {args.out_dir}")


if __name__ == "__main__":
    main()
