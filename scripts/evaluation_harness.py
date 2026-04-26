#!/usr/bin/env python3
"""
Benchmark v1 and v2 orchestrators on the same prompt and capture evaluation data.

This script is intended to support paper metrics such as:
- end-to-end execution time
- total tool calls
- redundant tool calls
- report completeness by stage coverage
- machine-checkable tool invocation validity

It records raw run artifacts so stricter manual review can be performed later.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import statistics
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Tuple

from dotenv import load_dotenv

from agents.orchestrator_agent import OrchestratorAgent
from v2.orchestrator import V2DeepOrchestrator


DEFAULT_PROMPT_TEMPLATE = (
    "Perform reconnaissance, web vulnerability scanning, and exploit lookup "
    "against {target}."
)

STAGE_BY_TOOL = {
    "nmap": "service_discovery",
    "masscan": "service_discovery",
    "nikto": "web_scanning",
    "wpscan": "web_scanning",
    "list_available_exploits": "exploit_recon",
    "search_exploits_by_cve": "exploit_recon",
    "get_exploit_details": "exploit_recon",
}

STAGE_BY_AGENT = {
    "nmap": "service_discovery",
    "wpscan": "web_scanning",
    "nikto": "web_scanning",
    "metasploit": "exploit_recon",
    "service_discover_agent": "service_discovery",
    "web_scan_agent": "web_scanning",
    "exploit_recon_agent": "exploit_recon",
}


@dataclass
class ToolCallRecord:
    tool: str
    stage: str
    invocation: str
    started_at: float
    finished_at: float
    duration_seconds: float
    outcome: str
    output_excerpt: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "stage": self.stage,
            "invocation": self.invocation,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": self.duration_seconds,
            "outcome": self.outcome,
            "output_excerpt": self.output_excerpt,
        }


@dataclass
class RunArtifact:
    orchestrator: str
    run_index: int
    target: str
    prompt: str
    started_at: float
    finished_at: float
    duration_seconds: float
    result: Dict[str, Any]
    tool_calls: List[ToolCallRecord] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "orchestrator": self.orchestrator,
            "run_index": self.run_index,
            "target": self.target,
            "prompt": self.prompt,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": self.duration_seconds,
            "result": self.result,
            "tool_calls": [record.to_dict() for record in self.tool_calls],
            "metrics": self.metrics,
        }


def _extract_invocation(tool_name: str, args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> str:
    if "command" in kwargs:
        return str(kwargs["command"])
    if "vulnerability_keywords" in kwargs:
        return str(kwargs["vulnerability_keywords"])
    if "vulnerability_info" in kwargs:
        return str(kwargs["vulnerability_info"])
    if "cve_id" in kwargs:
        return str(kwargs["cve_id"])
    if "exploit_path" in kwargs:
        return str(kwargs["exploit_path"])
    if args:
        return str(args[0])
    return ""


def _classify_outcome(output: Any) -> str:
    text = str(output)
    text_upper = text.upper()
    if "TIMEOUT_ERROR:" in text_upper:
        return "timeout"
    if "NOT_INSTALLED" in text_upper:
        return "not_installed"
    if text.startswith("Error") or "Error executing" in text:
        return "error"
    if "failed to connect to metasploit rpc" in text.lower():
        return "error"
    return "ok"


def _trim_output(output: Any, limit: int = 300) -> str:
    text = " ".join(str(output).split())
    return text[:limit]


def _normalize_invocation(invocation: str) -> str:
    return " ".join(str(invocation).strip().lower().split())


def _safe_mean(values: Iterable[float]) -> float:
    values = list(values)
    return statistics.mean(values) if values else 0.0


def _safe_stdev(values: Iterable[float]) -> float:
    values = list(values)
    return statistics.stdev(values) if len(values) >= 2 else 0.0


def _stage_coverage(execution_history: List[Dict[str, Any]]) -> Dict[str, bool]:
    covered = {
        "service_discovery": False,
        "web_scanning": False,
        "exploit_recon": False,
    }
    for entry in execution_history:
        stage = STAGE_BY_AGENT.get(entry.get("agent"))
        if stage:
            covered[stage] = True
    return covered


def _compute_metrics(result: Dict[str, Any], tool_calls: List[ToolCallRecord], duration_seconds: float) -> Dict[str, Any]:
    execution_history = result.get("execution_history", []) or []
    coverage = _stage_coverage(execution_history)

    signatures: Dict[Tuple[str, str], int] = {}
    redundant = 0
    valid = 0
    for call in tool_calls:
        signature = (call.tool, _normalize_invocation(call.invocation))
        signatures[signature] = signatures.get(signature, 0) + 1
        if signatures[signature] > 1:
            redundant += 1
        if call.outcome == "ok":
            valid += 1

    return {
        "end_to_end_seconds": round(duration_seconds, 3),
        "total_tool_calls": len(tool_calls),
        "redundant_tool_calls": redundant,
        "valid_tool_calls": valid,
        "tool_invocation_validity_pct": round((valid / len(tool_calls)) * 100, 2)
        if tool_calls
        else 0.0,
        "service_discovery_covered": coverage["service_discovery"],
        "web_scanning_covered": coverage["web_scanning"],
        "exploit_recon_covered": coverage["exploit_recon"],
        "report_complete_all_stages": all(coverage.values()),
        "execution_history_length": len(execution_history),
        "success": bool(result.get("success")),
    }


@contextmanager
def instrument_tools() -> List[ToolCallRecord]:
    """
    Monkeypatch tool functions in both v1 and v2 entry points so real tool usage
    can be counted without modifying the application logic.
    """
    import agents.nikto_agent as agents_nikto_agent
    import agents.nmap_agent as agents_nmap_agent
    import agents.wpscan_agent as agents_wpscan_agent
    import tools.metasploit_passive_tool as metasploit_passive_tool
    import tools.nikto_tool as nikto_tool
    import tools.nmap_tool as nmap_tool
    import tools.wpscan_tool as wpscan_tool
    import v2.subagents as v2_subagents
    import v2.tools.masscan_tool as masscan_tool

    records: List[ToolCallRecord] = []
    originals: List[Tuple[Any, str, Callable[..., Any]]] = []

    def patch(module: Any, attribute: str, tool_name: str) -> None:
        original = getattr(module, attribute)
        originals.append((module, attribute, original))

        def wrapped(*args: Any, **kwargs: Any) -> Any:
            invocation = _extract_invocation(tool_name, args, kwargs)
            started_at = time.perf_counter()
            output = original(*args, **kwargs)
            finished_at = time.perf_counter()
            record = ToolCallRecord(
                tool=tool_name,
                stage=STAGE_BY_TOOL.get(tool_name, "unknown"),
                invocation=invocation,
                started_at=started_at,
                finished_at=finished_at,
                duration_seconds=round(finished_at - started_at, 3),
                outcome=_classify_outcome(output),
                output_excerpt=_trim_output(output),
            )
            records.append(record)
            return output

        setattr(module, attribute, wrapped)

    patch(nmap_tool, "execute_nmap", "nmap")
    patch(agents_nmap_agent, "execute_nmap", "nmap")
    patch(v2_subagents, "execute_nmap", "nmap")

    patch(nikto_tool, "execute_nikto", "nikto")
    patch(agents_nikto_agent, "execute_nikto", "nikto")
    patch(v2_subagents, "execute_nikto", "nikto")

    patch(wpscan_tool, "execute_wpscan", "wpscan")
    patch(agents_wpscan_agent, "execute_wpscan", "wpscan")
    patch(v2_subagents, "execute_wpscan", "wpscan")

    patch(masscan_tool, "execute_masscan", "masscan")
    patch(v2_subagents, "execute_masscan", "masscan")

    patch(metasploit_passive_tool, "list_available_exploits", "list_available_exploits")
    patch(metasploit_passive_tool, "search_exploits_by_cve", "search_exploits_by_cve")
    patch(metasploit_passive_tool, "get_exploit_details", "get_exploit_details")
    patch(v2_subagents, "list_available_exploits", "list_available_exploits")
    patch(v2_subagents, "search_exploits_by_cve", "search_exploits_by_cve")
    patch(v2_subagents, "get_exploit_details", "get_exploit_details")

    try:
        yield records
    finally:
        for module, attribute, original in reversed(originals):
            setattr(module, attribute, original)


def _build_orchestrator(name: str) -> Any:
    if name == "v1":
        return OrchestratorAgent()
    if name == "v2":
        return V2DeepOrchestrator()
    raise ValueError(f"Unsupported orchestrator: {name}")


def _run_single(orchestrator_name: str, run_index: int, target: str, prompt: str) -> RunArtifact:
    with instrument_tools() as tool_records:
        orchestrator = _build_orchestrator(orchestrator_name)
        started_at = time.perf_counter()
        result = orchestrator.run_workflow(prompt)
        finished_at = time.perf_counter()

    duration_seconds = finished_at - started_at
    metrics = _compute_metrics(result, tool_records, duration_seconds)
    return RunArtifact(
        orchestrator=orchestrator_name,
        run_index=run_index,
        target=target,
        prompt=prompt,
        started_at=started_at,
        finished_at=finished_at,
        duration_seconds=round(duration_seconds, 3),
        result=result,
        tool_calls=list(tool_records),
        metrics=metrics,
    )


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _write_summary_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    if not rows:
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _aggregate(artifacts: List[RunArtifact]) -> List[Dict[str, Any]]:
    grouped: Dict[str, List[RunArtifact]] = {}
    for artifact in artifacts:
        grouped.setdefault(artifact.orchestrator, []).append(artifact)

    rows: List[Dict[str, Any]] = []
    for orchestrator, runs in sorted(grouped.items()):
        rows.append(
            {
                "orchestrator": orchestrator,
                "runs": len(runs),
                "mean_end_to_end_seconds": round(
                    _safe_mean(run.metrics["end_to_end_seconds"] for run in runs), 3
                ),
                "stdev_end_to_end_seconds": round(
                    _safe_stdev(run.metrics["end_to_end_seconds"] for run in runs), 3
                ),
                "mean_total_tool_calls": round(
                    _safe_mean(run.metrics["total_tool_calls"] for run in runs), 3
                ),
                "mean_redundant_tool_calls": round(
                    _safe_mean(run.metrics["redundant_tool_calls"] for run in runs), 3
                ),
                "mean_tool_invocation_validity_pct": round(
                    _safe_mean(
                        run.metrics["tool_invocation_validity_pct"] for run in runs
                    ),
                    2,
                ),
                "complete_reports": sum(
                    1 for run in runs if run.metrics["report_complete_all_stages"]
                ),
                "successful_runs": sum(1 for run in runs if run.metrics["success"]),
            }
        )
    return rows


def _write_manual_review_csv(path: Path, artifacts: List[RunArtifact]) -> None:
    rows: List[Dict[str, Any]] = []
    for artifact in artifacts:
        for index, call in enumerate(artifact.tool_calls, start=1):
            rows.append(
                {
                    "orchestrator": artifact.orchestrator,
                    "run_index": artifact.run_index,
                    "call_index": index,
                    "tool": call.tool,
                    "stage": call.stage,
                    "invocation": call.invocation,
                    "outcome": call.outcome,
                    "duration_seconds": call.duration_seconds,
                    "output_excerpt": call.output_excerpt,
                    "appropriate_for_subtask": "",
                    "review_notes": "",
                }
            )
    if rows:
        _write_summary_csv(path, rows)


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate v1 and v2 orchestrators on the same target/prompt."
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target to scan, for example localhost:31337",
    )
    parser.add_argument(
        "--prompt",
        help="Full prompt to use. If omitted, a default paper-style prompt is generated.",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=3,
        help="Number of runs per orchestrator.",
    )
    parser.add_argument(
        "--output-dir",
        default="evaluation_artifacts",
        help="Directory where raw run artifacts and summaries are written.",
    )
    parser.add_argument(
        "--orchestrators",
        nargs="+",
        default=["v1", "v2"],
        choices=["v1", "v2"],
        help="Which orchestrators to benchmark.",
    )
    parser.add_argument(
        "--sleep-between-runs",
        type=float,
        default=0.0,
        help="Optional delay between runs in seconds.",
    )
    return parser.parse_args(argv)


def main(argv: List[str]) -> int:
    load_dotenv()
    args = parse_args(argv)

    prompt = args.prompt or DEFAULT_PROMPT_TEMPLATE.format(target=args.target)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    artifacts: List[RunArtifact] = []

    print(f"Target: {args.target}")
    print(f"Prompt: {prompt}")
    print(f"Runs per orchestrator: {args.runs}")
    print(f"Output directory: {output_dir}")

    for orchestrator_name in args.orchestrators:
        for run_index in range(1, args.runs + 1):
            print(f"\n[{orchestrator_name}] Run {run_index}/{args.runs}")
            artifact = _run_single(
                orchestrator_name=orchestrator_name,
                run_index=run_index,
                target=args.target,
                prompt=prompt,
            )
            artifacts.append(artifact)

            file_name = f"{orchestrator_name}_run_{run_index}.json"
            _write_json(output_dir / file_name, artifact.to_dict())

            print(
                "  "
                f"time={artifact.metrics['end_to_end_seconds']}s, "
                f"tool_calls={artifact.metrics['total_tool_calls']}, "
                f"redundant={artifact.metrics['redundant_tool_calls']}, "
                f"complete={artifact.metrics['report_complete_all_stages']}"
            )

            if args.sleep_between_runs > 0 and run_index != args.runs:
                time.sleep(args.sleep_between_runs)

    summary_rows = _aggregate(artifacts)
    _write_summary_csv(output_dir / "summary.csv", summary_rows)
    _write_json(output_dir / "summary.json", summary_rows)
    _write_manual_review_csv(output_dir / "manual_review.csv", artifacts)

    print("\nSummary")
    for row in summary_rows:
        print(
            "  "
            f"{row['orchestrator']}: "
            f"mean_time={row['mean_end_to_end_seconds']}s, "
            f"mean_calls={row['mean_total_tool_calls']}, "
            f"mean_redundant={row['mean_redundant_tool_calls']}, "
            f"validity={row['mean_tool_invocation_validity_pct']}%, "
            f"complete_reports={row['complete_reports']}/{row['runs']}"
        )

    print(
        "\nArtifacts written:\n"
        f"- {output_dir / 'summary.csv'}\n"
        f"- {output_dir / 'summary.json'}\n"
        f"- {output_dir / 'manual_review.csv'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
