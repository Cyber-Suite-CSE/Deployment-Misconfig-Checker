"""Metric collection from a single run."""

from __future__ import annotations

from typing import Any

from eval.reference import (
    REFERENCE_WORKFLOW,
    is_appropriate,
    is_redundant,
    stages_covered_by_report,
    stages_invoked,
)


def collect_metrics(run: dict[str, Any]) -> dict[str, Any]:
    """Compute the five paper metrics from a single run's trace + final report."""
    calls: list[dict] = run.get("tool_calls", [])
    final_message: str = run.get("final_message", "") or ""

    redundant = sum(1 for i, c in enumerate(calls) if is_redundant(c, calls[:i]))
    appropriate = sum(1 for c in calls if is_appropriate(c))
    accuracy_pct = (appropriate / len(calls) * 100.0) if calls else 0.0
    stages_in_report = stages_covered_by_report(final_message)
    stages_run = stages_invoked(calls)

    return {
        "wall_clock_seconds": float(run.get("wall_clock_seconds", 0.0)),
        "total_tool_calls": len(calls),
        "redundant_tool_calls": redundant,
        "tool_invocation_accuracy_pct": round(accuracy_pct, 2),
        "stages_invoked": stages_run,
        "stages_covered_by_report": stages_in_report,
        "report_covers_all_stages": stages_in_report
        == len(REFERENCE_WORKFLOW["stages"]),
    }
