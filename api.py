import os
import uuid
import asyncio
from datetime import datetime
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, BackgroundTasks, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import the orchestrator agent
# Ensure this file is in the root directory alongside main.py
from agents.orchestrator_agent import OrchestratorAgent

app = FastAPI(title="Deployment Misconfig Checker API")

# Job store
jobs: Dict[str, Dict[str, Any]] = {}


class ScanRequest(BaseModel):
    domain: str


class ScanResponse(BaseModel):
    success: bool
    job_id: str
    message: str


class JobStatusResponse(BaseModel):
    job_id: str
    status: str
    execution_history: Optional[List[Dict[str, Any]]] = None
    scan_results: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class JobSummary(BaseModel):
    job_id: str
    domain: str
    status: str
    created_at: str
    has_results: bool
    error: Optional[str] = None


class PaginatedJobsResponse(BaseModel):
    jobs: List[JobSummary]
    total: int
    page: int
    page_size: int
    total_pages: int


def log_execution_step(job_id: str, step_data: Dict[str, Any]):
    """
    Callback to log execution steps in real-time to the job store.
    This allows the frontend to poll and see progress as it happens.
    """
    if job_id in jobs:
        if "execution_history" not in jobs[job_id]:
            jobs[job_id]["execution_history"] = []
        jobs[job_id]["execution_history"].append(step_data)


def _filter_jobs(
    jobs_dict: Dict[str, Dict[str, Any]],
    status: Optional[str] = None,
    domain_search: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Filter jobs by status, domain, and date range.

    Args:
        jobs_dict: Dictionary of all jobs
        status: Optional status filter (pending, running, completed, failed)
        domain_search: Optional domain substring search (case-insensitive)
        date_from: Optional ISO 8601 date string for start of range
        date_to: Optional ISO 8601 date string for end of range

    Returns:
        List of filtered jobs
    """
    valid_statuses = {"pending", "running", "completed", "failed"}

    if status and status not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status '{status}'. Valid values: {', '.join(sorted(valid_statuses))}",
        )

    filtered = []

    for job in jobs_dict.values():
        job_date_str = job.get("created_at", "")

        if status and job["status"] != status:
            continue

        if domain_search:
            if domain_search.lower() not in job["domain"].lower():
                continue

        if date_from or date_to:
            try:
                job_date = datetime.fromisoformat(job_date_str)
            except (ValueError, TypeError):
                continue

            if date_from:
                try:
                    from_date = datetime.fromisoformat(date_from)
                    if job_date < from_date:
                        continue
                except ValueError:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Invalid date_from format: {date_from}. Use ISO 8601 format (e.g., 2024-01-01T00:00:00)",
                    )

            if date_to:
                try:
                    to_date = datetime.fromisoformat(date_to)
                    if job_date > to_date:
                        continue
                except ValueError:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Invalid date_to format: {date_to}. Use ISO 8601 format (e.g., 2024-12-31T23:59:59)",
                    )

        filtered.append(job)

    return filtered


def _paginate_and_sort_jobs(
    jobs_list: List[Dict[str, Any]],
    page: int,
    page_size: int,
) -> tuple:
    """
    Sort jobs by created_at descending (newest first) and paginate.

    Args:
        jobs_list: List of jobs to paginate
        page: Page number (1-indexed)
        page_size: Number of items per page

    Returns:
        Tuple of (paginated_jobs, total_count, total_pages)
    """
    sorted_jobs = sorted(jobs_list, key=lambda j: j.get("created_at", ""), reverse=True)

    total = len(sorted_jobs)
    total_pages = (total + page_size - 1) // page_size if page_size > 0 else 1

    start = (page - 1) * page_size
    end = start + page_size

    paginated = sorted_jobs[start:end]

    return paginated, total, total_pages


def run_scan_job(job_id: str, domain: str):
    """
    Background task to run the scan
    """
    try:
        jobs[job_id]["status"] = "running"

        # Initialize orchestrator
        orchestrator = OrchestratorAgent()

        # Construct specific request for full scan
        # We phrase it to trigger a comprehensive scan workflow
        request = f"Perform a comprehensive security scan on {domain}. Check for open ports, web vulnerabilities, and any misconfigurations."

        # Create callback that logs to this specific job
        progress_callback = lambda step: log_execution_step(job_id, step)

        # Run workflow with progress callback for real-time updates
        result = orchestrator.run_workflow(
            request, max_iterations=5, progress_callback=progress_callback
        )

        if result["success"]:
            jobs[job_id]["status"] = "completed"
            jobs[job_id]["scan_results"] = result

            # Parse specific counts for the dashboard if possible
            # The dashboard expects 'critical_count', 'high_count', etc.
            # We try to extract these from the vulnerabilities found
            vuln_data = result.get("vulnerabilities", {})
            details = vuln_data.get("vulnerability_details", [])

            critical_count = 0
            high_count = 0
            exploitable_count = len(vuln_data.get("exploitable_services", []))

            for detail in details:
                detail_lower = str(detail).lower()
                if (
                    "critical" in detail_lower
                    or "sql injection" in detail_lower
                    or "rce" in detail_lower
                ):
                    critical_count += 1
                elif "high" in detail_lower or "xss" in detail_lower:
                    high_count += 1

            # Add these counts to the data
            jobs[job_id]["scan_results"]["critical_count"] = critical_count
            jobs[job_id]["scan_results"]["high_count"] = high_count
            jobs[job_id]["scan_results"]["exploitable_count"] = exploitable_count

        else:
            jobs[job_id]["status"] = "failed"
            jobs[job_id]["error"] = result.get("error", "Unknown error")

    except Exception as e:
        jobs[job_id]["status"] = "failed"
        jobs[job_id]["error"] = str(e)


@app.post("/api/scan", response_model=ScanResponse)
async def submit_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    job_id = str(uuid.uuid4())

    jobs[job_id] = {
        "job_id": job_id,
        "domain": request.domain,
        "status": "pending",
        "execution_history": [],
        "created_at": datetime.utcnow().isoformat() + "Z",
    }

    background_tasks.add_task(run_scan_job, job_id, request.domain)

    return {"success": True, "job_id": job_id, "message": "Scan job submitted"}


@app.get("/api/status/{job_id}", response_model=JobStatusResponse)
async def get_job_status(job_id: str):
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")

    job = jobs[job_id]

    return {
        "job_id": job_id,
        "status": job["status"],
        "execution_history": job.get("execution_history", []),
        "scan_results": job.get("scan_results"),
        "error": job.get("error"),
    }


@app.get("/api/health")
async def health_check():
    return {"status": "ok"}


@app.get("/api/jobs", response_model=PaginatedJobsResponse)
async def list_jobs(
    page: int = 1,
    page_size: int = 20,
    status: Optional[str] = None,
    domain_search: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
):
    """
    List all scan jobs with pagination, filtering, and sorting.

    Query Parameters:
    - page: Page number (default: 1, min: 1)
    - page_size: Items per page (default: 20, min: 1, max: 100)
    - status: Filter by status (pending, running, completed, failed)
    - domain_search: Search domains by substring (case-insensitive)
    - date_from: Filter by creation date from (ISO 8601 format)
    - date_to: Filter by creation date to (ISO 8601 format)

    Jobs are sorted by created_at descending (newest first).
    """
    if page < 1:
        page = 1
    if page_size < 1 or page_size > 100:
        page_size = 20

    filtered_jobs = _filter_jobs(
        jobs,
        status=status,
        domain_search=domain_search,
        date_from=date_from,
        date_to=date_to,
    )

    paginated_jobs, total, total_pages = _paginate_and_sort_jobs(
        filtered_jobs,
        page,
        page_size,
    )

    job_summaries = [
        JobSummary(
            job_id=j["job_id"],
            domain=j["domain"],
            status=j["status"],
            created_at=j["created_at"],
            has_results=bool(j.get("scan_results")),
            error=j.get("error"),
        )
        for j in paginated_jobs
    ]

    return PaginatedJobsResponse(
        jobs=job_summaries,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )
