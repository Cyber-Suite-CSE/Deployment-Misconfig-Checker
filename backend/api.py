import os
import uuid
import asyncio
from datetime import datetime
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, BackgroundTasks, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

from agents.orchestrator_agent import OrchestratorAgent
from .database import Database, DatabaseException

app = FastAPI(title="Deployment Misconfig Checker API")

db = Database()


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
    Callback to log execution steps in real-time to the database.
    This allows the frontend to poll and see progress as it happens.
    """
    db.append_execution_step(job_id, step_data)


def run_scan_job(job_id: str, domain: str):
    """
    Background task to run the scan
    """
    try:
        db.update_job(job_id, status="running")

        orchestrator = OrchestratorAgent()

        request = f"Perform a comprehensive security scan on {domain}. Check for open ports, web vulnerabilities, and any misconfigurations."

        progress_callback = lambda step: log_execution_step(job_id, step)

        result = orchestrator.run_workflow(
            request, max_iterations=5, progress_callback=progress_callback
        )

        if result["success"]:
            db.update_job(job_id, status="completed", scan_results=result)

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

            job = db.get_job(job_id)
            if job and job.get("scan_results"):
                job["scan_results"]["critical_count"] = critical_count
                job["scan_results"]["high_count"] = high_count
                job["scan_results"]["exploitable_count"] = exploitable_count
                db.update_job(job_id, scan_results=job["scan_results"])

        else:
            db.update_job(
                job_id, status="failed", error=result.get("error", "Unknown error")
            )

    except Exception as e:
        db.update_job(job_id, status="failed", error=str(e))


@app.post("/api/scan", response_model=ScanResponse)
async def submit_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    job_id = str(uuid.uuid4())

    db.create_job(
        job_id=job_id,
        domain=request.domain,
        status="pending",
        created_at=datetime.utcnow().isoformat() + "Z",
    )

    background_tasks.add_task(run_scan_job, job_id, request.domain)

    return {"success": True, "job_id": job_id, "message": "Scan job submitted"}


@app.get("/api/status/{job_id}", response_model=JobStatusResponse)
async def get_job_status(job_id: str):
    job = db.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

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

    try:
        jobs_list, total, total_pages = db.list_jobs(
            page=page,
            page_size=page_size,
            status=status,
            domain_search=domain_search,
            date_from=date_from,
            date_to=date_to,
        )
    except DatabaseException as e:
        raise HTTPException(status_code=400, detail=str(e))

    job_summaries = [
        JobSummary(
            job_id=j["job_id"],
            domain=j["domain"],
            status=j["status"],
            created_at=j["created_at"],
            has_results=bool(j.get("scan_results")),
            error=j.get("error"),
        )
        for j in jobs_list
    ]

    return PaginatedJobsResponse(
        jobs=job_summaries,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )
