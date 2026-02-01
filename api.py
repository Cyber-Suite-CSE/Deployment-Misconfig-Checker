import os
import uuid
import asyncio
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
    scan_results: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

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
        
        # Run workflow
        result = orchestrator.run_workflow(request, max_iterations=5)
        
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
                if "critical" in detail_lower or "sql injection" in detail_lower or "rce" in detail_lower:
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
        "created_at": os.getenv("Start_Time", "") # Just as a placeholder or use datetime
    }
    
    background_tasks.add_task(run_scan_job, job_id, request.domain)
    
    return {
        "success": True,
        "job_id": job_id,
        "message": "Scan job submitted"
    }

@app.get("/api/status/{job_id}", response_model=JobStatusResponse)
async def get_job_status(job_id: str):
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    
    job = jobs[job_id]
    
    return {
        "job_id": job_id,
        "status": job["status"],
        "scan_results": job.get("scan_results"),
        "error": job.get("error")
    }

@app.get("/api/health")
async def health_check():
    return {"status": "ok"}
