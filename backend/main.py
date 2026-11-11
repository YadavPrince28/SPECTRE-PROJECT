import asyncio
from datetime import datetime
import logging
import os
from pathlib import Path
import shutil
from typing import Any
import uuid

from fastapi import BackgroundTasks, FastAPI, File, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

# Silence external library logging
logging.getLogger("androguard").setLevel(logging.ERROR)

from pipeline import run_pipeline

app = FastAPI(
    title="SPECTRE API",
    version="1.0.0",
    description="Android APK Fraud Intelligence Platform",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory store for active and completed analysis jobs
job_status: dict[str, dict[str, Any]] = {}


@app.get("/")
def root():
    return {
        "message": "SPECTRE API is running",
        "status": "ok",
        "version": "1.0.0",
    }


@app.get("/health")
def health():
    return {"status": "healthy", "version": "1.0.0"}


@app.post("/analyze")
async def analyze(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
):
    job_id = str(uuid.uuid4())[:8]

    upload_dir = Path("D:/Spectre_BOI_project/SPECTRE/data/uploads")
    upload_dir.mkdir(parents=True, exist_ok=True)

    apk_path = str(upload_dir / f"{job_id}_{file.filename}")

    with open(apk_path, "wb") as f_out:
        shutil.copyfileobj(file.file, f_out)

    job_status[job_id] = {
        "job_id": job_id,
        "status": "queued",
        "filename": file.filename,
        "apk_path": apk_path,
        "created_at": datetime.now().isoformat(),
        "latest_log": "Job queued for analysis...",
        "live_mitm_console": [],
        "result": None,
        "error": None,
    }

    background_tasks.add_task(run_analysis_background, job_id, apk_path)

    return {
        "job_id": job_id,
        "status": "queued",
        "filename": file.filename,
        "message": f"Analysis started. Connect to /status/{job_id} for live updates.",
    }


async def run_analysis_background(job_id: str, apk_path: str):
    def _telemetry_bridge(j_id: str, entry: dict[str, Any]):
        if j_id in job_status:
            job_status[j_id].setdefault("live_mitm_console", []).append(entry)
            job_status[j_id]["latest_log"] = entry.get("raw_line", "")

    try:
        job_status[job_id]["status"] = "running"
        job_status[job_id]["latest_log"] = "Analysis engine initialized..."

        # Execute blocking pipeline in a separate thread to keep the asyncio loop responsive
        result = await asyncio.to_thread(
            run_pipeline,
            apk_path=apk_path,
            job_id=job_id,
            telemetry_callback=_telemetry_bridge,
        )

        job_status[job_id]["status"] = "complete"
        job_status[job_id]["result"] = result
        job_status[job_id]["latest_log"] = "Analysis pipeline completed successfully."

        # Ensure final dynamic telemetry from pipeline results is mirrored in top-level status
        if result and isinstance(result, dict) and "dynamic" in result:
            dynamic_res = result.get("dynamic", {})
            if dynamic_res.get("mitm_console"):
                job_status[job_id]["live_mitm_console"] = dynamic_res["mitm_console"]

    except Exception as e:
        job_status[job_id]["status"] = "error"
        job_status[job_id]["error"] = str(e)
        job_status[job_id]["latest_log"] = f"[ERROR] Pipeline failed: {e}"
        print(f"[ERROR] Pipeline failed for job {job_id}: {e}")


@app.websocket("/status/{job_id}")
async def websocket_status(websocket: WebSocket, job_id: str):
    await websocket.accept()

    if job_id not in job_status:
        await websocket.send_json({"error": "Job ID not found"})
        await websocket.close()
        return

    # Immediately replay current state to prevent race conditions on fast/cached runs
    current = job_status.get(job_id, {})
    await websocket.send_json({
        "job_id": job_id,
        "status": current.get("status", "unknown"),
        "latest_log": current.get("latest_log", ""),
        "live_mitm_console": current.get("live_mitm_console", []),
        "result": current.get("result"),
        "error": current.get("error"),
    })

    if current.get("status") in ["complete", "error"]:
        await websocket.close()
        return

    last_log_count = len(current.get("live_mitm_console", []))

    try:
        while True:
            await asyncio.sleep(0.4)
            if job_id not in job_status:
                continue

            current = job_status[job_id]
            current_logs = current.get("live_mitm_console", [])
            status = current.get("status", "unknown")

            # Stream updates if new telemetry lines arrive or analysis reaches a terminal state
            if len(current_logs) > last_log_count or status in ["complete", "error"]:
                last_log_count = len(current_logs)
                await websocket.send_json({
                    "job_id": job_id,
                    "status": status,
                    "latest_log": current.get("latest_log", ""),
                    "live_mitm_console": current_logs,
                    "result": current.get("result"),
                    "error": current.get("error"),
                })

            if status in ["complete", "error"]:
                await websocket.close()
                break

    except WebSocketDisconnect:
        pass


@app.get("/result/{job_id}")
def get_result(job_id: str):
    if job_id not in job_status:
        return {"error": "Job ID not found"}
    return job_status[job_id]