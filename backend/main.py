from fastapi import FastAPI, UploadFile, File, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
import uuid, asyncio, os, shutil
from datetime import datetime

import logging
logging.getLogger('androguard').setLevel(logging.ERROR)

from pipeline import run_pipeline


app = FastAPI(
    title='SPECTRE API', 
    version='1.0.0',
    description="Android APK Fraud Intelligence Platform"   
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*']
)


job_status = {}

@app.get('/')
def root():
    return {
        'message': 'SPECTRE API is running', 
        'status': 'ok',
        'version': '1.0.0'
    }

@app.get('/health')
def health():
    return {'status': 'healthy', 'version': '1.0.0'}



@app.post('/analyze')
async def analyze(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...)
):
    
    job_id = str(uuid.uuid4())[:8]
    
    upload_dir = "D:/Spectre_BOI_project/SPECTRE/data/uploads"
    os.makedirs(upload_dir, exist_ok=True)

    apk_path = f"{upload_dir}/{job_id}_{file.filename}"
    
    with open(apk_path, 'wb') as f_out:
        shutil.copyfileobj(file.file, f_out)
    

    job_status[job_id] = {
        'status': 'queued',
        'filename': file.filename,
        'apk_path': apk_path,
        'created_at': datetime.now().isoformat(),
        'result': None
    }
    
    background_tasks.add_task(run_analysis_background, job_id, apk_path)

    return {
        'job_id': job_id,
        'status': 'queued',
        'filename': file.filename,
        'message': f'Analysis started. Connect to /status/{job_id} for live updates.'
    }

async def run_analysis_background(job_id: str, apk_path: str):
    try:
        job_status[job_id]["status"] = "running"
        result = run_pipeline(apk_path, job_id)

        job_status[job_id]["status"] = "complete"
        job_status[job_id]["result"] = result
    
    except Exception as e:
        job_status[job_id]["status"] = "error"
        job_status[job_id]["error"] = str(e)

        print(f"[ERROR] Pipeline failed for job {job_id}: {e}")

@app.websocket('/status/{job_id}')
async def websocket_status(websocket: WebSocket, job_id: str):
    await websocket.accept()
    
    try:
        if job_id not in job_status:
            await websocket.send_json({'error': 'Job ID not found'})
            await websocket.close()
            return
        while True:
            current = job_status.get(job_id, {})

            await websocket.send_json({
                "job_id": job_id,
                "status": current.get("status", "unknown"),
                "result": current.get("result"),
                "error": current.get("error")
            })

            if current.get("status") in ["complete", "error"]:
                break

            await asyncio.sleep(2)

    except WebSocketDisconnect:
        print(f"[INFO] Client disconnected from job {job_id}")
        

@app.get('/result/{job_id}')
def get_result(job_id: str):
    if job_id not in job_status:
        return {'error': 'Job ID not found'}
    return job_status[job_id]

