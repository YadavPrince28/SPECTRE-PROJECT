from fastapi import FastAPI, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import uuid, asyncio, os, shutil

app = FastAPI(title='SPECTRE API', version='1.0.0')


app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_methods=['*'],
    allow_headers=['*']
)

# Temporary storage for job status
job_status = {}

@app.get('/')
def root():
    return {'message': 'SPECTRE API is running', 'status': 'ok'}

@app.post('/analyze')
async def analyze(file: UploadFile = File(...)):
    # Generate unique job ID
    job_id = str(uuid.uuid4())[:8]
    
    # Save uploaded APK to disk
    apk_path = f'D:/spectre_boi_project/data/uploads/{job_id}_{file.filename}'
    os.makedirs('D:/spectre_boi_project/data/uploads', exist_ok=True)
    
    with open(apk_path, 'wb') as f:
        shutil.copyfileobj(file.file, f)
    
    # Store initial job status
    job_status[job_id] = {
        'status': 'queued',
        'filename': file.filename,
        'apk_path': apk_path,
        'result': None
    }
    
    return {
        'job_id': job_id,
        'status': 'queued',
        'filename': file.filename,
        'message': 'APK received. Connect to /status/{job_id} for updates.'
    }

@app.websocket('/status/{job_id}')
async def status(websocket: WebSocket, job_id: str):
    await websocket.accept()
    
    try:
        if job_id not in job_status:
            await websocket.send_json({'error': 'Job ID not found'})
            await websocket.close()
            return
        
        # Simulate pipeline stages (real calls added in Week 2-7)
        stages = [
            'APK received...',
            'Module 1: Static Analysis running...',
            'Module 2: Behavioral DNA running...',
            'Module 3: Dynamic Analysis running...',
            'Module 4: Social Engineering Extractor running...',
            'Module 5: GenAI Intelligence running...',
            'Analysis complete!'
        ]
        
        for stage in stages:
            job_status[job_id]['status'] = stage
            await websocket.send_json({
                'job_id': job_id,
                'status': stage,
                'result': job_status[job_id]['result']
            })
            await asyncio.sleep(1)
            
    except WebSocketDisconnect:
        print(f'Client disconnected from job {job_id}')

@app.get('/result/{job_id}')
def get_result(job_id: str):
    if job_id not in job_status:
        return {'error': 'Job ID not found'}
    return job_status[job_id]

@app.get('/health')
def health():
    return {'status': 'healthy', 'version': '1.0.0'}