"""
AI Bug Hunting Agent - FastAPI Backend
Entry point with REST API + WebSocket endpoints
"""

import asyncio
import json
import uuid
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from dotenv import load_dotenv

from models.scan_request import ScanRequest
from models.scan_result import ScanSession, ScanStatus
from agent.orchestrator import ScanOrchestrator

load_dotenv()

app = FastAPI(
    title="AI Bug Hunting Agent",
    description="Automated bug bounty hunting agent with AI triage",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory scan session store
active_sessions: dict[str, ScanSession] = {}
active_orchestrators: dict[str, ScanOrchestrator] = {}

# ─────────────────────────────────────────────
# REST Endpoints
# ─────────────────────────────────────────────

@app.get("/api/providers")
async def get_providers():
    """Return list of available AI providers and their configured status."""
    import os
    providers = [
        {"id": "gemini",  "name": "Google Gemini",  "configured": bool(os.getenv("GEMINI_API_KEY"))},
        {"id": "groq",    "name": "Groq",            "configured": bool(os.getenv("GROQ_API_KEY") or os.getenv("GROK_API_KEY"))},
        {"id": "grok",    "name": "xAI Grok",        "configured": bool(os.getenv("GROK_API_KEY") or os.getenv("GROQ_API_KEY"))},
    ]
    return {"providers": providers}


@app.post("/api/scan/start")
async def start_scan(request: ScanRequest):
    """Start a new bug hunting scan session."""
    scan_id = str(uuid.uuid4())
    session = ScanSession(
        scan_id=scan_id,
        target=request.target,
        status=ScanStatus.PENDING,
        provider=request.provider,
    )
    active_sessions[scan_id] = session
    return {"scan_id": scan_id, "status": "pending"}


@app.get("/api/scan/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """Poll the status of a running scan."""
    session = active_sessions.get(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail="Scan session not found")
    return session.model_dump()


@app.post("/api/scan/{scan_id}/stop")
async def stop_scan(scan_id: str):
    """Stop a running scan."""
    orch = active_orchestrators.get(scan_id)
    if orch:
        orch.stop()
    session = active_sessions.get(scan_id)
    if session:
        session.status = ScanStatus.STOPPED
    return {"status": "stopped"}


@app.get("/api/scan/{scan_id}/report")
async def get_report(scan_id: str):
    """Get the final report for a completed scan."""
    session = active_sessions.get(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"scan_id": scan_id, "findings": [f.model_dump() for f in session.findings]}


# ─────────────────────────────────────────────
# WebSocket Endpoint
# ─────────────────────────────────────────────

@app.websocket("/ws/scan/{scan_id}")
async def websocket_scan(websocket: WebSocket, scan_id: str):
    """
    WebSocket endpoint that streams real-time scan progress.
    Expects an initial JSON message with the ScanRequest payload.
    """
    await websocket.accept()

    try:
        # Receive scan configuration
        raw = await websocket.receive_text()
        data = json.loads(raw)
        request = ScanRequest(**data)

        session = active_sessions.get(scan_id)
        if not session:
            await websocket.send_json({"type": "error", "message": "Invalid scan_id"})
            return

        session.status = ScanStatus.RUNNING

        async def emit(event: dict):
            """Send event to the frontend. Ignore closed connections."""
            try:
                await websocket.send_json(event)
            except Exception:
                pass

        orchestrator = ScanOrchestrator(request, session, emit)
        active_orchestrators[scan_id] = orchestrator

        await orchestrator.run()

        session.status = ScanStatus.COMPLETE
        await emit({"type": "complete", "scan_id": scan_id, "total_findings": len(session.findings)})

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        try:
            await websocket.send_json({"type": "error", "message": str(exc)})
        except Exception:
            pass
    finally:
        active_orchestrators.pop(scan_id, None)


# ─────────────────────────────────────────────
# Static Files (Frontend)
# ─────────────────────────────────────────────

frontend_path = Path(__file__).parent.parent / "frontend"
if frontend_path.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_path)), name="static")

    @app.get("/")
    async def serve_frontend():
        return FileResponse(str(frontend_path / "index.html"))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
