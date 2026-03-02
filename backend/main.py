"""
IoT Security Appliance - Main Backend Server
Production-ready FastAPI application for home network IoT security monitoring
"""

import asyncio
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from scanner import NetworkScanner
from profiler import DeviceProfiler
from ai_agent import IoTSecurityAgent
from risk_engine import RiskEngine
from database import DeviceDatabase
from shodan_enricher import ShodanEnricher

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("iot-security")

# ─────────────────────────────────────────────
# Global State
# ─────────────────────────────────────────────
class AppState:
    scanner: Optional[NetworkScanner] = None
    profiler: Optional[DeviceProfiler] = None
    ai_agent: Optional[IoTSecurityAgent] = None
    risk_engine: Optional[RiskEngine] = None
    db: Optional[DeviceDatabase] = None
    shodan: Optional[ShodanEnricher] = None
    scan_task: Optional[asyncio.Task] = None
    connected_clients: List[WebSocket] = []
    last_scan_time: Optional[float] = None
    scanning: bool = False

app_state = AppState()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize and cleanup resources"""
    logger.info("🚀 Starting IoT Security Appliance...")

    app_state.db = DeviceDatabase()
    await app_state.db.initialize()

    app_state.scanner = NetworkScanner()
    app_state.profiler = DeviceProfiler()
    app_state.risk_engine = RiskEngine()
    app_state.shodan = ShodanEnricher()
    app_state.ai_agent = IoTSecurityAgent(
        api_key=os.getenv("GROQ_API_KEY"),
        model=os.getenv("GROQ_MODEL", "llama3-70b-8192")
    )

    # Start continuous background scanning
    app_state.scan_task = asyncio.create_task(continuous_scan_loop())
    logger.info("✅ IoT Security Appliance started successfully")

    yield

    # Cleanup
    if app_state.scan_task:
        app_state.scan_task.cancel()
    logger.info("👋 IoT Security Appliance shutting down")


app = FastAPI(
    title="IoT Security Appliance",
    description="AI-powered home network IoT security monitoring system",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend static files
frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.exists(frontend_path):
    app.mount("/static", StaticFiles(directory=frontend_path), name="static")


# ─────────────────────────────────────────────
# Pydantic Models
# ─────────────────────────────────────────────
class ScanRequest(BaseModel):
    network_range: Optional[str] = None
    aggressive: bool = False

class DeviceActionRequest(BaseModel):
    device_ip: str
    action: str  # "isolate" | "analyze" | "ignore"

class AlertAckRequest(BaseModel):
    alert_id: str


# ─────────────────────────────────────────────
# Background Scan Loop
# ─────────────────────────────────────────────
async def continuous_scan_loop():
    """Continuously scan the network every N seconds"""
    interval = int(os.getenv("SCAN_INTERVAL_SECONDS", "120"))
    logger.info(f"🔄 Continuous scan loop started (interval: {interval}s)")

    while True:
        try:
            await run_full_scan()
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Scan loop error: {e}")
            await asyncio.sleep(30)


async def run_full_scan(network_range: str = None):
    """Execute complete scan-profile-analyze pipeline"""
    if app_state.scanning:
        logger.warning("Scan already in progress, skipping")
        return

    app_state.scanning = True
    scan_start = time.time()

    try:
        # Step 1: Discover devices
        logger.info("📡 Starting network discovery...")
        await broadcast_event("scan_started", {"timestamp": datetime.now().isoformat()})

        network = network_range or os.getenv("NETWORK_RANGE", "auto")
        raw_devices = await asyncio.get_event_loop().run_in_executor(
            None, app_state.scanner.discover_devices, network
        )
        logger.info(f"Found {len(raw_devices)} devices")

        # Step 2: Profile each device
        logger.info("🔍 Profiling devices...")
        profiled_devices = []
        for device in raw_devices:
            try:
                profile = await asyncio.get_event_loop().run_in_executor(
                    None, app_state.profiler.profile_device, device
                )
                profiled_devices.append(profile)
                await broadcast_event("device_profiled", {"device": profile})
            except Exception as e:
                logger.warning(f"Profile failed for {device.get('ip')}: {e}")
                profiled_devices.append(device)

        # Step 3: Shodan enrichment (public IPs only, free, no key needed)
        logger.info("🔍 Running Shodan InternetDB enrichment...")
        shodan_results = await app_state.shodan.enrich_devices_batch(profiled_devices)
        for device in profiled_devices:
            ip = device.get("ip")
            if ip in shodan_results:
                device["shodan"] = shodan_results[ip]

        # Step 4: AI risk analysis (now includes Shodan context)
        logger.info("🤖 Running AI risk analysis...")
        risk_results = await app_state.ai_agent.analyze_devices(profiled_devices)

        # Step 5: Compute risk scores
        for device in profiled_devices:
            ip = device.get("ip")
            ai_analysis = risk_results.get(ip, {})
            risk_data = app_state.risk_engine.compute_risk_score(device, ai_analysis)
            device.update(risk_data)

        # Step 6: Persist and broadcast
        for device in profiled_devices:
            await app_state.db.upsert_device(device)

        scan_duration = round(time.time() - scan_start, 2)
        app_state.last_scan_time = time.time()

        summary = build_scan_summary(profiled_devices, scan_duration)
        await broadcast_event("scan_complete", summary)

        logger.info(f"✅ Scan complete: {len(profiled_devices)} devices in {scan_duration}s")
        return profiled_devices

    except Exception as e:
        logger.error(f"Scan pipeline error: {e}", exc_info=True)
        await broadcast_event("scan_error", {"error": str(e)})
        raise
    finally:
        app_state.scanning = False


def build_scan_summary(devices: List[Dict], duration: float) -> Dict:
    risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for d in devices:
        level = d.get("risk_level", "low")
        risk_counts[level] = risk_counts.get(level, 0) + 1

    return {
        "timestamp": datetime.now().isoformat(),
        "total_devices": len(devices),
        "risk_distribution": risk_counts,
        "scan_duration_seconds": duration,
        "devices": devices
    }


# ─────────────────────────────────────────────
# WebSocket Manager
# ─────────────────────────────────────────────
async def broadcast_event(event_type: str, data: Any):
    """Broadcast event to all connected WebSocket clients"""
    if not app_state.connected_clients:
        return

    message = json.dumps({
        "event": event_type,
        "timestamp": datetime.now().isoformat(),
        "data": data
    })

    disconnected = []
    for ws in app_state.connected_clients:
        try:
            await ws.send_text(message)
        except Exception:
            disconnected.append(ws)

    for ws in disconnected:
        app_state.connected_clients.remove(ws)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    app_state.connected_clients.append(websocket)
    logger.info(f"WebSocket client connected ({len(app_state.connected_clients)} total)")

    try:
        # Send current state on connect
        devices = await app_state.db.get_all_devices()
        await websocket.send_text(json.dumps({
            "event": "initial_state",
            "timestamp": datetime.now().isoformat(),
            "data": {
                "devices": devices,
                "scanning": app_state.scanning,
                "last_scan": app_state.last_scan_time
            }
        }))

        while True:
            try:
                msg = await asyncio.wait_for(websocket.receive_text(), timeout=30)
                await handle_ws_message(websocket, json.loads(msg))
            except asyncio.TimeoutError:
                await websocket.send_text(json.dumps({"event": "ping"}))

    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        if websocket in app_state.connected_clients:
            app_state.connected_clients.remove(websocket)


async def handle_ws_message(ws: WebSocket, msg: Dict):
    """Handle incoming WebSocket messages"""
    action = msg.get("action")
    if action == "ping":
        await ws.send_text(json.dumps({"event": "pong"}))
    elif action == "request_scan":
        asyncio.create_task(run_full_scan(msg.get("network_range")))


# ─────────────────────────────────────────────
# REST API Endpoints
# ─────────────────────────────────────────────
@app.get("/")
async def root():
    index_path = os.path.join(frontend_path, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"status": "running", "service": "IoT Security Appliance API v1.0"}


@app.get("/api/health")
async def health():
    return {
        "status": "healthy",
        "scanning": app_state.scanning,
        "last_scan": app_state.last_scan_time,
        "connected_clients": len(app_state.connected_clients),
        "timestamp": datetime.now().isoformat()
    }


@app.get("/api/devices")
async def get_devices(risk_level: Optional[str] = None, device_type: Optional[str] = None):
    devices = await app_state.db.get_all_devices()
    if risk_level:
        devices = [d for d in devices if d.get("risk_level") == risk_level]
    if device_type:
        devices = [d for d in devices if d.get("device_type") == device_type]
    return {"devices": devices, "total": len(devices)}


@app.get("/api/devices/{ip}")
async def get_device(ip: str):
    device = await app_state.db.get_device(ip.replace("-", "."))
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


@app.post("/api/scan")
async def trigger_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    if app_state.scanning:
        return JSONResponse(status_code=409, content={"message": "Scan already in progress"})
    background_tasks.add_task(run_full_scan, req.network_range)
    return {"message": "Scan started", "timestamp": datetime.now().isoformat()}


@app.post("/api/devices/action")
async def device_action(req: DeviceActionRequest):
    device = await app_state.db.get_device(req.device_ip)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    if req.action == "analyze":
        analysis = await app_state.ai_agent.deep_analyze_device(device)
        await app_state.db.update_device(req.device_ip, {"deep_analysis": analysis})
        return {"status": "analyzed", "analysis": analysis}
    elif req.action in ("isolate", "ignore"):
        await app_state.db.update_device(req.device_ip, {"status": req.action})
        await broadcast_event("device_status_changed", {"ip": req.device_ip, "status": req.action})
        return {"status": f"Device marked as {req.action}"}

    raise HTTPException(status_code=400, detail=f"Unknown action: {req.action}")


@app.get("/api/alerts")
async def get_alerts(unread_only: bool = False):
    alerts = await app_state.db.get_alerts(unread_only=unread_only)
    return {"alerts": alerts, "total": len(alerts)}


@app.post("/api/alerts/ack")
async def acknowledge_alert(req: AlertAckRequest):
    await app_state.db.acknowledge_alert(req.alert_id)
    return {"status": "acknowledged"}


@app.get("/api/stats")
async def get_stats():
    devices = await app_state.db.get_all_devices()
    alerts = await app_state.db.get_alerts(unread_only=True)

    risk_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    device_types = {}
    avg_risk_score = 0

    for d in devices:
        lvl = d.get("risk_level", "low")
        risk_dist[lvl] = risk_dist.get(lvl, 0) + 1
        dtype = d.get("device_type", "unknown")
        device_types[dtype] = device_types.get(dtype, 0) + 1
        avg_risk_score += d.get("risk_score", 0)

    if devices:
        avg_risk_score = round(avg_risk_score / len(devices), 1)

    return {
        "total_devices": len(devices),
        "risk_distribution": risk_dist,
        "device_types": device_types,
        "unread_alerts": len(alerts),
        "avg_risk_score": avg_risk_score,
        "scanning": app_state.scanning,
        "last_scan": app_state.last_scan_time
    }


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
        reload=os.getenv("DEV", "false").lower() == "true",
        log_level="info"
    )
