import time

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

router = APIRouter(tags=["intel"])


def _db(request: Request):
    return request.app.state.session.db


@router.get("/intel/probes")
async def probe_summary(request: Request):
    return await _db(request).probe_summary()


@router.get("/intel/probes/{ssid}")
async def clients_probing(ssid: str, request: Request):
    clients = await _db(request).clients_probing_ssid(ssid)
    return {"ssid": ssid, "clients": clients}


@router.get("/intel/rogues")
async def list_rogues(request: Request):
    rogues = await _db(request).list_rogue_alerts()
    return {"rogues": rogues, "count": len(rogues)}


@router.post("/intel/rogues/{alert_id}/dismiss")
async def dismiss_rogue(alert_id: int, request: Request):
    await _db(request).dismiss_rogue_alert(alert_id)
    return {"ok": True}


@router.get("/history/sessions")
async def list_sessions(request: Request):
    sessions = await _db(request).list_sessions()
    return {"sessions": sessions}


@router.get("/history/aps/{bssid}/power")
async def ap_power_history(bssid: str, request: Request, hours: int = 24):
    points = await _db(request).ap_power_history(bssid, hours)
    return {"bssid": bssid, "hours": hours, "points": points}


@router.get("/export/csv")
async def export_csv(request: Request, what: str = "aps"):
    if what not in ("aps", "clients", "events"):
        raise HTTPException(status_code=400, detail="what must be aps, clients, or events")
    csv_data = await _db(request).export_csv(what)
    filename = f"camjam_{what}_{int(time.time())}.csv"
    return StreamingResponse(
        iter([csv_data]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/export/json")
async def export_json(request: Request):
    data = await _db(request).export_json()
    return JSONResponse(content=data)
