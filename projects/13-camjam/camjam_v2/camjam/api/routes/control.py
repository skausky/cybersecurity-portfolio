from fastapi import APIRouter, HTTPException, Request

from camjam.radio.capabilities import probe_interface
from camjam.store.models import DeauthStartRequest, InterfaceSelect, ScanRequest, TargetsUpdate

router = APIRouter(tags=["control"])


def session(request: Request):
    return request.app.state.session


@router.get("/interfaces")
async def list_interfaces(request: Request):
    s = session(request)
    return {"interfaces": s.radio.list_wifi_interfaces()}


@router.get("/interface/{iface}/capabilities")
async def interface_capabilities(iface: str):
    return probe_interface(iface).to_dict()


@router.post("/interface")
async def select_interface(body: InterfaceSelect, request: Request):
    s = session(request)
    try:
        mon = s.setup_interface(body.interface)
        caps = probe_interface(mon)
        if caps.warnings:
            s.emit("radio:warning", {"capabilities": caps.to_dict()})
        return {
            "physical": body.interface,
            "monitor": mon,
            "capabilities": caps.to_dict(),
        }
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/status")
async def status(request: Request):
    s = session(request)
    return {
        "physical_iface": s.physical_iface,
        "monitor_iface": s.monitor_iface,
        "networks_cached": len(s.networks),
        "session_id": s.session_id,
    }


@router.get("/aps")
async def list_cached_aps(request: Request):
    s = session(request)
    aps = await s.db.list_aps()
    return {"count": len(aps), "networks": aps}


@router.get("/targets")
async def get_targets(request: Request):
    s = session(request)
    bssids = await s.db.get_selected_targets()
    return {"targets": bssids}


@router.put("/targets")
async def set_targets(body: TargetsUpdate, request: Request):
    s = session(request)
    await s.db.set_selected_targets(body.targets)
    return {"targets": body.targets}


@router.post("/scan")
async def scan(body: ScanRequest, request: Request):
    s = session(request)
    if not s.scanner:
        raise HTTPException(status_code=400, detail="Select interface first")
    nets = await s.scan_networks(body.band, body.duration)
    return {"count": len(nets), "networks": nets}


@router.post("/scan/clients/{bssid}")
async def scan_clients(bssid: str, request: Request):
    s = session(request)
    try:
        clients = await s.scan_clients_for(bssid)
        return {"bssid": bssid, "count": len(clients), "clients": clients}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/deauth/start")
async def deauth_start(body: DeauthStartRequest, request: Request):
    s = session(request)
    if not body.targets:
        raise HTTPException(status_code=400, detail="No targets selected")
    try:
        s.start_deauth(body.targets, packets=body.packets, loop=body.loop)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"started": True, "targets": len(body.targets)}


@router.post("/deauth/stop")
async def deauth_stop(request: Request):
    session(request).stop_deauth()
    return {"stopped": True}


@router.post("/scan/cancel")
async def scan_cancel(request: Request):
    s = session(request)
    cancel = getattr(s, "_scan_cancel", None)
    if cancel:
        cancel.set()
    return {"cancelled": True}