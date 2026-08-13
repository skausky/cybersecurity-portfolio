from fastapi import APIRouter, HTTPException, Request

from camjam.store.models import DeviceLabelRequest

router = APIRouter(tags=["devices"])


def _db(request: Request):
    return request.app.state.session.db


@router.get("/devices")
async def list_devices(request: Request):
    devices = await _db(request).list_devices_enriched()
    return {"devices": devices, "count": len(devices)}


@router.put("/devices/{mac}/label")
async def set_label(mac: str, body: DeviceLabelRequest, request: Request):
    await _db(request).upsert_device_label(mac, body.label, body.notes, body.color, body.watch)
    return {"ok": True, "mac": mac}


@router.delete("/devices/{mac}/label")
async def clear_label(mac: str, request: Request):
    await _db(request).delete_device_label(mac)
    return {"ok": True, "mac": mac}


@router.get("/devices/{mac}/power")
async def device_power_history(mac: str, request: Request, hours: int = 24):
    points = await _db(request).ap_power_history(mac, hours)
    return {"mac": mac, "points": points}
