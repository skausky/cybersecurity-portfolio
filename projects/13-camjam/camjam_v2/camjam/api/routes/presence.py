from fastapi import APIRouter, Request

from camjam.store.models import PresenceWatchRequest

router = APIRouter(tags=["presence"])


def _session(request: Request):
    return request.app.state.session


def _db(request: Request):
    return request.app.state.session.db


@router.post("/presence/watch/start")
async def start_watch(body: PresenceWatchRequest, request: Request):
    s = _session(request)
    s.start_presence_watch(body.interval, body.bssids)
    watched = await _db(request).get_watched_macs()
    return {"watching": True, "interval": body.interval, "watched_count": len(watched)}


@router.post("/presence/watch/stop")
async def stop_watch(request: Request):
    _session(request).stop_presence_watch()
    return {"watching": False}


@router.get("/presence/state")
async def presence_state(request: Request):
    states = await _db(request).get_all_presence_states()
    return {"states": states}


@router.get("/presence/history/{mac}")
async def presence_history(mac: str, request: Request, limit: int = 100):
    history = await _db(request).get_presence_history(mac, limit)
    return {"mac": mac, "history": history}


@router.get("/presence/timeline/{mac}")
async def presence_timeline(mac: str, request: Request, hours: int = 24):
    timeline = await _db(request).get_presence_timeline(mac, hours)
    return {"mac": mac, "hours": hours, "timeline": timeline}
