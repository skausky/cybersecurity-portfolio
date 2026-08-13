from fastapi import APIRouter

from camjam.api.routes import control, devices, intel, presence, stats

api_router = APIRouter(prefix="/api")
api_router.include_router(control.router)
api_router.include_router(stats.router)
api_router.include_router(devices.router)
api_router.include_router(presence.router)
api_router.include_router(intel.router)
