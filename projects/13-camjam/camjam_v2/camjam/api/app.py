import asyncio
import secrets
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from camjam import config
from camjam.api.routes import api_router
from camjam.api.security import ServerBinding
from camjam.api.ws import EventHub
from camjam.engine.session import AppSession

STATIC = config.WEB_DIR
_bearer = HTTPBearer(auto_error=False)


def create_app(binding: ServerBinding) -> FastAPI:
    hub = EventHub()

    def broadcast(msg: dict) -> None:
        hub.publish_sync(msg)

    app_session = AppSession(broadcast=broadcast)

    async def verify_token(
        credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
        token: str | None = Query(default=None),
    ) -> None:
        provided = credentials.credentials if credentials else token
        if not provided or not secrets.compare_digest(provided, binding.token):
            raise HTTPException(status_code=401, detail="Invalid or missing token")

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        hub.set_loop(asyncio.get_running_loop())
        task = asyncio.create_task(hub.broadcaster())
        yield
        task.cancel()
        app_session.shutdown()

    app = FastAPI(title="CamJam", version="2.0.0", lifespan=lifespan)
    app.state.session = app_session
    app.state.binding = binding
    app.state.hub = hub

    STATIC.mkdir(parents=True, exist_ok=True)
    if STATIC.exists():
        app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.get("/config.json")
    async def client_config():
        return JSONResponse({"token": binding.token, "version": "2.0.0"})

    @app.get("/")
    async def index():
        index_path = STATIC / "index.html"
        if index_path.exists():
            return FileResponse(index_path)
        return JSONResponse({"message": "CamJam API", "url": binding.url})

    app.include_router(api_router, dependencies=[Depends(verify_token)])

    @app.websocket("/ws")
    async def ws_endpoint(websocket: WebSocket, token: str | None = Query(default=None)):
        if not token or not secrets.compare_digest(token, binding.token):
            await websocket.close(code=1008)
            return
        await hub.connect(websocket)
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            hub.disconnect(websocket)

    return app