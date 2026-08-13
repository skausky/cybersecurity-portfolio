import asyncio
import json
from typing import Set

from fastapi import WebSocket, WebSocketDisconnect


class EventHub:
    def __init__(self):
        self._clients: Set[WebSocket] = set()
        self._queue: asyncio.Queue | None = None

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._queue = asyncio.Queue()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._clients.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self._clients.discard(ws)

    def publish_sync(self, message: dict) -> None:
        if not self._queue:
            return
        try:
            self._queue.put_nowait(message)
        except asyncio.QueueFull:
            pass

    async def broadcaster(self) -> None:
        while True:
            if not self._queue:
                await asyncio.sleep(0.1)
                continue
            msg = await self._queue.get()
            dead = []
            data = json.dumps(msg)
            for ws in list(self._clients):
                try:
                    await ws.send_text(data)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                self.disconnect(ws)


async def websocket_endpoint(ws: WebSocket, hub: EventHub):
    await hub.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        hub.disconnect(ws)