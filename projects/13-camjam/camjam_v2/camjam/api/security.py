import secrets
import socket
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Query, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_bearer = HTTPBearer(auto_error=False)


@dataclass
class ServerBinding:
    host: str
    port: int
    token: str

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}/?token={self.token}"


def create_binding(host: str = "127.0.0.1") -> ServerBinding:
    token = secrets.token_urlsafe(32)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, 0))
    port = sock.getsockname()[1]
    sock.close()
    return ServerBinding(host=host, port=port, token=token)


def make_auth_dependency(expected_token: str):
    async def verify(
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
        token: str | None = Query(default=None),
    ) -> None:
        if request.url.path in ("/", "/index.html", "/static/app.css", "/static/app.js", "/config.json"):
            return
        provided = None
        if credentials:
            provided = credentials.credentials
        elif token:
            provided = token
        if not provided or not secrets.compare_digest(provided, expected_token):
            raise HTTPException(status_code=401, detail="Invalid or missing token")

    return verify