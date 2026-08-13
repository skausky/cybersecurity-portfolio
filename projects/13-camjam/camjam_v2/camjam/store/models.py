from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class DeauthMode(str, Enum):
    ap_broadcast = "ap_broadcast"
    all_clients = "all_clients"
    selected_clients = "selected_clients"


class DeauthTarget(BaseModel):
    bssid: str
    ssid: Optional[str] = None
    channel: int
    mode: DeauthMode = DeauthMode.all_clients
    client_macs: List[str] = Field(default_factory=list)


class DeauthStartRequest(BaseModel):
    targets: List[DeauthTarget]
    packets: int = 3
    loop: bool = False
    duration_seconds: int = 0


class InterfaceSelect(BaseModel):
    interface: str


class ScanRequest(BaseModel):
    band: str = "abg"
    duration: int = 20


class DeviceLabelRequest(BaseModel):
    label: str
    notes: Optional[str] = None
    color: str = "#5b9dff"
    watch: bool = False


class PresenceWatchRequest(BaseModel):
    interval: int = 120
    bssids: List[str] = Field(default_factory=list)


class TargetsUpdate(BaseModel):
    targets: List[str] = Field(default_factory=list)