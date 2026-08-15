"""Validated domain models used by the CLI, API, database, and renderer."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from ipaddress import ip_address, ip_network
from typing import Any
from uuid import uuid4


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class Direction(StrEnum):
    INPUT = "input"
    FORWARD = "forward"
    OUTPUT = "output"


class Action(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"


class Protocol(StrEnum):
    ANY = "any"
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"


PORT_PATTERN = re.compile(r"^(\d{1,5})(?:-(\d{1,5}))?$")


def normalize_network(value: str | None) -> str | None:
    if value is None or not str(value).strip() or str(value).lower() == "any":
        return None
    try:
        return str(ip_network(str(value).strip(), strict=False))
    except ValueError as exc:
        raise ValueError(f"Invalid network or host: {value}") from exc


def normalize_port(value: str | int | None) -> str | None:
    if value is None or str(value).strip().lower() in {"", "any"}:
        return None
    text = str(value).strip()
    match = PORT_PATTERN.fullmatch(text)
    if not match:
        raise ValueError(f"Invalid port or port range: {value}")
    start = int(match.group(1))
    end = int(match.group(2) or start)
    if not 1 <= start <= 65535 or not 1 <= end <= 65535 or start > end:
        raise ValueError(f"Invalid port or port range: {value}")
    return str(start) if start == end else f"{start}-{end}"


@dataclass(slots=True)
class Rule:
    name: str
    direction: Direction
    action: Action
    protocol: Protocol = Protocol.ANY
    source: str | None = None
    destination: str | None = None
    source_port: str | None = None
    destination_port: str | None = None
    log: bool = True
    enabled: bool = True
    priority: int = 500
    id: str = field(default_factory=lambda: str(uuid4()))
    created_at: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        self.name = str(self.name).strip()
        if not self.name or len(self.name) > 80:
            raise ValueError("Rule name must contain 1 to 80 characters")
        self.direction = Direction(self.direction)
        self.action = Action(self.action)
        self.protocol = Protocol(self.protocol)
        self.source = normalize_network(self.source)
        self.destination = normalize_network(self.destination)
        self.source_port = normalize_port(self.source_port)
        self.destination_port = normalize_port(self.destination_port)
        self.priority = int(self.priority)
        if not 1 <= self.priority <= 10_000:
            raise ValueError("Priority must be between 1 and 10000")
        if (self.source_port or self.destination_port) and self.protocol not in {
            Protocol.TCP,
            Protocol.UDP,
        }:
            raise ValueError("Ports can only be used with TCP or UDP rules")
        networks = [ip_network(value) for value in (self.source, self.destination) if value]
        if len({network.version for network in networks}) > 1:
            raise ValueError("Source and destination must use the same IP family")
        try:
            parsed_id = str(uuid4()) if not self.id else str(self.id)
            if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", parsed_id):
                raise ValueError
            self.id = parsed_id
        except (TypeError, ValueError) as exc:
            raise ValueError("Rule id contains unsupported characters") from exc

    @property
    def ip_version(self) -> int | None:
        value = self.source or self.destination
        return ip_network(value).version if value else None

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["direction"] = self.direction.value
        result["action"] = self.action.value
        result["protocol"] = self.protocol.value
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Rule:
        allowed = {item.name for item in cls.__dataclass_fields__.values()}
        return cls(**{key: value for key, value in data.items() if key in allowed})


@dataclass(slots=True)
class Event:
    event_type: str
    severity: str
    action: str
    source_ip: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    protocol: str | None = None
    rule_id: str | None = None
    raw: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    occurred_at: str = field(default_factory=utc_now)
    id: int | None = None

    def __post_init__(self) -> None:
        if self.severity not in {"info", "low", "medium", "high", "critical"}:
            raise ValueError("Unsupported event severity")
        for value in (self.source_ip, self.destination_ip):
            if value:
                ip_address(value)
        if self.destination_port is not None and not 1 <= int(self.destination_port) <= 65535:
            raise ValueError("Invalid destination port")
        if self.destination_port is not None:
            self.destination_port = int(self.destination_port)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Ban:
    ip: str
    reason: str
    created_at: str
    expires_at: str
    active: bool = True

    def __post_init__(self) -> None:
        self.ip = str(ip_address(self.ip))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

