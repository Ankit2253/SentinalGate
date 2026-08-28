"""FastAPI control plane and local dashboard."""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from sentinelgate.demo import seed_demo
from sentinelgate.models import Action, Direction, Protocol
from sentinelgate.nftables import NftablesError
from sentinelgate.service import FirewallService


class RuleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    direction: Direction
    action: Action
    protocol: Protocol = Protocol.ANY
    source: str | None = None
    destination: str | None = None
    source_port: str | int | None = None
    destination_port: str | int | None = None
    log: bool = True
    enabled: bool = True
    priority: int = Field(default=500, ge=1, le=10_000)


class RulePatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=80)
    direction: Direction | None = None
    action: Action | None = None
    protocol: Protocol | None = None
    source: str | None = None
    destination: str | None = None
    source_port: str | int | None = None
    destination_port: str | int | None = None
    log: bool | None = None
    enabled: bool | None = None
    priority: int | None = Field(default=None, ge=1, le=10_000)


class ApplyRequest(BaseModel):
    confirmation: str = ""
    reason: str = Field(default="Dashboard apply", max_length=200)


class RollbackRequest(BaseModel):
    confirmation: str = ""


class BanRequest(BaseModel):
    address: str
    reason: str = Field(default="Manual dashboard ban", min_length=1, max_length=200)
    seconds: int | None = Field(default=None, ge=30, le=604_800)

class C2ResponseRequest(BaseModel):
    reason: str = "Analyst-approved C2 response"
    seconds: int | None = None

def create_app(service: FirewallService) -> FastAPI:
    app = FastAPI(
        title="SentinelGate API",
        version="1.0.0",
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
        )
        response.headers["Cache-Control"] = "no-store"
        return response
    @app.get("/api/c2/status")
    def c2_status() -> dict[str, Any]:
        return service.c2_status()
    @app.get("/api/c2/alerts")
    def c2_alerts(limit: int = 50) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 250))

        events = [
            event
            for event in service.database.list_events(limit=1000)
            if event.event_type == "suspected_c2_beacon"
        ]

        return [event.to_dict() for event in events[:limit]]
    def require_auth(authorization: str | None = Header(default=None)) -> None:
        expected = service.config.server.admin_token
        if not expected:
            return
        prefix = "Bearer "
        supplied = authorization[len(prefix) :] if authorization and authorization.startswith(prefix) else ""
        if not supplied or not secrets.compare_digest(supplied, expected):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="A valid bearer token is required",
                headers={"WWW-Authenticate": "Bearer"},
            )

    router = APIRouter(prefix="/api", dependencies=[Depends(require_auth)])

    @router.get("/status")
    def get_status() -> dict[str, Any]:
        return service.status()

    @router.get("/stats")
    def get_stats() -> dict[str, Any]:
        return service.database.event_stats()

    @router.get("/rules")
    def get_rules() -> list[dict[str, Any]]:
        return [rule.to_dict() for rule in service.database.list_rules()]

    @router.post("/rules", status_code=status.HTTP_201_CREATED)
    def create_rule(payload: RuleCreate) -> dict[str, Any]:
        try:
            return service.add_rule(payload.model_dump()).to_dict()
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @router.patch("/rules/{rule_id}")
    def update_rule(rule_id: str, payload: RulePatch) -> dict[str, Any]:
        try:
            values = payload.model_dump(exclude_unset=True)
            return service.update_rule(rule_id, values).to_dict()
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
    def delete_rule(rule_id: str) -> None:
        if not service.delete_rule(rule_id):
            raise HTTPException(status_code=404, detail="Rule not found")
    @router.post("/c2/alerts/{event_id}/block")
    def block_c2_alert(
        event_id: int,
        payload: C2ResponseRequest,
    ) -> dict[str, Any]:
        try:
            return service.respond_to_c2_alert(
                event_id,
                reason=payload.reason,
                seconds=payload.seconds,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except NftablesError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
    @router.post("/apply")
    def apply_rules(payload: ApplyRequest) -> dict[str, Any]:
        confirmed = payload.confirmation == "APPLY"
        try:
            return service.apply(reason=payload.reason, confirmed=confirmed)
        except PermissionError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except NftablesError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @router.get("/render", response_model=None)
    def render_rules() -> dict[str, str]:
        return {"ruleset": service.render()}

    @router.get("/events")
    def get_events(
        limit: int = Query(default=100, ge=1, le=1000),
        severity: Literal["info", "low", "medium", "high", "critical"] | None = None,
        source_ip: str | None = None,
    ) -> list[dict[str, Any]]:
        try:
            return [
                event.to_dict()
                for event in service.database.list_events(limit, severity, source_ip)
            ]
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @router.get("/bans")
    def get_bans() -> list[dict[str, Any]]:
        return [ban.to_dict() for ban in service.database.list_bans()]

    @router.post("/bans", status_code=status.HTTP_201_CREATED)
    def create_ban(payload: BanRequest) -> dict[str, Any]:
        try:
            return service.ban(payload.address, payload.reason, payload.seconds).to_dict()
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except NftablesError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @router.delete("/bans/{address}")
    def delete_ban(address: str) -> dict[str, bool]:
        try:
            return {"removed": service.unban(address)}
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except NftablesError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @router.get("/snapshots")
    def get_snapshots() -> list[dict[str, Any]]:
        return service.database.list_snapshots()

    @router.post("/snapshots/{snapshot_id}/rollback")
    def rollback(snapshot_id: int, payload: RollbackRequest) -> dict[str, Any]:
        try:
            return service.rollback(snapshot_id, confirmed=payload.confirmation == "ROLLBACK")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except NftablesError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @router.post("/demo/seed")
    def demo_seed() -> dict[str, int]:
        if service.config.firewall.mode != "dry-run":
            raise HTTPException(status_code=409, detail="Demo data is only available in dry-run mode")
        return seed_demo(service)

    app.include_router(router)

    static_directory = Path(__file__).resolve().parent / "static"
    app.mount("/assets", StaticFiles(directory=static_directory), name="assets")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/", response_class=FileResponse)
    def dashboard() -> FileResponse:
        return FileResponse(static_directory / "index.html")

    return app

