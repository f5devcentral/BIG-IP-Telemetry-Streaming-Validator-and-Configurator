"""FastAPI service: BIG-IP sessions, validation, AS3/TS remediation."""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from as3_services import build_as3_declaration
from bigip_ts_validator import (
    BigIPClient,
    BigIPError,
    ensure_extensions,
    ensure_modules_provisioned,
    modules_required_for_services,
    validate,
)
from ts_declaration_builder import build_ts_declaration, normalize_consumer_type

SESSION_TTL_SEC = 45 * 60
REPO_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class _Session:
    client: BigIPClient
    created: float


_sessions: dict[str, _Session] = {}


def _gc_sessions() -> None:
    now = time.time()
    for sid, s in list(_sessions.items()):
        if now - s.created > SESSION_TTL_SEC:
            _sessions.pop(sid, None)


def _get_session(session_id: str) -> _Session:
    _gc_sessions()
    s = _sessions.get(session_id)
    if not s:
        raise HTTPException(status_code=404, detail="Unknown or expired session")
    return s


def _json_safe_for_response(value: Any) -> Any:
    """Recursively coerce values so ``json.dumps`` / FastAPI response encoding cannot fail on odd BIG-IP payloads."""
    if isinstance(value, dict):
        return {str(k): _json_safe_for_response(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_safe_for_response(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", errors="replace")
    return str(value)


class ConnectBody(BaseModel):
    host: str = Field(..., description="BIG-IP management IP or hostname")
    username: str
    password: str
    verify_tls: bool = False


class ServicesBody(BaseModel):
    ltm: bool = False
    asm: bool = False
    afm: bool = False
    http_analytics: bool = False
    tcp_analytics: bool = False
    dns: bool = False


class ValidateBody(BaseModel):
    consumer: str
    services: ServicesBody
    include_system_poller: bool = Field(
        default=True,
        description="Expect TS System Poller in declaration (informational for validate)",
    )


class RemediateBody(BaseModel):
    consumer: str
    consumer_params: dict[str, Any] = Field(default_factory=dict)
    services: ServicesBody
    install_prereqs: bool = False
    apply_as3: bool = True
    post_ts: bool = True
    include_system_poller: bool = True
    as3_version: str | None = None
    ts_version: str | None = None
    provision_modules: bool = False
    provision_level: str = Field(default="nominal", description="TMOS provision level (usually nominal)")
    assume_yes: bool = True
    avr_log_publisher_fullpath: str | None = Field(
        default=None,
        description=(
            "Log_Publisher full path for AVR (F5 TS example: /Common/telemetry_publisher). "
            "During AS3 remediation the per-item analytics PATCH defaults to /Common/Shared/telemetry_publisher; "
            "the end-of-remediation TS+AVR collection PATCH uses this field or /Common/telemetry_publisher if unset. "
            "See https://clouddocs.f5.com/products/extensions/f5-telemetry-streaming/latest/avr.html#modifying-avr-configuration-to-use-the-log-publisher"
        ),
    )


class RollbackBody(BaseModel):
    confirm: bool = Field(
        default=False,
        description="Must be true to execute destructive rollback (safety latch)",
    )
    clear_ts: bool = Field(default=True, description="POST {class: Telemetry} to clear TS declaration")
    delete_as3_shared: bool = Field(
        default=True,
        description="DELETE AS3 Common/Shared application (telemetry pool, publisher, profiles, local listener)",
    )
    reset_sys_db_loopback: bool = Field(
        default=True,
        description="PUT tmm.tcl.rule.node.allow_loopback_addresses back to false",
    )
    reset_analytics_global_settings: bool = Field(
        default=True,
        description="PATCH analytics global-settings to disable off-box / HSL (AVR undo)",
    )
    save_sys_config_after: bool = Field(default=True, description="POST save sys config after rollback changes")


app = FastAPI(title="BIG-IP Telemetry Streaming helper", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/session")
def create_session(body: ConnectBody) -> dict[str, str]:
    _gc_sessions()
    try:
        client = BigIPClient(body.host, body.username, body.password, verify_tls=body.verify_tls)
    except BigIPError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    sid = secrets.token_urlsafe(24)
    _sessions[sid] = _Session(client=client, created=time.time())
    return {"session_id": sid, "host": body.host}


@app.post("/api/session/{session_id}/validate")
def session_validate(session_id: str, body: ValidateBody) -> dict[str, Any]:
    s = _get_session(session_id)
    svc = body.services.model_dump()
    findings = validate(
        s.client,
        body.consumer,
        svc,
        include_local_listener=True,
    )
    findings["consumer_normalized"] = normalize_consumer_type(body.consumer)
    return findings


@app.post("/api/session/{session_id}/remediate")
def session_remediate(session_id: str, body: RemediateBody) -> dict[str, Any]:
    try:
        return _session_remediate_impl(session_id, body)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Remediate failed: {exc}") from exc


def _session_remediate_impl(session_id: str, body: RemediateBody) -> dict[str, Any]:
    s = _get_session(session_id)
    svc = body.services.model_dump()
    if not any(svc.values()):
        raise HTTPException(status_code=400, detail="Select at least one telemetry service")

    steps: list[dict[str, Any]] = []

    if body.install_prereqs:
        try:
            installed = ensure_extensions(
                s.client,
                cache_dir=REPO_ROOT / "rpms",
                as3_version=body.as3_version,
                ts_version=body.ts_version,
                assume_yes=body.assume_yes,
            )
            steps.append({"step": "install_extensions", "installed": installed})
        except BigIPError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    if body.provision_modules:
        needed = list(modules_required_for_services(svc).keys())
        if needed:
            # Extension install often leaves restjavad / Config Utility restarting (503 HTML).
            provision_wait = 420 if body.install_prereqs else 300
            try:
                patched = ensure_modules_provisioned(
                    s.client,
                    needed,
                    level=body.provision_level,
                    wait_timeout=provision_wait,
                )
                steps.append(
                    {
                        "step": "provision_modules",
                        "modules": needed,
                        "patched": patched,
                        "level": body.provision_level,
                    }
                )
            except BigIPError as exc:
                raise HTTPException(status_code=502, detail=str(exc)) from exc

    if body.apply_as3:
        try:
            as3_decl = build_as3_declaration(svc, include_local_listener=True)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if svc.get("asm"):
            # Freshly provisioned ASM can take several minutes before restjavad
            # registers /mgmt/tm/asm/* (404 "not registered" until then).
            asm_wait = 600 if body.provision_modules else 300
            try:
                s.client.wait_asm_policy_api_ready(timeout=asm_wait)
            except BigIPError as exc:
                raise HTTPException(status_code=502, detail=str(exc)) from exc
        try:
            as3_resp = s.client.post_as3(as3_decl, retries=6, retry_delay=20.0)
            steps.append({"step": "post_as3", "response": as3_resp})
        except BigIPError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        if svc.get("http_analytics") or svc.get("tcp_analytics"):
            pub = body.avr_log_publisher_fullpath or "/Common/Shared/telemetry_publisher"
            try:
                avr_gs = s.client.configure_analytics_global_settings_for_avr(log_publisher_fullpath=pub)
                steps.append(
                    {
                        "step": "analytics_global_settings_avr",
                        "log_publisher": pub,
                        "response": avr_gs,
                    }
                )
                try:
                    save_resp = s.client.save_sys_config()
                    steps.append({"step": "save_sys_config", "response": save_resp})
                except BigIPError as exc:
                    raise HTTPException(status_code=502, detail=str(exc)) from exc
            except BigIPError as exc:
                steps.append(
                    {
                        "step": "analytics_global_settings_avr",
                        "log_publisher": pub,
                        "status": "skipped",
                        "warning": str(exc),
                    }
                )

    if body.post_ts:
        try:
            ts_decl = build_ts_declaration(
                body.consumer,
                body.consumer_params,
                include_event_listener=True,
                include_system_poller=body.include_system_poller,
            )
            ts_resp = s.client.post_ts_declaration(ts_decl)
            steps.append({"step": "post_ts", "response": ts_resp})
        except BigIPError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    try:
        loopback_db = s.client.put_sys_db_allow_loopback_tcl_rule_node()
        steps.append(
            {
                "step": "sys_db_allow_loopback_tcl_rule_node",
                "path": "/mgmt/tm/sys/db/tmm.tcl.rule.node.allow_loopback_addresses",
                "response": loopback_db,
            }
        )
    except BigIPError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    if svc.get("http_analytics") or svc.get("tcp_analytics"):
        try:
            avr_pub = body.avr_log_publisher_fullpath or "/Common/telemetry_publisher"
            avr_coll = s.client.patch_analytics_global_settings_collection_ts_avr(
                external_logging_publisher=avr_pub
            )
            steps.append(
                {
                    "step": "analytics_global_settings_collection_ts_avr",
                    "externalLoggingPublisher": avr_pub,
                    "response": avr_coll,
                }
            )
        except BigIPError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    findings = validate(
        s.client,
        body.consumer,
        svc,
        include_local_listener=True,
    )
    findings["consumer_normalized"] = normalize_consumer_type(body.consumer)
    return {"steps": _json_safe_for_response(steps), "findings": findings}


@app.post("/api/session/{session_id}/rollback")
def session_rollback(session_id: str, body: RollbackBody) -> dict[str, Any]:
    try:
        return _session_rollback_impl(session_id, body)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Rollback failed: {exc}") from exc


def _session_rollback_impl(session_id: str, body: RollbackBody) -> dict[str, Any]:
    """Remove TS config, AS3 Shared telemetry app, and remediate-time TMOS tweaks (best-effort)."""
    if not body.confirm:
        raise HTTPException(
            status_code=400,
            detail="Rollback refused: set confirm=true in the JSON body (safety latch).",
        )
    s = _get_session(session_id)
    steps: list[dict[str, Any]] = []

    if body.clear_ts:
        try:
            ts_resp = s.client.post_ts_clear_configuration()
            steps.append({"step": "ts_clear_configuration", "response": ts_resp})
        except BigIPError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    if body.delete_as3_shared:
        try:
            as3_resp = s.client.delete_as3_application()
            steps.append({"step": "as3_delete_common_shared", "response": as3_resp})
        except BigIPError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    if body.reset_sys_db_loopback:
        try:
            db_resp = s.client.put_sys_db_allow_loopback_tcl_rule_node(allow_loopback=False)
            steps.append(
                {
                    "step": "sys_db_allow_loopback_disabled",
                    "value": "false",
                    "response": db_resp,
                }
            )
        except BigIPError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    if body.reset_analytics_global_settings:
        try:
            ar = s.client.reset_analytics_global_settings_offbox()
            steps.append({"step": "analytics_global_settings_reset_offbox", "response": ar})
        except BigIPError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    if body.save_sys_config_after:
        try:
            save_resp = s.client.save_sys_config()
            steps.append({"step": "save_sys_config", "response": save_resp})
        except BigIPError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    return {"steps": _json_safe_for_response(steps)}


@app.get("/api/consumers")
def list_consumers() -> dict[str, Any]:
    """Consumer types aligned with F5 TS docs (Push Consumers)."""
    return {
        "docs_url": "https://clouddocs.f5.com/products/extensions/f5-telemetry-streaming/latest/setting-up-consumer.html",
        "consumers": [
            {"type": "Splunk", "label": "Splunk (HEC)"},
            {"type": "Azure_Log_Analytics", "label": "Microsoft Azure Log Analytics"},
            {"type": "Azure_Application_Insights", "label": "Microsoft Azure Application Insights"},
            {"type": "AWS_CloudWatch", "label": "AWS CloudWatch"},
            {"type": "AWS_S3", "label": "AWS S3"},
            {"type": "DataDog", "label": "Datadog"},
            {"type": "ElasticSearch", "label": "ElasticSearch"},
            {"type": "Sumo_Logic", "label": "Sumo Logic"},
            {"type": "Generic_HTTP", "label": "Generic HTTP"},
            {"type": "Kafka", "label": "Kafka"},
            {"type": "Graphite", "label": "Graphite"},
            {"type": "Statsd", "label": "StatsD"},
            {"type": "default", "label": "Default (troubleshooting)"},
            {"type": "OpenTelemetry_Exporter", "label": "OpenTelemetry Exporter (advanced)"},
            {"type": "Google_Cloud_Monitoring", "label": "Google Cloud Monitoring"},
            {"type": "Google_Cloud_Logging", "label": "Google Cloud Logging"},
            {"type": "F5_Cloud", "label": "F5 Cloud"},
        ],
    }


def create_app() -> FastAPI:
    return app


_UI_DIST = REPO_ROOT / "frontend" / "dist"
if _UI_DIST.is_dir():
    app.mount("/", StaticFiles(directory=str(_UI_DIST), html=True), name="frontend")
else:

    @app.get("/", include_in_schema=False)
    def _ui_not_built() -> HTMLResponse:
        dist_path = _UI_DIST.resolve()
        return HTMLResponse(
            content=(
                "<!DOCTYPE html>\n"
                '<html lang="en"><head><meta charset="utf-8"/><title>UI not built</title></head>\n'
                '<body style="font-family:system-ui;max-width:42rem;margin:2rem;line-height:1.5">\n'
                "<h1>Static UI has not been built yet</h1>\n"
                "<p>The API is running, but <code>frontend/dist</code> is missing, so there is no "
                "bundled React app to serve from this port.</p>\n"
                "<p><strong>Fix (pick one):</strong></p>\n"
                "<ol>\n"
                "<li><strong>Production-style (single port):</strong> from the repo root run:<br/>\n"
                "<pre style=\"background:#f4f4f5;padding:0.75rem;overflow:auto\">cd frontend &amp;&amp; npm install "
                "&amp;&amp; npm run build &amp;&amp; cd ..\n"
                ".venv/bin/python run_server.py</pre>\n"
                "Then open <a href=\"/\">/</a> again (default <code>http://127.0.0.1:8000/</code>).</li>\n"
                "<li><strong>Development (two processes):</strong> Terminal A: "
                "<code>.venv/bin/python run_server.py</code> (API on port 8000). "
                "Terminal B: <code>cd frontend &amp;&amp; npm run dev</code> — open "
                "<strong>http://127.0.0.1:5173/</strong> (Vite proxies <code>/api</code> to port 8000).</li>\n"
                "</ol>\n"
                '<p>API check: <a href="/api/health"><code>GET /api/health</code></a> · '
                '<a href="/docs">OpenAPI docs</a></p>\n'
                f'<p style="color:#666">Expected dist directory:<br/><code>{dist_path}</code></p>\n'
                "</body></html>"
            ),
            status_code=200,
        )
