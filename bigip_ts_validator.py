#!/usr/bin/env python3
"""Validate (and optionally remediate) BIG-IP readiness for F5 Telemetry Streaming.

Checks the device for:
  * AS3 and Telemetry Streaming iControl LX extensions
  * The AS3-managed logging resources required by the TS "local listener" pattern
    (pool, iRule, virtual, HSL + formatted log destinations, log publisher,
    traffic / analytics / TCP-analytics / security / DNS logging profiles)
  * A Telemetry_Consumer of the expected type on the TS declaration

If anything is missing the script can POST the supplied AS3 declaration to
/mgmt/shared/appsvcs/declare to create the resources, then re-validate.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import requests
import urllib3

from as3_services import build_as3_declaration, required_as3_object_names
from ts_declaration_builder import build_ts_rollback_declaration, normalize_consumer_type

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


REQUIRED_AS3_OBJECTS: list[tuple[str, str]] = [
    ("telemetry", "Pool"),
    ("telemetry_hsl", "Log_Destination"),
    ("telemetry_formatted", "Log_Destination"),
    ("telemetry_publisher", "Log_Publisher"),
    ("telemetry_traffic_log_profile", "Traffic_Log_Profile"),
    ("telemetry_http_analytics_profile", "Analytics_Profile"),
    ("telemetry_tcp_analytics_profile", "Analytics_TCP_Profile"),
    ("telemetry_asm_security_log_profile", "Security_Log_Profile"),
]

# Optional resources used when TS listens locally on the BIG-IP rather than
# pushing directly to a remote consumer. Missing entries here are warnings.
OPTIONAL_AS3_OBJECTS: list[tuple[str, str]] = [
    ("telemetry_local_rule", "iRule"),
    ("telemetry_local", "Service_TCP"),
]


F5_AS3_REPO = "F5Networks/f5-appsvcs-extension"
F5_TS_REPO = "F5Networks/f5-telemetry-streaming"
DEFAULT_RPM_CACHE = Path(__file__).parent / "rpms"


class BigIPError(RuntimeError):
    pass


def _as3_post_error_transient(body: str) -> bool:
    t = body.lower()
    return (
        "connection refused" in t
        or "connectexception" in t
        or "localhost:8100" in t
        or "failure querying config" in t and "asm/policies" in t
    )


def _install_task_failed_because_already_installed(error_message: str, task_payload: dict) -> bool:
    """True when iControl LX reports INSTALL FAILED only because the RPM is already on the box."""
    blob = f"{error_message}\n{task_payload}".lower()
    return (
        "already installed" in blob
        or "is already installed" in blob
        or "package is already installed" in blob
        or "same version" in blob and "installed" in blob
    )


def _provision_patch_busy_response(status_code: int, body: str) -> bool:
    """True when TMOS rejects PATCH because another provisioning job is still running (01071003)."""
    if status_code != 400:
        return False
    t = body.lower()
    return (
        "01071003" in body
        or "provisioning operation is in progress" in t
        or "previous provisioning operation is in progress" in t
        or "try again when the bigip is active" in t
    )


def _mgmt_plane_unavailable(status_code: int, body: str = "") -> bool:
    """True when iControl REST / Configuration Utility is restarting or otherwise transiently down.

    Common after extension install or module provisioning: HTTP **503** with an HTML page titled
    ``BIG-IP® - Configuration Utility restarting...`` (tomcat_unavailable), or **502**/**504**.
    """
    if status_code in (502, 503, 504):
        return True
    t = (body or "").lower()
    return (
        "configuration utility restarting" in t
        or "tomcat_unavailable" in t
        or "service temporarily unavailable" in t
    )


def _extension_info_with_settle(
    client: BigIPClient,
    name: str,
    *,
    attempts: int = 5,
    delay: float = 1.5,
) -> dict | None:
    """Poll ``/mgmt/shared/{name}/info``; after restarts it may briefly not return 200."""
    last: dict | None = None
    for attempt in range(attempts):
        last = client.extension_info(name)
        if last:
            return last
        if attempt + 1 < attempts:
            time.sleep(delay)
            try:
                client.reauthenticate()
            except BigIPError:
                pass
    return last


AVR_GLOBAL_SETTINGS_ITEM_DEFAULT = (
    "/mgmt/tm/analytics/global-settings/~Common~global-settings"
)


class BigIPClient:
    def __init__(self, host: str, username: str, password: str, verify_tls: bool = False, timeout: int = 30):
        self.base_url = f"https://{host}"
        self.timeout = timeout
        self._username = username
        self._password = password
        self.session = requests.Session()
        self.session.verify = verify_tls
        self.session.headers.update({"Content-Type": "application/json"})
        self._authenticate(username, password)

    def reauthenticate(self) -> None:
        self.session.headers.pop("X-F5-Auth-Token", None)
        self._authenticate(self._username, self._password)

    def _authenticate(self, username: str, password: str) -> None:
        url = f"{self.base_url}/mgmt/shared/authn/login"
        body = {"username": username, "password": password, "loginProviderName": "tmos"}
        try:
            resp = self.session.post(url, json=body, timeout=self.timeout)
        except requests.RequestException as exc:
            raise BigIPError(f"Could not reach BIG-IP at {self.base_url}: {exc}") from exc
        if resp.status_code != 200:
            raise BigIPError(f"Authentication failed ({resp.status_code}): {resp.text}")
        token = resp.json().get("token", {}).get("token")
        if not token:
            raise BigIPError("Authentication response did not contain a token")
        self.session.headers.update({"X-F5-Auth-Token": token})

    def _get(self, path: str) -> requests.Response:
        return self.session.get(f"{self.base_url}{path}", timeout=self.timeout)

    def _post(self, path: str, body: Any) -> requests.Response:
        return self.session.post(f"{self.base_url}{path}", json=body, timeout=self.timeout)

    def _patch(self, path: str, body: Any) -> requests.Response:
        return self.session.patch(f"{self.base_url}{path}", json=body, timeout=self.timeout)

    def _put(self, path: str, body: Any) -> requests.Response:
        return self.session.put(f"{self.base_url}{path}", json=body, timeout=self.timeout)

    def _delete(self, path: str) -> requests.Response:
        return self.session.delete(f"{self.base_url}{path}", timeout=self.timeout)

    def provision_query(self, *, settle_timeout: int = 300, poll: float = 5.0) -> dict[str, str]:
        """Return TMOS module slug (lowercase) -> provision level (lowercase).

        Retries while the management plane is restarting (**503** Configuration Utility
        page, etc.) — common immediately after RPM install or a prior provision PATCH.
        """
        deadline = time.time() + settle_timeout
        last_err = ""
        while True:
            try:
                resp = self._get("/mgmt/tm/sys/provision")
            except requests.RequestException as exc:
                last_err = str(exc)
                if time.time() >= deadline:
                    raise BigIPError(
                        f"Could not reach /mgmt/tm/sys/provision after {settle_timeout}s: {exc}"
                    ) from exc
                time.sleep(poll)
                try:
                    self.reauthenticate()
                except BigIPError:
                    pass
                continue

            if resp.status_code == 200:
                data = resp.json()
                out: dict[str, str] = {}
                for it in data.get("items", []):
                    name = str(it.get("name", "")).lower().strip()
                    if not name:
                        continue
                    out[name] = str(it.get("level", "none")).lower().strip()
                return out

            last_err = f"({resp.status_code}): {(resp.text or '')[:500]}"
            if _mgmt_plane_unavailable(resp.status_code, resp.text or ""):
                if time.time() >= deadline:
                    raise BigIPError(
                        f"Could not read /mgmt/tm/sys/provision after {settle_timeout}s "
                        f"(management plane still unavailable) {last_err}"
                    )
                time.sleep(poll)
                try:
                    self.reauthenticate()
                except BigIPError:
                    pass
                continue

            raise BigIPError(f"Could not read /mgmt/tm/sys/provision {last_err}")

    def patch_provision_level(
        self,
        module: str,
        level: str = "nominal",
        *,
        busy_poll: float = 10.0,
        busy_timeout: int = 360,
    ) -> dict:
        """PATCH a single module to the given provision level (default nominal).

        Retries on **400 / 01071003** when another provisioning operation is still
        active, and on **502/503/504** (Configuration Utility restarting), which is
        common when enabling several modules or right after extension install.
        """
        mod = module.lower().strip()
        deadline = time.time() + busy_timeout
        last_body = ""
        while time.time() < deadline:
            try:
                resp = self._patch(f"/mgmt/tm/sys/provision/{mod}", {"level": level})
            except requests.RequestException:
                time.sleep(busy_poll)
                try:
                    self.reauthenticate()
                except BigIPError:
                    pass
                continue
            if resp.status_code in (200, 202):
                try:
                    return resp.json() if resp.text.strip() else {}
                except json.JSONDecodeError:
                    return {}
            last_body = resp.text or ""
            if _provision_patch_busy_response(resp.status_code, last_body) or _mgmt_plane_unavailable(
                resp.status_code, last_body
            ):
                time.sleep(busy_poll)
                try:
                    self.reauthenticate()
                except BigIPError:
                    pass
                continue
            raise BigIPError(
                f"Provisioning PATCH for {mod} failed ({resp.status_code}): {last_body[:800]}"
            )
        raise BigIPError(
            f"Provisioning PATCH for {mod} timed out after {busy_timeout}s waiting for prior "
            f"provisioning / management plane readiness (last response): {last_body[:800]}"
        )

    def configure_analytics_global_settings_for_avr(
        self,
        *,
        log_publisher_fullpath: str = "/Common/Shared/telemetry_publisher",
        wait_for_items_timeout: float = 120.0,
        wait_interval: float = 5.0,
    ) -> dict[str, Any]:
        """Enable AVR off-box analytics logging over HSL to the Shared ``telemetry_publisher``.

        REST equivalent of::

            modify analytics global-settings {
                external-logging-publisher <publisher>
                offbox-protocol hsl
                use-offbox enabled
            }

        Some platforms return an empty ``items`` array on
        ``GET /mgmt/tm/analytics/global-settings`` until AVR is fully ready after
        provisioning, or only expose the singleton via a fixed URI. This method
        **polls** the collection, then falls back to **PATCH** ``~Common~global-settings``
        and finally a **PATCH** on the collection with the same body.

        See ``/mgmt/tm/analytics/global-settings`` (``useHsl``, ``useOffbox``,
        ``externalLoggingPublisher``). The default publisher path matches AS3
        objects created under ``/Common/Shared/`` by this tool.

        F5 TS documents the same **tmsh** intent (publisher name may differ) at:
        https://clouddocs.f5.com/products/extensions/f5-telemetry-streaming/latest/avr.html#modifying-avr-configuration-to-use-the-log-publisher
        """
        body = {
            "externalLoggingPublisher": log_publisher_fullpath,
            "useHsl": "enabled",
            "useOffbox": "enabled",
        }
        deadline = time.time() + wait_for_items_timeout
        last_snip = ""
        while time.time() < deadline:
            r = self._get("/mgmt/tm/analytics/global-settings")
            if r.status_code != 200:
                raise BigIPError(
                    f"Cannot read /mgmt/tm/analytics/global-settings ({r.status_code}): {r.text[:800]}"
                )
            data = r.json() or {}
            items = data.get("items")
            if isinstance(items, list) and len(items) > 0:
                item = items[0]
                part = str(item.get("partition") or "Common")
                nm = str(item.get("name") or "global-settings")
                path = f"/mgmt/tm/analytics/global-settings/~{part}~{nm}"
                pr = self._patch(path, body)
                if pr.status_code not in (200, 202):
                    raise BigIPError(
                        f"PATCH analytics global-settings failed ({pr.status_code}): {pr.text[:1200]}"
                    )
                try:
                    out = pr.json() if pr.text.strip() else {}
                except json.JSONDecodeError:
                    out = {}
                if isinstance(out, dict):
                    out["_avrPatchMode"] = "collection_item"
                return out if isinstance(out, dict) else {"_avrPatchMode": "collection_item"}
            last_snip = (r.text or "")[:500]
            time.sleep(wait_interval)
            try:
                self.reauthenticate()
            except BigIPError:
                pass

        last_err = last_snip or "(empty body)"
        for label, uri in (
            ("singleton", AVR_GLOBAL_SETTINGS_ITEM_DEFAULT),
            ("collection_useHsl", "/mgmt/tm/analytics/global-settings"),
        ):
            pr = self._patch(uri, body)
            if pr.status_code in (200, 202):
                try:
                    out = pr.json() if pr.text.strip() else {}
                except json.JSONDecodeError:
                    out = {}
                if isinstance(out, dict):
                    out["_avrPatchMode"] = label
                return out if isinstance(out, dict) else {"_avrPatchMode": label}
            last_err = pr.text[:1200]

        raise BigIPError(
            "Could not configure AVR analytics global-settings: "
            f"GET had no items for {wait_for_items_timeout:.0f}s; "
            f"fallback PATCHs also failed: {last_err}"
        )

    def save_sys_config(self) -> dict[str, Any]:
        """REST equivalent of ``tmsh save sys config`` (persist running config to disk).

        POST ``/mgmt/tm/sys/config`` with ``command: save``. See F5 iControl REST
        ``sys/config`` task reference.
        """
        r = self._post("/mgmt/tm/sys/config", {"command": "save"})
        if r.status_code not in (200, 202):
            raise BigIPError(
                f"save sys config failed ({r.status_code}): {r.text[:1200]}"
            )
        try:
            return r.json() if r.text.strip() else {}
        except json.JSONDecodeError:
            return {}

    def patch_analytics_global_settings_collection_ts_avr(
        self,
        *,
        external_logging_publisher: str = "/Common/telemetry_publisher",
    ) -> dict[str, Any]:
        """Telemetry Streaming + AVR workaround: PATCH analytics global-settings collection.

        Some TS deployments require a final **PATCH** to ``/mgmt/tm/analytics/global-settings``
        (collection URI) with ``offboxProtocol`` / ``useOffbox`` / ``externalLoggingPublisher``,
        distinct from per-item PATCHes used elsewhere.
        """
        path = "/mgmt/tm/analytics/global-settings"
        body = {
            "externalLoggingPublisher": external_logging_publisher,
            "offboxProtocol": "hsl",
            "useOffbox": "enabled",
        }
        r = self._patch(path, body)
        if r.status_code not in (200, 202):
            raise BigIPError(
                f"PATCH {path} (TS+AVR workaround) failed ({r.status_code}): {r.text[:1200]}"
            )
        try:
            return r.json() if r.text.strip() else {}
        except json.JSONDecodeError:
            return {}

    def put_sys_db_allow_loopback_tcl_rule_node(self, *, allow_loopback: bool = True) -> dict[str, Any]:
        """Set DB var ``tmm.tcl.rule.node.allow_loopback_addresses`` (TS loopback / iRule workaround).

        When ``allow_loopback`` is True, sets ``value`` to ``"true"``; when False, sets ``"false"``
        (rollback).
        """
        path = "/mgmt/tm/sys/db/tmm.tcl.rule.node.allow_loopback_addresses"
        r = self._put(path, {"value": "true" if allow_loopback else "false"})
        if r.status_code not in (200, 202):
            raise BigIPError(
                f"PUT {path} failed ({r.status_code}): {r.text[:1200]}"
            )
        try:
            return r.json() if r.text.strip() else {}
        except json.JSONDecodeError:
            return {}

    def wait_asm_policy_api_ready(self, timeout: int = 300, interval: float = 5.0) -> None:
        """Wait until ASM policy REST is usable on the management API.

        After ASM (or related) provisioning or TMM/restjavad restarts, AS3 may POST
        successfully to ``/declare`` but return **422** while it queries ASM policies
        via **localhost:8100** on the device (``java.net.ConnectException: Connection
        refused``). Polling ``/mgmt/tm/asm/policies`` from here usually tracks the
        same readiness window.
        """
        deadline = time.time() + timeout
        path = "/mgmt/tm/asm/policies?$top=1&$select=name"
        while time.time() < deadline:
            try:
                r = self._get(path)
            except requests.RequestException:
                time.sleep(interval)
                try:
                    self.reauthenticate()
                except BigIPError:
                    pass
                continue
            if r.status_code == 200:
                return
            text = (r.text or "").lower()
            if r.status_code in (401, 403):
                try:
                    self.reauthenticate()
                except BigIPError:
                    pass
                time.sleep(interval)
                continue
            transient = r.status_code in (502, 503, 504) or (
                r.status_code == 400
                and (
                    "connection refused" in text
                    or "connectexception" in text
                    or "temporarily unavailable" in text
                )
            )
            if transient:
                time.sleep(interval)
                continue
            raise BigIPError(
                f"ASM policy API returned ({r.status_code}) while waiting for readiness: {r.text[:1200]}"
            )
        raise BigIPError(f"Timed out after {timeout}s waiting for ASM policy REST ({path})")

    def wait_provision_and_rest(self, modules: list[str], timeout: int = 300) -> None:
        """Wait until provisioned modules leave ``none``, then allow REST to settle."""
        want = {m.lower().strip() for m in modules if m.strip()}
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                levels = self.provision_query()
            except (BigIPError, requests.RequestException):
                time.sleep(5)
                try:
                    self.reauthenticate()
                except BigIPError:
                    pass
                continue
            if want and any(levels.get(m, "none") in ("none", "") for m in want):
                time.sleep(5)
                try:
                    self.reauthenticate()
                except BigIPError:
                    pass
                continue
            break
        else:
            raise BigIPError(
                f"Timed out after {timeout}s waiting for module levels (expected: {sorted(want)})"
            )

        settle_deadline = time.time() + min(120, max(30, timeout // 4))
        while time.time() < settle_deadline:
            try:
                self.reauthenticate()
            except BigIPError:
                pass
            try:
                r = self._get("/mgmt/shared/appsvcs/info")
                if r.status_code == 200:
                    time.sleep(3)
                    return
                if r.status_code == 404:
                    # AS3 RPM not installed yet; provisioning restart is still finished.
                    time.sleep(8)
                    return
            except requests.RequestException:
                pass
            time.sleep(5)

    def extension_info(self, name: str) -> dict | None:
        resp = self._get(f"/mgmt/shared/{name}/info")
        if resp.status_code == 200:
            data = resp.json()
            return data[0] if isinstance(data, list) and data else data
        return None

    def as3_declaration(self) -> dict | None:
        resp = self._get("/mgmt/shared/appsvcs/declare")
        if resp.status_code == 204:
            return {}
        if resp.status_code == 200:
            return resp.json()
        return None

    def ts_declaration(self) -> dict | None:
        resp = self._get("/mgmt/shared/telemetry/declare")
        if resp.status_code == 200:
            return resp.json()
        return None

    def post_as3(
        self,
        declaration: dict,
        *,
        retries: int = 1,
        retry_delay: float = 20.0,
    ) -> dict:
        """POST to AS3 ``/declare``. Retries on transient 422 (ASM control plane warming)."""
        last_err: str | None = None
        for attempt in range(max(1, retries)):
            resp = self._post("/mgmt/shared/appsvcs/declare", declaration)
            if resp.status_code < 400:
                return resp.json()
            body = resp.text or ""
            last_err = f"AS3 POST failed ({resp.status_code}): {body}"
            if (
                resp.status_code == 422
                and attempt + 1 < retries
                and _as3_post_error_transient(body)
            ):
                time.sleep(retry_delay)
                try:
                    self.reauthenticate()
                except BigIPError:
                    pass
                continue
            raise BigIPError(last_err)
        raise BigIPError(last_err or "AS3 POST failed")

    def post_ts_declaration(self, declaration: dict) -> dict:
        """POST a Telemetry Streaming declaration to /mgmt/shared/telemetry/declare."""
        resp = self._post("/mgmt/shared/telemetry/declare", declaration)
        if resp.status_code >= 400:
            raise BigIPError(f"TS declaration POST failed ({resp.status_code}): {resp.text[:2000]}")
        if not (resp.text or "").strip():
            return {}
        try:
            return resp.json()
        except json.JSONDecodeError:
            return {"_raw_text": resp.text}

    def post_ts_clear_configuration(self) -> dict[str, Any]:
        """Remove all Telemetry Streaming configuration (``{\"class\": \"Telemetry\"}``)."""
        return self.post_ts_declaration(build_ts_rollback_declaration())

    def delete_as3_application(self, tenant: str = "Common", application: str = "Shared") -> dict[str, Any]:
        """DELETE an AS3 application (default ``Common`` / ``Shared`` telemetry bundle)."""
        t = tenant.strip("/")
        a = application.strip("/")
        path = f"/mgmt/shared/appsvcs/declare/{t}/applications/{a}"
        resp = self._delete(path)
        if resp.status_code in (200, 202, 204):
            if not (resp.text or "").strip():
                return {"_status": resp.status_code, "_path": path}
            try:
                out = resp.json()
                if isinstance(out, dict):
                    out["_path"] = path
                return out if isinstance(out, dict) else {"_status": resp.status_code, "_path": path}
            except json.JSONDecodeError:
                return {"_status": resp.status_code, "_path": path, "_raw_text": resp.text[:2000]}
        if resp.status_code == 404:
            return {
                "_status": 404,
                "_path": path,
                "_note": "AS3 application not found (already removed or never deployed on this target).",
            }
        raise BigIPError(f"AS3 DELETE {path} failed ({resp.status_code}): {resp.text[:2000]}")

    def reset_analytics_global_settings_offbox(self) -> dict[str, Any]:
        """Best-effort undo of AVR off-box / HSL global-settings changes from remediation."""
        bodies: tuple[dict[str, Any], ...] = (
            {"useOffbox": "disabled", "useHsl": "disabled", "externalLoggingPublisher": ""},
            {"useOffbox": "disabled", "useHsl": "disabled"},
        )
        paths = ("/mgmt/tm/analytics/global-settings", AVR_GLOBAL_SETTINGS_ITEM_DEFAULT)
        last_err = ""
        for path in paths:
            for body in bodies:
                r = self._patch(path, body)
                if r.status_code in (200, 202):
                    try:
                        out = r.json() if r.text.strip() else {}
                    except json.JSONDecodeError:
                        out = {}
                    if isinstance(out, dict):
                        out["_rollback_patch_path"] = path
                    return out if isinstance(out, dict) else {"_rollback_patch_path": path}
                last_err = f"{path}: ({r.status_code}) {r.text[:800]}"
        raise BigIPError(f"Could not reset analytics global-settings: {last_err}")

    def upload_file(self, local_path: Path) -> str:
        """Chunk-upload a file to /var/config/rest/downloads/<name>. Returns the remote path."""
        name = local_path.name
        size = local_path.stat().st_size
        if size == 0:
            raise BigIPError(f"Refusing to upload zero-byte file {local_path}")
        chunk_size = 1024 * 1024
        url = f"{self.base_url}/mgmt/shared/file-transfer/uploads/{name}"
        headers = {
            "Content-Type": "application/octet-stream",
            "X-F5-Auth-Token": self.session.headers.get("X-F5-Auth-Token", ""),
        }
        with local_path.open("rb") as f:
            start = 0
            while start < size:
                chunk = f.read(chunk_size)
                end = start + len(chunk) - 1
                headers["Content-Range"] = f"{start}-{end}/{size}"
                resp = self.session.post(url, data=chunk, headers=headers, timeout=self.timeout, verify=self.session.verify)
                if resp.status_code >= 400:
                    raise BigIPError(f"Upload chunk {start}-{end}/{size} of {name} failed ({resp.status_code}): {resp.text[:300]}")
                start = end + 1
        return f"/var/config/rest/downloads/{name}"

    def install_package(self, remote_rpm_path: str, timeout: int = 300) -> dict:
        body = {"operation": "INSTALL", "packageFilePath": remote_rpm_path}
        resp = self._post("/mgmt/shared/iapp/package-management-tasks", body)
        if resp.status_code >= 400:
            raise BigIPError(f"Install task POST failed ({resp.status_code}): {resp.text[:300]}")
        task_id = resp.json().get("id")
        if not task_id:
            raise BigIPError(f"Install task POST returned no id: {resp.text[:300]}")
        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(3)
            r = self._get(f"/mgmt/shared/iapp/package-management-tasks/{task_id}")
            if r.status_code == 401:
                # The rest framework restart after install can invalidate the token.
                self.reauthenticate()
                continue
            if r.status_code != 200:
                continue
            data = r.json()
            status = data.get("status")
            if status == "FINISHED":
                return data
            if status == "FAILED":
                err = str(data.get("errorMessage") or data.get("message") or "")
                if _install_task_failed_because_already_installed(err, data):
                    return data
            if status in ("FAILED", "CANCELED"):
                raise BigIPError(f"Install task {task_id} {status}: {data.get('errorMessage') or data}")
        raise BigIPError(f"Install task {task_id} timed out after {timeout}s")

    def wait_for_extension(self, name: str, timeout: int = 420) -> dict:
        deadline = time.time() + timeout
        last_err = None
        while time.time() < deadline:
            try:
                info = self.extension_info(name)
            except requests.RequestException as exc:
                last_err = exc
                info = None
            if info:
                return info
            time.sleep(3)
            # Rest framework restarts can churn the token; try a re-auth on the way out.
            try:
                self.reauthenticate()
            except BigIPError as exc:
                last_err = exc
        raise BigIPError(f"Extension '{name}' did not come online within {timeout}s ({last_err})")


def _shared_block(as3_decl: Any) -> dict | None:
    """Extract Common.Shared from whatever shape /mgmt/shared/appsvcs/declare returns."""
    if not isinstance(as3_decl, dict):
        return None
    # /declare can return either the ADC object directly or a wrapper with a "declaration" key.
    adc = as3_decl.get("declaration") if "declaration" in as3_decl else as3_decl
    if isinstance(adc, list):
        adc = adc[0] if adc else None
    if not isinstance(adc, dict):
        return None
    common = adc.get("Common")
    if not isinstance(common, dict):
        return None
    shared = common.get("Shared")
    return shared if isinstance(shared, dict) else None


def _find_consumers(ts_decl: Any) -> list[dict]:
    """Walk the TS declaration and return every Telemetry_Consumer object found."""
    consumers: list[dict] = []
    if not isinstance(ts_decl, dict):
        return consumers
    decl = ts_decl.get("declaration", ts_decl)

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if node.get("class") == "Telemetry_Consumer":
                consumers.append(node)
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(decl)
    return consumers


def resolve_github_rpm(repo: str, version: str | None) -> tuple[str, str, str]:
    """Look up an iControl LX RPM asset on a F5 GitHub release.

    Returns (tag, asset_name, download_url). If version is None, uses /releases/latest.
    """
    if version:
        tag = version if version.startswith("v") else f"v{version}"
        url = f"https://api.github.com/repos/{repo}/releases/tags/{tag}"
    else:
        url = f"https://api.github.com/repos/{repo}/releases/latest"
    headers = {"Accept": "application/vnd.github+json"}
    gh_token = os.environ.get("GITHUB_TOKEN")
    if gh_token:
        headers["Authorization"] = f"Bearer {gh_token}"
    try:
        r = requests.get(url, headers=headers, timeout=30)
    except requests.RequestException as exc:
        raise BigIPError(f"GitHub release lookup for {repo} failed: {exc}") from exc
    if r.status_code != 200:
        raise BigIPError(f"GitHub release lookup for {repo} returned {r.status_code}: {r.text[:200]}")
    rel = r.json()
    for asset in rel.get("assets", []):
        name = asset.get("name", "")
        if name.endswith(".noarch.rpm"):
            return rel.get("tag_name", "unknown"), name, asset["browser_download_url"]
    raise BigIPError(f"No .noarch.rpm asset found in {repo} release {rel.get('tag_name')}")


def download_rpm(url: str, dest: Path) -> None:
    if dest.is_file() and dest.stat().st_size > 0:
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    try:
        with requests.get(url, stream=True, timeout=180) as r:
            if r.status_code != 200:
                raise BigIPError(f"RPM download failed ({r.status_code}) for {url}")
            with tmp.open("wb") as f:
                for chunk in r.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        f.write(chunk)
        tmp.rename(dest)
    except requests.RequestException as exc:
        if tmp.exists():
            tmp.unlink()
        raise BigIPError(f"RPM download failed: {exc}") from exc


def ensure_extensions(
    client: BigIPClient,
    cache_dir: Path,
    as3_version: str | None,
    ts_version: str | None,
    assume_yes: bool,
    *,
    extension_wait_timeout: int = 600,
) -> list[str]:
    """Install any missing AS3/TS extensions. Returns the list of names actually installed.

    ``extension_wait_timeout`` bounds polling of ``/mgmt/shared/{appsvcs,telemetry}/info``
    after each RPM install; large or busy systems often exceed 180s while restjavad restarts.
    """
    targets: list[tuple[str, str, str | None]] = []  # (extension_name, github_repo, pinned_version)
    if not _extension_info_with_settle(client, "appsvcs"):
        targets.append(("appsvcs", F5_AS3_REPO, as3_version))
    if not _extension_info_with_settle(client, "telemetry"):
        targets.append(("telemetry", F5_TS_REPO, ts_version))
    if not targets:
        return []

    plan: list[tuple[str, str, Path]] = []  # (extension_name, tag, local_rpm)
    print("\nResolving F5 GitHub releases for missing extensions ...")
    for ext_name, repo, ver in targets:
        tag, asset_name, dl_url = resolve_github_rpm(repo, ver)
        local = cache_dir / asset_name
        print(f"  {ext_name}: {tag} -> {asset_name}")
        plan.append((ext_name, tag, local))
        download_rpm(dl_url, local)

    print(f"\nAbout to install on {client.base_url}:")
    for ext_name, tag, local in plan:
        print(f"  - {ext_name} {tag}  ({local.name})")
    if not assume_yes:
        confirm = input("Proceed with install? [y/N]: ").strip().lower()
        if confirm != "y":
            raise BigIPError("Extension install aborted by user")

    installed: list[str] = []
    for ext_name, tag, local in plan:
        print(f"\nUploading {local.name} ...")
        remote = client.upload_file(local)
        print(f"Installing {ext_name} ({tag}) ...")
        client.install_package(remote)
        print(f"Waiting for {ext_name} to come online ...")
        info = client.wait_for_extension(ext_name, timeout=extension_wait_timeout)
        print(f"  -> {ext_name} version {info.get('version', 'unknown')} is up")
        installed.append(ext_name)
    return installed


def modules_required_for_services(services: dict[str, bool]) -> dict[str, str]:
    """TMOS module slug (lowercase) -> human-readable reason."""
    need: dict[str, str] = {}
    if services.get("http_analytics") or services.get("tcp_analytics"):
        need["avr"] = "HTTP or TCP Analytics profiles (Analytics_Profile / Analytics_TCP_Profile)"
    if services.get("asm"):
        need["asm"] = "ASM security log profile (application)"
    if services.get("afm"):
        need["afm"] = "AFM security log profile (network)"
    if services.get("dns"):
        need["gtm"] = "DNS logging profile (GTM / DNS services module)"
    return need


def ensure_modules_provisioned(
    client: BigIPClient,
    modules: list[str],
    *,
    level: str = "nominal",
    wait_timeout: int = 300,
) -> list[str]:
    """PATCH any listed module that is at level ``none``; wait for REST. Returns slugs PATCHed.

    Modules are processed **one at a time**: after each PATCH the device must
    finish that provisioning step before the next, or TMOS returns **01071003**
    (provisioning already in progress).
    """
    modules = [m.lower().strip() for m in modules if m.strip()]
    if not modules:
        return []
    patched: list[str] = []
    # After RPM install the Configuration Utility often returns 503 HTML for a while.
    settle = max(300, wait_timeout)
    for m in modules:
        try:
            levels = client.provision_query(settle_timeout=settle)
        except BigIPError as exc:
            raise BigIPError(
                f"Cannot read provisioning state before PATCH (waited up to {settle}s for "
                f"management plane / Configuration Utility): {exc}"
            ) from exc
        cur = levels.get(m, "none")
        if cur in ("none", ""):
            client.patch_provision_level(m, level=level, busy_timeout=max(360, wait_timeout))
            patched.append(m)
            client.wait_provision_and_rest([m], timeout=wait_timeout)
    return patched


def validate(
    client: BigIPClient,
    expected_consumer: str,
    services: dict[str, bool] | None = None,
    *,
    include_local_listener: bool = True,
) -> dict:
    checks: list[str] = []
    missing: list[str] = []
    warnings: list[str] = []

    expected_consumer_norm = normalize_consumer_type(expected_consumer)

    required_objects: list[tuple[str, str]]
    if services is not None and not any(
        services.get(k, False) for k in ("ltm", "asm", "afm", "http_analytics", "tcp_analytics", "dns")
    ):
        missing.append(
            "Select at least one telemetry scope (LTM, ASM, AFM, HTTP/TCP Analytics, or DNS logging)"
        )
        required_objects = []
    else:
        required_objects = required_as3_object_names(services, include_local_listener=include_local_listener)

    modules_detail: dict[str, Any] = {}
    needed_mods = modules_required_for_services(services) if services is not None else {}
    if needed_mods:
        try:
            provision = client.provision_query()
        except BigIPError as exc:
            warnings.append(f"Could not read TMOS provisioning: {exc}")
            provision = {}
        for mod, reason in needed_mods.items():
            level = provision.get(mod, "none")
            modules_detail[mod] = {"level": level, "required_for": reason}
            if level in ("none", ""):
                missing.append(
                    f"TMOS module '{mod.upper()}' is not provisioned ({reason}). "
                    "Enable 'Provision required TMOS modules' during remediation to set nominal level."
                )
            else:
                checks.append(f"TMOS module {mod.upper()} is provisioned ({level}) — {reason}")

    as3_info = client.extension_info("appsvcs")
    if as3_info:
        checks.append(f"AS3 extension installed (version {as3_info.get('version', 'unknown')})")
    else:
        missing.append("AS3 extension is not installed on the BIG-IP")

    ts_info = client.extension_info("telemetry")
    if ts_info:
        checks.append(f"Telemetry Streaming installed (version {ts_info.get('version', 'unknown')})")
    else:
        missing.append("Telemetry Streaming extension is not installed on the BIG-IP")

    shared = _shared_block(client.as3_declaration()) if as3_info else None
    if shared is None:
        if as3_info:
            for name, cls in required_objects:
                missing.append(f"AS3 resource missing in /Common/Shared: {name} ({cls})")
    else:
        for name, cls in required_objects:
            obj = shared.get(name)
            if isinstance(obj, dict) and obj.get("class") == cls:
                checks.append(f"AS3 resource present: {name} ({cls})")
            else:
                missing.append(f"AS3 resource missing in /Common/Shared: {name} ({cls})")
        optional_skip = {"telemetry_local_rule", "telemetry_local"} if include_local_listener else set()
        for name, cls in OPTIONAL_AS3_OBJECTS:
            if name in optional_skip:
                continue
            obj = shared.get(name)
            if isinstance(obj, dict) and obj.get("class") == cls:
                checks.append(f"Optional AS3 resource present: {name} ({cls})")
            else:
                warnings.append(f"Optional AS3 resource not found: {name} ({cls}) — required only for the TS local-listener pattern")

    consumer_status = "skipped (TS not installed)"
    if ts_info:
        consumers = _find_consumers(client.ts_declaration())
        if not consumers:
            missing.append("TS declaration has no Telemetry_Consumer configured")
            consumer_status = "none configured"
        else:
            types = [c.get("type", "<no type>") for c in consumers]
            matching = [c for c in consumers if normalize_consumer_type(str(c.get("type", ""))) == expected_consumer_norm]
            if matching:
                checks.append(
                    f"TS consumer of type {expected_consumer_norm} is configured ({len(matching)} found)"
                )
                consumer_status = f"{expected_consumer_norm} configured"
            else:
                missing.append(
                    f"TS declaration has no Telemetry_Consumer of type '{expected_consumer_norm}' "
                    f"(found: {', '.join(types) or 'none'})"
                )
                consumer_status = f"have [{', '.join(types)}], need {expected_consumer_norm}"

    return {
        "checks": checks,
        "missing": missing,
        "warnings": warnings,
        "consumer_status": consumer_status,
        "modules": modules_detail,
        "ready": not missing,
    }


def print_report(host: str, findings: dict) -> None:
    line = "=" * 72
    print(line)
    print(f"BIG-IP Telemetry Streaming readiness report — {host}")
    print(line)
    for c in findings["checks"]:
        print(f"  [OK]      {c}")
    for w in findings["warnings"]:
        print(f"  [WARN]    {w}")
    for m in findings["missing"]:
        print(f"  [MISSING] {m}")
    mods = findings.get("modules") or {}
    if mods:
        print("  Modules:")
        for slug, info in sorted(mods.items()):
            lvl = info.get("level", "?")
            why = info.get("required_for", "")
            print(f"    {slug.upper():<6} level={lvl} — {why}")
    print("-" * 72)
    print(f"  Consumer: {findings['consumer_status']}")
    print(f"  STATUS:   {'READY' if findings['ready'] else 'NOT READY'}")
    print(line)


def resolve_password(args: argparse.Namespace) -> str:
    if args.password:
        return args.password
    env_pw = os.environ.get("BIGIP_PASSWORD")
    if env_pw:
        return env_pw
    return getpass.getpass(f"Password for {args.username}@{args.host}: ")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate (and remediate) BIG-IP readiness for F5 Telemetry Streaming.")
    parser.add_argument("--host", required=True, help="BIG-IP management IP or hostname")
    parser.add_argument("--username", required=True, help="BIG-IP admin username")
    parser.add_argument("--password", help="Password (else uses $BIGIP_PASSWORD or prompts)")
    parser.add_argument("--consumer", required=True,
                        help="Expected TS consumer type, e.g. Splunk, Azure_Log_Analytics, "
                             "AWS_CloudWatch, DataDog (Datadog accepted as alias), Generic_HTTP, "
                             "Sumo_Logic, ElasticSearch")
    parser.add_argument("--as3-file", default=str(Path(__file__).parent / "examples" / "as3-telemetry-resources.json"),
                        help="AS3 declaration to apply when remediating")
    parser.add_argument("--no-remediate", action="store_true",
                        help="Validate only; do not offer to apply the AS3 declaration")
    parser.add_argument("--yes", action="store_true",
                        help="Skip the confirmation prompt before applying changes (install + AS3)")
    parser.add_argument("--install-prereqs", action="store_true",
                        help="If AS3 and/or TS iControl LX extensions are missing, download "
                             "RPMs from F5's GitHub releases and install them before validating")
    parser.add_argument("--as3-version", help="Pin AS3 version, e.g. v3.55.0 (default: latest release)")
    parser.add_argument("--ts-version", help="Pin TS version, e.g. v1.36.0 (default: latest release)")
    parser.add_argument("--rpm-cache-dir", default=str(DEFAULT_RPM_CACHE),
                        help="Directory where downloaded RPMs are cached")
    parser.add_argument(
        "--extension-wait-timeout",
        type=int,
        default=600,
        metavar="SEC",
        help="After each RPM install, wait up to SEC for the extension /info endpoint (default: 600)",
    )
    parser.add_argument("--verify-tls", action="store_true", help="Verify the BIG-IP TLS certificate")
    parser.add_argument("--json", action="store_true", help="Emit the final findings as JSON on stdout")
    args = parser.parse_args()

    password = resolve_password(args)

    try:
        client = BigIPClient(args.host, args.username, password, verify_tls=args.verify_tls)
    except BigIPError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.install_prereqs:
        try:
            installed = ensure_extensions(
                client,
                cache_dir=Path(args.rpm_cache_dir),
                as3_version=args.as3_version,
                ts_version=args.ts_version,
                assume_yes=args.yes,
                extension_wait_timeout=args.extension_wait_timeout,
            )
        except BigIPError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 4
        if installed:
            print(f"\nInstalled: {', '.join(installed)}")

    findings = validate(client, args.consumer)
    print_report(args.host, findings)

    if findings["ready"]:
        if args.json:
            print(json.dumps(findings, indent=2))
        return 0

    if args.no_remediate:
        if args.json:
            print(json.dumps(findings, indent=2))
        return 1

    as3_path = Path(args.as3_file)
    if not as3_path.is_file():
        print(f"ERROR: AS3 declaration not found at {as3_path}", file=sys.stderr)
        return 2
    try:
        declaration = json.loads(as3_path.read_text())
    except json.JSONDecodeError as exc:
        print(f"ERROR: {as3_path} is not valid JSON: {exc}", file=sys.stderr)
        return 2

    if not args.yes:
        print(f"\nThe following AS3 declaration will be POSTed to {args.host}: {as3_path}")
        confirm = input("Apply now? [y/N]: ").strip().lower()
        if confirm != "y":
            print("Aborted by user.")
            return 1

    print(f"\nApplying AS3 declaration from {as3_path} ...")
    try:
        result = client.post_as3(declaration)
    except BigIPError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3
    print("AS3 response:")
    print(json.dumps(result, indent=2))

    print("\nRe-validating ...")
    findings = validate(client, args.consumer)
    print_report(args.host, findings)
    if args.json:
        print(json.dumps(findings, indent=2))
    return 0 if findings["ready"] else 1


if __name__ == "__main__":
    sys.exit(main())
