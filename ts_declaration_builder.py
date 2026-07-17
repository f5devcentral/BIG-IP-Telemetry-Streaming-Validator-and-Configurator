"""Build F5 Telemetry Streaming declarations (consumer + system + optional listener)."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import unquote, urlparse

# TS consumer ``type`` values must match F5 docs. CLI historically used ``Datadog``;
# BIG-IP expects ``DataDog``.
CONSUMER_ALIASES: dict[str, str] = {
    "Datadog": "DataDog",
    "datadog": "DataDog",
    "STATSd": "Statsd",
    "STATSD": "Statsd",
    "StatsD": "Statsd",
}


def normalize_consumer_type(name: str) -> str:
    return CONSUMER_ALIASES.get(name, name)


def _passphrase(secret: str) -> dict[str, Any]:
    return {"cipherText": secret}


def _truthy(value: Any) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "on")


_SUMO_HTTP_PATH_MARKER = "/receiver/v1/http/"


def _parse_sumo_logic_endpoint(url: str) -> dict[str, Any]:
    """Split a Sumo HTTP collector URL into host, protocol, port, path, secret."""
    raw = (url or "").strip()
    if not raw:
        raise ValueError("Sumo Logic collector URL is empty")
    if not re.match(r"^[a-zA-Z][-a-zA-Z0-9+.]*://", raw):
        raw = "https://" + raw
    p = urlparse(raw)
    scheme = (p.scheme or "https").lower()
    if scheme not in ("http", "https"):
        raise ValueError("Sumo Logic URL must use http or https")
    host = p.hostname
    if not host:
        raise ValueError("Missing host in Sumo Logic URL")
    port = p.port
    if port is None:
        port = 443 if scheme == "https" else 80
    path = p.path or "/"
    low = path.lower()
    idx = low.find(_SUMO_HTTP_PATH_MARKER)
    if idx >= 0:
        base_path = path[: idx + len(_SUMO_HTTP_PATH_MARKER)]
        secret = path[idx + len(_SUMO_HTTP_PATH_MARKER) :]
    else:
        last = path.rfind("/")
        if last <= 0:
            raise ValueError(
                "Could not parse Sumo URL: expected path containing /receiver/v1/http/ followed by the token"
            )
        base_path = path[: last + 1]
        secret = path[last + 1 :]
    secret = unquote(secret.lstrip("/"))
    if not secret:
        raise ValueError("Missing collector token in Sumo Logic URL")
    if not base_path.endswith("/"):
        base_path += "/"
    return {"host": host, "protocol": scheme, "port": port, "path": base_path, "secret": secret}


def _sumo_logic_resolved_params(consumer_params: dict[str, Any]) -> dict[str, Any]:
    raw = consumer_params.get("sumoEndpoint") or consumer_params.get("sumo_endpoint")
    if isinstance(raw, str) and raw.strip():
        return _parse_sumo_logic_endpoint(raw)
    return consumer_params


def build_ts_declaration(
    consumer_type: str,
    consumer_params: dict[str, Any],
    *,
    include_event_listener: bool = True,
    include_system_poller: bool = True,
) -> dict[str, Any]:
    """Compose a POSTable TS declaration body.

    ``consumer_params`` are raw string values from the UI (already trimmed).
    """
    ctype = normalize_consumer_type(consumer_type)
    decl: dict[str, Any] = {"class": "Telemetry"}

    if include_system_poller:
        decl["TS_System"] = {
            "class": "Telemetry_System",
            "enable": True,
            "systemPoller": {"interval": 60},
        }

    if include_event_listener:
        decl["TS_Listener"] = {"class": "Telemetry_Listener", "port": 6514}

    consumer: dict[str, Any] = {"class": "Telemetry_Consumer", "type": ctype}

    if ctype == "Splunk":
        consumer["host"] = consumer_params["host"]
        consumer["protocol"] = consumer_params.get("protocol", "https")
        consumer["port"] = int(consumer_params.get("port", 8088))
        consumer["passphrase"] = _passphrase(consumer_params["hec_token"])
        fmt = consumer_params.get("format")
        if fmt in ("legacy", "multiMetric"):
            consumer["format"] = fmt
        if consumer_params.get("compressionType"):
            consumer["compressionType"] = consumer_params["compressionType"]

    elif ctype == "Azure_Log_Analytics":
        consumer["workspaceId"] = consumer_params["workspaceId"]
        use_mi = str(consumer_params.get("useManagedIdentity", "false")).lower() in (
            "1",
            "true",
            "yes",
        )
        consumer["useManagedIdentity"] = use_mi
        if not use_mi:
            consumer["passphrase"] = _passphrase(consumer_params["sharedKey"])
        if consumer_params.get("region"):
            consumer["region"] = consumer_params["region"]
        if consumer_params.get("format"):
            consumer["format"] = consumer_params["format"]

    elif ctype == "Azure_Application_Insights":
        use_mi = str(consumer_params.get("useManagedIdentity", "false")).lower() in (
            "1",
            "true",
            "yes",
        )
        consumer["useManagedIdentity"] = use_mi
        if not use_mi:
            consumer["instrumentationKey"] = consumer_params["instrumentationKey"]
        else:
            if consumer_params.get("appInsightsResourceName"):
                consumer["appInsightsResourceName"] = consumer_params["appInsightsResourceName"]
        if consumer_params.get("region"):
            consumer["region"] = consumer_params["region"]

    elif ctype == "AWS_CloudWatch":
        consumer["region"] = consumer_params["region"]
        data_type = consumer_params.get("dataType", "logs")
        if data_type == "metrics":
            consumer["dataType"] = "metrics"
            consumer["metricNamespace"] = consumer_params["metricNamespace"]
        else:
            consumer["logGroup"] = consumer_params["logGroup"]
            consumer["logStream"] = consumer_params.get("logStream", "default")
        if consumer_params.get("username"):
            consumer["username"] = consumer_params["username"]
        if consumer_params.get("secretAccessKey"):
            consumer["passphrase"] = _passphrase(consumer_params["secretAccessKey"])
        if consumer_params.get("endpointUrl"):
            consumer["endpointUrl"] = consumer_params["endpointUrl"]

    elif ctype == "AWS_S3":
        consumer["region"] = consumer_params["region"]
        consumer["bucket"] = consumer_params["bucket"]
        if consumer_params.get("username"):
            consumer["username"] = consumer_params["username"]
        if consumer_params.get("secretAccessKey"):
            consumer["passphrase"] = _passphrase(consumer_params["secretAccessKey"])
        if consumer_params.get("endpointUrl"):
            consumer["endpointUrl"] = consumer_params["endpointUrl"]

    elif ctype == "Generic_HTTP":
        consumer["host"] = consumer_params["host"]
        consumer["protocol"] = consumer_params.get("protocol", "https")
        consumer["port"] = int(consumer_params.get("port", 443))
        consumer["path"] = consumer_params.get("path", "/")
        consumer["method"] = consumer_params.get("method", "POST")
        if consumer_params.get("apiKey"):
            consumer["headers"] = [
                {"name": "content-type", "value": "application/json"},
                {"name": consumer_params.get("apiKeyHeader", "x-api-key"), "value": "`>@/passphrase`"},
            ]
            consumer["passphrase"] = _passphrase(consumer_params["apiKey"])
        else:
            consumer["headers"] = [{"name": "content-type", "value": "application/json"}]

    elif ctype == "Sumo_Logic":
        sp = _sumo_logic_resolved_params(consumer_params)
        consumer["host"] = sp["host"]
        consumer["protocol"] = sp.get("protocol", "https")
        consumer["port"] = int(sp.get("port", 443))
        consumer["path"] = sp.get("path", "/receiver/v1/http/")
        consumer["passphrase"] = _passphrase(sp["secret"])

    elif ctype == "ElasticSearch":
        consumer["host"] = consumer_params["host"]
        consumer["index"] = consumer_params["index"]
        consumer["port"] = int(consumer_params.get("port", 9200))
        consumer["protocol"] = consumer_params.get("protocol", "https")
        if consumer_params.get("apiVersion"):
            consumer["apiVersion"] = consumer_params["apiVersion"]
        if consumer_params.get("dataType"):
            consumer["dataType"] = consumer_params["dataType"]
        if consumer_params.get("username"):
            consumer["username"] = consumer_params["username"]
        if consumer_params.get("password"):
            consumer["passphrase"] = _passphrase(consumer_params["password"])

    elif ctype == "DataDog":
        consumer["apiKey"] = consumer_params["apiKey"]
        consumer["region"] = consumer_params.get("region", "US1")
        if consumer_params.get("compressionType"):
            consumer["compressionType"] = consumer_params["compressionType"]
        if consumer_params.get("service"):
            consumer["service"] = consumer_params["service"]

    elif ctype == "Kafka":
        consumer["host"] = consumer_params["host"]
        consumer["port"] = int(consumer_params["port"])
        consumer["topic"] = consumer_params["topic"]
        consumer["protocol"] = consumer_params.get("protocol", "binaryTcpTls")
        if consumer_params.get("authenticationProtocol"):
            consumer["authenticationProtocol"] = consumer_params["authenticationProtocol"]
        if consumer_params.get("username") and consumer_params.get("kafkaPassword"):
            consumer["username"] = consumer_params["username"]
            consumer["passphrase"] = _passphrase(consumer_params["kafkaPassword"])

    elif ctype == "Graphite":
        consumer["host"] = consumer_params["host"]
        consumer["protocol"] = consumer_params.get("protocol", "https")
        consumer["port"] = int(consumer_params.get("port", 443))

    elif ctype == "Statsd":
        consumer["host"] = consumer_params["host"]
        proto = str(consumer_params.get("protocol", "udp")).lower()
        consumer["protocol"] = "tcp" if proto == "tcp" else "udp"
        consumer["port"] = int(consumer_params.get("port", 8125))

    elif ctype == "OpenTelemetry_Exporter":
        consumer["host"] = consumer_params["host"]
        consumer["port"] = int(consumer_params["port"])
        if consumer_params.get("metricsPath"):
            consumer["metricsPath"] = consumer_params["metricsPath"]
        if consumer_params.get("logsPath"):
            consumer["logsPath"] = consumer_params["logsPath"]

    elif ctype == "default":
        pass  # no extra fields

    else:
        # Advanced: merge user-supplied JSON fragment (must set type consistently)
        extra = consumer_params.get("consumerJson")
        if isinstance(extra, dict):
            consumer.update({k: v for k, v in extra.items() if k != "class"})

    # TS-schema property to skip TLS certificate validation on the consumer
    # connection (self-signed Splunk HEC, ElasticSearch, Generic_HTTP, etc.).
    if _truthy(consumer_params.get("allowSelfSignedCert")):
        consumer["allowSelfSignedCert"] = True

    decl["TS_Consumer"] = consumer
    return decl


def build_ts_rollback_declaration() -> dict[str, Any]:
    """Return a TS POST body that removes all Telemetry Streaming configuration.

    Per F5 *Deleting the TS configuration*, POST ``{\"class\": \"Telemetry\"}`` to
    ``/mgmt/shared/telemetry/declare`` clears the managed declaration.
    """
    return {"class": "Telemetry"}
