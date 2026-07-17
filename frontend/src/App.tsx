import { useEffect, useMemo, useState } from "react";

import f5LogoUrl from "./assets/F5-logo-F5-rgb.svg";

const api = (path: string) => path;

/**
 * Same-origin ``fetch`` for API paths, with clearer errors when the browser reports a network failure
 * (otherwise you only see "Failed to fetch").
 */
async function apiFetch(path: string, init?: RequestInit): Promise<Response> {
  const url = api(path);
  try {
    return await fetch(url, init);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const name = err instanceof Error ? err.name : "";
    if (
      name === "TypeError" &&
      (message === "Failed to fetch" ||
        message.includes("Failed to load") ||
        message.includes("Load failed") ||
        message.includes("NetworkError") ||
        message.includes("network"))
    ) {
      const port =
        typeof window !== "undefined" && window.location.port ? window.location.port : "";
      const longOpHint =
        " Remediation can take many minutes (RPMs, provisioning, AS3, TS). If work actually finished on the BIG-IP but you see this here, the connection was often closed early by a **timeout** (reverse proxy, load balancer, or corporate filter) — not because the API was down. Increase proxy read timeouts (e.g. nginx `proxy_read_timeout 900s;` for `/api`) or run the UI directly on the API port.";
      const viteHint =
        port === "5173"
          ? " Vite dev proxies `/api` to http://127.0.0.1:8000 — ensure that process is running; `vite.config.ts` sets a long proxy timeout for `/api`."
          : " Ensure the FastAPI process is listening on this host/port (e.g. `python run_server.py` binding `0.0.0.0:8000`).";
      throw new Error(`Network error calling ${url}.${viteHint}${longOpHint} (${message})`);
    }
    throw err instanceof Error ? err : new Error(message);
  }
}

/** Parse JSON from fetch; avoids ``r.json()`` throwing when the server returns HTML or plain text. */
async function readJsonResponse<T>(r: Response): Promise<T> {
  const text = await r.text();
  if (!text.trim()) {
    if (!r.ok) throw new Error(`${r.status} ${r.statusText}`.trim());
    return {} as T;
  }
  try {
    return JSON.parse(text) as T;
  } catch {
    const snip = text.replace(/\s+/g, " ").trim().slice(0, 280);
    throw new Error(
      `Expected JSON from API (${r.status} ${r.statusText}). Body starts with: ${snip}${text.length > 280 ? "…" : ""}`,
    );
  }
}

const THEME_STORAGE_KEY = "bigip-ts-ui-theme";

type ThemeMode = "light" | "dark" | "system";

type Services = {
  ltm: boolean;
  asm: boolean;
  afm: boolean;
  http_analytics: boolean;
  tcp_analytics: boolean;
  dns: boolean;
};

type Findings = {
  checks: string[];
  missing: string[];
  warnings: string[];
  consumer_status: string;
  ready: boolean;
  consumer_normalized?: string;
  modules?: Record<string, { level: string; required_for: string }>;
};

const defaultServices: Services = {
  ltm: true,
  asm: false,
  afm: false,
  http_analytics: false,
  tcp_analytics: false,
  dns: false,
};

const SUMO_HTTP_COLLECTOR_PREFIX = "/receiver/v1/http/";

/** Parse a Sumo Logic HTTP collector URL into TS consumer fields (host, protocol, port, path, secret). */
function parseSumoLogicEndpoint(input: string): {
  host: string;
  protocol: string;
  port: number;
  path: string;
  secret: string;
} {
  const trimmed = input.trim();
  if (!trimmed) {
    throw new Error("Sumo Logic collector URL is required");
  }
  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    try {
      url = new URL(`https://${trimmed}`);
    } catch {
      throw new Error("Invalid Sumo Logic collector URL");
    }
  }
  const protocol = url.protocol.replace(/:$/, "").toLowerCase();
  if (protocol !== "http" && protocol !== "https") {
    throw new Error("Sumo Logic URL must use http or https");
  }
  const host = url.hostname;
  if (!host) {
    throw new Error("Missing host in Sumo Logic URL");
  }
  const port = url.port
    ? parseInt(url.port, 10)
    : protocol === "https"
      ? 443
      : 80;
  if (Number.isNaN(port)) {
    throw new Error("Invalid port in Sumo Logic URL");
  }
  const pathname = url.pathname || "/";
  const low = pathname.toLowerCase();
  const idx = low.indexOf(SUMO_HTTP_COLLECTOR_PREFIX.toLowerCase());
  let path: string;
  let secret: string;
  if (idx >= 0) {
    path = pathname.slice(0, idx + SUMO_HTTP_COLLECTOR_PREFIX.length);
    secret = pathname.slice(idx + SUMO_HTTP_COLLECTOR_PREFIX.length);
  } else {
    const last = pathname.lastIndexOf("/");
    if (last <= 0) {
      throw new Error(
        "Could not parse Sumo URL: expected path containing /receiver/v1/http/ followed by the collector token",
      );
    }
    path = pathname.slice(0, last + 1);
    secret = pathname.slice(last + 1);
  }
  secret = decodeURIComponent(secret.replace(/^\/+/, ""));
  if (!secret) {
    throw new Error("Missing collector token in the Sumo Logic URL (after the HTTP path)");
  }
  if (!path.endsWith("/")) {
    path += "/";
  }
  return { host, protocol, port, path, secret };
}

function buildConsumerPayload(raw: Record<string, string>, consumer: string): Record<string, unknown> {
  const o: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(raw)) {
    if (v.trim() !== "") o[k] = v.trim();
  }
  const text = String(o.consumerJsonText ?? "").trim();
  delete o.consumerJsonText;
  if (text) {
    try {
      o.consumerJson = JSON.parse(text) as object;
    } catch {
      throw new Error("Consumer JSON must be valid JSON");
    }
  }
  if (consumer === "Sumo_Logic") {
    const endpoint = String(o.sumoEndpoint ?? "").trim();
    delete o.sumoEndpoint;
    if (endpoint) {
      const parsed = parseSumoLogicEndpoint(endpoint);
      o.host = parsed.host;
      o.protocol = parsed.protocol;
      o.port = parsed.port;
      o.path = parsed.path;
      o.secret = parsed.secret;
    }
  }
  return o;
}

function ConsumerFields({
  consumer,
  values,
  onChange,
}: {
  consumer: string;
  values: Record<string, string>;
  onChange: (k: string, v: string) => void;
}) {
  const field = (key: string, label: string, type: string = "text", placeholder?: string) => (
    <div className="field" key={key}>
      <label htmlFor={key}>{label}</label>
      <input
        id={key}
        type={type}
        autoComplete="off"
        placeholder={placeholder}
        value={values[key] ?? ""}
        onChange={(e) => onChange(key, e.target.value)}
      />
    </div>
  );

  // TS Telemetry_Consumer property `allowSelfSignedCert` — skip TLS certificate
  // validation toward the consumer (self-signed Splunk HEC, ElasticSearch, etc.).
  const selfSignedField = (
    <label className="check" key="allowSelfSignedCert">
      <input
        type="checkbox"
        checked={(values.allowSelfSignedCert ?? "") === "true"}
        onChange={(e) => onChange("allowSelfSignedCert", e.target.checked ? "true" : "")}
      />
      Ignore certificate warnings (allow self-signed TLS cert on the consumer)
    </label>
  );

  if (consumer === "Splunk") {
    return (
      <>
        {field("host", "Splunk HEC host / IP")}
        {field("port", "HEC port", "number", "8088")}
        {field("protocol", "Protocol (https or http)", "text", "https")}
        {field("hec_token", "HEC token", "password")}
        {field("format", "Format (optional: legacy | multiMetric)", "text")}
        {field("compressionType", "Compression (optional: gzip | none)", "text")}
        {selfSignedField}
      </>
    );
  }
  if (consumer === "Azure_Log_Analytics") {
    return (
      <>
        {field("workspaceId", "Workspace ID")}
        {field("sharedKey", "Shared key (if not using managed identity)", "password")}
        {field("useManagedIdentity", "Use managed identity (true/false)", "text", "false")}
        {field("region", "Region (optional)", "text", "westus")}
        {field("format", "Format (optional: propertyBased)", "text")}
      </>
    );
  }
  if (consumer === "Azure_Application_Insights") {
    return (
      <>
        {field("instrumentationKey", "Instrumentation key (if not using managed identity)", "password")}
        {field("useManagedIdentity", "Use managed identity (true/false)", "text", "false")}
        {field("appInsightsResourceName", "App Insights resource filter (optional)", "text")}
        {field("region", "Region (optional)", "text")}
      </>
    );
  }
  if (consumer === "AWS_CloudWatch") {
    return (
      <>
        {field("region", "AWS region", "text", "us-west-2")}
        {field("dataType", "Data type: logs | metrics", "text", "logs")}
        {field("logGroup", "Log group (logs mode)", "text")}
        {field("logStream", "Log stream (logs mode)", "text", "default")}
        {field("metricNamespace", "Metric namespace (metrics mode)", "text")}
        {field("username", "Access key ID (optional if instance role)", "text")}
        {field("secretAccessKey", "Secret access key (optional)", "password")}
        {field("endpointUrl", "Custom endpoint URL (optional)", "text")}
      </>
    );
  }
  if (consumer === "AWS_S3") {
    return (
      <>
        {field("region", "AWS region")}
        {field("bucket", "Bucket name")}
        {field("username", "Access key ID (optional)", "text")}
        {field("secretAccessKey", "Secret access key (optional)", "password")}
        {field("endpointUrl", "Custom endpoint URL (optional)", "text")}
      </>
    );
  }
  if (consumer === "Generic_HTTP") {
    return (
      <>
        {field("host", "Remote host")}
        {field("protocol", "Protocol", "text", "https")}
        {field("port", "Port", "number", "443")}
        {field("path", "URL path", "text", "/")}
        {field("method", "HTTP method", "text", "POST")}
        {field("apiKey", "API key / bearer secret (optional)", "password")}
        {field("apiKeyHeader", "Header name for API key (optional)", "text", "x-api-key")}
        {selfSignedField}
      </>
    );
  }
  if (consumer === "Sumo_Logic") {
    return (
      <>
        <div className="field" key="sumoEndpoint">
          <label htmlFor="sumoEndpoint">Sumo Logic collector URL (full URL)</label>
          <textarea
            id="sumoEndpoint"
            autoComplete="off"
            rows={3}
            spellCheck={false}
            placeholder="https://&lt;deployment&gt;.sumologic.com/receiver/v1/http/&lt;token&gt;"
            value={values.sumoEndpoint ?? ""}
            onChange={(e) => onChange("sumoEndpoint", e.target.value)}
          />
          <p className="muted">
            Paste the full HTTP(S) collector URL. Host, protocol, port, path, and path secret are derived
            automatically (default port 443 for https, 80 for http when omitted).
          </p>
        </div>
        {selfSignedField}
      </>
    );
  }
  if (consumer === "ElasticSearch") {
    return (
      <>
        {field("host", "ElasticSearch host")}
        {field("index", "Index name")}
        {field("port", "Port", "number", "9200")}
        {field("protocol", "Protocol", "text", "https")}
        {field("apiVersion", "API version (optional)", "text", "8.0")}
        {field("dataType", "Data type (optional)", "text")}
        {field("username", "Username (optional)", "text")}
        {field("password", "Password (optional)", "password")}
        {selfSignedField}
      </>
    );
  }
  if (consumer === "DataDog") {
    return (
      <>
        {field("apiKey", "Datadog API key", "password")}
        {field("region", "Region (US1, EU1, …)", "text", "US1")}
        {field("compressionType", "Compression (optional: gzip)", "text")}
        {field("service", "Service tag (optional)", "text", "f5-telemetry")}
      </>
    );
  }
  if (consumer === "Kafka") {
    return (
      <>
        {field("host", "Broker host")}
        {field("port", "Broker port", "number", "9092")}
        {field("topic", "Topic name")}
        {field("protocol", "Protocol", "text", "binaryTcpTls")}
        {field("authenticationProtocol", "Auth (optional: SASL-PLAIN, TLS, None)", "text")}
        {field("username", "Username (optional)", "text")}
        {field("kafkaPassword", "Password (optional)", "password")}
        {selfSignedField}
      </>
    );
  }
  if (consumer === "Graphite") {
    return (
      <>
        {field("host", "Graphite host")}
        {field("protocol", "Protocol", "text", "https")}
        {field("port", "Port", "number", "443")}
        {selfSignedField}
      </>
    );
  }
  if (consumer === "Statsd") {
    return (
      <>
        {field("host", "StatsD host")}
        {field("protocol", "Protocol (udp or tcp)", "text", "udp")}
        {field("port", "Port", "number", "8125")}
      </>
    );
  }
  if (consumer === "OpenTelemetry_Exporter") {
    return (
      <>
        {field("host", "Collector host")}
        {field("port", "Collector port", "number", "4318")}
        {field("metricsPath", "Metrics path (optional)", "text")}
        {field("logsPath", "Logs path (optional)", "text")}
        {selfSignedField}
      </>
    );
  }
  if (["Google_Cloud_Monitoring", "Google_Cloud_Logging", "F5_Cloud"].includes(consumer)) {
    return (
      <div className="field">
        <label htmlFor="cj">Consumer object JSON (merged into Telemetry_Consumer)</label>
        <textarea
          id="cj"
          placeholder='{"host":"...","projectId":"..."}'
          value={values.consumerJsonText ?? ""}
          onChange={(e) => onChange("consumerJsonText", e.target.value)}
        />
        <p className="muted">
          See F5 examples for {consumer} in the Telemetry Streaming documentation.
        </p>
      </div>
    );
  }
  if (consumer === "default") {
    return <p className="muted">No remote parameters required for the default consumer.</p>;
  }
  return (
    <div className="field">
      <label htmlFor="adv">Advanced: Telemetry_Consumer JSON fragment (optional)</label>
      <textarea
        id="adv"
        placeholder='{"host":"example.com","port":443}'
        value={values.consumerJsonText ?? ""}
        onChange={(e) => onChange("consumerJsonText", e.target.value)}
      />
    </div>
  );
}

export default function App() {
  const [themeMode, setThemeMode] = useState<ThemeMode>(() => {
    try {
      const v = localStorage.getItem(THEME_STORAGE_KEY);
      if (v === "light" || v === "dark" || v === "system") return v;
    } catch {
      /* private mode */
    }
    return "system";
  });

  useEffect(() => {
    try {
      localStorage.setItem(THEME_STORAGE_KEY, themeMode);
    } catch {
      /* ignore */
    }
    const apply = () => {
      const resolved =
        themeMode === "system"
          ? window.matchMedia("(prefers-color-scheme: dark)").matches
            ? "dark"
            : "light"
          : themeMode;
      document.documentElement.setAttribute("data-theme", resolved);
    };
    apply();
    if (themeMode !== "system") return undefined;
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    mq.addEventListener("change", apply);
    return () => mq.removeEventListener("change", apply);
  }, [themeMode]);

  const [host, setHost] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [verifyTls, setVerifyTls] = useState(false);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [consumer, setConsumer] = useState("Splunk");
  const [services, setServices] = useState<Services>({ ...defaultServices });
  const [params, setParams] = useState<Record<string, string>>({ protocol: "https", port: "8088" });
  const [installPrereqs, setInstallPrereqs] = useState(false);
  const [provisionModules, setProvisionModules] = useState(false);
  const [includeSystemPoller, setIncludeSystemPoller] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [findings, setFindings] = useState<Findings | null>(null);
  const [remediation, setRemediation] = useState<{ steps: unknown[]; findings: Findings } | null>(null);
  const [rollbackAck, setRollbackAck] = useState(false);
  const [rollbackResult, setRollbackResult] = useState<{ steps: unknown[] } | null>(null);
  /** After a successful rollback, re-enable rollback only after a full remediate succeeds. */
  const [rollbackDisabledUntilRemediate, setRollbackDisabledUntilRemediate] = useState(false);
  const [busy, setBusy] = useState(false);

  const servicesPayload = useMemo(() => ({ ...services }), [services]);

  const setParam = (k: string, v: string) => setParams((p) => ({ ...p, [k]: v }));

  async function connect() {
    setError(null);
    setBusy(true);
    try {
      const r = await apiFetch("/api/session", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ host, username, password, verify_tls: verifyTls }),
      });
      const data = await readJsonResponse<{ detail?: string; session_id?: string }>(r);
      if (!r.ok) throw new Error(data.detail ?? r.statusText);
      setSessionId(data.session_id!);
      setFindings(null);
      setRemediation(null);
      setRollbackResult(null);
      setRollbackAck(false);
      setRollbackDisabledUntilRemediate(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function runValidate() {
    if (!sessionId) return;
    setError(null);
    setBusy(true);
    try {
      const r = await apiFetch(`/api/session/${sessionId}/validate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ consumer, services: servicesPayload, include_system_poller: includeSystemPoller }),
      });
      const data = await readJsonResponse<Findings & { detail?: string }>(r);
      if (!r.ok) throw new Error((data as { detail?: string }).detail ?? r.statusText);
      setFindings(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function runRemediate() {
    if (!sessionId) return;
    setError(null);
    setBusy(true);
    try {
      const consumer_params = buildConsumerPayload(params, consumer);
      const r = await apiFetch(`/api/session/${sessionId}/remediate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          consumer,
          consumer_params,
          services: servicesPayload,
          install_prereqs: installPrereqs,
          provision_modules: provisionModules,
          provision_level: "nominal",
          apply_as3: true,
          post_ts: true,
          include_system_poller: includeSystemPoller,
          assume_yes: true,
        }),
      });
      const data = await readJsonResponse<{
        detail?: string;
        steps?: unknown[];
        findings?: Findings;
      }>(r);
      if (!r.ok) throw new Error(data.detail ?? r.statusText);
      setRemediation({ steps: data.steps ?? [], findings: data.findings! });
      setFindings(data.findings!);
      setRollbackDisabledUntilRemediate(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function runRollback() {
    if (!sessionId) return;
    if (!rollbackAck) {
      setError("Check the box to acknowledge rollback before continuing.");
      return;
    }
    setError(null);
    setBusy(true);
    try {
      const r = await apiFetch(`/api/session/${sessionId}/rollback`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          confirm: true,
          clear_ts: true,
          delete_as3_shared: true,
          reset_sys_db_loopback: true,
          reset_analytics_global_settings: true,
          save_sys_config_after: true,
        }),
      });
      const data = await readJsonResponse<{ detail?: string; steps?: unknown[] }>(r);
      if (!r.ok) throw new Error(data.detail ?? r.statusText);
      setRollbackResult({ steps: data.steps ?? [] });
      setRemediation(null);
      setFindings(null);
      setRollbackAck(false);
      setRollbackDisabledUntilRemediate(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const toggleService = (key: keyof Services) => {
    setServices((s) => ({ ...s, [key]: !s[key] }));
  };

  return (
    <>
      {busy ? (
        <div
          className="app-busy-overlay"
          role="status"
          aria-live="polite"
          aria-label="Working, please wait"
        >
          <div className="app-busy-spinner" aria-hidden />
        </div>
      ) : null}
      <div className="app">
      <header className="app-header">
        <div className="app-header-brand">
          <img
            className="app-header-logo"
            src={f5LogoUrl}
            width={44}
            height={44}
            alt="F5"
          />
          <div className="app-header-main">
            <h1 className="app-title">BIG-IP Telemetry Streaming Validator/Configurator</h1>
            <p className="muted" style={{ marginTop: 0 }}>
              Connect to a BIG-IP, validate readiness, apply AS3 logging resources for the services you select, and post a
              Telemetry Streaming declaration. Consumer reference:{" "}
              <a
                href="https://clouddocs.f5.com/products/extensions/f5-telemetry-streaming/latest/setting-up-consumer.html"
                target="_blank"
                rel="noreferrer"
              >
                Push Consumers
              </a>
              .
            </p>
          </div>
        </div>
        <div className="theme-toolbar">
          <span className="theme-toolbar-label" id="theme-label">
            Appearance
          </span>
          <div className="theme-segment" role="group" aria-labelledby="theme-label">
            <button
              type="button"
              aria-pressed={themeMode === "light"}
              onClick={() => setThemeMode("light")}
            >
              Light
            </button>
            <button
              type="button"
              aria-pressed={themeMode === "dark"}
              onClick={() => setThemeMode("dark")}
            >
              Dark
            </button>
            <button
              type="button"
              aria-pressed={themeMode === "system"}
              onClick={() => setThemeMode("system")}
            >
              System
            </button>
          </div>
        </div>
      </header>

      {error && <div className="banner-error">{error}</div>}

      <div className="card">
        <h2>Connection</h2>
        <div className="row">
          <div className="field">
            <label htmlFor="host">Management IP or hostname</label>
            <input id="host" value={host} onChange={(e) => setHost(e.target.value)} autoComplete="off" />
          </div>
          <div className="field">
            <label htmlFor="user">Username</label>
            <input id="user" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" />
          </div>
        </div>
        <div className="row">
          <div className="field">
            <label htmlFor="pw">Password</label>
            <input
              id="pw"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
            />
          </div>
          <div className="field" style={{ flex: "0 0 auto", justifyContent: "flex-end" }}>
            <label className="check" style={{ marginTop: "1.4rem" }}>
              <input type="checkbox" checked={verifyTls} onChange={(e) => setVerifyTls(e.target.checked)} />
              Verify TLS certificate
            </label>
          </div>
        </div>
        <div className="actions">
          <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void connect()}>
            Connect
          </button>
          {sessionId && (
            <span className="muted" style={{ alignSelf: "center" }}>
              Session active (in-memory; expires after idle timeout on server).
            </span>
          )}
        </div>
      </div>

      <div className="card">
        <h2>Telemetry sources (AS3)</h2>
        <p className="muted">
          Choose which profiles to create under /Common/Shared. AVR must be provisioned for HTTP/TCP analytics. DNS
          logging requires the GTM/DNS module and attaches a <code>DNS_Logging</code> profile to the Shared publisher
          chain — assign it to DNS profiles in TMOS or the GUI per F5 docs.
        </p>
        <div className="check-grid">
          {(
            [
              ["ltm", "LTM logging"],
              ["asm", "ASM (application security)"],
              ["afm", "AFM (network security)"],
              ["http_analytics", "HTTP Analytics (AVR)"],
              ["tcp_analytics", "TCP Analytics (AVR)"],
              ["dns", "DNS (GTM) logging"],
            ] as const
          ).map(([k, label]) => (
            <label key={k} className="check">
              <input type="checkbox" checked={services[k]} onChange={() => toggleService(k)} />
              {label}
            </label>
          ))}
        </div>
      </div>

      <div className="card">
        <h2>Telemetry consumer</h2>
        <div className="row">
          <div className="field" style={{ flex: "2 1 320px" }}>
            <label htmlFor="cons">Consumer type</label>
            <select
              id="cons"
              value={consumer}
              onChange={(e) => {
                const v = e.target.value;
                setConsumer(v);
                if (v === "Sumo_Logic") {
                  setParams({ sumoEndpoint: "" });
                } else {
                  // Security-relevant flag; require an explicit opt-in per consumer.
                  setParams((p) => ({ ...p, allowSelfSignedCert: "" }));
                }
              }}
            >
              <option value="Splunk">Splunk (HEC)</option>
              <option value="Azure_Log_Analytics">Azure Log Analytics</option>
              <option value="Azure_Application_Insights">Azure Application Insights</option>
              <option value="AWS_CloudWatch">AWS CloudWatch</option>
              <option value="AWS_S3">AWS S3</option>
              <option value="DataDog">Datadog</option>
              <option value="ElasticSearch">ElasticSearch</option>
              <option value="Sumo_Logic">Sumo Logic</option>
              <option value="Generic_HTTP">Generic HTTP</option>
              <option value="Kafka">Kafka</option>
              <option value="Graphite">Graphite</option>
              <option value="Statsd">StatsD</option>
              <option value="OpenTelemetry_Exporter">OpenTelemetry Exporter</option>
              <option value="Google_Cloud_Monitoring">Google Cloud Monitoring</option>
              <option value="Google_Cloud_Logging">Google Cloud Logging</option>
              <option value="F5_Cloud">F5 Cloud</option>
              <option value="default">Default (diagnostics)</option>
            </select>
          </div>
        </div>
        <div className="row" style={{ marginTop: "0.75rem" }}>
          <ConsumerFields consumer={consumer} values={params} onChange={setParam} />
        </div>
      </div>

      <div className="card">
        <h2>Remediation options</h2>
        <label className="check">
          <input type="checkbox" checked={installPrereqs} onChange={(e) => setInstallPrereqs(e.target.checked)} />
          Install missing AS3 / Telemetry Streaming RPMs from F5 GitHub (workstation needs internet)
        </label>
        <label className="check" style={{ marginTop: "0.5rem" }}>
          <input
            type="checkbox"
            checked={includeSystemPoller}
            onChange={(e) => setIncludeSystemPoller(e.target.checked)}
          />
          Collect BIG-IP system metrics (TS System Poller / Telemetry_System) — separate from the virtual/iRule; sends
          device stats to your consumer on the configured interval
        </label>
        <label className="check" style={{ marginTop: "0.5rem" }}>
          <input type="checkbox" checked={provisionModules} onChange={(e) => setProvisionModules(e.target.checked)} />
          Provision required TMOS modules at nominal level (AVR for HTTP/TCP analytics, ASM / AFM / GTM when those
          sources are selected). Causes a short TMM/REST restart on the BIG-IP.
        </label>
      </div>

      <div className="actions" style={{ marginBottom: "1rem" }}>
        <button type="button" className="btn btn-secondary" disabled={!sessionId || busy} onClick={() => void runValidate()}>
          Validate only
        </button>
        <button type="button" className="btn btn-primary" disabled={!sessionId || busy} onClick={() => void runRemediate()}>
          Validate + remediate + post TS
        </button>
      </div>

      {findings && (
        <div className="card report">
          <h2>Last report</h2>
          <p>
            Consumer status: {findings.consumer_status}{" "}
            {findings.consumer_normalized && (
              <span className="muted">(normalized type: {findings.consumer_normalized})</span>
            )}
          </p>
          <p className={findings.ready ? "status-ready" : "status-not"}>{findings.ready ? "READY" : "NOT READY"}</p>
          {findings.modules && Object.keys(findings.modules).length > 0 && (
            <>
              <p>TMOS modules (for selected telemetry sources)</p>
              <ul>
                {Object.entries(findings.modules).map(([slug, info]) => (
                  <li key={slug}>
                    <strong>{slug.toUpperCase()}</strong> — level <code>{info.level}</code>: {info.required_for}
                  </li>
                ))}
              </ul>
            </>
          )}
          <p>Checks</p>
          <ul>
            {findings.checks.map((c) => (
              <li key={c}>{c}</li>
            ))}
          </ul>
          {findings.warnings.length > 0 && (
            <>
              <p>Warnings</p>
              <ul>
                {findings.warnings.map((w) => (
                  <li key={w}>{w}</li>
                ))}
              </ul>
            </>
          )}
          {findings.missing.length > 0 && (
            <>
              <p>Missing</p>
              <ul>
                {findings.missing.map((m) => (
                  <li key={m}>{m}</li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}

      {remediation && remediation.steps.length > 0 && (
        <div className="card report">
          <h2>Remediation steps</h2>
          <pre className="report-pre">{JSON.stringify(remediation.steps, null, 2)}</pre>
        </div>
      )}

      {rollbackResult && (
        <div className="card report">
          <h2>Rollback steps</h2>
          <pre className="report-pre">{JSON.stringify(rollbackResult.steps, null, 2)}</pre>
        </div>
      )}

      <div className="card">
        <h2>Rollback (destructive)</h2>
        <p className="muted">
          Removes Telemetry Streaming configuration (POST body <code>{'{"class": "Telemetry"}'}</code> per F5 docs),{" "}
          <strong>deletes</strong> the AS3 <code>Common/Shared</code> application this tool manages (pool, log
          publisher, profiles, local listener virtual, etc.), sets{" "}
          <code>tmm.tcl.rule.node.allow_loopback_addresses</code> back to <code>false</code>, disables AVR off-box / HSL
          on analytics global-settings, then runs <code>save sys config</code>. Installed RPMs and TMOS module
          provisioning levels are <strong>not</strong> changed.
        </p>
        {rollbackDisabledUntilRemediate ? (
          <p className="muted" role="status">
            Rollback completed. Run <strong>Validate + remediate + post TS</strong> above before using rollback again.
          </p>
        ) : null}
        <label className="check">
          <input
            type="checkbox"
            checked={rollbackAck}
            disabled={rollbackDisabledUntilRemediate}
            onChange={(e) => setRollbackAck(e.target.checked)}
          />
          I understand this will remove the above configuration from the connected BIG-IP.
        </label>
        <div className="actions" style={{ marginTop: "0.75rem" }}>
          <button
            type="button"
            className="btn btn-danger"
            disabled={!sessionId || busy || !rollbackAck || rollbackDisabledUntilRemediate}
            onClick={() => void runRollback()}
          >
            Rollback
          </button>
        </div>
      </div>
    </div>
    </>
  );
}
