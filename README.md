# BIG-IP Telemetry Streaming Validator and Configurator

Validate (and optionally remediate) a F5 BIG-IP for F5 Telemetry Streaming (TS)
readiness against a named third-party consumer (Splunk, Azure Log Analytics,
AWS CloudWatch, Datadog, Generic HTTP, Sumo Logic, ElasticSearch, etc.).

<img src="./images/example.png" alt="Screenshot" width="800">

***

The validator:

- Confirms the AS3 and Telemetry Streaming iControl LX extensions are installed
- Verifies the AS3-managed logging resources required by the TS "local listener"
  pattern are present in `/Common/Shared`
- Walks the active TS declaration looking for a `Telemetry_Consumer` whose
  `type` matches the expected consumer
- (Optional) installs missing iControl LX extensions from F5 GitHub releases
- (Optional) POSTs an AS3 declaration to create logging resources (the **Web UI**
  builds this declaration dynamically from selected LTM / ASM / AFM / DNS /
  analytics options; the CLI uses `--as3-file`, defaulting to the static example under `examples/`)
- **Web UI:** optional validate + remediate workflow that can also POST a TS
  declaration to `/mgmt/shared/telemetry/declare` for supported consumers

The tool is intentionally read-only by default and explicit about every
mutation: it tells you what it's about to do, asks to confirm, and reports
what changed.

## Table of contents

- [Overview](#bigip-ts-validator)
- [Repository layout](#repository-layout)
- [Requirements](#requirements)
  - [Workstation](#workstation)
  - [Installing prerequisites on Linux and macOS](#installing-prerequisites-on-linux-and-macos)
  - [BIG-IP](#big-ip)
- [Installation](#installation)
  - [Web UI (React + FastAPI)](#web-ui-react-fastapi)
- [Run as a Linux service (systemd)](#run-as-a-linux-service-systemd)
- [Run on Kubernetes](#run-on-kubernetes)
- [Inputs](#inputs)
- [Usage](#usage)
  - [Validate only](#validate-only)
  - [Validate, install missing extensions, apply AS3](#validate-install-missing-extensions-apply-as3)
- [Workflow steps](#workflow-steps)
- [What is validated](#what-is-validated)
- [Exit codes](#exit-codes)
- [Module compatibility](#module-compatibility)
- [Limitations and known gaps](#limitations-and-known-gaps)
- [Roadmap](#roadmap)
  - [Near term](#near-term)
  - [Frontend UI](#frontend-ui)
  - [Stretch](#stretch)
- [Contributing](#contributing)
- [License](#license)

## Repository layout

```
bigip-ts-validator/
├── bigip_ts_validator.py          # CLI + library (BigIPClient, validate, ensure_extensions)
├── as3_services.py                # Dynamic AS3 builder + required object list
├── ts_declaration_builder.py      # TS declaration composer (consumers)
├── server/app.py                  # FastAPI session API
├── run_server.py                  # `uvicorn` entrypoint
├── deploy/
│   └── systemd/
│       └── bigip-ts-validator.service   # sample systemd unit (Linux service)
├── frontend/                      # React (Vite) SPA
├── requirements.txt
├── examples/
│   └── as3-telemetry-resources.json            # static reference (CLI default --as3-file)
├── agents/
│   └── bigip-ts-validator.md
├── rpms/                          # RPM cache (tracked .gitkeep; *.rpm gitignored)
└── LICENSE
```

## Requirements

### Workstation

- Python 3.10 or newer (see [Installing prerequisites](#installing-prerequisites-on-linux-and-macos) for OS packages)
- For the **Web UI**: Node.js **18+** and `npm` to build `frontend/`
- Network reachability to the BIG-IP management interface (port 443)
- For `--install-prereqs`: outbound HTTPS to `api.github.com` and
  `github.com` to fetch RPMs (about ~55 MB combined for AS3 + TS)

### Installing prerequisites on Linux and macOS

Everything below is on the machine where you run the validator (laptop, jump
host, or CI agent), not on the BIG-IP.

**Common (CLI only)**

- **Git** — to clone the repository.
- **Python 3.10+** with **pip** and the **venv** module so you can run:
  `python3 -m venv .venv` then `.venv/bin/pip install -r requirements.txt`.

**macOS**

- Install Python 3.10+ using the [python.org macOS installer](https://www.python.org/downloads/macos/) or [Homebrew](https://brew.sh/):  
  `brew install python@3.12`  
  Then use that interpreter for the venv, for example:  
  `/opt/homebrew/opt/python@3.12/bin/python3 -m venv .venv`  
  (on Intel Homebrew, `/usr/local/opt/python@3.12/bin/python3` is typical).
- If `python3 -m venv` fails with *ensurepip is not available*, install a full
  Python from python.org or Homebrew; the system `/usr/bin/python3` on some
  macOS versions is stripped and not suitable for venvs.
- **Web UI only:** install **Node.js 18+** (LTS recommended), e.g.  
  `brew install node`  
  or the installer from [nodejs.org](https://nodejs.org/). You need `npm` for
  `cd frontend && npm install && npm run build`.

**Debian and Ubuntu**

```bash
sudo apt-get update
sudo apt-get install -y git curl ca-certificates python3 python3-venv python3-pip
python3 --version   # should be 3.10 or newer
```

If `python3` is older than 3.10, use [deadsnakes](https://launchpad.net/~deadsnakes/+archive/ubuntu/ppa) or install Python from python.org, then create the venv with that binary.

For the Web UI, install a current Node.js (distribution packages are often too old). Typical options: install **nvm** and then `nvm install --lts`, or follow [NodeSource](https://github.com/nodesource/distributions) for your Ubuntu/Debian release, or install the Linux binary from [nodejs.org](https://nodejs.org/).

**RHEL, Fedora, AlmaLinux, Rocky Linux**

```bash
# Fedora / RHEL 8+ with dnf
sudo dnf install -y git curl python3 python3-pip
python3 --version
```

On some images the venv module is separate:

```bash
sudo dnf install -y python3-virtualenv   # or: python3 -m ensurepip --user (if available)
python3 -m venv .venv
```

Amazon Linux 2 example:

```bash
sudo yum install -y git python3 python3-pip
python3 -m venv .venv   # if this fails: sudo yum install -y python3-virtualenv
```

Install Node.js for the Web UI via [nvm](https://github.com/nvm-sh/nvm), NodeSource, or the official tarball from nodejs.org. Distro `nodejs` packages may be below 18.

**Minimal / container images**

If `pip install -r requirements.txt` fails while building wheels (e.g. for
`pydantic-core`), install a compiler toolchain and Python headers, then retry.
Examples:

- Debian/Ubuntu: `sudo apt-get install -y build-essential python3-dev`
- RHEL/Fedora: `sudo dnf install -y gcc python3-devel`

### BIG-IP

- TMOS 14.1+ (TS 1.x and AS3 3.x require relatively modern TMOS)
- REST management interface enabled and reachable
- An admin account with permission to:
  - Authenticate via `/mgmt/shared/authn/login`
  - Upload to `/mgmt/shared/file-transfer/uploads/` (for `--install-prereqs`)
  - POST to `/mgmt/shared/iapp/package-management-tasks` (for `--install-prereqs`)
  - PATCH `/mgmt/tm/sys/provision/<module>` (only if you provision modules)
  - POST to `/mgmt/shared/appsvcs/declare` (AS3)
  - GET `/mgmt/shared/telemetry/declare` (TS, read-only validation)
  - POST to `/mgmt/tm/sys/config` with `command: save` (after AVR analytics
    global-settings in Web UI remediation)
- Modules: at minimum **LTM**. Depending on what you deploy, you may also need
  **AVR** (HTTP/TCP analytics), **ASM** (application security logging),
  **AFM** (network security logging), and/or **GTM/DNS** (when using DNS logging
  in the Web UI). See **Module compatibility** below.

## Installation

Install [host prerequisites](#installing-prerequisites-on-linux-and-macos) first, then:

```bash
git clone https://github.com/gregcoward/bigip_ts_validator.git
cd bigip_ts_validator
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

If your clone directory name differs, use that path in the commands below.

### Web UI (React + FastAPI)

The repository includes a small browser UI to connect to a BIG-IP, pick which
logging and analytics profiles to create (LTM, ASM, AFM, HTTP Analytics, TCP
Analytics), choose a [Telemetry Streaming push consumer](https://clouddocs.f5.com/products/extensions/f5-telemetry-streaming/latest/setting-up-consumer.html),
fill in consumer-specific parameters (HEC token, workspace keys, and so on),
validate readiness, and optionally install extensions, **provision TMOS modules**
(AVR when HTTP/TCP analytics are selected, ASM/AFM when those sources are selected),
POST an **AS3 declaration generated only for the telemetry options you checked** (no
extra logging profiles), and POST a composed TS declaration.

**Security model:** the BIG-IP password is sent once to this application's Python
process over HTTPS to your workstation. It is kept only in an in-memory session
(about 45 minutes of idle TTL) and is never written to disk or returned in API
responses. Run the API on `127.0.0.1` unless you intentionally expose it inside
a trusted management network.

```bash
# Terminal 1 — API (serves built UI from frontend/dist when present)
cd bigip_ts_validator
.venv/bin/pip install -r requirements.txt
cd frontend && npm install && npm run build && cd ..
.venv/bin/python run_server.py
# Open http://127.0.0.1:8000 when frontend/dist exists, else use Terminal 2.

# Terminal 2 — optional hot-reload UI during development
cd bigip_ts_validator/frontend
npm run dev
# Vite proxies /api to http://127.0.0.1:8000
```

API endpoints (for custom integrations): `POST /api/session`, `POST /api/session/{id}/validate`,
`POST /api/session/{id}/remediate`, `GET /api/consumers`, `GET /api/health`.

## Run as a Linux service (systemd)

These steps assume a **systemd**-based distribution (RHEL, AlmaLinux, Ubuntu
22.04+, Debian, etc.) and that the app lives at **`/opt/bigip-ts-validator`**
(adjust paths to match your install).

### 1. Install the application and build the UI

```bash
sudo mkdir -p /opt && sudo git clone https://github.com/gregcoward/bigip_ts_validator.git /opt/bigip-ts-validator
cd /opt/bigip-ts-validator
sudo python3 -m venv .venv
sudo .venv/bin/pip install --upgrade pip
sudo .venv/bin/pip install -r requirements.txt
cd frontend && sudo npm ci && sudo npm run build && cd ..
```

Using `sudo` here is only for illustration; on your own hosts you may prefer a
dedicated deployment user with write access to `/opt/bigip-ts-validator`.

### 2. Create an unprivileged service account

```bash
sudo useradd --system --home /opt/bigip-ts-validator --shell /usr/sbin/nologin \
  --user-group bigip-ts
sudo chown -R bigip-ts:bigip-ts /opt/bigip-ts-validator
```

The service needs **read** access to the repo and `frontend/dist`, and **write**
access to `rpms/` if operators use **Install missing AS3 / TS RPMs** from the UI.

### 3. Install a systemd unit

The canonical unit file is **`deploy/systemd/bigip-ts-validator.service`**
(paths assume the repo lives at **`/opt/bigip-ts-validator`**). Copy it into
place, then edit **`User`**, **`Group`**, **`WorkingDirectory`**, and
**`ExecStart`** if your layout differs:

```bash
sudo cp /opt/bigip-ts-validator/deploy/systemd/bigip-ts-validator.service /etc/systemd/system/
sudo nano /etc/systemd/system/bigip-ts-validator.service   # adjust if needed
```

Defaults in the sample: runs as **`bigip-ts`**, binds Uvicorn to **`127.0.0.1:8000`**
(no `--reload`), and **`ProtectSystem=true`** (so **`/opt`** stays visible; do not
use **`ProtectSystem=strict`** here unless you also whitelist the whole app tree
— otherwise you get **`status=226/NAMESPACE`**). The sample does **not** use
**`ReadWritePaths=`** on **`rpms/`**: systemd requires that path to exist at
start-up, and a fresh clone may not have **`rpms/`** yet; with **`true`**, the
service user can still create **`rpms/`** on first RPM download.

Install notes live in the README only: the unit file **starts with `[Unit]`** so
systemd never sees “assignments” before a section (some versions warn on long
comment blocks before the first header).

To listen on **all interfaces**, change **`--host 127.0.0.1`** to **`--host 0.0.0.0`**
in **`ExecStart`** and restrict access with **firewall** rules.

Reload systemd and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now bigip-ts-validator.service
sudo systemctl status bigip-ts-validator.service
```

Verify locally:

```bash
curl -sS http://127.0.0.1:8000/api/health
```

Open **`http://127.0.0.1:8000/`** in a browser on the same host (or tunnel via
SSH: `ssh -L 8000:127.0.0.1:8000 user@server`).

If **`status`** shows **`code=exited, status=226/NAMESPACE`**, you were likely on
an older sample using **`ProtectSystem=strict`** without whitelisting the app tree.
Re-copy **`deploy/systemd/bigip-ts-validator.service`**, run **`systemctl
daemon-reload`**, then **`systemctl restart`**. Use **`journalctl -u
bigip-ts-validator.service -b`** for Python tracebacks (missing **`venv`**, import
errors, or permission denied on **`WorkingDirectory`**).

### 4. Logs and operations

```bash
sudo journalctl -u bigip-ts-validator.service -f       # follow logs
sudo systemctl restart bigip-ts-validator.service     # after code or dependency updates
```

After `git pull` or changing Python dependencies, run **`pip install -r
requirements.txt`** (and **`npm run build`** if the frontend changed), then
**`systemctl restart`**.

## Run on Kubernetes

The Web UI is a single process (FastAPI + uvicorn) that serves the built React
SPA from `frontend/dist` on port **8000**. There is no Dockerfile or Helm chart
in the repo yet (see [Roadmap](#frontend-ui)); use the patterns below to run it
on a cluster.

**Security model (same as local / systemd):** operators POST BIG-IP credentials
to this app. Passwords are kept only in an **in-memory session** (about **45
minutes** idle TTL) and are never written to disk or returned in API responses.
Treat the workload as an **internal management-plane** console — TLS at Ingress,
VPN / private DNS, NetworkPolicy egress limited to BIG-IP management ranges, and
preferably an identity-aware proxy or SSO in front of the UI. Do **not** expose
it on the public internet.

### Constraints that drive the cluster design

| Constraint | Implication |
|------------|-------------|
| Sessions are process-local (`server/app.py`) | Run **`replicas: 1`**. Horizontal scale requires an external session store the app does not have today. |
| Remediate can download RPMs / provision modules / POST AS3+TS for many minutes | Set Ingress (and any reverse proxy) **read/send timeouts ≥ 900s** (same guidance as the Vite proxy and `run_server.py` banner). |
| Optional RPM install writes under `./rpms` | Mount a writable volume at `/app/rpms` (EmptyDir or PVC). Air-gapped: pre-bake RPMs into the image or volume instead of allowing GitHub egress. |
| Production entrypoint | Use **`uvicorn server.app:app --host 0.0.0.0 --port 8000`**. Do **not** use `run_server.py` in the cluster — it enables `--reload`. |
| Health check | `GET /api/health` on port 8000 (liveness and readiness). |

Traffic path: operator browser → Ingress (TLS) → ClusterIP Service `:8000` →
app pod → BIG-IP management HTTPS (`:443`). Optional dashed egress to
`api.github.com` / GitHub release CDN only when **Install missing AS3 / TS RPMs**
is used (~55 MB combined).

### Suggested multi-stage Dockerfile

Build the UI with Node 18+, then a Python 3.10+ (3.12 recommended) runtime image
that installs `requirements.txt`, copies app sources and `frontend/dist`, and
runs as a non-root user:

```dockerfile
# syntax=docker/dockerfile:1
FROM node:20-alpine AS ui
WORKDIR /src/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim AS runtime
WORKDIR /app
RUN useradd -r -u 10001 appuser
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=appuser:appuser \
  bigip_ts_validator.py as3_services.py ts_declaration_builder.py \
  run_server.py server/ examples/ ./
COPY --from=ui --chown=appuser:appuser /src/frontend/dist ./frontend/dist
RUN mkdir -p /app/rpms && chown appuser:appuser /app/rpms
USER appuser
EXPOSE 8000
CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "8000"]
```

Build and push to your registry (adjust the image name and tag):

```bash
docker build -t YOUR_REGISTRY/bigip-ts-validator:VERSION .
docker push YOUR_REGISTRY/bigip-ts-validator:VERSION
```

### Minimal Deployment and Service

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bigip-ts-validator
  namespace: bigip-ts-tools
spec:
  replicas: 1
  selector:
    matchLabels:
      app: bigip-ts-validator
  template:
    metadata:
      labels:
        app: bigip-ts-validator
    spec:
      containers:
        - name: app
          image: YOUR_REGISTRY/bigip-ts-validator:VERSION
          ports:
            - containerPort: 8000
              name: http
          volumeMounts:
            - name: rpm-cache
              mountPath: /app/rpms
          readinessProbe:
            httpGet:
              path: /api/health
              port: http
            initialDelaySeconds: 5
            periodSeconds: 10
          livenessProbe:
            httpGet:
              path: /api/health
              port: http
            initialDelaySeconds: 15
            periodSeconds: 20
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
          securityContext:
            allowPrivilegeEscalation: false
            runAsNonRoot: true
            runAsUser: 10001
      volumes:
        - name: rpm-cache
          emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: bigip-ts-validator
  namespace: bigip-ts-tools
spec:
  selector:
    app: bigip-ts-validator
  ports:
    - port: 8000
      targetPort: http
      name: http
```

Starting resource requests are deliberately small; raise memory if operators run
concurrent remediations that cache large RPMs.

### Ingress timeouts

**nginx Ingress example annotations:**

```yaml
nginx.ingress.kubernetes.io/proxy-read-timeout: "900"
nginx.ingress.kubernetes.io/proxy-send-timeout: "900"
nginx.ingress.kubernetes.io/proxy-connect-timeout: "60"
```

**Traefik:** configure a middleware (or IngressRoute) with responding /
read timeouts of **900s** for the `/api` paths used by validate and remediate.
Without this, long RPM installs or module provisioning often surface as **504**
errors even though the pod is still working.

Also terminate TLS on the Ingress and restrict who can reach the hostname
(private DNS, allow-lists, or an auth proxy).

### NetworkPolicy outline

- **Ingress:** allow only from the Ingress controller (or mesh gateway) to
  pod port 8000.
- **Egress:** DNS; HTTPS to BIG-IP management CIDRs the operators will target;
  optionally HTTPS to GitHub if RPM install from the UI is enabled. Deny
  everything else by default.

### Deploy and verify

1. Create the namespace (for example `bigip-ts-tools`).
2. Build and push the image; apply Deployment and Service (and NetworkPolicy).
3. Attach an internal TLS Ingress with **≥900s** proxy timeouts.
4. Check health: `curl -sS https://<host>/api/health`
5. Open the UI, connect to a lab BIG-IP, run **validate** before any remediate.
6. If using install-prereqs, confirm a full remediate finishes without Ingress
   timeouts.

## Inputs

| Input            | Where it goes                | Notes                                                                 |
|------------------|------------------------------|-----------------------------------------------------------------------|
| BIG-IP host      | `--host <ip-or-hostname>`    | Required. Management address.                                         |
| Username         | `--username <name>`          | Required. Admin or admin-equivalent.                                  |
| Password         | `$BIGIP_PASSWORD` (preferred), `--password`, or interactive `getpass` prompt | Avoid passing on the command line — it shows in shell history / `ps`. |
| Consumer type    | `--consumer <Type>`          | Required. e.g. `Splunk`, `Azure_Log_Analytics`, `AWS_CloudWatch`, `DataDog` (BIG-IP spelling; `Datadog` is accepted as an alias), `Generic_HTTP`, `Sumo_Logic`, `ElasticSearch`. |
| AS3 file         | `--as3-file <path>`          | Optional. Defaults to `examples/as3-telemetry-resources.json`.        |
| Install prereqs  | `--install-prereqs`          | Optional. Download + install AS3/TS RPMs if missing.                  |
| Pin AS3 version  | `--as3-version vX.Y.Z`       | Optional. Defaults to GitHub `latest` for `F5Networks/f5-appsvcs-extension`. |
| Pin TS version   | `--ts-version vX.Y.Z`        | Optional. Defaults to GitHub `latest` for `F5Networks/f5-telemetry-streaming`. |
| RPM cache dir    | `--rpm-cache-dir <path>`     | Optional. Defaults to `./rpms`.                                       |
| Mode             | `--no-remediate` / `--yes`   | `--no-remediate` is read-only. `--yes` skips both install and AS3 confirmations. |
| TLS              | `--verify-tls`               | Optional. Off by default since lab boxes usually have self-signed certs. |
| Output           | `--json`                     | Optional. Append the final findings as JSON to stdout.                |

## Usage

### Validate only

```bash
export BIGIP_PASSWORD='...'
.venv/bin/python bigip_ts_validator.py \
    --host 10.0.0.10 --username admin --consumer Splunk --no-remediate
```

### Validate, install missing extensions, apply AS3

```bash
export BIGIP_PASSWORD='...'
.venv/bin/python bigip_ts_validator.py \
    --host 10.0.0.10 --username admin --consumer Splunk \
    --install-prereqs --yes
```

## Workflow steps

1. **Authenticate** — POST `/mgmt/shared/authn/login`. The returned token is
   used for the rest of the session and re-issued after any TMOS-side restart
   (extension install, module provisioning).
2. **Probe extensions** — GET `/mgmt/shared/appsvcs/info` and
   `/mgmt/shared/telemetry/info`.
3. **(Optional) Install extensions** — when `--install-prereqs` is set and an
   extension is missing:
   - Resolve the GitHub release (`latest` unless pinned).
   - Download the `.noarch.rpm` to `./rpms/` (cached; re-runs are fast).
   - Confirm in chat (unless `--yes`) showing the host, RPM name and tag.
   - Chunk-upload (`Content-Range` framing) to
     `/mgmt/shared/file-transfer/uploads/<name>`. The upload lands at
     `/var/config/rest/downloads/<name>` on the BIG-IP.
   - POST to `/mgmt/shared/iapp/package-management-tasks` with
     `{operation: "INSTALL", packageFilePath: ...}`.
   - Poll the task ID until `FINISHED` (or fail on `FAILED`/`CANCELED`).
   - Wait for the extension's `/info` endpoint to return.
4. **Validate AS3 resources** — GET `/mgmt/shared/appsvcs/declare`, dig into
   `Common.Shared`, and check each required class is present.
5. **Validate TS consumer** — GET `/mgmt/shared/telemetry/declare` and walk
   the document for `class: Telemetry_Consumer` with a `type` matching
   `--consumer`.
6. **Print report** — `[OK]`, `[WARN]`, `[MISSING]` lines and an overall
   `READY` / `NOT READY` verdict.
7. **(Optional) Remediate** — unless `--no-remediate`, when missing AS3
   resources are present:
   - Show the AS3 file and the host.
   - Confirm in chat (unless `--yes`).
   - POST the AS3 to `/mgmt/shared/appsvcs/declare`.
   - Re-run the validation.

## What is validated

Depending on context, the tool checks only the AS3 objects that should exist for
your **selected telemetry sources** (Web UI and API), or—when you use the CLI
without a service scope—the full set matching the default `--as3-file` example
(all LTM / ASM / AFM / DNS / analytics profiles below).

Possible objects under `/Common/Shared` (subset required per selection):

| Object                                  | Class                  |
|-----------------------------------------|------------------------|
| `telemetry`                             | `Pool`                 |
| `telemetry_hsl`                         | `Log_Destination`      |
| `telemetry_formatted`                   | `Log_Destination`      |
| `telemetry_publisher`                   | `Log_Publisher`        |
| `telemetry_traffic_log_profile`         | `Traffic_Log_Profile`  |
| `telemetry_http_analytics_profile`      | `Analytics_Profile`    |
| `telemetry_tcp_analytics_profile`       | `Analytics_TCP_Profile`|
| `telemetry_asm_security_log_profile`    | `Security_Log_Profile` |
| `telemetry_dns_logging`                 | `DNS_Logging_Profile`  |

When **DNS (GTM) logging** is selected in the Web UI or API, AS3 declares
**`telemetry_dns_logging`** (`DNS_Logging_Profile`) with **`logPublisher`** pointing at
the Shared **`telemetry_publisher`** (so the same HSL → Splunk-formatted →
publisher chain as LTM/AFM). The **GTM / DNS services** module must be
provisioned on the BIG-IP (TMOS **`gtm`** slot in **`/mgmt/tm/sys/provision`** on
most images). Attach the published logging profile to **DNS profiles** or other
objects per F5 documentation for your version; this tool only creates the Shared
publisher chain and **`DNS_Logging_Profile`**.

Optional objects (only needed for the TS "local listener" pattern, missing is a `[WARN]`):

| Object                  | Class         |
|-------------------------|---------------|
| `telemetry_local_rule`  | `iRule`       |
| `telemetry_local`       | `Service_TCP` |

## Exit codes

| Code | Meaning                                    |
|------|--------------------------------------------|
| 0    | Device is READY for the named consumer     |
| 1    | Device is NOT READY                        |
| 2    | Configuration / connectivity / auth error  |
| 3    | AS3 declaration apply failed               |
| 4    | iControl LX extension install failed       |

## Module compatibility

The **Web UI** and remediation API build AS3 **only for the options you select**
(for example, AFM logging objects are omitted if AFM is unchecked, so you do
not need a separate “AFM-free” declaration file).

If you still use the CLI with the default `examples/as3-telemetry-resources.json`,
that static file includes **AVR**, **ASM**, **AFM**, and optional **`DNS_Logging_Profile`**
objects together.
AS3 returns HTTP **422** if a referenced module is not provisioned on the box.

Mitigations:

- **Web UI:** clear telemetry sources you are not licensed for, enable **Provision
  required TMOS modules** when remediating, or provision modules yourself.
- **CLI:** supply your own `--as3-file` that matches the modules on the device, or
  provision missing modules (PATCH `/mgmt/tm/sys/provision/<m>` with
  `{"level": "nominal"}`). Provisioning causes a short REST/TMM restart and may
  exceed CPU/RAM on small vBIG-IPs.

**Provisioning 400 / 01071003 (“previous provisioning operation is in progress”):**
TMOS applies one module change at a time. Remediation **PATCHes each required
module in sequence**, **waits** for that module to finish provisioning before the
next, and each PATCH **retries** (with backoff) while the device reports a busy
state. If you still see this after other admin activity, wait until the BIG-IP
finishes its current provisioning cycle, then run **validate + remediate** again.

**Provisioning / Config Utility 503 (“Configuration Utility restarting…”):**
After AS3/TS RPM install (or a prior module change), iControl REST often returns
**503** HTML for `GET/PATCH /mgmt/tm/sys/provision` until `restjavad` / Tomcat
finish restarting. The Web UI and CLI **retry and re-authenticate** for several
minutes before failing. If remediation still stops here, open the BIG-IP GUI
until the dashboard loads again, then re-run **validate + remediate** (you can
uncheck Install RPMs if they already succeeded).

**AVR and Telemetry Streaming (F5 guidance):** F5 documents pointing AVR at the
TS Log Publisher in [Modifying AVR configuration to use the Log
Publisher](https://clouddocs.f5.com/products/extensions/f5-telemetry-streaming/latest/avr.html#modifying-avr-configuration-to-use-the-log-publisher)
(**Exporting data from AVR**). That page lists prerequisites (AVR provisioned,
TS **Event Listener** with an existing Log Publisher—see [Event Listener /
logging sources](https://clouddocs.f5.com/products/extensions/f5-telemetry-streaming/latest/event-listener.html),
analytics profiles on virtual servers) and the **tmsh** form:

`modify analytics global-settings { external-logging-publisher /Common/telemetry_publisher offbox-protocol hsl use-offbox enabled }`

(use your publisher’s full path if the name differs).

When you enable **HTTP Analytics** or **TCP Analytics** here and remediation runs
**Apply AS3**, the Web UI path **PATCHes**
[`/mgmt/tm/analytics/global-settings`](https://clouddocs.f5.com/api/icontrol-rest/APIRef_tm_analytics_global-settings.html)
with **`externalLoggingPublisher`**, **`useHsl`**, and **`useOffbox`** (REST
equivalent of that **tmsh** line). The default publisher is
**`/Common/Shared/telemetry_publisher`**, matching this tool’s AS3 **Shared**
Log Publisher. Set **`avr_log_publisher_fullpath`** on **`POST .../remediate`**
for **`/Common/telemetry_publisher`** or any other path. It then **POSTs**
[`/mgmt/tm/sys/config`](https://clouddocs.f5.com/api/icontrol-rest/APIRef_tm_sys_config.html)
with **`{"command":"save"}`** (**`tmsh save sys config`**) so the configuration
is written to disk.

**ASM and AS3 422 (`localhost:8100`, `Connection refused`):** after provisioning
ASM (or other restarts), AS3 may still return **422** while it queries
`/mgmt/tm/asm/policies` through an on-box listener (often **localhost:8100**)
that is not accepting connections yet. That is a **warm-up race**, not a bad
declaration. The Web UI remediation path waits on **`GET /mgmt/tm/asm/policies`**
when **ASM** is selected, then **retries** the AS3 POST on transient 422
responses. If it still fails, wait one to two minutes and run **validate +
remediate** again without re-installing RPMs.

## Limitations and known gaps

- **TS declaration creation (CLI).** The CLI still reports whether a
  `Telemetry_Consumer` of the expected type exists, but does not POST a new
  declaration. Use the **Web UI** (or call `BigIPClient.post_ts_declaration`
  yourself) to push a composed consumer declaration to
  `/mgmt/shared/telemetry/declare`.
- **TLS verification off by default.** Lab boxes typically have self-signed
  certs; `--verify-tls` opts in to certificate validation.
- **`--install-prereqs` requires internet access** from the workstation
  running the script (to `api.github.com` and the GitHub release CDN).
  Air-gapped environments need a pre-downloaded RPM cache pointed at via
  `--rpm-cache-dir`.
- **Single-device.** No batch or fleet-wide operation. Loop the script over
  a list of hosts if you need that.
- **No rollback.** AS3 is declarative so re-applying an old declaration
  reverts changes, but the script does not snapshot or restore state on
  failure.
- **BIG-IQ / Statistics Collection.** F5 notes that if the device is managed by
  BIG-IQ with Statistics Collection enabled, AVR configuration may be
  overwritten to publish only to BIG-IQ, which can conflict with TS-oriented AVR
  setup. See [Exporting data from AVR](https://clouddocs.f5.com/products/extensions/f5-telemetry-streaming/latest/avr.html).

## Roadmap

### Near term

- `--ts-declaration <file>`: POST a TS declaration from the CLI (the Web UI
  already performs an equivalent POST for common consumers).
- `--provision <module>:<level>`: provision an arbitrary module from the CLI
  (currently done out-of-band; the AVR provisioning flow was inlined for
  the lab session).
- Make the `Analytics_Profile` / `Analytics_TCP_Profile` checks
  module-conditional: `[WARN]` instead of `[MISSING]` when AVR isn't
  provisioned.
- Optional structured logging (`--log-format json`) to feed CI pipelines.

### Frontend UI

Delivered as `server/app.py` + `frontend/` (see **Web UI** above). Remaining
nice-to-haves: library split for cleaner imports, SSE for long RPM installs,
and a packaged `Dockerfile` / `deploy/k8s` manifests (deployment guidance for
Kubernetes is documented under [Run on Kubernetes](#run-on-kubernetes)).

### Stretch

- Fleet view (validate N BIG-IPs in parallel, group by readiness state).
- Optional integration with F5 BIG-IQ for credentials and inventory.
- Compatibility matrix view: show which telemetry source and module combination
  will work for a given device, based on what is provisioned.

## Contributing

Conventional Git workflow. The Python is targeted at 3.10+, uses standard
library + `requests`, and stays under 400 lines for readability. Don't add
abstractions without a second use case in sight.

## License

See [LICENSE](LICENSE).
