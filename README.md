# SNMPathy

**Self-hosted network monitoring: SNMP polling, syslog ingest, uptime checks, alerting,
Grafana-style dashboards and reporting in one small Python service.**

SNMPathy covers the everyday jobs of tools like Zabbix, Observium, PRTG, Uptime Robot
and a lightweight ELK stack:

| Area | What you get |
|---|---|
| **SNMP polling** (Observium / PRTG style) | v1, v2c and v3 (auth + priv). Auto-discovery of system info, vendor, every interface (64-bit counters when available), CPU, memory, storage and load averages. Custom OIDs per device. Traffic, utilisation, errors and discards per port. Reboot and port up/down detection. |
| **Syslog** (ELK style) | UDP and TCP listeners (RFC 5424, RFC 3164, RFC 6587 framing, Cisco / Juniper / FortiGate variants). Full-text search, filters by host / app / severity / facility / time, volume histogram, top-N facets and live tail. |
| **Uptime checks** (Uptime Robot style) | ICMP ping, TCP port, HTTP(S) (status code, keyword, TLS certificate expiry), DNS and SNMP checks with retry-before-down, outage history, 90-day uptime bars and a public status page. |
| **Alerting** (Zabbix style) | Threshold rules on any metric (with wildcards), device-unreachable, check-down and syslog pattern rules. Pending → firing → resolved lifecycle, "for" durations, acknowledgements, maintenance windows. Notifications via email, Slack / Mattermost, Microsoft Teams, Discord, PagerDuty and generic webhooks. |
| **Dashboards** (Grafana style) | Built-in, editable dashboards with 13 panel types, a time-range picker, auto-refresh, light / dark themes, a kiosk / TV mode and a JSON model editor. Five dashboards ship ready to use. |
| **Grafana integration** | A Grafana JSON data-source endpoint at `/grafana`, plus five pre-built Grafana dashboards that are provisioned automatically by the Docker Compose stack. |
| **Reporting** | Availability / SLA, device health, bandwidth with 95th percentile and data volume, syslog summary and alert history. Each report can be viewed in the browser, exported to CSV, printed or saved as PDF, and scheduled for daily, weekly or monthly delivery by email, chat or webhook. |
| **Everything is an API** | A REST API with interactive OpenAPI docs at `/docs`. Configuration can be exported and imported as JSON. |

It runs anywhere Python 3.10+ runs (**Windows, macOS, Linux**) or in **Docker**. There is
nothing else to install: data lives in a single SQLite file.

---

## Quick start

### Try it with simulated devices (30 seconds)

```bash
pip install .
snmpathy demo
```

Open <http://localhost:8080>. Demo mode creates seven simulated devices (switches, a
firewall, servers, a NAS, a flaky branch router and an access point), five web / TCP / DNS
checks, a week of history and a live syslog feed, so every page, dashboard and report has
data. It uses its own database (`snmpathy-demo.db`), and you can add real devices alongside
the simulated ones.

### Linux / macOS

```bash
python3 -m venv ~/.snmpathy && source ~/.snmpathy/bin/activate
pip install .                      # from a checkout of this repository
snmpathy init-config               # writes snmpathy.yaml (optional)
snmpathy serve --config snmpathy.yaml
```

### Windows (PowerShell)

```powershell
py -3 -m venv $env:USERPROFILE\snmpathy
& $env:USERPROFILE\snmpathy\Scripts\Activate.ps1
pip install .
snmpathy serve
```

To run it as a Windows service see [`deploy/windows`](deploy/windows). The syslog port
needs an inbound firewall rule: `New-NetFirewallRule -DisplayName SNMPathy-Syslog -Direction Inbound -Protocol UDP -LocalPort 5514 -Action Allow`.

### Standalone executable (no Python needed to run it)

Build a single-file `SNMPathy.exe` (Windows) or `SNMPathy` (macOS / Linux) and store it in
your **Claude folder**, next to KASTR, DiskWorks and LinkTest:

```text
Windows:        scripts\build_executable.cmd          (double-click, or run from a prompt)
macOS / Linux:  ./scripts/build_executable.sh
```

The script builds in an isolated environment under `build/`, smoke-tests the result and
copies it into `<Claude folder>/SNMPathy/`. It finds the Claude folder by looking for the
one that contains KASTR, DiskWorks or LinkTest, starting with the folders above this
repository and then `~`, `~/Documents` and OneDrive. It also writes a default
`snmpathy.yaml` and a `README.txt` there. Rebuilding replaces only the executable:
the database and configuration are kept. Use `--dest <folder>` or the `SNMPATHY_EXE_DIR`
variable to store it somewhere else, or `--no-copy` to only build into `dist/`.

```text
Claude/
├── DiskWorks/
├── KASTR/
├── LinkTest/
└── SNMPathy/
    ├── SNMPathy.exe      double-click: starts the server and opens http://localhost:8080
    ├── snmpathy.yaml     configuration (edit, then restart)
    ├── snmpathy.db       all data (created on first start)
    └── README.txt
```

The script prints `step 1/4` to `step 4/4` as it runs and ends with **BUILD OK** or
**BUILD FAILED**. If it fails, the cause is the first `ERROR` line above that message;
run the script again with `--fresh` to rebuild its environment from scratch. The build
uses its own pip cache in `build/pip-cache`, so pip's "Cache entry deserialization
failed" warnings from a shared cache don't apply.

The packaged app keeps its database and configuration next to the executable, whatever
directory it is started from. PyInstaller builds for the OS it runs on. CI also builds the
Windows, macOS and Linux executables on every push; download them from the run's
*Artifacts* section.

### Docker

```bash
docker compose up -d                 # SNMPathy only
docker compose --profile grafana up -d   # SNMPathy + Grafana with dashboards pre-provisioned
```

* SNMPathy: <http://localhost:8080>
* Grafana (optional profile): <http://localhost:3000> (admin / admin on first login)
* Syslog: UDP and TCP port **514** on the host, mapped to 5514 in the container

Data is kept in the `snmpathy-data` volume. To try the demo in Docker:
`docker build -t snmpathy . && docker run --rm -p 8080:8080 snmpathy snmpathy demo`.

---

## Using SNMPathy

### Add devices

Go to **Devices → Add device** and enter the hostname or IP and the SNMP credentials. Use
**Test SNMP** to confirm they work before saving. Each new device gets a ping check
automatically; untick that option if you don't want one. Discovery runs straight away and
then every 6 hours.

From the command line:

```bash
snmpathy add-device core-sw01 10.0.0.1 -c public --tag core
snmpathy add-device fw01 10.0.0.2 -v 3 -u monitor -a sha -A 'authpass' -x aes -X 'privpass'
```

The built-in SNMP tools work on every platform, including Windows where net-snmp is not
usually installed:

```bash
snmpathy get 10.0.0.1 1.3.6.1.2.1.1.5.0
snmpathy walk 10.0.0.1 1.3.6.1.2.1.2.2.1.2
snmpathy discover 10.0.0.1 -c public      # shows exactly what would be monitored
snmpathy ping 10.0.0.1
```

**What is collected:** sysDescr / sysObjectID / uptime / location / contact, vendor
detection (40+ vendors), ifTable / ifXTable, HOST-RESOURCES CPU and storage, and UCD-SNMP
load and memory. **Custom metrics:** on a device's *Metrics* tab, add any numeric OID as
a gauge, counter (converted to a rate) or ratio.

### Syslog

Point your devices at the SNMPathy host on port **5514** (UDP or TCP). Port 514 needs
root or Administrator rights; with Docker, map 514 to 5514. Examples:

```text
# Cisco IOS
logging host 192.0.2.10 transport udp port 5514
# Juniper
set system syslog host 192.0.2.10 any any port 5514
# rsyslog (/etc/rsyslog.d/snmpathy.conf)
*.* @@192.0.2.10:5514
```

To test it: `snmpathy send-syslog "hello from the CLI" --severity 3`.

Search syntax: plain words match anywhere, `"exact phrase"`, `-exclude`, `prefix*`,
and `AND` / `OR` / `NOT`. Filter by host (wildcards allowed), app, minimum severity,
facility and time range. You can click any facet value to filter by it.

### Uptime checks

**Uptime checks → Add check**:

| Type | Target | Options |
|---|---|---|
| `icmp` | host / IP | packet count |
| `tcp` | host + port | |
| `http` | URL | method, expected status (`200-399`, `200,204`, `2xx`), keyword present / absent, TLS verification, certificate-expiry warning (days) |
| `dns` | name | expected address |
| `snmp` | host | uses the device's credentials |

A check is marked down only after *retries + 1* consecutive failures. While it is failing
it is probed faster. Outages are backdated to the first failure, so the downtime figures
are accurate. Tick **Public** to show a check on `/status`.

ICMP uses raw sockets when the process is allowed to (root or CAP_NET_RAW, which Docker
grants by default), unprivileged ICMP sockets on macOS and suitably configured Linux,
and otherwise falls back to the system `ping` (always used on Windows) and finally to a
TCP probe. `snmpathy ping <host>` shows which mode is in use.

### Alerts and notifications

Default rules are created on first start: device unreachable, check down, high CPU, high
memory, disk almost full, interface saturated, interface errors and critical syslog.
Edit them or add your own under **Alerts → Rules**:

* **metric**: `cpu.avg > 90 for 600s`. Keys accept wildcards (`if.*_util`), instances
  accept globs (`Gi1/0/*`), and rules can be scoped to one device or a device tag.
* **check / device**: fires when a check is down or a device stops answering SNMP.
* **syslog**: N matching messages per host within a window (search query plus a minimum
  severity).

Add notification channels under **Alerts → Channels** and use **Test** to send a sample
message. A rule with no channels selected notifies every enabled channel. **Maintenance
windows** (for everything, one device or one check) suppress alerts and are excluded from
SLA calculations.

### Dashboards

**Dashboards** lists the built-in boards (Network Overview, Traffic & Interfaces, Server &
Device Health, Availability, Syslog) and any you create. On any board you can:

* pick a time range (15 minutes to 1 year, or a custom range) and an auto-refresh interval
* **Edit layout**: add, remove, reorder, resize or duplicate panels
* **Edit** a panel: choose the visualisation (time series lines / area / stacked bars,
  stat, gauge, top-N table, status grid, uptime bars, syslog volume / stream / top,
  firing alerts, events, overview counters, text), its queries (metric key + device /
  tag / instance filters + aggregation), units, thresholds, Y-axis limits and legend
  style, with a live preview
* **Kiosk** mode for a wall display, **JSON** to export or import a board, **Duplicate**

### Grafana

SNMPathy works as a data source for the Grafana
[JSON data source plugin](https://grafana.com/grafana/plugins/simpod-json-datasource/)
(`simpod-json-datasource`).

* **Docker:** `docker compose --profile grafana up -d`. The plugin, the data source and
  five dashboards (Overview, Device, Traffic & Interfaces, Availability, Syslog) are all
  provisioned for you.
* **Existing Grafana:** install the plugin, add a *JSON* data source with URL
  `http://<snmpathy-host>:8080/grafana` (add the header `X-API-Key: <token>` if you set an
  API token), then import the dashboards from **Settings → Grafana** in SNMPathy or from
  [`deploy/grafana/provisioning/dashboards/json`](deploy/grafana/provisioning/dashboards/json).
  To regenerate the provisioning files, run `snmpathy grafana-export <dir>`.

Query targets: `metric` (payload `key`, `device`, `tag`, `instance`, `agg`, `limit`),
`check` (response time or availability), `syslog` (message counts), `count` (single
values) and the tables `devices`, `checks`, `interfaces`, `alerts`, `syslog_events`,
`events` and `top`. Template variables: `devices`, `tags`, `checks`, `keys`,
`interfaces <device>`, `hosts`.

### Reports

**Reports** offers five reports, each for any time range (a sliding window such as
`24h` / `7d` / `30d`, or a calendar period such as yesterday, last week or last month),
optionally filtered to a device or tag:

| Report | Contents |
|---|---|
| Availability / SLA | uptime % per check vs. an SLA target, downtime, outages, longest outage, MTTR, MTBF, response time, outage list |
| Device health | CPU / memory averages and peaks, fullest disk, ping availability, SNMP response time, reboots, ports down, log errors, flagged issues |
| Bandwidth & 95th percentile | per-interface average / peak / 95th percentile (from 5-minute averages, the burstable-billing method), utilisation, and GB received / sent |
| Syslog summary | volume by severity, top hosts and apps, most frequent warning / error patterns (numbers, IPs and MACs collapsed), per-day counts |
| Alert history | alerts fired by rule and severity, noisiest subjects, mean time to acknowledge and to resolve |

Every report has **CSV** export and a print-friendly layout you can save as PDF. You can
also schedule a report for daily, weekly or monthly delivery: email sends HTML plus a CSV
attachment, Slack / Teams / Discord get a summary, and a webhook receives the JSON.

---

## Configuration

Settings come from built-in defaults, then a YAML file (`--config` or `SNMPATHY_CONFIG`),
then environment variables named `SNMPATHY_<SETTING>`. Run `snmpathy init-config` for a
commented example.

| Setting | Default | |
|---|---|---|
| `database` | `snmpathy.db` | SQLite file |
| `http_host` / `http_port` | `0.0.0.0` / `8080` | web UI, API and Grafana endpoint |
| `api_token` | *(empty)* | when set, the UI asks for it at login and the API requires `Authorization: Bearer <token>` or `X-API-Key` |
| `public_url` | *(empty)* | external URL used for links in notifications and reports |
| `syslog_host` / `syslog_udp_port` / `syslog_tcp_port` | `0.0.0.0` / `5514` / `5514` | `0` disables a listener |
| `default_poll_interval` | `300` | seconds between SNMP polls (per device override) |
| `default_check_interval` | `60` | seconds between checks (per check override) |
| `poller_concurrency` | `64` | simultaneous polls and checks |
| `snmp_timeout` / `snmp_retries` | `2.0` / `1` | |
| `retention_raw_days` | `7` | raw samples; 5-minute rollups kept 35 days, hourly rollups for `retention_rollup_days` |
| `retention_rollup_days` | `400` | |
| `retention_syslog_days` | `30` | |
| `retention_heartbeat_days` | `90` | check results |
| `alert_eval_interval` | `30` | seconds (state changes also trigger an immediate evaluation) |
| `smtp_host`, `smtp_port`, `smtp_user`, `smtp_password`, `smtp_from`, `smtp_starttls` | | defaults for email channels |

The CLI flags `--db`, `--host`, `--port`, `--syslog-udp`, `--syslog-tcp`, `--token`,
`--no-syslog` and `--no-poller` override the file.

## Running as a service

| Platform | How |
|---|---|
| Linux (systemd) | [`deploy/systemd/snmpathy.service`](deploy/systemd/snmpathy.service) |
| macOS (launchd) | [`deploy/macos/com.snmpathy.agent.plist`](deploy/macos/com.snmpathy.agent.plist) |
| Windows | [`deploy/windows/install-service.ps1`](deploy/windows/install-service.ps1) (NSSM or a scheduled task) |
| Docker | [`Dockerfile`](Dockerfile), [`docker-compose.yml`](docker-compose.yml) |

Back up by copying the SQLite file (safe while running, thanks to WAL mode, via
`sqlite3 snmpathy.db ".backup backup.db"`). Configuration alone can be exported with
`snmpathy export config.json` and restored with `snmpathy import config.json`.

## API

Interactive docs are at `/docs`. Some examples:

```bash
curl localhost:8080/api/status
curl -X POST localhost:8080/api/devices -H 'Content-Type: application/json' \
     -d '{"name":"edge1","hostname":"10.0.0.9","snmp_community":"public","tags":["wan"]}'
curl 'localhost:8080/api/syslog?q=%22link%20down%22&severity=4&range=24h'
curl 'localhost:8080/api/reports/bandwidth?range=last_month&format=csv' -o bandwidth.csv
curl -X POST 'localhost:8080/api/query?range=7d' -H 'Content-Type: application/json' \
     -d '{"key":"if.in_bps","device":"core-sw01","limit":5}'
```

## Architecture

Everything runs as one asyncio process: FastAPI serves the UI and API, and background tasks
handle SNMP polling, checks, the syslog listeners, alert evaluation, rollups, retention and
scheduled reports. All data is stored in one SQLite database in WAL mode. For the full
design, data model and requirements, see
[`docs/ARCHITECTURE_AND_REQUIREMENTS.md`](docs/ARCHITECTURE_AND_REQUIREMENTS.md).

```
snmpathy/
  app.py          FastAPI app factory, auth
  api.py          REST API            web/        UI pages, templates, JS/CSS
  monitor.py      scheduler           grafana.py  Grafana JSON data source + dashboards
  snmp/           client, discovery, poller
  checks/         ping/TCP/HTTP/DNS/SNMP probes, state machine
  syslog/         parser, UDP/TCP server, search
  alerting/       rule engine, notification channels
  dashboards.py   panel queries       reporting.py / scheduled.py  reports
  storage.py      rollups, retention  db.py       schema
```

## Development

```bash
pip install -e '.[dev]'
pytest
snmpathy demo --log-level debug
```

CI runs the test suite on Linux, macOS and Windows with Python 3.10 to 3.13.

## License

MIT
