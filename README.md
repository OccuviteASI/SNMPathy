# SNMPathy

**Self-hosted network monitoring: SNMP polling, syslog ingest, uptime checks, alerting,
Grafana-style dashboards and reporting in one small Python service.**

SNMPathy covers the everyday jobs of tools like Zabbix, Observium, PRTG, Uptime Robot,
Auvik, the Nagios family (distributed monitoring, Fusion, Log Server, Network Analyzer)
and a lightweight ELK stack:

| Area | What you get |
|---|---|
| **SNMP polling** (Observium / PRTG style) | v1, v2c and v3 (auth + priv). Auto-discovery of system info, vendor, every interface (64-bit counters when available), CPU, memory, storage and load averages. Custom OIDs per device. Traffic, utilisation, errors and discards per port. Reboot and port up/down detection. |
| **Syslog** (ELK style) | UDP and TCP listeners (RFC 5424, RFC 3164, RFC 6587 framing, Cisco / Juniper / FortiGate variants). Full-text search, filters by host / app / severity / facility / time, volume histogram, top-N facets and live tail. |
| **Uptime checks** (Uptime Robot / Nagios style) | ICMP ping, TCP port, HTTP(S) (status code, keyword, TLS certificate expiry), DNS, SNMP, **Nagios plugins** (exit codes, perfdata graphed) and **passive checks** (results pushed in, NRDP-style, with freshness checking) with retry-before-down, outage history, 90-day uptime bars and a public status page. |
| **Network discovery** | Scan CIDR blocks and ranges with ping, TCP ports and SNMP (several communities / SNMPv3 users), see what answers, and add devices automatically or with one click. Scans can repeat on a schedule and run from a remote site. |
| **Online / offline rules** (Nagios style) | A device is judged on every method that watches it (SNMP polling, ping, TCP, HTTP, plugins): online if *any* responds (default), only if *all* respond, or if *N* respond. One failing method shows the device as *degraded*, not down. Parent devices make downstream devices *unreachable* instead of alerting for each. |
| **Remote collectors** (Nagios distributed / PRTG remote probes / Auvik collectors) | Install a collector at each site with a one-line command (downloaded from your server). It connects out over HTTPS, polls and checks the site's devices locally, buffers results through WAN outages and runs network scans there. |
| **Network map** (Auvik style) | Topology drawn from LLDP / CDP neighbours, grouped by site, with live device status and link utilisation, unmanaged neighbours, drag-and-save layouts and manual links. |
| **Network Analyzer** (Nagios Network Analyzer style) | Built-in NetFlow v5/v9, IPFIX and sFlow collector: bandwidth by talker, application, protocol or exporter; top talkers, destinations, applications, conversations; per-host drill-down; bandwidth alerts and a traffic report, next to SNMP interface bandwidth. |
| **Fusion** (Nagios Fusion style) | One tactical dashboard across several SNMPathy servers: totals, per-server health, merged problems and alerts, cross-server top metrics. |
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

**Vendor-specific metrics** are added automatically when discovery recognises the device
(by sysObjectID, or by probing devices that report a generic Net-SNMP ID):

| Vendor | What is collected (private MIB) |
|---|---|
| **Rajant** BreadCrumb (RAJANT-CORPORATION-MIB, enterprise 34861) | model / serial / firmware, system temperature, free memory, CPU (from the idle counter when HOST-RESOURCES is absent), InstaMesh packets received / sent / dropped / floods dropped, per-radio (wlan0-3) frequency and noise floor, GPS position and satellites. The Rajant MIB has no per-peer table, so mesh peer signal is not available over SNMP |
| **Ubiquiti airMAX** (UBNT-AirMAX-MIB) | model / firmware (IEEE 802.11 MIB), frequency, TX power, signal, noise, CCQ, TX / RX rate, station count, airMAX quality / capacity / airtime, temperature, memory; per station: signal, CCQ, airMAX capacity, TX / RX rate and capacity, latency, distance, traffic. Stations appear on the map |
| **Ubiquiti UniFi** APs (UBNT-UniFi-MIB) | model / firmware, clients per SSID and band, CCQ, traffic per SSID, channel and TX power, channel utilisation (total, own RX / TX, other networks) per radio |
| **Ubiquiti UISP / airFiber** (UBNT-AirFIBER-MIB, UBNT-AFLTU-MIB, UI-AF60-MIB) | airFiber classic: link capacity, local and remote RX power per chain, radio temperatures, link state and uptime, distance, RF traffic. LTU / airFiber 5XHD and airFiber 60 / Wave: CPU, memory, frequency and per station RSSI / remote RSSI, SNR, MCS, capacity, latency, distance, traffic. Links appear on the map |
| **Ubiquiti EdgeMAX / EdgeSwitch** (UBNT-EdgeMAX-MIB, EdgeSwitch-BOXSERVICES-PRIVATE-MIB) | EdgeRouter / UFiber / UISP Fiber OLT / EdgePower: model, serial, firmware, temperatures, fans, PoE output. EdgeSwitch and first-generation UniFi switches: model, serial, firmware, CPU, memory, temperatures, fan speed and state, PSU state. Newer UniFi switches and gateways only expose standard MIBs (interfaces, CPU, memory, PoE) |
| **Tachyon Networks** TNA-30x (TACHYON-MIB, enterprise 57344) | model / serial / firmware, CPU %, memory %, CPU / modem / radio temperature, radio TX power, frequency and channel width, peer count, and per peer: RSSI, SNR, TX / RX PHY rate, TX / RX MCS, link uptime, distance and traffic. Peers also appear as **wireless links on the network map** |

Any switch that implements the standard POWER-ETHERNET-MIB also gets PoE budget and power
used. Example alert rules: `wireless.rssi < -70` (instance glob per peer), `wireless.snr < 10`,
`wireless.ccq < 80`, `radio.channel_util > 70`, `hw.temperature > 75`, `hw.psu_state != 2`. Devices discovered before an upgrade pick these up at their next
rediscovery (every 6 hours) or immediately with **Rediscover** on the device page.

### Change SNMP settings later

Open the device and click **Edit** (or **Change SNMP settings** next to the SNMP line on
the device page). The **Community string** field sits next to **Version** for v1 / v2c;
with v3 it is replaced by the user, auth and privacy fields. Saving new credentials
triggers a fresh discovery. To change many devices at once (for example after rotating a
community), tick them in the **Devices** list and use **Edit SNMP / settings…**: only the
fields you tick are changed.

### Scan the network and add devices automatically

**Devices → Scan network → New scan**. Enter targets such as `10.0.0.0/24, 10.0.1.1-50,
192.168.5.10` (plus optional exclusions), the SNMP communities and/or SNMPv3 user to try,
and optionally TCP ports (e.g. `22, 443, 3389`) so hosts that block ping are still found.
Each responding host is listed with its ping time, open ports, SNMP version, sysName,
vendor and description; hosts you already monitor are marked.

* **Add automatically**: *Hosts that answer SNMP* or *Every host that answers*. New
  devices get the credentials that worked, the scan's tags, location and online rule,
  a ping check if they answered ping (or a TCP check if only a port answered).
* **Pick by hand**: tick results and click **Add selected as devices**.
* **Repeat**: hourly, every 6 hours, daily or weekly, so new devices appear on their own.
* **Run from**: this server, or a remote collector to scan another site's network.

From the command line (prints results; `--add snmp|alive` also adds them to the database):

```bash
snmpathy scan 10.0.0.0/24 -c public -c s3cret --tcp 22,443 --add snmp --tag lab
```

### Brand tags

When discovery or a network scan detects who made a device, SNMPathy tags it with the brand:
`Cisco`, `Ubiquiti`, `Rajant`, `Tachyon`, `Juniper`, `Fortinet`, `Synology`, ... The brand
comes from the SNMP sysObjectID (or a vendor MIB such as Ubiquiti's); devices that only
report a generic Net-SNMP agent are recognised from their description (Synology, QNAP,
pfSense, OPNsense, MikroTik, UniFi, Proxmox, ...). Plain Linux servers get no brand tag.

Use the tags to filter **Devices** or to scope an alert rule (*Device tag*). Your own tags are
never changed; if you delete a brand tag from a device it is not added back, and if a
different device later answers at that address the old brand tag is swapped for the new one.
Existing devices are tagged when SNMPathy starts. Turn it off, or tag existing devices on
demand, under **Settings → Device tagging** (API: `GET/PUT /api/system/brand-tags`).

### Online / offline rules: one failing method is not an outage

A device is watched by SNMP polling and by every check linked to it (ping, TCP, HTTP,
plugins). **Edit device → Online / offline rule** decides how they combine:

| Rule | Online when |
|---|---|
| Any method responds (default) | at least one of SNMP, ping, … answers. A device that pings but whose SNMP agent hangs (or that blocks ICMP but answers SNMP) stays **online** and is flagged **degraded** |
| Every method responds | all of them answer |
| At least N methods respond | N or more answer |
| SNMP only / checks only | just that kind of method decides |

Also per device: *SNMP failures before SNMP counts as down*. Per check: *Counts toward the
linked device's online/offline status* (untick for, say, a web check on a server whose
website being down is not the server being down).

The device page shows each method with its state, the overall verdict and the 30-day
device uptime; uptime and health reports include **availability by device**. The
**Device offline** alert fires only when the rule says the device is offline, and the
**Availability check down** rule skips checks on devices that are still online (untick
*Ignore failing checks on devices that are still online* on the rule to be told anyway).

**Parents (Nagios-style unreachable):** set a device's **Parent device** (its upstream
switch or router, or let **Network map → Set parents…** fill them in from the topology).
When the parent is down, its children are shown as **unreachable** rather than down and
do not raise their own alerts. Devices behind an offline collector are unreachable too.

### Remote sites: collectors

A **collector** is SNMPathy running at another site (Windows, Linux, macOS or Docker).
It connects *out* to the main server over HTTP(S), so the site needs no inbound firewall
rules or VPN, then:

* pulls the devices and checks assigned to it, polls SNMP and runs checks on their own
  schedules (like Nagios distributed monitoring with passive results),
* keeps results on disk while the main server is unreachable and replays them with their
  original timestamps, so graphs and uptime have no gaps,
* runs discovery, *check now* and network scans for the main server.

**Install one:** **Collectors → Add collector** shows a token (once) and copy-paste install
commands. Each downloads the collector **from your SNMPathy server** and sets it up as a
service:

```powershell
# Windows (elevated PowerShell): scheduled task at startup, restarts on failure
& ([scriptblock]::Create((iwr -UseBasicParsing 'https://nms.example.com/collector/install.ps1').Content)) -Token 'col_...'
```

```bash
# Linux (systemd) or macOS (launchd)
curl -fsSL https://nms.example.com/collector/install.sh | sudo bash -s -- --token col_...
# Docker
docker run -d --name snmpathy-collector --restart unless-stopped --network host \
  -e SNMPATHY_COLLECTOR_SERVER=https://nms.example.com -e SNMPATHY_COLLECTOR_TOKEN=col_... \
  snmpathy collector --state-dir /data
# Anything else
snmpathy collector --server https://nms.example.com --token col_...
```

The **Downloads** list on the Collectors page serves the files directly from the main host
at `/collector/download/…`. A server started from the standalone executable offers itself
for its own OS; put the executables for other platforms (from `scripts/build_executable`
or the CI artifacts, named e.g. `SNMPathy-windows.exe`, `SNMPathy-linux`, `SNMPathy-macos`)
in the `downloads` folder next to the database (or set `downloads_dir`). Without a
prebuilt executable the installers fall back to the Python package the server also
serves (`snmpathy-<version>.tar.gz`, needs Python 3.10+ at the site).

Then set **Monitored from** on devices (or run a scan from the collector). Checks follow
their device's collector unless you choose otherwise. A collector that stops reporting
for 90 s (`collector_offline_after`) is marked offline and an event is logged; its devices
become unreachable until it returns. Use HTTPS (a reverse proxy) when collectors cross
the internet: the token and SNMP credentials travel over that connection. `--insecure`
and `--ca-file` cover self-signed and private-CA certificates.

### Network map

**Network map** draws devices and the links between them from LLDP and CDP neighbour
tables (collected during SNMP discovery; enable LLDP/CDP on switches and routers).
Devices are grouped by site: the collector's site, or the first part of the location
(`HQ / MDF rack A1` belongs to `HQ`). Node rings show status (green up, amber degraded or
unreachable, red down); links are coloured by utilisation from SNMP counters and drawn
thicker for faster links. Neighbours that are not monitored appear dashed, ready to add.
Drag nodes and **Save layout**, filter by site or tag, search, toggle port labels, click a
node or link for details, **Add link** for connections LLDP cannot see (WAN circuits,
unmanaged switches), and **Set parents…** to derive parent devices from the topology.

### Network Analyzer (NetFlow / IPFIX / sFlow)

Point flow exporters at the SNMPathy host: **NetFlow v5/v9 → UDP 2055**, **IPFIX → UDP 4739**,
**sFlow → UDP 6343** (any of these ports accepts every format; set a port to 0 to disable it).
Exporters appear automatically under **Network analyzer → Exporters**, where you can name
them, link them to devices, override the sampling rate or disable them. The analyzer shows
total / average / peak traffic, stacked bandwidth by top talkers, applications, protocols,
destinations or exporters, and top-N tables you can click to filter (IP, CIDR, port or
service name, protocol, exporter) or drill into one host. The **Exporter setup guide** on
the page has copy-paste configs for Cisco, Juniper, MikroTik, pfSense / OPNsense, Linux
(softflowd / pmacct) and HPE / Aruba sFlow.

Alert on traffic with a **Traffic (flow) bandwidth** rule (for example filter `dport=443`
or `cidr=10.1.0.0/16 proto=udp`, threshold in bits/s, averaged over a window; add `by=src`
for one alert per talker). The **Traffic** report summarises talkers, applications,
conversations and exporters for any period. Flow records are aggregated per minute and
kept for 14 days (`retention_flow_days`).

### Fusion: several servers on one screen

On the server you want as the "master", open **Fusion → Manage servers** and add each other
SNMPathy server's URL and API token. Every minute it fetches each server's summary and shows
one tactical overview: servers reporting, hosts up / down / unreachable, checks OK /
warning / critical, firing alerts, one merged problems list (each linking into the server
that owns it), and the highest CPU, memory, busiest interfaces and worst availability
across all servers. A server that cannot be reached keeps its last data, marked stale.

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

**Other log sources:** Windows Event Logs via NXLog (JSON lines to TCP **5544**, or GELF),
Graylog / Docker `--log-driver gelf` senders (GELF on UDP **12201**, compressed and
chunked), and Fluent Bit / Vector / Filebeat JSON. Extra fields (EventID, user names, …)
become searchable fields. **Logs → Sources** shows what is listening, which hosts are
sending, and copy-paste setup for rsyslog, syslog-ng, journald, NXLog on Windows, network
vendors, Docker, Fluent Bit and Vector.

**Log explorer** (Nagios Log Server / Kibana style): a field sidebar with counts and top
values (click + / − to include or exclude), filter pills, several colour-coded queries on
one histogram, expandable events showing every field, saved searches, CSV export, live
tail and *Create alert* from the current query. Query language:

| Example | Meaning |
|---|---|
| `error`, `"changed state"`, `fail*` | words, phrases, wildcards (full-text) |
| `-x`, `NOT x`, `a OR b`, `(a b)` | exclude, combine, group (operators in capitals) |
| `host:core-sw*`, `host:10.0.0.0/8`, `app:sshd` | host name or source IP (wildcards / CIDR), application |
| `severity:<=warning`, `severity:err`, `facility:local7` | severity / facility by name or number, with comparisons |
| `EventID:4625`, `user.name:bob`, `bytes:>1000`, `field:*` | any structured field (JSON from GELF / NXLog / JSON inputs) |

### Uptime checks

**Uptime checks → Add check**:

| Type | Target | Options |
|---|---|---|
| `icmp` | host / IP | packet count |
| `tcp` | host + port | |
| `http` | URL | method, expected status (`200-399`, `200,204`, `2xx`), keyword present / absent, TLS verification, certificate-expiry warning (days) |
| `dns` | name | expected address |
| `snmp` | host | uses the device's credentials |
| `nagios` | host (`$HOSTADDRESS$`) | plugin name (e.g. `check_disk`) and arguments; exit code 0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN; performance data is stored as graphable metrics on the linked device |
| `passive` | source name | no probing: results are submitted to `POST /api/passive` (see below) and the check fails if none arrive within interval × (retries + 1) |

**Nagios plugins** are looked up by name (never by path) in `plugins/` next to the
database/executable and the usual locations (`/usr/lib/nagios/plugins`,
`/usr/local/nagios/libexec`, `C:\Program Files\NSClient++\scripts`, …) or the folders in
`SNMPATHY_PLUGIN_DIRS`. A plugin check assigned to a collector runs on the collector,
like NRPE.

**Passive results** (NRDP / NSCA style), authenticated with the API token:

```bash
curl -X POST https://nms.example.com/api/passive -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"results": [{"host": "backup01", "service": "Nightly backup", "state": 0, "output": "OK - 42 GB | size=42GB"}]}'
```

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

## Updating

Right-click the tray icon and choose **Update SNMPathy**. A small window shows the progress
(checking, downloading, building, restarting) with the full log under **Show details**; no
console window opens. **Run in background** hides the window and lets the update finish on its
own. If the update fails, the window says why and SNMPathy keeps running the previous version.

You can also double-click **Update SNMPathy** (created next to `SNMPathy.exe` in your Claude
folder by the build) or `scripts\update.cmd` in the source folder (`scripts/update.sh` on
macOS / Linux), which show the same steps in a console window. Every way of updating:

1. fetches the latest `main` and fast-forwards your source folder (it refuses, and changes
   nothing, if you have local edits),
2. stops when nothing changed and the installed executable is already that build,
3. closes the running SNMPathy, rebuilds, copies the new executable into place, and
4. starts it again in the tray.

To have it happen automatically, run `scripts\update.cmd --schedule` once: a scheduled task
(cron on macOS / Linux) checks every night at 03:17 and only rebuilds when something new was
merged; it runs hidden and logs to `build/update.log`. `--unschedule` removes it. Git must
be installed (Git for Windows on Windows).

Only one update runs at a time: a tray click while the nightly update is running is refused
with "another update is already running". The progress window uses the Python that built the
executable (recorded in `updater.json` next to it); if you move the source folder or reinstall
Python, run `scripts\build_executable.cmd` once to refresh it.

## Running in the system tray

Double-clicking the executable (and autostart at login, and the restart after an update) runs
SNMPathy in the **system tray** instead of a console window. The icon turns red when a device
or check is down; its tooltip and menu show the current status. Right-click for **Open
SNMPathy**, **Start at login**, **Update SNMPathy**, **Open data folder**, **View log**
(`snmpathy.log` next to the executable) and **Quit SNMPathy**. `snmpathy tray` does the same
from a Python install (`pip install .[tray]`). On a Linux machine without a desktop, or when
started from a terminal with `serve`, SNMPathy runs in the console as before.

## Open the firewall for syslog

**Settings → Firewall**: tick what to open (**Syslog** by default; also *Web UI and API*,
*GELF / JSON log inputs*, *NetFlow / IPFIX / sFlow*) and click **Add firewall rules**
(**Remove** takes them out again). The table shows which ports are already open. From the
command line: `snmpathy firewall status`, `snmpathy firewall add --include syslog,flows`,
`snmpathy firewall remove`.

| OS | What it does |
|---|---|
| Windows | inbound allow rules in Windows Defender Firewall (`netsh`, named `SNMPathy …`, all profiles). Needs Administrator: if SNMPathy is not elevated, a UAC prompt appears on the SNMPathy computer |
| Linux | firewalld (`--permanent --add-port`, then reload) or ufw (`ufw allow`), as root or through password-less `sudo`; otherwise the exact commands are shown to paste into a terminal. Without firewalld / ufw, iptables commands are shown |
| macOS | the application firewall is per app: SNMPathy (or its Python) is added and unblocked with `socketfilterfw` |
| Docker | not needed: publish the ports (the Compose file maps 514 → 5514) |

## Start automatically at login

**Settings → Startup → Start SNMPathy automatically when I log in** (or
`snmpathy autostart on` / `off` / `status`). No admin rights are needed; it uses the
normal per-user mechanism of each OS:

| OS | What it creates |
|---|---|
| Windows | `HKCU\…\CurrentVersion\Run\SNMPathy`, launching through a small VBScript so no console window appears |
| macOS | `~/Library/LaunchAgents/com.snmpathy.autostart.plist` (logs in `~/Library/Logs/SNMPathy.log`) |
| Linux | a systemd user service (`~/.config/systemd/user/snmpathy.service`), or `~/.config/autostart/snmpathy.desktop` without systemd |

The autostarted server uses the same executable / Python, configuration file and database
as the one you enabled it from, and does not open a browser. For a machine that should
monitor without anyone logged in, use a service (below) instead. In Docker, use the
container restart policy.

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
