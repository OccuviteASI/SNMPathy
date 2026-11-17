# Changelog

The running version is shown at the bottom of the sidebar, on **Settings**, and by
`snmpathy version`. Executables built with `scripts/build_executable` also show the git
commit and build date, e.g. `0.5.0 (build 5c25a54, 2026-11-12)`.

## 0.7.11
- **Server admin**: a new page (left menu, under Configure) for managing the computer SNMPathy
  runs on: system information, **Updates** (check; *Update now* on the executable), **Startup**,
  **Firewall**, **Database**, **Configuration backup** and the settings in effect. **Settings**
  keeps device tagging, Grafana and the API.
- The tray's menu has a **Server admin** item that expands: **Start at login**, **Firewall**
  (open SNMPathy's ports per group or all of them, or remove its rules), **Update SNMPathy**,
  the **Server admin page**, **Open data folder** and **View log**.
- The left menu no longer shows counts next to **Devices** and **Uptime checks**.

## 0.7.10
- CI no longer tests or builds for macOS (Windows, Linux and Docker only); releases carry the
  Windows and Linux executables.
- **SNMP filter on the Devices page:** Responding / Not responding / Not polled yet / SNMP off,
  with counts; it combines with the status and tag filters.

## 0.7.9
- **Status filter on the Devices page:** All / Online / Offline / Unreachable / Degraded / Unknown /
  Disabled, with counts; it combines with the tag filter.
- **Acknowledge all** on the Alerts page acknowledges every firing alert at once.
- The **Alerts** count in the sidebar shows only firing alerts nobody has acknowledged yet.
- Network scans no longer tag every device they add **discovered**. On the first start of this
  version the tag is removed from the devices that have it and from the scans' saved tags (your
  other tags stay); a scan's *Tags* field now starts empty.

## 0.7.8
- **Scans no longer bog everything down.** Every SNMP attempt in a scan used to create its own
  SNMP engine (~60 ms of CPU each, on the thread that serves the web UI): a /24 with a few
  communities froze the website for seconds at a time. Scans now share one engine: the same
  254-address scan uses 4 s of CPU instead of 95 s, finishes in 37 s instead of 128 s, and
  pages keep loading during it.
- **Windows pings no longer start a `ping.exe` per address.** They use the Windows ICMP API
  (no Administrator rights needed); where `ping` processes are still used, at most 16 run at once.
- The ARP table is read less often during a scan, and once more after it.
- **"Devices added" is the total over all runs** of a scan, with the latest run's count under it.

## 0.7.7
- **Devices on other subnets / VLANs get their MAC address, maker and brand tag.** SNMPathy
  reads the ARP table of every router it polls over SNMP (UniFi gateway, pfSense, OPNsense,
  MikroTik, EdgeRouter, Cisco, ...) every 10 minutes, after each network scan and with *Tag
  existing devices now*. Before, MACs came only from this computer's own subnet. The device page
  shows which router a MAC came from; Settings > Device tagging shows how many entries were read.

## 0.7.6
- **Fixed: the website did not start after updating to 0.7.5** (tray status *No module named
  _sqlite3*). When SNMPathy restarted itself (to close its console window, or after an update)
  the new copy reused the old copy's temporary files, which disappear when the old copy exits.
  Every restart now gets a clean start. CI now checks that a restarted copy keeps working and
  that the executable's web UI starts.
- The updater on Linux recognises a running SNMPathy however it was started.

## 0.7.5
- **More devices get a brand tag, and their model.**
  - Scans ask each device who made it: **Ubiquiti discovery** (model such as `U6-Lite`, firmware,
    name) and **UPnP** (manufacturer and model of routers, TVs, speakers, printers, NAS).
    Existing devices without SNMP are asked once a day and by *Tag existing devices now*.
  - MAC makers come from **Wireshark's maker list**, downloaded weekly into the data folder
    (*Settings → Device tagging → Refresh maker list*). It is far more current than the bundled
    list (e.g. 48 Ubiquiti prefixes instead of 30) and includes the MA-M / MA-S blocks.
  - **Every known maker becomes a tag**, not only ~70 well-known brands: `Espressif`, `Tuya`,
    `Bilian`, ... (randomised phone MACs still get none).
- **No console window** when SNMPathy.exe is double-clicked on Windows 11: it restarts itself in
  the background so the Windows Terminal tab closes (hiding the window did not work there).

## 0.7.4
- **Updating needs nothing installed.** CI now publishes the Windows, macOS and Linux executables
  as a GitHub release for every change to `main`, and the tray's **Update SNMPathy** downloads
  the latest one and swaps it in: no Python, Git or local build. The download is checked (size,
  SHA-256, and that it starts) before the running SNMPathy is replaced, and the old executable
  is put back if the swap fails. The tray checks for a new release every 6 hours and says when
  one is available. `SNMPathy.exe self-update [--check]` does the same from a prompt.
- New computers: download `SNMPathy-windows.exe` from the latest release instead of building it.

## 0.7.3
- **Brand tags without SNMP.** Network scans read the MAC address of every host that answers
  (from the ARP table) and look up its maker, so home and small-office gear that has SNMP
  off (Ubiquiti, TP-Link, Netgear, eero, printers, cameras, ...) is tagged too. Existing
  devices on the local network pick up their MAC at startup, every 10 minutes and with
  **Settings → Device tagging → Tag existing devices now**. The MAC and its maker show on the
  device page and in scan results.
- **Scans always try the `public` community** (after the ones you list) and add the hosts
  that answer it as devices, even when *Add automatically* is *No* (a per-scan checkbox
  turns this off).
- **Several communities and SNMPv3 logins per scan.** The scan form lists each community in its
  own box and each SNMPv3 user (with its own protocols, passphrases and context) in its own row:
  **+ Add community** / **+ Add SNMPv3 user**, × to remove. They are tried in order and the one
  that answers is saved on the device.
- **Edit a network scan** after creating it (targets, credentials, schedule, adding rules):
  **Edit** on the scan list and the scan page, with **Save & run now**.
- **Updating a copy on another computer works.** A copy that came from another computer (for
  example a synced OneDrive Desktop) opened a console saying *The system cannot find the path
  specified*. The tray now finds the source folder, or downloads it once with Git into
  `%LOCALAPPDATA%\SNMPathy\source`, and uses the Python it finds on this computer. If Python
  or Git is missing, it says so instead of failing.
- Form fields side by side line up: a hint such as *optional* sits on the label line instead
  of pushing that field's box down (every page).

## 0.7.2
- **Sort any table by clicking a column heading** (again to reverse), on every page and in
  dashboards. Understands units (Gbps / MiB / % / ms), "5m ago" times, dates, IP addresses
  and status (problems first); blanks stay last; the choice is remembered per page and
  survives refreshes.

## 0.7.1
- The update window closes itself 5 seconds after a successful update (the button counts
  down; failures stay open, and opening the details stops the countdown).
- Dropdown lists are readable in dark mode (the dashboard switcher showed light text on a
  white list on Windows).

## 0.7.0
- **Nagios-style dashboards.** New dashlets: status donuts (devices, checks, ports, alerts),
  status bars by site / collector / device type / tag, latest state changes with
  CRITICAL / WARNING / OK pills, ranked bars with thresholds, group status tile, device &
  service treemap, Hypermap (radial map), devices with service chips, log events per query
  and log field top values. Compact dashlet chrome with a ⋯ menu.
- **Overview is now the Main HUD** dashboard (editable; the old page is at `/?classic=1`).
  Donut segments open the matching devices or checks (`/devices?state=…`, `/checks?state=…`).
- **Cluster dashboards**: limit any dashboard to a group of devices (tag, site and/or device
  list), or create one from *New cluster dashboard*.
- **Log Analysis** built-in dashboard.

## 0.6.3
- **Network map redesign.** Sites are boxes that never overlap; devices inside a site are
  arranged as a tree by their links, with unlinked devices in a grid by type and name.
  Devices with no site are in a separate, dashed **Unassigned** box instead of floating
  over other sites. Sites can be collapsed, dragged, renamed and tidied; changes animate
  and the layout saves itself.
- **Move devices to a site from the map**: drag them onto a site, multi-select with
  Shift, use the device or site panel, or the new **Sites & devices** list; every move can
  be undone.
- A device's site now comes from its Location first, then its collector's site. The
  location reported over SNMP is only a suggestion (it used to place devices in sites).
  Saved map layouts from earlier versions are reset once.

## 0.6.2
- **Brand tags**: devices are tagged with their brand (Cisco, Ubiquiti, Rajant, Tachyon,
  Synology, ...) when discovery or a network scan detects it; existing devices are tagged at
  startup. A brand tag you remove is not added back. On/off and "Tag existing devices now"
  under Settings > Device tagging.

## 0.6.1
- **Update from the tray shows a progress window** instead of a command prompt: current step,
  progress bar, full log under "Show details", and the actual error when an update fails.
  "Run in background" hides it while the update finishes.
- Only one update runs at a time (tray, double-click and the nightly scheduled update).
- Builds no longer print setuptools `project.license` deprecation warnings.

## 0.6.0
- Runs in the **system tray** when started by double-click, at login or after an update: no
  console window. Tray menu: Open SNMPathy, live status (red marker when something is down),
  Start at login, Update SNMPathy, Open data folder, View log, Quit. Log in `snmpathy.log`.
- **One-click updates**: `scripts\update.cmd` (or "Update SNMPathy" next to the executable, or
  the tray menu) pulls the latest code, rebuilds, and restarts SNMPathy; does nothing when
  already current. `update.cmd --schedule` checks for updates every night automatically.
- Ubiquiti private-MIB support, detected automatically:
  - **airMAX** (LiteBeam, NanoStation, PowerBeam, Rocket, Prism…): model / firmware, frequency,
    TX power, signal, noise, CCQ, rates, airMAX quality / capacity / airtime, temperature, memory,
    and per-station signal, CCQ, capacity, rates, latency, distance and traffic.
  - **UniFi** APs: model / firmware, clients per SSID and band, CCQ, traffic, channel and TX
    power, channel utilisation per radio.
  - **UISP / airFiber**: airFiber classic (capacity, local / remote RX power per chain,
    temperatures, link state), LTU and airFiber 5XHD, airFiber 60 / Wave (per-station RSSI,
    SNR, MCS, capacity, traffic, distance); EdgeRouter / UFiber / UISP Fiber OLT / EdgePower
    (identity, temperatures, fans, PoE output); EdgeSwitch and FASTPATH UniFi switches
    (identity, CPU, memory, temperatures, fans, PSUs).
  - Wireless stations and links appear on the network map.
- Standard POWER-ETHERNET-MIB PoE budget / consumption for any switch.

## 0.5.0
- Settings → Startup: start SNMPathy automatically at login (Windows, macOS, Linux).
- Settings → Firewall: add inbound firewall rules for syslog (and optionally the web UI,
  log inputs and flow ports).
- Rajant BreadCrumb and Tachyon TNA-30x private-MIB metrics; Tachyon peers on the map.
- Version and build stamp shown in the UI.

## 0.4.0
- Online / offline rules combining ping, SNMP and checks (degraded, unreachable, parents).
- Network scanning with auto-add; remote collectors with downloads and install scripts.
- Network map (LLDP / CDP), Fusion multi-server dashboard, Network Analyzer
  (NetFlow / IPFIX / sFlow), Log Server-style explorer with GELF / JSON / NXLog inputs.
- Nagios plugin and passive checks; bulk SNMP editing.

## 0.2.0
- Standalone executables and the build script that stores them in the Claude folder.

## 0.1.0
- SNMP polling, syslog, uptime checks, alerting, dashboards, Grafana integration, reports.
