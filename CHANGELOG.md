# Changelog

The running version is shown at the bottom of the sidebar, on **Settings**, and by
`snmpathy version`. Executables built with `scripts/build_executable` also show the git
commit and build date, e.g. `0.5.0 (build 5c25a54, 2026-11-12)`.

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
