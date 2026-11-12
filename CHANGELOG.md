# Changelog

The running version is shown at the bottom of the sidebar, on **Settings**, and by
`snmpathy version`. Executables built with `scripts/build_executable` also show the git
commit and build date, e.g. `0.5.0 (build 5c25a54, 2026-11-12)`.

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
