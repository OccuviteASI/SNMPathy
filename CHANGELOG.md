# Changelog

The running version is shown at the bottom of the sidebar, on **Settings**, and by
`snmpathy version`. Executables built with `scripts/build_executable` also show the git
commit and build date, e.g. `0.5.0 (build 5c25a54, 2026-11-12)`.

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
