"""Network topology map (Auvik-style): devices, their LLDP/CDP links and sites.

The graph is built from the ``links`` table (filled by LLDP/CDP discovery or
added by hand) plus parent relationships. Nodes are grouped into *sites*:
the site of the device's collector, else the device's location, else
"Main site". Link colour reflects utilisation from SNMP interface counters.
Node positions the user drags are stored per view in ``map_positions``.
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from .db import Database, loads

router = APIRouter()

MAIN_SITE = "Main site"

KIND_RULES: list[tuple[str, tuple[str, ...]]] = [
    ("firewall", ("fortigate", "fortios", "palo alto", "pan-os", "adaptive security appliance", "asa ", "firepower",
                  "sonicwall", "pfsense", "opnsense", "check point", "checkpoint", "srx", "watchguard", "sophos")),
    ("wireless", ("access point", "aironet", "unifi ap", "uap-", "wireless lan controller", "wlc", "meraki mr",
                  "aruba ap", "instant on ap", "ruckus", "airos")),
    ("router", ("ios xr", "ios-xe", " isr", "asr", "router", "routeros", "mikrotik", "edgerouter", "edgeos", "vyos",
                "junos mx", " mx", "juniper networks, inc. mx", "srx", "viptela", "velocloud")),
    ("switch", ("switch", "catalyst", "c2960", "c3560", "c3750", "c3850", "c9200", "c9300", "nexus", "nx-os",
                "procurve", "arubaos-cx", "aruba jl", "ex2300", "ex3400", "ex4300", "qfx", "dell networking", "powerconnect",
                "netgear", "unifi switch", "usw-", "comware", "icx", "fastiron", "edgeswitch", "cumulus", "sg350", "sg300")),
    ("printer", ("printer", "jetdirect", "laserjet", "officejet", "lexmark", "ricoh", "kyocera", "xerox", "brother")),
    ("ups", ("ups", "apc ", "american power conversion", "eaton", "network management card", "powerware")),
    ("storage", ("synology", "qnap", "netapp", "data ontap", "truenas", "freenas", "isilon")),
    ("server", ("linux", "windows", "net-snmp", "vmware esxi", "freebsd", "darwin", "ubuntu", "centos", "red hat",
                "debian", "hardware: intel", "hardware: amd64")),
]


def device_kind(device: dict[str, Any]) -> str:
    text = " ".join(str(device.get(k) or "") for k in ("sys_descr", "vendor", "sys_name", "name")).lower()
    text = f" {text} "
    for kind, needles in KIND_RULES:
        if any(n in text for n in needles):
            return kind
    return "device"


def site_of(device: dict[str, Any], collectors: dict[int, dict[str, Any]]) -> str:
    col = collectors.get(device.get("collector_id") or 0)
    if col and (col.get("site") or col.get("name")):
        return col.get("site") or col["name"]
    location = (device.get("location") or device.get("sys_location") or "").strip()
    # "HQ / MDF rack A1" and "HQ, IDF 2" both belong to site "HQ".
    for sep in (" / ", "/", " - ", ","):
        if sep in location:
            location = location.split(sep, 1)[0].strip()
            break
    return location or MAIN_SITE


def _util(iface: dict[str, Any] | None) -> float | None:
    if not iface or not iface.get("speed"):
        return None
    rate = max(iface.get("in_bps") or 0, iface.get("out_bps") or 0)
    return min(100.0, rate / iface["speed"] * 100.0)


def build_graph(db: Database, site: str = "", tag: str = "", unmanaged: bool = True) -> dict[str, Any]:
    """Nodes, edges and sites for the map. ``site`` / ``tag`` filter the devices shown."""
    from .snmp.neighbors import resolve_links

    try:
        resolve_links(db)
    except Exception:  # resolution is best-effort; the map still renders
        pass
    collectors = {c["id"]: c for c in db.query("SELECT id, name, site, status FROM collectors")}
    devices = db.query("SELECT * FROM devices ORDER BY name COLLATE NOCASE")
    sites_all: dict[str, dict[str, Any]] = {}
    for d in devices:
        d["site"] = site_of(d, collectors)
        s = sites_all.setdefault(d["site"], {"name": d["site"], "devices": 0, "down": 0, "unreachable": 0, "degraded": 0})
        s["devices"] += 1
        if d["enabled"] and d["status"] in ("down", "unreachable"):
            s[d["status"]] += 1
        if d["enabled"] and d["degraded"]:
            s["degraded"] += 1
    shown = [d for d in devices if (not site or d["site"] == site) and (not tag or tag in loads(d["tags"], []))]
    ids = {d["id"] for d in shown}
    ifaces: dict[tuple[int, int], dict[str, Any]] = {}
    if ids:
        marks = ",".join("?" for _ in ids)
        for i in db.query(f"SELECT device_id, if_index, name, speed, in_bps, out_bps, oper_status FROM interfaces "
                          f"WHERE device_id IN ({marks})", list(ids)):
            ifaces[(i["device_id"], i["if_index"])] = i

    nodes: dict[str, dict[str, Any]] = {}
    for d in shown:
        nodes[f"d{d['id']}"] = {
            "id": f"d{d['id']}", "device_id": d["id"], "name": d["name"], "ip": d["hostname"],
            "status": d["status"] if d["enabled"] else "paused", "degraded": bool(d["degraded"]),
            "reason": d["status_reason"], "vendor": d["vendor"], "kind": device_kind(d), "site": d["site"],
            "collector": (collectors.get(d["collector_id"] or 0) or {}).get("name"),
            "descr": (d["sys_descr"] or "")[:200], "managed": True,
        }

    edges: dict[tuple, dict[str, Any]] = {}
    for link in db.query("SELECT * FROM links ORDER BY last_seen DESC"):
        a = f"d{link['device_id']}"
        if a not in nodes:
            continue
        if link["remote_device_id"]:
            b = f"d{link['remote_device_id']}"
            if b not in nodes:
                continue
        else:
            if not unmanaged:
                continue
            label = link["remote_name"] or link["remote_ip"] or link["remote_chassis"]
            b = "u:" + (link["remote_chassis"] or label).lower()
            if b not in nodes:
                nodes[b] = {"id": b, "device_id": None, "name": label, "ip": link["remote_ip"], "status": "unmanaged",
                            "degraded": False, "reason": "", "vendor": "", "kind": device_kind(
                                {"sys_descr": link["remote_platform"], "name": label}),
                            "site": nodes[a]["site"], "collector": None, "descr": link["remote_platform"], "managed": False}
        local_if = ifaces.get((link["device_id"], link["if_index"])) if link["if_index"] is not None else None
        remote_if = ifaces.get((link["remote_device_id"], link["remote_if_index"])) \
            if link["remote_device_id"] and link["remote_if_index"] is not None else None
        # One edge per device pair and port pair, whichever side reported it.
        ends = sorted([(a, link["local_port"] or ""), (b, link["remote_port"] or "")])
        key = (ends[0][0], ends[1][0], ends[0][1].lower(), ends[1][1].lower())
        alt = (ends[0][0], ends[1][0])
        existing = edges.get(key) or next((e for k, e in edges.items() if k[:2] == alt and
                                           ({k[2], k[3]} & {ends[0][1].lower(), ends[1][1].lower()} - {""})), None)
        util_values = [u for u in (_util(local_if), _util(remote_if)) if u is not None]
        speed = (local_if or remote_if or {}).get("speed")
        down = any(i and i.get("oper_status") == 2 for i in (local_if, remote_if))
        if existing:
            existing["protocols"] = sorted(set(existing["protocols"]) | {link["protocol"]})
            if util_values:
                existing["util"] = max([existing["util"] or 0, *util_values])
            existing["speed"] = existing["speed"] or speed
            existing["down"] = existing["down"] or down
            continue
        edges[key] = {
            "id": f"l{link['id']}", "link_id": link["id"], "source": a, "target": b,
            "source_port": link["local_port"], "target_port": link["remote_port"],
            "util": max(util_values) if util_values else None, "speed": speed, "down": down,
            "protocols": [link["protocol"]], "manual": link["protocol"] == "manual",
            "in_bps": (local_if or {}).get("in_bps"), "out_bps": (local_if or {}).get("out_bps"),
        }
    linked_pairs = {(e["source"], e["target"]) for e in edges.values()} | {(e["target"], e["source"]) for e in edges.values()}
    for d in shown:
        if d["parent_id"] and f"d{d['parent_id']}" in nodes and (f"d{d['id']}", f"d{d['parent_id']}") not in linked_pairs:
            edges[("p", d["id"])] = {"id": f"p{d['id']}", "link_id": None, "source": f"d{d['parent_id']}",
                                     "target": f"d{d['id']}", "source_port": "", "target_port": "", "util": None,
                                     "speed": None, "down": False, "protocols": ["parent"], "manual": False,
                                     "parent": True}
    view = view_key(site, tag)
    positions = {r["node"]: [r["x"], r["y"]] for r in db.query("SELECT node, x, y FROM map_positions WHERE view = ?", (view,))}
    return {
        "view": view, "site": site, "tag": tag, "generated_at": time.time(),
        "nodes": list(nodes.values()), "edges": list(edges.values()), "positions": positions,
        "sites": sorted(sites_all.values(), key=lambda s: (s["name"] == MAIN_SITE, s["name"].lower())),
    }


def view_key(site: str = "", tag: str = "") -> str:
    return f"site={site}|tag={tag}"


def save_positions(db: Database, view: str, positions: dict[str, list[float]]) -> int:
    rows = [(view, node, float(xy[0]), float(xy[1])) for node, xy in positions.items()
            if isinstance(xy, (list, tuple)) and len(xy) == 2]
    with db.transaction() as conn:
        conn.executemany("INSERT OR REPLACE INTO map_positions (view, node, x, y) VALUES (?, ?, ?, ?)", rows)
    return len(rows)


def suggest_parents(db: Database, root_id: int) -> dict[int, int]:
    """Parent for every device reachable from ``root_id`` over discovered links (breadth-first)."""
    adjacency: dict[int, set[int]] = {}
    for link in db.query("SELECT device_id, remote_device_id FROM links WHERE remote_device_id IS NOT NULL"):
        a, b = link["device_id"], link["remote_device_id"]
        adjacency.setdefault(a, set()).add(b)
        adjacency.setdefault(b, set()).add(a)
    parents: dict[int, int] = {}
    seen = {root_id}
    frontier = [root_id]
    while frontier:
        nxt = []
        for node in frontier:
            for peer in sorted(adjacency.get(node, ())):
                if peer not in seen:
                    seen.add(peer)
                    parents[peer] = node
                    nxt.append(peer)
        frontier = nxt
    return parents


# ----------------------------------------------------------------------- API
def _db(request: Request) -> Database:
    return request.app.state.db


@router.get("/api/map", tags=["map"])
def get_map(request: Request, site: str = "", tag: str = "", unmanaged: bool = True):
    return build_graph(_db(request), site, tag, unmanaged)


class PositionsIn(BaseModel):
    view: str
    positions: dict[str, list[float]]


@router.put("/api/map/positions", tags=["map"])
def put_positions(body: PositionsIn, request: Request):
    return {"saved": save_positions(_db(request), body.view, body.positions)}


@router.delete("/api/map/positions", tags=["map"])
def reset_positions(request: Request, view: str):
    _db(request).execute("DELETE FROM map_positions WHERE view = ?", (view,))
    return {"ok": True}


class LinkIn(BaseModel):
    device_id: int
    remote_device_id: int
    local_port: str = Field("", max_length=100)
    remote_port: str = Field("", max_length=100)


@router.post("/api/map/links", status_code=201, tags=["map"])
def add_link(body: LinkIn, request: Request):
    db = _db(request)
    a = db.one("SELECT id, name FROM devices WHERE id = ?", (body.device_id,))
    b = db.one("SELECT id, name FROM devices WHERE id = ?", (body.remote_device_id,))
    if not a or not b or a["id"] == b["id"]:
        raise HTTPException(422, "pick two different existing devices")

    def if_index(device_id: int, port: str) -> int | None:
        if not port:
            return None
        row = db.one("SELECT if_index FROM interfaces WHERE device_id = ? AND (lower(name) = lower(?) OR lower(descr) = lower(?))",
                     (device_id, port, port))
        return row["if_index"] if row else None

    now = time.time()
    link_id = db.insert("links", {
        "device_id": a["id"], "if_index": if_index(a["id"], body.local_port), "local_port": body.local_port,
        "remote_device_id": b["id"], "remote_if_index": if_index(b["id"], body.remote_port),
        "remote_name": b["name"], "remote_port": body.remote_port, "protocol": "manual",
        "first_seen": now, "last_seen": now,
    })
    return {"id": link_id}


@router.delete("/api/map/links/{link_id}", status_code=204, tags=["map"])
def delete_link(link_id: int, request: Request):
    db = _db(request)
    row = db.one("SELECT protocol FROM links WHERE id = ?", (link_id,))
    if not row:
        raise HTTPException(404, "link not found")
    if row["protocol"] != "manual":
        raise HTTPException(422, "discovered links come back on the next discovery; only manual links can be deleted")
    db.execute("DELETE FROM links WHERE id = ?", (link_id,))


class ParentsIn(BaseModel):
    root_device_id: int
    apply: bool = False
    overwrite: bool = False


@router.post("/api/map/parents", tags=["map"])
def parents_from_topology(body: ParentsIn, request: Request):
    """Suggest (or apply) parent devices from the discovered topology, starting at a core device."""
    from .availability import evaluate_device

    db = _db(request)
    if not db.one("SELECT 1 FROM devices WHERE id = ?", (body.root_device_id,)):
        raise HTTPException(404, "device not found")
    suggestion = suggest_parents(db, body.root_device_id)
    changed = 0
    if body.apply:
        for child, parent in suggestion.items():
            current = db.scalar("SELECT parent_id FROM devices WHERE id = ?", (child,))
            if current and not body.overwrite:
                continue
            db.update("devices", child, {"parent_id": parent})
            changed += 1
        db.update("devices", body.root_device_id, {"parent_id": None})
        for child in suggestion:
            evaluate_device(db, child)
    names = {d["id"]: d["name"] for d in db.query("SELECT id, name FROM devices")}
    return {"parents": [{"device": names.get(c), "device_id": c, "parent": names.get(p), "parent_id": p}
                        for c, p in suggestion.items()], "applied": changed}


@router.get("/map", response_class=HTMLResponse, include_in_schema=False)
def map_page(request: Request, site: str = "", tag: str = ""):
    from .web import render

    db = _db(request)
    devices = db.query("SELECT id, name FROM devices ORDER BY name COLLATE NOCASE")
    tags = sorted({t for d in db.query("SELECT tags FROM devices") for t in loads(d["tags"], [])})
    return render(request, "map.html", nav="map", site=site, tag=tag, devices=devices, tags=tags)
