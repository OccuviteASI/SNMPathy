"""Network topology map (Auvik-style): devices, their LLDP/CDP links and sites.

The graph is built from the ``links`` table (filled by LLDP/CDP discovery or
added by hand) plus parent relationships. Nodes are grouped into *sites*: the
first part of the device's Location ("HQ / MDF rack A1" is in site "HQ"), else
its collector's site, else none ("Unassigned"). The location a device reports
over SNMP is only offered as a suggestion. Link colour reflects utilisation from
SNMP interface counters.

Saved layout (``map_positions``, per view): ``s:<site>`` is a site box's top-left
corner; device nodes are stored relative to their site box.
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from .db import Database, loads

router = APIRouter()

UNASSIGNED = ""             # site of devices with no Location and no collector site
UNASSIGNED_FILTER = "~unassigned"  # ?site= value that shows only unassigned devices
LAYOUT_VERSION = "v2"       # bump when the meaning of saved positions changes
SITE_SEPARATORS = (" / ", "/", ",")

KIND_RULES: list[tuple[str, tuple[str, ...]]] = [
    ("firewall", ("fortigate", "fortios", "palo alto", "pan-os", "adaptive security appliance", "asa ", "firepower",
                  "sonicwall", "pfsense", "opnsense", "check point", "checkpoint", "srx", "watchguard", "sophos")),
    ("wireless", ("rajant", "breadcrumb", "instamesh", "tachyon", "tna-30", "airmax", "airfiber", "litebeam",
                  "nanostation", "nanobeam", "powerbeam", "rocket", "prism", "isostation", "ltu", "wave ", "af60",
                  "uap-", "u6-", "u7-", "unifi ap", "access point", "aironet", "unifi ap", "uap-", "wireless lan controller", "wlc", "meraki mr",
                  "aruba ap", "instant on ap", "ruckus", "airos")),
    ("router", ("ios xr", "ios-xe", " isr", "asr", "router", "routeros", "mikrotik", "edgerouter", "edgeos", "ufiber",
                "uisp fiber", "ucg-", "udm", "vyos",
                "junos mx", " mx", "juniper networks, inc. mx", "srx", "viptela", "velocloud")),
    ("switch", ("switch", "catalyst", "c2960", "c3560", "c3750", "c3850", "c9200", "c9300", "nexus", "nx-os",
                "procurve", "arubaos-cx", "aruba jl", "ex2300", "ex3400", "ex4300", "qfx", "dell networking", "powerconnect",
                "netgear", "unifi switch", "usw-", "usw ", "edgeswitch", "edgepoint", "us-8", "us-24", "us-48", "comware", "icx", "fastiron", "edgeswitch", "cumulus", "sg350", "sg300")),
    ("printer", ("printer", "jetdirect", "laserjet", "officejet", "lexmark", "ricoh", "kyocera", "xerox", "brother")),
    ("ups", ("ups", "apc ", "american power conversion", "eaton", "network management card", "powerware")),
    ("storage", ("synology", "qnap", "netapp", "data ontap", "truenas", "freenas", "isilon")),
    ("server", ("linux", "windows", "net-snmp", "vmware esxi", "freebsd", "darwin", "ubuntu", "centos", "red hat",
                "debian", "hardware: intel", "hardware: amd64")),
]


def device_kind(device: dict[str, Any]) -> str:
    text = " ".join(str(device.get(k) or "") for k in ("hw_model", "sys_descr", "vendor", "sys_name", "name")).lower()
    text = f" {text} "
    for kind, needles in KIND_RULES:
        if any(n in text for n in needles):
            return kind
    return "device"


def location_site(location: str | None) -> str:
    """The site part of a location: "HQ / MDF rack A1" and "HQ, IDF 2" are both in site "HQ"."""
    location = (location or "").strip()
    for sep in SITE_SEPARATORS:
        if sep in location:
            return location.split(sep, 1)[0].strip()
    return location


def site_of(device: dict[str, Any], collectors: dict[int, dict[str, Any]]) -> str:
    """The device's map site: its Location, else its collector's site, else UNASSIGNED."""
    site = location_site(device.get("location"))
    if site:
        return site
    col = collectors.get(device.get("collector_id") or 0)
    if col and (col.get("site") or col.get("name")):
        return col.get("site") or col["name"]
    return UNASSIGNED


def valid_site_name(name: str) -> str:
    name = (name or "").strip()
    if len(name) > 100:
        raise ValueError("site names are limited to 100 characters")
    if any(sep.strip() in name for sep in SITE_SEPARATORS):
        raise ValueError("a site name cannot contain '/' or ','")
    return name


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
        s = sites_all.setdefault(d["site"], {"name": d["site"], "unassigned": d["site"] == UNASSIGNED, "devices": 0,
                                             "down": 0, "unreachable": 0, "degraded": 0})
        s["devices"] += 1
        if d["enabled"] and d["status"] in ("down", "unreachable"):
            s[d["status"]] += 1
        if d["enabled"] and d["degraded"]:
            s["degraded"] += 1
    wanted = UNASSIGNED if site == UNASSIGNED_FILTER else site
    shown = [d for d in devices if (not site or d["site"] == wanted) and (not tag or tag in loads(d["tags"], []))]
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
            "location": d["location"] or "",
            "suggested_site": location_site(d["sys_location"]) if d["site"] == UNASSIGNED else "",
            "parent": f"d{d['parent_id']}" if d["parent_id"] else None,
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
                            "site": nodes[a]["site"], "location": "", "suggested_site": "", "parent": a,
                            "collector": None, "descr": link["remote_platform"], "managed": False}
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
        "sites": sorted(sites_all.values(), key=lambda s: (not s["unassigned"], s["name"].lower())),
        "unassigned": (sites_all.get(UNASSIGNED) or {}).get("devices", 0),
    }


def view_key(site: str = "", tag: str = "") -> str:
    return f"{LAYOUT_VERSION}|site={site}|tag={tag}"


def save_positions(db: Database, view: str, positions: dict[str, list[float]]) -> int:
    rows = [(view, node, float(xy[0]), float(xy[1])) for node, xy in positions.items()
            if isinstance(xy, (list, tuple)) and len(xy) == 2]
    with db.transaction() as conn:
        conn.executemany("INSERT OR REPLACE INTO map_positions (view, node, x, y) VALUES (?, ?, ?, ?)", rows)
    return len(rows)


def move_devices(db: Database, device_ids: list[int], site: str) -> list[dict[str, Any]]:
    """Put devices in ``site`` (their Location becomes just the site name; '' = unassigned)."""
    from .services import update_device

    site = valid_site_name(site)
    moved = []
    for device_id in device_ids:
        moved.append(update_device(db, device_id, {"location": site}))
    if device_ids:
        # Their saved spots belonged to the old site box: lay them out afresh in the new one.
        marks = ",".join("?" for _ in device_ids)
        db.execute(f"DELETE FROM map_positions WHERE node IN ({marks})", [f"d{i}" for i in device_ids])
    return moved


def rename_site(db: Database, old: str, new: str) -> int:
    """Rename a site on every device in it, keeping the detail part ("Old / rack 2" -> "New / rack 2")."""
    old, new = (old or "").strip(), valid_site_name(new)
    if not old or not new:
        raise ValueError("both the current and the new site name are needed")
    collectors = {c["id"]: c for c in db.query("SELECT id, name, site FROM collectors")}
    changed = 0
    with db.transaction():
        for d in db.query("SELECT id, location, collector_id FROM devices"):
            if site_of(d, collectors) != old:
                continue
            location = (d["location"] or "").strip()
            if location_site(location) == old:  # keep whatever follows the site part
                location = new + location[len(location.split(old, 1)[0]) + len(old):]
            else:  # the site came from the collector: record it on the device
                location = new
            db.update("devices", d["id"], {"location": location})
            changed += 1
        db.execute("UPDATE OR REPLACE map_positions SET node = ? WHERE node = ?", (f"s:{new}", f"s:{old}"))
    return changed


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


class MoveIn(BaseModel):
    device_ids: list[int] = Field(min_length=1, max_length=5000)
    site: str = Field("", max_length=100)


@router.post("/api/map/move", tags=["map"])
def move_to_site(body: MoveIn, request: Request):
    """Move devices to a site (sets their Location to the site name); an empty site unassigns them."""
    db = _db(request)
    try:
        moved = move_devices(db, body.device_ids, body.site)
    except KeyError as exc:
        raise HTTPException(404, f"device {exc.args[0]} not found") from exc
    except ValueError as exc:  # also ValidationError
        raise HTTPException(422, str(exc)) from exc
    monitor = request.app.state.monitor
    if monitor:
        for device_id in body.device_ids:
            monitor.reschedule_device(device_id)
    return {"moved": len(moved), "site": body.site.strip(),
            "devices": [{"id": d["id"], "name": d["name"], "location": d["location"]} for d in moved]}


class SiteRenameIn(BaseModel):
    old: str = Field(min_length=1, max_length=100)
    new: str = Field(min_length=1, max_length=100)


@router.post("/api/map/sites/rename", tags=["map"])
def rename_site_api(body: SiteRenameIn, request: Request):
    """Rename a site: updates the Location of every device in it."""
    try:
        return {"renamed": rename_site(_db(request), body.old, body.new), "site": body.new.strip()}
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


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
