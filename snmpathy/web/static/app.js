/* SNMPathy front-end: API helpers, forms, SVG charts, dashboards, syslog explorer.
   No build step and no external dependencies. */
(function () {
  "use strict";

  const SP = (window.SP = {});
  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));
  SP.$ = $;
  SP.$$ = $$;

  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  SP.esc = esc;

  const store = {
    get(k, d) { try { const v = localStorage.getItem("snmpathy." + k); return v == null ? d : JSON.parse(v); } catch (e) { return d; } },
    set(k, v) { try { localStorage.setItem("snmpathy." + k, JSON.stringify(v)); } catch (e) { /* storage unavailable */ } },
  };
  SP.store = store;

  // ------------------------------------------------------------------ API
  SP.api = async function (method, url, body) {
    const opts = { method, headers: { Accept: "application/json" }, credentials: "same-origin" };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const resp = await fetch(url, opts);
    if (resp.status === 401) { location.href = "/login?next=" + encodeURIComponent(location.pathname); throw new Error("login required"); }
    if (resp.status === 204) return null;
    const text = await resp.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch (e) { data = text; }
    if (!resp.ok) {
      let msg = resp.statusText;
      if (data && data.detail) msg = Array.isArray(data.detail) ? data.detail.map((d) => (d.loc ? d.loc.slice(1).join(".") + ": " : "") + d.msg).join("; ") : data.detail;
      throw new Error(msg);
    }
    return data;
  };

  SP.toast = function (msg, kind) {
    let box = $("#toasts");
    if (!box) { box = document.createElement("div"); box.id = "toasts"; document.body.appendChild(box); }
    const t = document.createElement("div");
    t.className = "toast" + (kind === "error" ? " error" : "");
    t.textContent = msg;
    box.appendChild(t);
    setTimeout(() => t.remove(), kind === "error" ? 7000 : 3500);
  };

  // --------------------------------------------------------------- format
  const SI = [[1e12, "T"], [1e9, "G"], [1e6, "M"], [1e3, "k"]];
  const IEC = [[1125899906842624, "PiB"], [1099511627776, "TiB"], [1073741824, "GiB"], [1048576, "MiB"], [1024, "KiB"]];
  function trim(n, digits) {
    const s = Number(n).toFixed(digits);
    return s.indexOf(".") >= 0 ? s.replace(/\.?0+$/, "") : s;
  }
  SP.fmt = function (v, unit, digits) {
    if (v == null || isNaN(v)) return "-";
    const a = Math.abs(v);
    const d = digits == null ? (a >= 100 ? 0 : a >= 10 ? 1 : 2) : digits;
    if (unit === "bps") { for (const [div, s] of SI) if (a >= div) return trim(v / div, 2) + " " + s + "bps"; return trim(v, 0) + " bps"; }
    if (unit === "B") { for (const [div, s] of IEC) if (a >= div) return trim(v / div, 1) + " " + s; return trim(v, 0) + " B"; }
    if (unit === "%") return trim(v, a >= 10 ? 1 : 2) + "%";
    if (unit === "ms") return a >= 1000 ? trim(v / 1000, 2) + " s" : trim(v, a >= 10 ? 0 : 1) + " ms";
    if (unit === "s") return SP.duration(v);
    let out;
    if (a >= 1e4) { out = null; for (const [div, s] of SI) if (a >= div) { out = trim(v / div, 1) + s; break; } }
    else out = trim(v, d);
    return unit && unit !== "msgs" ? out + " " + unit : out;
  };
  SP.duration = function (sec) {
    if (sec == null) return "-";
    sec = Math.round(sec);
    if (sec < 60) return sec + "s";
    const m = Math.floor(sec / 60), s = sec % 60;
    if (m < 60) return m + "m" + (s ? " " + s + "s" : "");
    const h = Math.floor(m / 60), mm = m % 60;
    if (h < 48) return h + "h" + (mm ? " " + mm + "m" : "");
    const d = Math.floor(h / 24), hh = h % 24;
    return d + "d" + (hh ? " " + hh + "h" : "");
  };
  const pad = (n) => (n < 10 ? "0" : "") + n;
  const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  SP.fmtTime = function (ts, style) {
    const d = new Date(ts * 1000);
    const hm = pad(d.getHours()) + ":" + pad(d.getMinutes());
    if (style === "time") return hm;
    if (style === "timesec") return hm + ":" + pad(d.getSeconds());
    if (style === "date") return MONTHS[d.getMonth()] + " " + d.getDate();
    const now = new Date();
    if (style !== "full" && d.toDateString() === now.toDateString()) return hm + ":" + pad(d.getSeconds());
    return d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate()) + " " + hm + (style === "full" ? ":" + pad(d.getSeconds()) : "");
  };
  SP.ago = function (ts) {
    if (!ts) return "never";
    const delta = Date.now() / 1000 - ts;
    if (delta < 5) return "just now";
    return (delta < 0 ? "in " : "") + SP.duration(Math.abs(delta)) + (delta < 0 ? "" : " ago");
  };
  function localizeTimes(root) {
    $$("time[data-ts]", root).forEach((el) => {
      const ts = parseFloat(el.dataset.ts);
      const f = el.dataset.fmt || "datetime";
      el.textContent = f === "ago" ? SP.ago(ts) : SP.fmtTime(ts, f === "datetime" ? "full-min" : f);
      el.title = new Date(ts * 1000).toString();
    });
  }
  SP.localizeTimes = localizeTimes;

  // ---------------------------------------------------------------- theme
  function applyTheme(theme) {
    if (theme === "light" || theme === "dark") document.documentElement.setAttribute("data-theme", theme);
    else document.documentElement.removeAttribute("data-theme");
  }
  applyTheme(store.get("theme", "auto"));
  SP.cycleTheme = function () {
    const order = ["auto", "light", "dark"];
    const next = order[(order.indexOf(store.get("theme", "auto")) + 1) % 3];
    store.set("theme", next);
    applyTheme(next);
    SP.toast("Theme: " + next);
    document.dispatchEvent(new Event("sp:theme"));
  };

  // ---------------------------------------------------------------- forms
  function setPath(obj, path, value) {
    const parts = path.split(".");
    let o = obj;
    for (let i = 0; i < parts.length - 1; i++) { o[parts[i]] = o[parts[i]] || {}; o = o[parts[i]]; }
    o[parts[parts.length - 1]] = value;
  }
  SP.formData = function (form) {
    const data = {};
    $$("input, select, textarea", form).forEach((el) => {
      if (!el.name || el.disabled || el.closest("[data-skip]")) return;
      const type = el.dataset.type || (el.type === "number" ? "number" : el.type === "checkbox" ? "bool" : "text");
      let v;
      if (el.type === "checkbox") v = el.checked;
      else if (el.type === "radio") { if (!el.checked) return; v = el.value; }
      else if (el.multiple) v = Array.from(el.selectedOptions).map((o) => (type === "intlist" ? parseInt(o.value, 10) : o.value));
      else v = el.value;
      if (type === "number" || type === "int" || type === "float") {
        if (v === "") { if (el.dataset.empty === "null") v = null; else return; }
        else v = type === "int" ? parseInt(v, 10) : parseFloat(v);
      } else if (type === "list") v = String(v).split(",").map((s) => s.trim()).filter(Boolean);
      else if (type === "json") { try { v = v ? JSON.parse(v) : {}; } catch (e) { throw new Error("Invalid JSON in " + el.name); } }
      else if (type === "nullable") v = v === "" ? null : (isNaN(v) ? v : Number(v));
      else if (type === "text" && el.dataset.empty === "omit" && v === "") return;
      setPath(data, el.name, v);
    });
    return data;
  };

  document.addEventListener("submit", async (ev) => {
    const form = ev.target.closest("form[data-api]");
    if (!form) return;
    ev.preventDefault();
    const btn = $("button[type=submit]", form);
    if (btn) btn.disabled = true;
    try {
      const body = SP.formData(form);
      const hook = form.dataset.transform && SP.transforms[form.dataset.transform];
      const payload = hook ? hook(body, form) : body;
      const result = await SP.api(form.dataset.method || "POST", form.dataset.api, payload);
      if (form.dataset.success) SP.toast(form.dataset.success);
      if (form.dataset.redirect) location.href = form.dataset.redirect.replace("{id}", result && result.id);
      else if (form.dataset.then === "none") { /* stay */ }
      else location.reload();
    } catch (e) {
      SP.toast(e.message, "error");
    } finally {
      if (btn) btn.disabled = false;
    }
  });
  SP.transforms = {};

  document.addEventListener("click", async (ev) => {
    const el = ev.target.closest("[data-action]");
    if (!el) return;
    ev.preventDefault();
    const action = el.dataset.action;
    if (action === "theme") return SP.cycleTheme();
    if (action === "nav") return document.body.classList.toggle("nav-open");
    if (action === "modal") return SP.openModal($(el.dataset.target));
    if (action === "close-modal") return SP.closeModal(el.closest(".modal-back"));
    if (action === "print") return window.print();
    if (action === "api") {
      if (el.dataset.confirm && !confirm(el.dataset.confirm)) return;
      el.setAttribute("disabled", "");
      try {
        const body = el.dataset.body ? JSON.parse(el.dataset.body) : undefined;
        const res = await SP.api(el.dataset.method || "POST", el.dataset.url, body);
        if (el.dataset.success) SP.toast(el.dataset.success.replace(/\{(\w+)\}/g, (_, k) => (res && res[k] != null ? res[k] : "")));
        if (res && res.ok === false && res.error) SP.toast(res.error, "error");
        if (el.dataset.redirect) location.href = el.dataset.redirect;
        else if (el.dataset.then !== "none") setTimeout(() => location.reload(), el.dataset.success ? 600 : 0);
      } catch (e) {
        SP.toast(e.message, "error");
      } finally {
        el.removeAttribute("disabled");
      }
    }
  });

  SP.openModal = function (back) {
    if (!back) return;
    back.classList.remove("hidden");
    const first = $("input, select, textarea", back);
    if (first) setTimeout(() => first.focus(), 30);
  };
  SP.closeModal = function (back) { if (back) back.classList.add("hidden"); };
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") $$(".modal-back:not(.hidden)").forEach((m) => m.dataset.static || SP.closeModal(m));
  });
  document.addEventListener("click", (e) => {
    if (e.target.classList && e.target.classList.contains("modal-back") && !e.target.dataset.static) SP.closeModal(e.target);
  });

  // Sortable tables
  document.addEventListener("click", (ev) => {
    const th = ev.target.closest("th.sortable");
    if (!th) return;
    const table = th.closest("table");
    const idx = Array.from(th.parentNode.children).indexOf(th);
    const dir = th.dataset.dir === "asc" ? "desc" : "asc";
    $$("th", table).forEach((t) => delete t.dataset.dir);
    th.dataset.dir = dir;
    const body = table.tBodies[0];
    const rows = Array.from(body.rows);
    const val = (r) => { const c = r.cells[idx]; const s = c ? (c.dataset.sort != null ? c.dataset.sort : c.textContent.trim()) : ""; const n = parseFloat(s); return isNaN(n) || !/^-?[\d.]/.test(s) ? s.toLowerCase() : n; };
    rows.sort((a, b) => { const x = val(a), y = val(b); return (x > y ? 1 : x < y ? -1 : 0) * (dir === "asc" ? 1 : -1); });
    rows.forEach((r) => body.appendChild(r));
  });

  // Client-side table filter: <input data-filter="#table-id">
  document.addEventListener("input", (ev) => {
    const input = ev.target.closest("input[data-filter]");
    if (!input) return;
    const q = input.value.toLowerCase();
    $$(input.dataset.filter + " tbody tr").forEach((tr) => { tr.style.display = tr.textContent.toLowerCase().includes(q) ? "" : "none"; });
  });

  // ---------------------------------------------------------------- charts
  const SERIES_VARS = ["--s1", "--s2", "--s3", "--s4", "--s5", "--s6", "--s7", "--s8"];
  const NAMED = { red: "--critical", orange: "--warning", blue: "--s1", green: "--good", gray: "--s-other" };
  function cssVar(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }
  SP.seriesColor = function (i, named) {
    if (named && NAMED[named]) return cssVar(NAMED[named]);
    return cssVar(i < SERIES_VARS.length ? SERIES_VARS[i] : "--s-other");
  };
  const SVGNS = "http://www.w3.org/2000/svg";
  function svgEl(tag, attrs, parent) {
    const el = document.createElementNS(SVGNS, tag);
    for (const k in attrs) el.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(el);
    return el;
  }
  function niceTicks(min, max, count) {
    if (max === min) { max = min + 1; }
    const span = max - min;
    const raw = span / Math.max(1, count);
    const mag = Math.pow(10, Math.floor(Math.log10(raw)));
    const norm = raw / mag;
    const step = (norm < 1.5 ? 1 : norm < 3 ? 2 : norm < 7 ? 5 : 10) * mag;
    const ticks = [];
    for (let v = Math.floor(min / step) * step; v <= max + step * 0.001; v += step) ticks.push(+v.toFixed(10));
    if (ticks[ticks.length - 1] < max) ticks.push(ticks[ticks.length - 1] + step);
    return ticks;
  }
  function binaryTicks(max, count) {
    // Nice ticks for bits/bytes use SI steps of the display unit.
    return niceTicks(0, max, count);
  }
  const TIME_STEPS = [60, 300, 900, 1800, 3600, 10800, 21600, 43200, 86400, 172800, 604800, 2592000];
  function timeTicks(start, end, width) {
    const target = Math.max(2, Math.floor(width / 90));
    const span = end - start;
    let step = TIME_STEPS[TIME_STEPS.length - 1];
    for (const s of TIME_STEPS) if (span / s <= target) { step = s; break; }
    const tz = new Date(start * 1000).getTimezoneOffset() * 60;
    const first = Math.ceil((start - tz * -1) / step) * step + tz * -1;
    const ticks = [];
    // Align to local time boundaries.
    let t = step >= 86400 ? (() => { const d = new Date(start * 1000); d.setHours(0, 0, 0, 0); return d.getTime() / 1000 + 86400; })() : Math.ceil(start / step) * step;
    if (step < 86400 && step >= 3600) { const off = -new Date(start * 1000).getTimezoneOffset() * 60; t = Math.ceil((start + off) / step) * step - off; }
    for (; t <= end; t += step) ticks.push(t);
    return { ticks: ticks.length ? ticks : [first], step };
  }
  function tickLabel(ts, step) {
    const d = new Date(ts * 1000);
    if (step >= 86400) return MONTHS[d.getMonth()] + " " + d.getDate();
    if (d.getHours() === 0 && d.getMinutes() === 0) return MONTHS[d.getMonth()] + " " + d.getDate();
    return pad(d.getHours()) + ":" + pad(d.getMinutes());
  }

  /**
   * Render a time-series chart.
   * series: [{name, points: [[ts, value], ...], color?}]
   * opts: {type: line|area|stacked|bar, unit, start, end, height, yMin, yMax, legend: auto|list|table|none, thresholds}
   */
  SP.chart = function (el, series, opts) {
    opts = Object.assign({ type: "line", unit: "", height: parseInt(el.dataset.height || "220", 10), legend: "auto" }, opts || {});
    el.classList.add("chart");
    el._chart = { series, opts };
    const hidden = el._hidden || (el._hidden = new Set());
    draw();
    if (!el._observer && window.ResizeObserver) {
      let lastW = el.clientWidth;
      el._observer = new ResizeObserver(() => { if (Math.abs(el.clientWidth - lastW) > 4) { lastW = el.clientWidth; draw(); } });
      el._observer.observe(el);
    }
    if (!el._themeHook) { el._themeHook = true; document.addEventListener("sp:theme", () => el._chart && draw()); }

    function draw() {
      const { series, opts } = el._chart;
      el.innerHTML = "";
      const W = Math.max(200, el.clientWidth || 600);
      const H = opts.height;
      // Colours follow the entity: sort a copy by name so a re-ranked top-N keeps its colours.
      const colored = series.map((s, i) => Object.assign({}, s, { _i: i }));
      // Up to 8 series: colour by name order. More than 8: the top 8 (server order) get hues, the rest fold to grey.
      const order = series.length <= 8 ? colored.slice().sort((a, b) => String(a.name).localeCompare(String(b.name))) : colored;
      order.forEach((s, i) => { s.color = SP.seriesColor(Math.min(i, 8), series[s._i].color); });
      const visible = colored.filter((s) => !hidden.has(s.name));
      const allPts = visible.flatMap((s) => s.points);
      let start = opts.start, end = opts.end;
      if (start == null || end == null) {
        const ts = colored.flatMap((s) => s.points.map((p) => p[0]));
        start = ts.length ? Math.min(...ts) : Date.now() / 1000 - 3600;
        end = ts.length ? Math.max(...ts) : Date.now() / 1000;
      }
      if (end <= start) end = start + 60;
      const stacked = opts.type === "stacked" || opts.type === "bar";
      // union of timestamps for stacking / hover
      const tsSet = new Set();
      visible.forEach((s) => s.points.forEach((p) => tsSet.add(p[0])));
      const times = Array.from(tsSet).sort((a, b) => a - b);
      let maxV = 0, minV = 0;
      if (stacked) {
        const maps = visible.map((s) => new Map(s.points));
        times.forEach((t) => { let sum = 0; maps.forEach((m) => { sum += m.get(t) || 0; }); maxV = Math.max(maxV, sum); });
      } else {
        allPts.forEach((p) => { if (p[1] != null) { maxV = Math.max(maxV, p[1]); minV = Math.min(minV, p[1]); } });
      }
      if (opts.yMax != null && opts.yMax !== "") maxV = Math.max(maxV, Number(opts.yMax));
      if (opts.yMin != null && opts.yMin !== "") minV = Number(opts.yMin);
      if (maxV === minV) maxV = minV + 1;
      const yt = opts.unit === "B" ? binaryTicks(maxV, Math.max(2, Math.floor(H / 45))) : niceTicks(minV, maxV, Math.max(2, Math.floor(H / 45)));
      const yMin = yt[0], yMax = opts.yMax != null && opts.yMax !== "" && Number(opts.yMax) >= maxV ? Number(opts.yMax) : yt[yt.length - 1];
      const labels = yt.map((v) => SP.fmt(v, opts.unit));
      const ml = Math.min(90, 12 + Math.max(...labels.map((l) => l.length)) * 6.2);
      const m = { l: ml, r: 10, t: 8, b: 22 };
      const iw = W - m.l - m.r, ih = H - m.t - m.b;
      const x = (t) => m.l + ((t - start) / (end - start)) * iw;
      const y = (v) => m.t + ih - ((v - yMin) / (yMax - yMin || 1)) * ih;
      const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, height: H, role: "img", "aria-label": opts.title || "chart" });
      el.appendChild(svg);
      yt.forEach((v, i) => {
        if (v > yMax + 1e-9) return;
        svgEl("line", { x1: m.l, x2: W - m.r, y1: y(v), y2: y(v), class: v === 0 ? "axis" : "gridline" }, svg);
        const tx = svgEl("text", { x: m.l - 8, y: y(v) + 4, "text-anchor": "end" }, svg);
        tx.textContent = labels[i];
      });
      const { ticks, step: tstep } = timeTicks(start, end, iw);
      ticks.forEach((t) => {
        const tx = svgEl("text", { x: x(t), y: H - 6, "text-anchor": "middle" }, svg);
        tx.textContent = tickLabel(t, tstep);
      });
      (opts.thresholds || []).forEach((v, i) => {
        if (v == null || v === "" || v > yMax) return;
        svgEl("line", { x1: m.l, x2: W - m.r, y1: y(v), y2: y(v), stroke: i ? cssVar("--critical") : cssVar("--warning"), "stroke-width": 1, "stroke-dasharray": "0" , opacity: 0.8 }, svg);
      });
      if (!allPts.length) {
        const t = svgEl("text", { x: m.l + iw / 2, y: m.t + ih / 2, "text-anchor": "middle", class: "empty-msg" }, svg);
        t.textContent = "No data in this time range";
      }
      // median step -> gap detection
      const stepOf = (pts) => { if (pts.length < 2) return 0; const d = []; for (let i = 1; i < pts.length; i++) d.push(pts[i][0] - pts[i - 1][0]); d.sort((a, b) => a - b); return d[Math.floor(d.length / 2)]; };
      if (stacked) {
        const colW = times.length > 1 ? iw / ((end - start) / (stepOf(times.map((t) => [t])) || 60)) : 20;
        const bw = Math.max(1, Math.min(24, colW * 0.78));
        const base = new Map();
        visible.forEach((s, si) => {
          const g = svgEl("g", {}, svg);
          const mp = new Map(s.points);
          times.forEach((t) => {
            const v = mp.get(t) || 0;
            if (!v) return;
            const b0 = base.get(t) || 0;
            const y0 = y(b0), y1 = y(b0 + v);
            const h = Math.max(0, y0 - y1 - (b0 > 0 ? 2 : 0));
            if (h <= 0) { base.set(t, b0 + v); return; }
            const isTop = si === visible.length - 1 || visible.slice(si + 1).every((o) => !(new Map(o.points).get(t)));
            const bx = x(t) - bw / 2, by = y1;
            const r = isTop ? Math.min(4, bw / 2, h) : 0;
            const d = r ? `M${bx},${by + h}V${by + r}Q${bx},${by} ${bx + r},${by}H${bx + bw - r}Q${bx + bw},${by} ${bx + bw},${by + r}V${by + h}Z` : `M${bx},${by}h${bw}v${h}h${-bw}Z`;
            svgEl("path", { d, fill: s.color }, g);
            base.set(t, b0 + v);
          });
        });
      } else {
        visible.forEach((s) => {
          const pts = s.points.filter((p) => p[1] != null);
          if (!pts.length) return;
          const gap = Math.max(stepOf(pts) * 3, 1);
          let d = "", area = "", seg = [];
          const flush = () => {
            if (!seg.length) return;
            d += seg.map((p, i) => (i ? "L" : "M") + x(p[0]).toFixed(1) + "," + y(p[1]).toFixed(1)).join("");
            if (opts.type === "area") area += "M" + x(seg[0][0]).toFixed(1) + "," + y(Math.max(yMin, 0)) + seg.map((p) => "L" + x(p[0]).toFixed(1) + "," + y(p[1]).toFixed(1)).join("") + "L" + x(seg[seg.length - 1][0]).toFixed(1) + "," + y(Math.max(yMin, 0)) + "Z";
            seg = [];
          };
          pts.forEach((p, i) => { if (i && p[0] - pts[i - 1][0] > gap) flush(); seg.push(p); });
          flush();
          if (area) svgEl("path", { d: area, fill: s.color, opacity: 0.12 }, svg);
          svgEl("path", { d, class: "line", stroke: s.color }, svg);
          if (pts.length === 1) svgEl("circle", { cx: x(pts[0][0]), cy: y(pts[0][1]), r: 4, fill: s.color, class: "hover-dot" }, svg);
        });
      }
      // hover layer
      const hover = svgEl("g", { style: "display:none" }, svg);
      const cross = svgEl("line", { y1: m.t, y2: m.t + ih, class: "crosshair" }, hover);
      const overlay = svgEl("rect", { x: m.l, y: m.t, width: iw, height: ih, fill: "transparent" }, svg);
      const tip = document.createElement("div");
      tip.className = "tooltip hidden";
      el.appendChild(tip);
      const maps = visible.map((s) => ({ s, mp: new Map(s.points) }));
      overlay.addEventListener("mousemove", (ev) => {
        if (!times.length) return;
        const rect = svg.getBoundingClientRect();
        const px = ((ev.clientX - rect.left) / rect.width) * W;
        const t = start + ((px - m.l) / iw) * (end - start);
        let lo = 0, hi = times.length - 1;
        while (hi - lo > 1) { const mid = (lo + hi) >> 1; if (times[mid] < t) lo = mid; else hi = mid; }
        const ts = Math.abs(times[lo] - t) < Math.abs(times[hi] - t) ? times[lo] : times[hi];
        hover.style.display = "";
        cross.setAttribute("x1", x(ts)); cross.setAttribute("x2", x(ts));
        $$(".hover-dot.tmp", hover).forEach((n) => n.remove());
        const rows = [];
        let acc = 0;
        maps.forEach(({ s, mp }) => {
          const v = mp.get(ts);
          if (v == null) return;
          acc += v;
          rows.push({ s, v });
          if (!stacked) svgEl("circle", { cx: x(ts), cy: y(v), r: 4, fill: s.color, class: "hover-dot tmp" }, hover);
        });
        rows.sort((a, b) => b.v - a.v);
        tip.innerHTML = `<div class="tt-time">${esc(SP.fmtTime(ts, "full"))}</div>` +
          rows.slice(0, 12).map((r) => `<div class="tt-row"><span class="key" style="background:${r.s.color}"></span><span class="nm">${esc(r.s.name)}</span><span class="v">${esc(SP.fmt(r.v, opts.unit))}</span></div>`).join("") +
          (rows.length > 12 ? `<div class="muted">+${rows.length - 12} more</div>` : "") +
          (stacked && rows.length > 1 ? `<div class="tt-row"><span class="nm">Total</span><span class="v">${esc(SP.fmt(acc, opts.unit))}</span></div>` : "");
        tip.classList.remove("hidden");
        const ex = ev.clientX - el.getBoundingClientRect().left;
        const tw = tip.offsetWidth;
        tip.style.left = (ex + 16 + tw > el.clientWidth ? Math.max(0, ex - tw - 16) : ex + 16) + "px";
        tip.style.top = "8px";
      });
      overlay.addEventListener("mouseleave", () => { hover.style.display = "none"; tip.classList.add("hidden"); });

      // legend
      const mode = opts.legend === "auto" ? (colored.length > 4 ? "table" : colored.length > 1 ? "list" : "none") : opts.legend;
      if (mode !== "none" && colored.length) {
        const stats = (s) => { const vs = s.points.map((p) => p[1]).filter((v) => v != null); if (!vs.length) return {}; return { last: vs[vs.length - 1], max: Math.max(...vs), avg: vs.reduce((a, b) => a + b, 0) / vs.length }; };
        const lg = document.createElement("div");
        const toggle = (name, e) => {
          if (e && (e.ctrlKey || e.metaKey)) { if (hidden.has(name)) hidden.delete(name); else hidden.add(name); }
          else if (hidden.size === colored.length - 1 && !hidden.has(name)) hidden.clear();
          else { hidden.clear(); colored.forEach((o) => o.name !== name && hidden.add(o.name)); }
          draw();
        };
        if (mode === "table") {
          lg.className = "legend table-legend";
          const rows = colored.map((s) => ({ s, st: stats(s) })).sort((a, b) => (b.st.avg || 0) - (a.st.avg || 0));
          lg.innerHTML = `<table><thead><tr><th style="text-align:left">Series</th><th>Mean</th><th>Max</th><th>Last</th></tr></thead><tbody>` +
            rows.map(({ s, st }) => `<tr data-name="${esc(s.name)}" class="${hidden.has(s.name) ? "off" : ""}"><td><span class="key line" style="background:${s.color}"></span> ${esc(s.name)}</td><td class="num">${esc(SP.fmt(st.avg, opts.unit))}</td><td class="num">${esc(SP.fmt(st.max, opts.unit))}</td><td class="num">${esc(SP.fmt(st.last, opts.unit))}</td></tr>`).join("") + "</tbody></table>";
          $$("tr[data-name]", lg).forEach((tr) => tr.addEventListener("click", (e) => toggle(tr.dataset.name, e)));
        } else {
          lg.className = "legend";
          colored.forEach((s) => {
            const st = stats(s);
            const it = document.createElement("span");
            it.className = "item" + (hidden.has(s.name) ? " off" : "");
            // Counts (e.g. log messages per bucket) read better as a total than as the last bucket.
            const shown = opts.unit === "msgs" ? s.points.reduce((a, p) => a + (p[1] || 0), 0) : st.last;
            it.innerHTML = `<span class="key ${stacked ? "" : "line"}" style="background:${s.color}"></span><span class="nm">${esc(s.name)}</span><span class="v">${esc(SP.fmt(shown, opts.unit))}</span>`;
            it.title = "Click to isolate, Ctrl/Cmd-click to toggle";
            it.addEventListener("click", (e) => toggle(s.name, e));
            lg.appendChild(it);
          });
        }
        el.appendChild(lg);
      }
    }
  };

  SP.sparkline = function (el, points, unit) {
    el.innerHTML = "";
    if (!points || points.length < 2) return;
    const W = el.clientWidth || 200, H = parseInt(el.dataset.height || "36", 10);
    const vs = points.map((p) => p[1]);
    const min = Math.min(...vs, 0), max = Math.max(...vs) || 1;
    const t0 = points[0][0], t1 = points[points.length - 1][0] || t0 + 1;
    const x = (t) => ((t - t0) / (t1 - t0 || 1)) * (W - 4) + 2, y = (v) => H - 3 - ((v - min) / (max - min || 1)) * (H - 6);
    const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, class: "spark", preserveAspectRatio: "none" }, el);
    const d = points.map((p, i) => (i ? "L" : "M") + x(p[0]).toFixed(1) + "," + y(p[1]).toFixed(1)).join("");
    const color = cssVar("--s1");
    svgEl("path", { d: d + `L${x(t1)},${H}L${x(t0)},${H}Z`, fill: color, opacity: 0.12 }, svg);
    svgEl("path", { d, fill: "none", stroke: color, "stroke-width": 1.5 }, svg);
    el.title = "Last: " + SP.fmt(vs[vs.length - 1], unit);
  };

  SP.uptimeBars = function (daily) {
    return `<div class="ubars">` + daily.map((d) => {
      const cls = d.uptime_pct == null ? "nodata" : d.uptime_pct >= 99.95 ? "" : d.uptime_pct >= 99 ? "partial" : "bad";
      const tip = d.date + ": " + (d.uptime_pct == null ? "no data" : d.uptime_pct.toFixed(3) + "% uptime" + (d.outages ? ", " + d.outages + " outage(s), " + SP.duration(d.downtime_seconds) + " down" : ""));
      return `<span class="${cls}" title="${esc(tip)}"></span>`;
    }).join("") + `</div>`;
  };

  // --------------------------------------------------------- time ranges
  SP.RANGES = [["15m", "15m"], ["1h", "1h"], ["6h", "6h"], ["24h", "24h"], ["7d", "7d"], ["30d", "30d"], ["90d", "90d"], ["365d", "1y"]];
  SP.rangeSeconds = function (r) {
    const m = /^(\d+(?:\.\d+)?)([smhdw]?)$/.exec(r || "24h");
    if (!m) return 86400;
    return parseFloat(m[1]) * ({ "": 1, s: 1, m: 60, h: 3600, d: 86400, w: 604800 })[m[2]];
  };
  /** A time range picker. state: {range, start, end}; onChange(state). */
  SP.timePicker = function (container, state, onChange) {
    container.classList.add("row");
    const render = () => {
      container.innerHTML = `<div class="seg" role="group" aria-label="Time range">` +
        SP.RANGES.map(([v, l]) => `<button type="button" data-r="${v}" class="${!state.start && state.range === v ? "on" : ""}">${l}</button>`).join("") +
        `<button type="button" data-r="custom" class="${state.start ? "on" : ""}" title="Custom range">Custom</button></div>` +
        `<span class="custom-range ${state.start ? "" : "hidden"} row"><input type="datetime-local" class="from"> <span class="muted">to</span> <input type="datetime-local" class="to"> <button type="button" class="btn sm apply">Apply</button></span>`;
      const toLocal = (ts) => { const d = new Date(ts * 1000); return d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate()) + "T" + pad(d.getHours()) + ":" + pad(d.getMinutes()); };
      const now = Date.now() / 1000;
      $(".from", container).value = toLocal(state.start || now - SP.rangeSeconds(state.range));
      $(".to", container).value = toLocal(state.end || now);
      $$("button[data-r]", container).forEach((b) => b.addEventListener("click", () => {
        if (b.dataset.r === "custom") { $(".custom-range", container).classList.remove("hidden"); return; }
        state.range = b.dataset.r; state.start = null; state.end = null; render(); onChange(state);
      }));
      $(".apply", container).addEventListener("click", () => {
        const s = new Date($(".from", container).value).getTime() / 1000, e = new Date($(".to", container).value).getTime() / 1000;
        if (!(s < e)) return SP.toast("Start must be before end", "error");
        state.start = s; state.end = e; render(); onChange(state);
      });
    };
    render();
    return state;
  };
  SP.rangeQuery = function (state) {
    if (state.start && state.end) return `start=${Math.floor(state.start)}&end=${Math.floor(state.end)}`;
    return `range=${encodeURIComponent(state.range || "24h")}`;
  };
  SP.rangeBounds = function (state) {
    const end = state.end || Date.now() / 1000;
    return { start: state.start || end - SP.rangeSeconds(state.range), end };
  };
  SP.urlState = function (defaults) {
    const p = new URLSearchParams(location.search);
    return { range: p.get("range") || defaults.range || "24h", start: p.get("start") ? +p.get("start") : null, end: p.get("end") ? +p.get("end") : null };
  };
  SP.pushState = function (state, extra) {
    const p = new URLSearchParams(location.search);
    ["range", "start", "end"].forEach((k) => p.delete(k));
    if (state.start) { p.set("start", Math.floor(state.start)); p.set("end", Math.floor(state.end)); } else p.set("range", state.range);
    Object.entries(extra || {}).forEach(([k, v]) => (v == null || v === "" ? p.delete(k) : p.set(k, v)));
    history.replaceState(null, "", location.pathname + "?" + p.toString());
  };

  // ----------------------------------------------------- metric charts on pages
  /** Charts declared in HTML: <div data-chart='{"targets":[...], "type":"area"}'> or data-metric="id". */
  SP.loadCharts = async function (root, state) {
    const els = $$("[data-chart], [data-metric]", root);
    const b = SP.rangeBounds(state);
    await Promise.all(els.map(async (el) => {
      try {
        let spec = el.dataset.chart ? JSON.parse(el.dataset.chart) : null;
        let series = [], unit = "";
        if (el.dataset.metric) {
          const r = await SP.api("GET", `/api/metrics/${el.dataset.metric}/series?${SP.rangeQuery(state)}`);
          unit = r.metric.unit;
          series = [{ name: r.metric.label || r.metric.key, points: r.points.map((p) => [p.ts, p.avg]) }];
          spec = spec || {};
        } else {
          const results = await Promise.all(spec.targets.map((t) => SP.api("POST", `/api/query?${SP.rangeQuery(state)}`, t)));
          results.forEach((r) => (series = series.concat(r.series)));
          unit = spec.unit || (series[0] && series[0].unit) || "";
        }
        SP.chart(el, series, Object.assign({ start: b.start, end: b.end, unit }, spec));
      } catch (e) {
        el.innerHTML = `<div class="empty">${esc(e.message)}</div>`;
      }
    }));
  };

  // ------------------------------------------------------------ dashboards
  const PANEL_H = { 1: 110, 2: 250, 3: 390, 4: 540 };
  SP.renderPanel = async function (card, panel, state) {
    const body = $(".panel-body", card);
    const b = SP.rangeBounds(state);
    let data;
    try {
      data = await SP.api("POST", "/api/panel-data", Object.assign({ panel }, state.start ? { start: state.start, end: state.end } : { range: state.range }));
    } catch (e) {
      body.innerHTML = `<div class="empty">${esc(e.message)}</div>`;
      return;
    }
    const o = panel.options || {};
    const h = PANEL_H[panel.h] || 250;
    const type = panel.type;
    if (data.error) { body.innerHTML = `<div class="empty">${esc(data.error)}</div>`; return; }
    if (type === "timeseries") {
      body.innerHTML = "";
      const div = document.createElement("div");
      body.appendChild(div);
      const legendRoom = (o.legend || "auto") === "none" ? 0 : data.series.length > 4 ? 110 : data.series.length > 1 ? 30 : 0;
      SP.chart(div, data.series, { type: o.chart || "line", unit: o.unit || (data.series[0] && data.series[0].unit) || "", start: b.start, end: b.end, height: Math.max(120, h - legendRoom), yMin: o.y_min, yMax: o.y_max, legend: o.legend || "auto", thresholds: o.thresholds, title: panel.title });
    } else if (type === "stat") {
      const th = o.thresholds || [];
      const v = data.value;
      const cls = v == null ? "" : th[1] != null && v >= th[1] ? "crit" : th[0] != null && v >= th[0] ? "warn" : "good";
      body.innerHTML = `<div class="big-stat ${cls}"><div class="value">${esc(SP.fmt(v, data.unit))}</div>${o.sub ? `<div class="muted">${esc(o.sub)}</div>` : ""}<div class="spark-wrap"></div></div>`;
      if (data.sparkline && data.sparkline.length > 1 && panel.h > 1) SP.sparkline($(".spark-wrap", body), data.sparkline, data.unit);
    } else if (type === "gauge") {
      const max = Number(o.max || 100), v = data.value;
      const frac = v == null ? 0 : Math.max(0, Math.min(1, v / max));
      const th = o.thresholds || [];
      const color = v == null ? cssVar("--unknown") : th[1] != null && v >= th[1] ? cssVar("--critical") : th[0] != null && v >= th[0] ? cssVar("--warning") : cssVar("--s1");
      const R = 80, cx = 100, cy = 95, a0 = Math.PI, a1 = Math.PI * (1 - frac);
      const pt = (a) => [cx + R * Math.cos(a), cy - R * Math.sin(a)];
      const [x0, y0] = pt(a0), [x1, y1] = pt(a1), [xe, ye] = pt(0);
      body.innerHTML = `<div class="gauge"><svg viewBox="0 0 200 110"><path class="track" d="M${x0},${y0} A${R},${R} 0 0 1 ${xe},${ye}" fill="none" stroke-width="16" stroke-linecap="round"/>` +
        (frac > 0 ? `<path d="M${x0},${y0} A${R},${R} 0 0 1 ${x1.toFixed(2)},${y1.toFixed(2)}" fill="none" stroke="${color}" stroke-width="16" stroke-linecap="round"/>` : "") +
        `<text x="100" y="92" text-anchor="middle" font-size="26" font-weight="650" fill="currentColor">${esc(SP.fmt(v, data.unit))}</text></svg></div>`;
    } else if (type === "table") {
      if (!data.rows.length) { body.innerHTML = `<div class="empty">No data</div>`; return; }
      body.innerHTML = `<table class="table compact"><thead><tr><th>Device</th><th>Instance</th><th class="num">Value</th></tr></thead><tbody>` +
        data.rows.map((r) => {
          const pct = r.unit === "%" ? r.value : r.util;
          const meter = pct != null ? `<div class="meter ${pct > 90 ? "crit" : pct > 70 ? "warn" : ""}" style="width:60px;display:inline-block;vertical-align:middle;margin-left:8px"><span style="width:${Math.min(100, pct)}%"></span></div>` : "";
          return `<tr><td><a href="/devices/${r.device_id}">${esc(r.device)}</a></td><td>${esc(r.label)}</td><td class="num">${esc(SP.fmt(r.value, r.unit))}${meter}</td></tr>`;
        }).join("") + `</tbody></table>`;
    } else if (type === "status") {
      if (!data.items.length) { body.innerHTML = `<div class="empty">Nothing to show</div>`; return; }
      body.innerHTML = `<div class="status-grid">` + data.items.map((i) =>
        `<a class="status-cell ${i.state === "down" ? "down" : ""}" href="${i.link}"><span class="nm">${esc(i.name)}</span><span class="status ${esc(i.state)}">${esc(i.state)}</span>` +
        `<span class="detail">${i.uptime != null ? i.uptime.toFixed(2) + "% (24h)" : esc(i.detail || "")}${i.latency != null ? " · " + esc(SP.fmt(i.latency, "ms")) : ""}</span></a>`).join("") + `</div>`;
    } else if (type === "uptime") {
      if (!data.items.length) { body.innerHTML = `<div class="empty">No checks</div>`; return; }
      body.innerHTML = `<table class="table compact"><tbody>` + data.items.map((i) =>
        `<tr><td style="width:28%"><span class="status ${esc(i.state)}"></span> <a href="/checks/${i.id}">${esc(i.name)}</a></td><td>${SP.uptimeBars(i.daily)}</td><td class="num" style="width:90px">${i.uptime == null ? "-" : i.uptime.toFixed(3) + "%"}</td></tr>`).join("") + `</tbody></table>`;
    } else if (type === "syslog_histogram") {
      body.innerHTML = "";
      const div = document.createElement("div");
      body.appendChild(div);
      const series = [["error", "err and worse", "red"], ["warning", "warning", "orange"], ["info", "notice / info / debug", "blue"]].map(([k, n, c]) => ({ name: n, color: c, points: data.buckets.map((x) => [x.ts, x[k]]) }));
      SP.chart(div, series, { type: "stacked", unit: "msgs", start: data.start, end: data.end, height: h - 30, legend: "list" });
    } else if (type === "syslog_stream") {
      if (!data.rows.length) { body.innerHTML = `<div class="empty">No messages</div>`; return; }
      body.innerHTML = `<table class="table compact log-table"><tbody>` + data.rows.map((r) =>
        `<tr class="sev-${r.severity}"><td class="nowrap muted small">${esc(SP.fmtTime(r.ts))}</td><td class="nowrap">${esc(r.host)}</td><td><span class="badge ${esc(r.severity_name)}">${esc(r.severity_name)}</span></td><td class="msg">${esc(r.app ? r.app + ": " : "")}${esc(r.message)}</td></tr>`).join("") + `</tbody></table>`;
    } else if (type === "syslog_top") {
      const max = Math.max(1, ...data.rows.map((r) => r.count));
      const SEV = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"];
      body.innerHTML = data.rows.length ? data.rows.map((r) => {
        const label = data.field === "severity" ? (SEV[r.value] || "-") : (r.value || "(none)");
        const q = data.field === "severity" ? `severity=${r.value}` : `${data.field}=${encodeURIComponent(r.value || "")}`;
        return `<a class="facet" href="/syslog?${q}" style="display:block;color:inherit"><div class="row between"><span class="nm">${esc(label)}</span><span class="num muted">${r.count.toLocaleString()}</span></div><div class="bar" style="width:${(r.count / max) * 100}%"></div></a>`;
      }).join("") : `<div class="empty">No messages</div>`;
    } else if (type === "alerts") {
      body.innerHTML = data.rows.length ? data.rows.map((a) =>
        `<div class="alert-row"><span class="status ${esc(a.severity)}"></span><div class="body"><div class="subject">${esc(a.subject)}</div><div class="msg">${esc(a.message)}</div><div class="small muted">firing ${esc(SP.ago(a.fired_at))}${a.acknowledged ? " · acknowledged" : ""}</div></div></div>`).join("")
        : `<div class="empty"><span class="status ok">All clear</span><br><span class="small">No alerts are firing</span></div>`;
    } else if (type === "events") {
      body.innerHTML = data.rows.length ? data.rows.map((e) =>
        `<div class="event-row"><time>${esc(SP.fmtTime(e.ts))}</time><span class="status ${e.level === "error" ? "down" : e.level === "warning" ? "warning" : "info"}"></span><span>${esc(e.message)}</span></div>`).join("") : `<div class="empty">No events</div>`;
    } else if (type === "summary") {
      const d = data;
      const tile = (label, value, sub, bad, href) => `<a class="tile card ${bad ? "bad" : ""}" href="${href}" style="color:inherit"><div class="label">${label}</div><div class="value">${value}</div><div class="sub">${sub}</div></a>`;
      body.innerHTML = `<div class="tiles">` +
        tile("Devices", `${d.devices.up}/${d.devices.total - d.devices.disabled}`, d.devices.down ? `<span class="status down">${d.devices.down} down</span>` : `<span class="status up">all responding</span>`, d.devices.down, "/devices") +
        tile("Checks", `${d.checks.up}/${d.checks.total - d.checks.paused}`, d.checks.down ? `<span class="status down">${d.checks.down} down</span>` : `<span class="status up">all up</span>`, d.checks.down, "/checks") +
        tile("Alerts firing", d.alerts.firing, d.alerts.critical ? `<span class="status critical">${d.alerts.critical} critical</span>` : "none critical", d.alerts.critical, "/alerts") +
        tile("Ports down", d.interfaces.down, `of ${d.interfaces.total} interfaces`, false, "/devices") +
        tile("Syslog / hour", d.syslog.last_hour.toLocaleString(), `${d.syslog.errors_last_hour} errors`, false, "/syslog") + `</div>`;
      $$(".tile", body).forEach((t) => (t.style.boxShadow = "none"));
    } else if (type === "text") {
      body.innerHTML = `<div style="white-space:pre-wrap">${esc(data.text)}</div>`;
    }
  };

  SP.dashboard = function (root, dash, opts) {
    opts = opts || {};
    const grid = $(".dash-grid", root);
    const config = dash.config;
    const state = SP.urlState({ range: config.time || "24h" });
    let refresh = +(new URLSearchParams(location.search).get("refresh") || config.refresh || 0);
    let timer = null;
    let editing = false;

    const renderAll = () => { $$(".panel", grid).forEach((card) => SP.renderPanel(card, config.panels[+card.dataset.idx], state)); $("#dash-updated") && ($("#dash-updated").textContent = "updated " + SP.fmtTime(Date.now() / 1000, "timesec")); };
    const layout = () => {
      grid.innerHTML = "";
      grid.classList.toggle("editing", editing);
      config.panels.forEach((p, i) => {
        const card = document.createElement("div");
        card.className = `card panel h${p.h}`;
        card.dataset.idx = i;
        card.style.gridColumn = `span ${p.w}`;
        card.innerHTML = `<div class="card-head"><h3 title="${esc(p.title)}">${esc(p.title)}</h3><span class="panel-actions no-print">` +
          (editing ? `<button class="btn ghost sm" data-p="left" title="Move earlier">&larr;</button><button class="btn ghost sm" data-p="right" title="Move later">&rarr;</button><button class="btn ghost sm" data-p="narrow" title="Narrower">&minus;</button><button class="btn ghost sm" data-p="wide" title="Wider">+</button><button class="btn ghost sm" data-p="dup" title="Duplicate">&#x2398;</button><button class="btn ghost sm danger" data-p="del" title="Remove">&times;</button>` : "") +
          `<button class="btn ghost sm" data-p="edit" title="Edit panel">Edit</button><button class="btn ghost sm" data-p="view" title="View larger">&#x2922;</button></span></div><div class="panel-body" style="min-height:${PANEL_H[p.h]}px"><div class="muted small">Loading…</div></div>`;
        grid.appendChild(card);
      });
      renderAll();
    };
    grid.addEventListener("click", (ev) => {
      const btn = ev.target.closest("[data-p]");
      if (!btn) return;
      const card = btn.closest(".panel");
      const i = +card.dataset.idx;
      const ps = config.panels;
      const act = btn.dataset.p;
      if (act === "edit") return SP.panelEditor(ps[i], (np) => { ps[i] = np; dirty(); layout(); }, () => { ps.splice(i, 1); dirty(); layout(); });
      if (act === "view") return viewPanel(ps[i]);
      if (act === "left" && i > 0) [ps[i - 1], ps[i]] = [ps[i], ps[i - 1]];
      if (act === "right" && i < ps.length - 1) [ps[i + 1], ps[i]] = [ps[i], ps[i + 1]];
      if (act === "narrow") ps[i].w = Math.max(2, ps[i].w - 1);
      if (act === "wide") ps[i].w = Math.min(12, ps[i].w + 1);
      if (act === "dup") ps.splice(i + 1, 0, JSON.parse(JSON.stringify(ps[i])));
      if (act === "del") { if (!confirm("Remove this panel?")) return; ps.splice(i, 1); }
      dirty();
      layout();
    });
    const viewPanel = (p) => {
      const back = document.createElement("div");
      back.className = "modal-back";
      back.innerHTML = `<div class="modal wide"><div class="card-head"><h2>${esc(p.title)}</h2><button class="btn ghost" data-action="close-modal">&times;</button></div><div class="modal-body"><div class="card panel h4" style="box-shadow:none;border:0"><div class="panel-body"></div></div></div></div>`;
      document.body.appendChild(back);
      SP.renderPanel($(".panel", back), Object.assign({}, p, { h: 4 }), state);
      back.addEventListener("click", (e) => { if (e.target === back || e.target.closest("[data-action=close-modal]")) back.remove(); });
    };
    let isDirty = false;
    const dirty = () => { isDirty = true; const s = $("#dash-save"); if (s) s.classList.remove("hidden"); };
    const save = async () => {
      try {
        await SP.api("PATCH", `/api/dashboards/${dash.id}`, { config });
        isDirty = false;
        $("#dash-save").classList.add("hidden");
        SP.toast("Dashboard saved");
      } catch (e) { SP.toast(e.message, "error"); }
    };
    window.addEventListener("beforeunload", (e) => { if (isDirty) { e.preventDefault(); e.returnValue = ""; } });
    const setTimer = () => {
      clearInterval(timer);
      if (refresh > 0) timer = setInterval(() => { if (!document.hidden && !editing) renderAll(); }, refresh * 1000);
    };

    SP.timePicker($("#dash-time"), state, () => { SP.pushState(state, { refresh }); renderAll(); });
    const rsel = $("#dash-refresh");
    if (rsel) {
      rsel.value = String(refresh);
      if (rsel.value !== String(refresh)) { rsel.insertAdjacentHTML("beforeend", `<option value="${refresh}">${refresh}s</option>`); rsel.value = String(refresh); }
      rsel.addEventListener("change", () => { refresh = +rsel.value; SP.pushState(state, { refresh }); setTimer(); });
    }
    $("#dash-reload") && $("#dash-reload").addEventListener("click", renderAll);
    $("#dash-save") && $("#dash-save").addEventListener("click", save);
    $("#dash-edit") && $("#dash-edit").addEventListener("click", () => { editing = !editing; $("#dash-edit").classList.toggle("primary", editing); $("#dash-edit").textContent = editing ? "Done editing" : "Edit layout"; layout(); });
    $("#dash-add") && $("#dash-add").addEventListener("click", () => SP.panelEditor({ type: "timeseries", title: "New panel", w: 6, h: 2, options: {}, targets: [{ key: "if.in_bps" }] }, (np) => { config.panels.push(np); dirty(); layout(); }));
    $("#dash-kiosk") && $("#dash-kiosk").addEventListener("click", () => {
      document.body.classList.toggle("kiosk");
      if (document.body.classList.contains("kiosk") && document.documentElement.requestFullscreen) document.documentElement.requestFullscreen().catch(() => {});
      else if (document.fullscreenElement) document.exitFullscreen();
    });
    document.addEventListener("fullscreenchange", () => { if (!document.fullscreenElement) document.body.classList.remove("kiosk"); });
    $("#dash-json") && $("#dash-json").addEventListener("click", () => SP.jsonEditor(dash, (cfg) => { Object.assign(config, cfg); dirty(); layout(); }));
    $("#dash-settings") && $("#dash-settings").addEventListener("click", () => SP.openModal($("#dash-settings-modal")));
    layout();
    setTimer();
    return { config, renderAll };
  };

  SP.jsonEditor = function (dash, onApply) {
    const back = document.createElement("div");
    back.className = "modal-back";
    back.innerHTML = `<div class="modal wide"><div class="card-head"><h2>Dashboard JSON model</h2><button class="btn ghost" data-x>&times;</button></div>
      <div class="modal-body"><p class="muted small">Copy this to back up or share the dashboard, or paste a model and apply it.</p><textarea class="mono" style="min-height:420px" spellcheck="false">${esc(JSON.stringify(dash.config, null, 2))}</textarea></div>
      <div class="modal-foot"><button class="btn" data-x>Cancel</button><button class="btn primary" data-apply>Apply</button></div></div>`;
    document.body.appendChild(back);
    back.addEventListener("click", (e) => {
      if (e.target === back || e.target.closest("[data-x]")) back.remove();
      if (e.target.closest("[data-apply]")) {
        try { onApply(JSON.parse($("textarea", back).value)); back.remove(); } catch (err) { SP.toast("Invalid JSON: " + err.message, "error"); }
      }
    });
  };

  // Panel editor ------------------------------------------------------
  let editorMeta = null;
  async function loadEditorMeta() {
    if (editorMeta) return editorMeta;
    const [keys, devices, checks, types] = await Promise.all([
      SP.api("GET", "/api/metric-keys"), SP.api("GET", "/api/devices"), SP.api("GET", "/api/checks"), SP.api("GET", "/api/panel-types"),
    ]);
    const tags = Array.from(new Set(devices.flatMap((d) => d.tags))).sort();
    editorMeta = { keys, devices, checks, types, tags };
    return editorMeta;
  }
  const TARGET_TYPES = ["timeseries", "stat", "gauge", "table", "syslog_histogram", "syslog_stream", "syslog_top"];
  SP.panelEditor = async function (panel, onSave, onDelete) {
    const meta = await loadEditorMeta();
    const p = JSON.parse(JSON.stringify(panel));
    p.options = p.options || {};
    p.targets = p.targets && p.targets.length ? p.targets : [{}];
    const back = document.createElement("div");
    back.className = "modal-back";
    back.dataset.static = "1";
    document.body.appendChild(back);
    const opt = (v, cur, label) => `<option value="${esc(v)}" ${String(cur) === String(v) ? "selected" : ""}>${esc(label == null ? v : label)}</option>`;
    const keyList = `<datalist id="pe-keys">${meta.keys.map((k) => `<option value="${esc(k.key)}">${esc(k.name)}</option>`).join("")}</datalist>`;
    const targetRow = (t, i) => {
      const src = t.source || (p.type.startsWith("syslog") ? "syslog" : "metric");
      const syslogOnly = p.type.startsWith("syslog");
      return `<div class="card mb target" data-i="${i}" style="box-shadow:none"><div class="card-body"><div class="form-grid">
        <label class="field">Source<select data-t="source" ${syslogOnly ? "disabled" : ""}>${opt("metric", src, "SNMP metric")}${opt("check", src, "Check response time / availability")}${opt("syslog", src, "Syslog message count")}</select></label>` +
        (src === "metric" ? `
        <label class="field">Metric<input data-t="key" list="pe-keys" value="${esc(t.key || "")}" placeholder="if.in_bps, cpu.avg, if.*_util"></label>
        <label class="field">Device<select data-t="device">${opt("", t.device || "", "All devices")}${meta.devices.map((d) => opt(d.name, t.device, d.name)).join("")}</select></label>
        <label class="field">Tag<select data-t="tag">${opt("", t.tag || "", "Any")}${meta.tags.map((g) => opt(g, t.tag)).join("")}</select></label>
        <label class="field">Instance / label<input data-t="instance" value="${esc(t.instance || "")}" placeholder="e.g. Gi1/0/* or / "></label>
        <label class="field">Aggregate<select data-t="agg">${["each", "sum", "avg", "max", "min"].map((a) => opt(a, t.agg || "each", a === "each" ? "each series" : a + " of all")).join("")}</select></label>
        <label class="field">Max series<input data-t="limit" type="number" min="1" max="50" value="${esc(t.limit || "")}" placeholder="8"></label>
        <label class="field">Alias<input data-t="alias" value="${esc(t.alias || "")}" placeholder="{device} {label}"></label>` : "") +
        (src === "check" ? `
        <label class="field">Check<select data-t="check">${opt("*", t.check || "*", "All checks")}${meta.checks.map((c) => opt(c.id, t.check, c.name)).join("")}</select></label>
        <label class="field">Field<select data-t="field">${opt("latency", t.field || "latency", "Response time")}${opt("up", t.field, "Availability %")}</select></label>
        <label class="field">Max series<input data-t="limit" type="number" min="1" max="50" value="${esc(t.limit || "")}" placeholder="8"></label>` : "") +
        (src === "syslog" ? `
        <label class="field">Search<input data-t="q" value="${esc(t.q || "")}" placeholder="words, &quot;phrases&quot;, -exclude"></label>
        <label class="field">Severity<select data-t="severity">${opt("", t.severity == null ? "" : t.severity, "Any")}${["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"].map((s, n) => opt(n, t.severity, s + " and worse")).join("")}</select></label>
        <label class="field">Host<input data-t="host" value="${esc(t.host || "")}" placeholder="host or glob"></label>
        <label class="field">App<input data-t="app" value="${esc(t.app || "")}"></label>` : "") +
        `</div>${p.targets.length > 1 ? `<button class="btn sm danger mt" data-rm="${i}">Remove query</button>` : ""}</div></div>`;
    };
    const optField = (name, label, input) => `<label class="field">${label}${input}</label>`;
    const optionsHtml = () => {
      const o = p.options, t = p.type;
      let h = "";
      if (t === "timeseries") h += optField("chart", "Style", `<select data-o="chart">${opt("line", o.chart || "line", "Lines")}${opt("area", o.chart, "Area")}${opt("stacked", o.chart, "Stacked bars")}${opt("bar", o.chart, "Bars")}</select>`) +
        optField("legend", "Legend", `<select data-o="legend">${opt("auto", o.legend || "auto", "Auto")}${opt("list", o.legend, "List")}${opt("table", o.legend, "Table (mean/max/last)")}${opt("none", o.legend, "Hidden")}</select>`) +
        optField("y_min", "Y min", `<input data-o="y_min" type="number" value="${esc(o.y_min == null ? "" : o.y_min)}">`) +
        optField("y_max", "Y max", `<input data-o="y_max" type="number" value="${esc(o.y_max == null ? "" : o.y_max)}">`);
      if (["timeseries", "stat", "gauge"].includes(t)) h += optField("unit", "Unit override", `<select data-o="unit">${opt("", o.unit || "", "Automatic")}${["bps", "B", "%", "ms", "s", "/s", "msgs"].map((u) => opt(u, o.unit)).join("")}</select>`) +
        optField("thresholds", "Thresholds (warn, crit)", `<input data-o="thresholds" value="${esc((o.thresholds || []).join(", "))}" placeholder="70, 90">`);
      if (["stat", "gauge"].includes(t)) h += optField("reduce", "Calculation", `<select data-o="reduce">${["last", "avg", "max", "min", "sum"].map((r) => opt(r, o.reduce || "last")).join("")}</select>`);
      if (t === "gauge") h += optField("max", "Maximum", `<input data-o="max" type="number" value="${esc(o.max || 100)}">`);
      if (["table", "alerts", "events", "syslog_stream", "syslog_top", "uptime"].includes(t)) h += optField("limit", "Rows", `<input data-o="limit" type="number" min="1" value="${esc(o.limit || "")}" placeholder="10">`);
      if (t === "table") h += optField("order", "Order", `<select data-o="order">${opt("desc", o.order || "desc", "Highest first")}${opt("asc", o.order, "Lowest first")}</select>`);
      if (t === "status") h += optField("of", "Show", `<select data-o="of">${opt("devices", o.of || "devices", "Devices")}${opt("checks", o.of, "Checks")}</select>`) +
        optField("tag", "Device tag", `<select data-o="tag">${opt("", o.tag || "", "Any")}${meta.tags.map((g) => opt(g, o.tag)).join("")}</select>`);
      if (t === "uptime") h += optField("days", "Days of bars", `<input data-o="days" type="number" min="7" max="90" value="${esc(o.days || 30)}">`) +
        `<label class="check"><input type="checkbox" data-o="public_only" ${o.public_only ? "checked" : ""}> Public checks only</label>`;
      if (t === "syslog_top") h += optField("field", "Group by", `<select data-o="field">${["host", "app", "severity", "facility", "source_ip"].map((f) => opt(f, o.field || "host")).join("")}</select>`);
      if (t === "syslog_histogram") h += optField("buckets", "Bars", `<input data-o="buckets" type="number" min="10" max="300" value="${esc(o.buckets || 80)}">`);
      if (t === "text") h += `<label class="field wide">Text<textarea data-o="text">${esc(o.text || "")}</textarea></label>`;
      return h;
    };
    const render = () => {
      back.innerHTML = `<div class="modal wide"><div class="card-head"><h2>Edit panel</h2><button class="btn ghost" data-x>&times;</button></div>
        <div class="modal-body">${keyList}
          <div class="form-grid mb">
            <label class="field">Title<input data-f="title" value="${esc(p.title || "")}"></label>
            <label class="field">Visualisation<select data-f="type">${Object.entries(meta.types).map(([k, v]) => opt(k, p.type, v)).join("")}</select></label>
            <label class="field">Width (1-12 columns)<input data-f="w" type="number" min="1" max="12" value="${p.w || 6}"></label>
            <label class="field">Height<select data-f="h">${[1, 2, 3, 4].map((n) => opt(n, p.h || 2, ["", "Small", "Medium", "Large", "Extra large"][n])).join("")}</select></label>
          </div>
          ${TARGET_TYPES.includes(p.type) ? `<h3 class="mb">Queries</h3><div class="targets">${p.targets.map(targetRow).join("")}</div>${["timeseries", "stat", "gauge"].includes(p.type) ? `<button class="btn sm" data-add>+ Add query</button>` : ""}` : ""}
          <h3 class="mt mb">Display options</h3><div class="form-grid">${optionsHtml() || `<span class="muted">No options for this panel type.</span>`}</div>
          <h3 class="mt mb">Preview</h3><div class="card panel h${p.h || 2}" style="box-shadow:none"><div class="panel-body preview"></div></div>
        </div>
        <div class="modal-foot">${onDelete ? `<button class="btn danger" data-del style="margin-right:auto">Remove panel</button>` : ""}<button class="btn" data-preview>Refresh preview</button><button class="btn" data-x>Cancel</button><button class="btn primary" data-save>Apply</button></div></div>`;
      preview();
    };
    const collect = () => {
      $$("[data-f]", back).forEach((el) => { p[el.dataset.f] = ["w", "h"].includes(el.dataset.f) ? +el.value : el.value; });
      $$(".target", back).forEach((row) => {
        const t = {};
        $$("[data-t]", row).forEach((el) => { if (el.value !== "" && !el.disabled) t[el.dataset.t] = ["limit", "severity"].includes(el.dataset.t) ? +el.value : el.value; });
        if (p.type.startsWith("syslog")) delete t.source;
        p.targets[+row.dataset.i] = t;
      });
      const o = {};
      $$("[data-o]", back).forEach((el) => {
        const k = el.dataset.o;
        if (el.type === "checkbox") { if (el.checked) o[k] = true; return; }
        if (el.value === "") return;
        if (k === "thresholds") o[k] = el.value.split(",").map((s) => parseFloat(s)).filter((n) => !isNaN(n));
        else if (el.type === "number") o[k] = parseFloat(el.value);
        else o[k] = el.value;
      });
      p.options = o;
      return p;
    };
    const preview = () => SP.renderPanel($(".preview", back).closest(".panel"), collect(), SP.urlState({ range: "24h" }));
    back.addEventListener("change", (e) => {
      if (e.target.matches("[data-f=type], [data-t=source], [data-f=h]")) { collect(); render(); }
    });
    back.addEventListener("click", (e) => {
      if (e.target.closest("[data-x]")) back.remove();
      else if (e.target.closest("[data-add]")) { collect(); p.targets.push({ key: "" }); render(); }
      else if (e.target.closest("[data-rm]")) { collect(); p.targets.splice(+e.target.closest("[data-rm]").dataset.rm, 1); render(); }
      else if (e.target.closest("[data-preview]")) preview();
      else if (e.target.closest("[data-save]")) { onSave(collect()); back.remove(); }
      else if (e.target.closest("[data-del]")) { if (confirm("Remove this panel?")) { onDelete(); back.remove(); } }
    });
    render();
  };

  // ---------------------------------------------------------- syslog explorer
  SP.syslogExplorer = function (root) {
    const form = $("form.searchbar", root);
    const state = SP.urlState({ range: "24h" });
    const table = $("#log-body", root);
    let oldest = null, live = false, liveTimer = null, newest = null;
    const params = () => {
      const p = new URLSearchParams();
      $$("input, select", form).forEach((el) => { if (el.name && el.value) p.set(el.name, el.value); });
      const b = SP.rangeBounds(state);
      if (state.start) { p.set("start", Math.floor(state.start)); p.set("end", Math.floor(state.end)); }
      else p.set("start", Math.floor(b.start));
      return p;
    };
    const row = (r) => `<tr class="sev-${r.severity}" data-id="${r.id}"><td class="nowrap small" title="${esc(SP.fmtTime(r.ts, "full"))}">${esc(SP.fmtTime(r.ts))}</td><td class="nowrap">${r.device_id ? `<a href="/devices/${r.device_id}">${esc(r.host)}</a>` : esc(r.host)}</td><td><span class="badge ${esc(r.severity_name)}">${esc(r.severity_name || "-")}</span></td><td class="small">${esc(r.facility_name)}</td><td class="nowrap">${esc(r.app)}</td><td class="msg">${esc(r.message)}</td></tr>`;
    const load = async (append) => {
      const p = params();
      p.set("limit", "200");
      if (append && oldest) p.set("before_id", oldest);
      const rows = await SP.api("GET", "/api/syslog?" + p.toString());
      if (!append) { table.innerHTML = ""; newest = rows.length ? rows[0].id : newest; }
      table.insertAdjacentHTML("beforeend", rows.map(row).join(""));
      if (rows.length) oldest = rows[rows.length - 1].id;
      $("#log-more", root).classList.toggle("hidden", rows.length < 200);
      if (!append && !rows.length) table.innerHTML = `<tr><td colspan="6" class="empty">No messages match. ${$("#listen-hint", root) ? $("#listen-hint", root).innerHTML : ""}</td></tr>`;
    };
    const stats = async () => {
      const p = params();
      const [count, hist, hosts, apps, sevs] = await Promise.all([
        SP.api("GET", "/api/syslog/count?" + p), SP.api("GET", "/api/syslog/histogram?buckets=90&" + p),
        SP.api("GET", "/api/syslog/top?field=host&" + p), SP.api("GET", "/api/syslog/top?field=app&" + p), SP.api("GET", "/api/syslog/top?field=severity&" + p),
      ]);
      $("#log-count").textContent = count.count.toLocaleString() + " messages";
      const series = [["error", "err and worse", "red"], ["warning", "warning", "orange"], ["info", "notice / info / debug", "blue"]].map(([k, n, c]) => ({ name: n, color: c, points: hist.buckets.map((x) => [x.ts, x[k]]) }));
      SP.chart($("#log-hist", root), series, { type: "stacked", unit: "msgs", start: hist.start, end: hist.end, height: 150, legend: "list" });
      const SEV = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"];
      const facet = (el, rows, field) => {
        const max = Math.max(1, ...rows.map((r) => r.count));
        el.innerHTML = rows.length ? rows.map((r) => `<div class="facet" data-field="${field}" data-value="${esc(r.value == null ? "" : r.value)}"><div style="flex:1;min-width:0"><div class="nm">${esc(field === "severity" ? SEV[r.value] || "-" : r.value || "(none)")}</div><div class="bar" style="width:${(r.count / max) * 100}%"></div></div><span class="num muted">${r.count.toLocaleString()}</span></div>`).join("") : `<div class="muted small">-</div>`;
      };
      facet($("#facet-host", root), hosts, "host");
      facet($("#facet-app", root), apps, "app");
      facet($("#facet-sev", root), sevs, "severity");
    };
    const run = () => {
      oldest = null;
      const extra = {};
      $$("input, select", form).forEach((el) => { if (el.name) extra[el.name] = el.value; });
      SP.pushState(state, extra);
      load(false).catch((e) => SP.toast(e.message, "error"));
      stats().catch((e) => SP.toast(e.message, "error"));
    };
    form.addEventListener("submit", (e) => { e.preventDefault(); run(); });
    $$("select", form).forEach((s) => s.addEventListener("change", run));
    root.addEventListener("click", (e) => {
      const f = e.target.closest(".facet[data-field]");
      if (f) {
        const input = $(`[name=${f.dataset.field}]`, form);
        if (input) { input.value = f.dataset.value; run(); }
        return;
      }
      const tr = e.target.closest("#log-body tr[data-id]");
      if (tr && !e.target.closest("a")) {
        const next = tr.nextElementSibling;
        if (next && next.classList.contains("detail-row")) { next.remove(); tr.classList.remove("expanded"); return; }
        tr.classList.add("expanded");
        SP.api("GET", "/api/syslog?limit=1&before_id=" + (+tr.dataset.id + 1)).then((rows) => {
          const r = rows[0];
          if (!r) return;
          const fields = Object.entries(r).filter(([k]) => !["message"].includes(k)).map(([k, v]) => `${k}: ${v}`).join("\n");
          tr.insertAdjacentHTML("afterend", `<tr class="detail-row"><td colspan="6"><div class="log-detail">${esc(r.message)}\n\n${esc(fields)}</div><div class="row"><a class="btn sm" href="/syslog?host=${encodeURIComponent(r.host)}">Only this host</a><a class="btn sm" href="/syslog?app=${encodeURIComponent(r.app)}">Only this app</a><a class="btn sm" href="/alerts?tab=rules&syslog_query=${encodeURIComponent(r.message.slice(0, 60))}">Alert on messages like this</a></div></td></tr>`);
        });
      }
    });
    $("#log-more", root).addEventListener("click", () => load(true));
    $("#log-live").addEventListener("click", (e) => {
      live = !live;
      e.target.classList.toggle("primary", live);
      e.target.textContent = live ? "Live tail on" : "Live tail";
      clearInterval(liveTimer);
      if (live) {
        liveTimer = setInterval(async () => {
          if (document.hidden) return;
          const p = params();
          p.delete("start"); p.delete("end");
          p.set("limit", "200");
          const rows = await SP.api("GET", "/api/syslog?" + p.toString());
          const fresh = rows.filter((r) => !newest || r.id > newest);
          if (fresh.length) {
            newest = fresh[0].id;
            const emptyRow = $("td.empty", table);
            if (emptyRow) table.innerHTML = "";
            table.insertAdjacentHTML("afterbegin", fresh.map(row).join(""));
          }
        }, 2000);
      }
    });
    SP.timePicker($("#log-time", root), state, run);
    run();
  };

  // --------------------------------------------------------------- boot
  SP.autoRefresh = function (seconds) {
    setInterval(() => { if (!document.hidden && !$(".modal-back:not(.hidden)") && !document.activeElement.closest("form")) location.reload(); }, seconds * 1000);
  };
  document.addEventListener("DOMContentLoaded", () => {
    localizeTimes(document);
    setInterval(() => $$("time[data-fmt=ago]").forEach((el) => (el.textContent = SP.ago(+el.dataset.ts))), 15000);
    $$("[data-spark]").forEach((el) => { try { SP.sparkline(el, JSON.parse(el.dataset.spark), el.dataset.unit); } catch (e) { /* ignore */ } });
    const refresh = document.body.dataset.refresh;
    if (refresh) SP.autoRefresh(+refresh);
  });
})();
