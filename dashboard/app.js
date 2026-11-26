"use strict";
const $ = (s, r = document) => r.querySelector(s);
const el = (tag, attrs = {}, ...kids) => {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") e.className = v; else if (k.startsWith("on")) e.addEventListener(k.slice(2), v); else e.setAttribute(k, v);
  }
  for (const c of kids.flat()) if (c != null) e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return e;
};
const fmtT = ts => ts ? new Date(ts * 1000).toLocaleString() : "—";
const fmtB = n => { n = +n || 0; const u = ["B/s", "KB/s", "MB/s", "GB/s"]; let i = 0; while (n >= 1024 && i < 3) { n /= 1024; i++; } return n.toFixed(i ? 1 : 0) + " " + u[i]; };
const fmtBytes = n => { n = +n || 0; const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0; while (n >= 1024 && i < 4) { n /= 1024; i++; } return n.toFixed(i > 1 ? 2 : i ? 1 : 0) + " " + u[i]; };
let TOKEN = sessionStorage.getItem("ww_token") || "", ROLE = "", timer = null, cur = "overview";

async function api(path, opts = {}) {
  const r = await fetch("/api" + path, { ...opts, headers: { Authorization: "Bearer " + TOKEN, "Content-Type": "application/json", ...(opts.headers || {}) } });
  if (r.status === 401) { if (!$("#app").hidden || TOKEN) logout(); throw new Error("Sesión inválida"); }
  if (!r.ok) { let m = r.statusText; try { const j = await r.json(); m = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail); } catch (e) {} throw new Error(m); }
  return r;
}
const get = async p => (await api(p)).json();
const send = async (p, method, body) => (await api(p, { method, body: JSON.stringify(body || {}) })).json();
async function download(path, name) {
  const b = await (await api(path)).blob(); const a = el("a", { href: URL.createObjectURL(b), download: name }); document.body.append(a); a.click(); a.remove();
}
async function openHtml(path) { const b = await (await api(path)).blob(); window.open(URL.createObjectURL(b), "_blank", "noopener"); }

function table(cols, rows, onclick, rowClass, extra) {
  const t = el("table", {}, el("thead", {}, el("tr", {}, cols.map(c => el("th", {}, c.h)))));
  const tb = el("tbody");
  for (const r of rows) {
    const tr = el("tr", { class: [onclick ? "click" : "", rowClass ? rowClass(r) : ""].join(" ").trim() }); if (onclick) tr.addEventListener("click", () => onclick(r));
    for (const c of cols) { const v = c.f ? c.f(r) : r[c.k]; tr.append(el("td", { class: c.m ? "m" : "" }, v instanceof Node ? v : (v ?? ""))); }
    tb.append(tr);
  }
  if (!rows.length) tb.append(el("tr", {}, el("td", { colspan: cols.length, class: "mut" }, "Sin datos todavía")));
  t.append(tb);
  return el("div", { class: "tw " + (extra || "") }, t);
}
const tag = (txt, cls = "") => el("span", { class: "tag " + cls }, txt);
const cards = items => el("div", { class: "cards" }, items.map(([k, v]) => el("div", { class: "card" }, el("div", { class: "k" }, k), el("div", { class: "v" }, v))));
function searchBar(reload, extra = []) {
  const i = el("input", { placeholder: "Buscar…", id: "q", value: window.__q || "" });
  i.addEventListener("input", () => { window.__q = i.value; clearTimeout(window.__d); window.__d = setTimeout(reload, 250); });
  return el("div", { class: "bar" }, i, ...extra);
}
const PENDING = [];
function flushCharts() { while (PENDING.length) { const f = PENDING.shift(); try { f(); } catch (e) { console.error(e); } } }
function chart(canvas, series) { PENDING.push(() => drawChart(canvas, series)); if (canvas.isConnected) flushCharts(); }
function drawChart(canvas, series) {
  const dpr = devicePixelRatio || 1, w = canvas.clientWidth, h = canvas.clientHeight; canvas.width = w * dpr; canvas.height = h * dpr;
  const c = canvas.getContext("2d"); c.scale(dpr, dpr); c.clearRect(0, 0, w, h);
  const css = getComputedStyle(document.documentElement), pts = series.flatMap(s => s.data);
  const max = Math.max(1, ...pts.map(p => p[1])), t0 = Math.min(...pts.map(p => p[0]), Infinity), t1 = Math.max(...pts.map(p => p[0]), -Infinity);
  c.strokeStyle = css.getPropertyValue("--line"); c.fillStyle = css.getPropertyValue("--mut"); c.font = "11px monospace";
  for (let i = 0; i <= 3; i++) { const y = 10 + (h - 30) * i / 3; c.beginPath(); c.moveTo(0, y); c.lineTo(w, y); c.stroke(); c.fillText(fmtB(max * (1 - i / 3)), 4, y - 2); }
  if (!isFinite(t0) || t1 === t0) { c.fillText("Recopilando muestras…", w / 2 - 60, h / 2); return; }
  series.forEach(s => { c.strokeStyle = s.color; c.lineWidth = 1.6; c.beginPath(); s.data.forEach((p, i) => { const x = (p[0] - t0) / (t1 - t0) * (w - 8) + 4, y = 10 + (h - 30) * (1 - p[1] / max); i ? c.lineTo(x, y) : c.moveTo(x, y); }); c.stroke(); });
}

function usageTable(u) {
  const rows = [["Última hora", u.last_hour], ["Hoy", u.today], ["Últimas 24 h", u.last_24h], ["Últimos 7 días", u.last_7d]];
  return table([{ h: "Periodo", k: "p" }, { h: "↓ Bajada", f: r => fmtBytes(r.d.rx) }, { h: "↑ Subida", f: r => fmtBytes(r.d.tx) }, { h: "Total", f: r => el("b", {}, fmtBytes(r.d.total)) }], rows.map(([p, d]) => ({ p, d })));
}
const barRow = (label, value, max, text) => el("div", { style: "display:flex;gap:.5rem;align-items:center;font:11px var(--mono)" }, el("span", { style: "width:5.5rem" }, label),
  el("span", { style: `display:inline-block;height:9px;border-radius:2px;background:var(--ac);width:${Math.max(1, value / max * 70)}%` }), el("span", { class: "mut" }, text));

const ACCIONES = { block_device: "Bloquear dispositivo", unblock_device: "Desbloquear dispositivo", suspend_device: "Suspender dispositivo (temporal)", block_domain: "Bloquear dominio",
  unblock_domain: "Desbloquear dominio", limit_bandwidth: "Limitar ancho de banda", schedule: "Horarios de acceso" };
const ADAPTADORES = { nftables: ["Firewall nftables", "Firewall de este equipo Linux. Bloquea dispositivos por IP solo si este equipo es el gateway de la red (reenvío IP activo)."],
  adguard: ["AdGuard Home", "DNS filtrante. Registra y bloquea dominios para todos los dispositivos que lo usen como DNS. Es la vía más simple para ver y bloquear sitios de todos los equipos."] };
const EVT_LVL = { port_scan: "high", arp_sweep: "high", arp_conflict: "high", dhcp_rogue: "high", tcp_probe_failed: "medium", dhcp_nak: "medium", tcp_reset_seen: "medium", icmp_echo: "info" };
const STATUS_ES = { open: "Abierta", investigating: "En investigación", resolved: "Cerrada", false_positive: "Falso positivo" };
const RISKY_LVL = l => (l === "high" || l === "critical") ? "high" : (l === "medium" || l === "warn" || l === "low") ? "medium" : "info";
const devBar = (rows, cat, st, q) => rows.filter(r => (!cat || r.category === cat) && (!st || (st === "on" ? r.online : !r.online)) && (!q || [r.display_name, r.ip, r.mac, r.vendor, r.detected_as, r.hostname].join(" ").toLowerCase().includes(q.toLowerCase())));

async function auditSection(v) {
  const rows = await get("/audit"), cols = [{ h: "Fecha", f: r => fmtT(r.ts) }, { h: "Actor", k: "actor" }, { h: "Acción", k: "action" }, { h: "Objetivo", k: "target", m: 1 }, { h: "Detalle", k: "detail" }, { h: "OK", f: r => r.ok ? "✓" : tag("rechazado", "high") }];
  v.append(el("h3", {}, "Auditoría de dispositivo"), el("div", { class: "row1" }, saveList("auditoria", cols, rows)), table(cols, rows));
}

const VIEWS = {
  overview: ["Resumen", async v => {
    const o = await get("/dashboard"), u = o.usage, fw = o.firewall, al = o.alerts, tf = o.traffic || {};
    v.append(el("h2", {}, "Resumen"));
    if (!o.connected) v.append(el("div", { class: "note" }, "Sin conexión de red detectada. Conéctate a una red y WhiteWidow la identificará automáticamente."));
    else if (o.network && !o.network.authorized) v.append(el("div", { class: "note" }, "Red sin autorizar: solo se ven los dispositivos que ya hablaron con este equipo. Como todos los dispositivos de la red son tuyos, ve a Perfiles de red y autoriza esta red para listarlos TODOS."));
    if (o.devices.total > 1 && o.visibility.other_devices_with_activity === 0) v.append(el("div", { class: "note" }, `Hay ${o.devices.total} dispositivos en la red, pero la actividad (dominios y apps) solo se ve de este equipo: el tráfico de los demás no llega a esta computadora. Para verlos todos, WhiteWidow necesita recibir su tráfico (DNS del router hacia AdGuard Home, gateway o puerto espejo). Detalle en Integraciones.`));
    v.append(el("div", { class: "big4" },
      el("div", { class: "bc" }, el("div", { class: "k" }, "Dispositivos"), el("div", { class: "v" }, `${o.devices.online}/${o.devices.total}`), el("div", { class: "s" }, "en línea / detectados")),
      el("div", { class: "bc " + (fw.hits ? "warn" : "ok") }, el("div", { class: "k" }, "Firewall"), el("div", { class: "v" }, fw.hits ? fw.hits : "OK"),
        el("div", { class: "s" }, fw.hits ? "Entradas (1 h): " + fw.services.join(", ") : `${fw.rules} reglas · sin entradas en la última hora`)),
      el("div", { class: "bc " + (al.open ? "bad" : "ok") }, el("div", { class: "k" }, "Alertas"), el("div", { class: "v" }, al.open), el("div", { class: "s" }, al.open ? `sin revisar${al.serious ? " · " + al.serious + " media/alta" : ""}` : "todo revisado")),
      el("div", { class: "bc" }, el("div", { class: "k" }, "Subida y bajada"), el("div", { class: "ud" }, el("span", { class: "dn" }, "↓ " + fmtB(tf.rx_rate)), el("span", { class: "up" }, "↑ " + fmtB(tf.tx_rate))), el("div", { class: "s" }, "en vivo, interfaz de este equipo"))));

    v.append(el("h3", {}, "Conexiones y desconexiones"));
    v.append(el("div", { class: "panel" }, o.presence.length ? o.presence.map(p => el("div", { style: "display:flex;gap:.8rem;align-items:center;margin:.3rem 0;font-size:15px" },
      lvl(p.event, p.level), el("b", {}, p.name), el("span", { class: "mut m" }, p.ip), el("span", { class: "mut", style: "margin-left:auto" }, fmtH(p.ts) + " · " + fmtD(p.ts)))) : el("span", { class: "mut" }, "Aún no hay conexiones ni desconexiones registradas.")));

    v.append(el("h3", {}, "Dominios y apps (últimas 24 h)"));
    const gs = await get("/groups?hours=24"), apps = gs.filter(g => g.kind === "app"), doms = gs.filter(g => g.kind !== "app");
    const grp = g => keepOpen(el("details", { class: "grp" }, el("summary", {}, g.label, tag(g.kind === "app" ? "app" : "dominio", g.kind === "app" ? "on" : ""),
      el("span", { class: "meta" }, `${g.visits} visitas · ${g.devices.length} disp. · última ${fmtH(g.last)}`)),
      el("div", { class: "body" }, g.devices.map(d => el("div", { class: "dv" }, el("b", {}, d.name), el("span", { class: "mut m" }, " " + d.ip + " · " + d.count + (d.count === 1 ? " visita" : " visitas")),
        ...d.visits.map(x => el("div", { class: "vs" }, `${fmtD(x.start)}  ${fmtH(x.start)}${x.end - x.start >= 60 ? " – " + fmtH(x.end) : ""}  ·  ${x.domain}${x.nth > 1 ? "  (regresó, visita " + x.nth + ")" : ""}`))))
        .concat(el("div", { class: "mut", style: "font-size:12px" }, "Consultas repetidas del mismo dispositivo dentro de 30 min cuentan como una sola visita; pasado ese lapso es una visita nueva (retención).")))), "g:" + g.key);
    v.append(...(apps.length ? apps.map(grp) : [el("p", { class: "mut" }, "Sin apps ni servicios reconocidos todavía.")]));
    if (doms.length) v.append(el("h3", {}, `Otros dominios (${doms.length})`), ...doms.slice(0, 25).map(grp));

    v.append(el("h3", {}, "Datos usados (este equipo)"));
    const cp = (t, d) => el("span", {}, el("small", {}, t), `↓ ${fmtBytes(d.rx)}  ↑ ${fmtBytes(d.tx)}  = ${fmtBytes(d.total)}`);
    v.append(el("div", { class: "panel compact" }, cp("Última hora", u.last_hour), cp("Hoy", u.today)));

    v.append(el("h3", {}, "Tráfico de la interfaz"));
    v.append(el("div", { class: "legend" }, el("span", {}, el("i", { style: "background:#2fb67c" }), "Bajada (verde)"), el("span", {}, el("i", { style: "background:#f0b429" }), "Subida (amarillo)")));
    const cv = el("canvas"); v.append(el("div", { class: "panel" }, cv));
    const tfSel = el("select", {}, [["30", "30 min"], ["120", "2 h"], ["1440", "24 h"]].map(([a, b]) => el("option", { value: a, ...(a === (window.__tf || "30") ? { selected: "" } : {}) }, b)));
    const drawTr = async () => { const tr = await get("/traffic?minutes=" + tfSel.value); chart(cv, [{ color: "#2fb67c", data: tr.map(r => [r.ts, r.rx_rate]) }, { color: "#f0b429", data: tr.map(r => [r.ts, r.tx_rate]) }]); };
    tfSel.addEventListener("change", () => { window.__tf = tfSel.value; drawTr(); });
    v.append(el("div", { class: "bar" }, el("span", { class: "mut" }, "Periodo:"), tfSel)); await drawTr();

    v.append(el("h3", {}, "Últimas actividades"));
    const fc = [{ h: "Hora", f: r => fmtH(r.ts) }, { h: "Fecha", f: r => fmtD(r.ts) }, { h: "IP", k: "ip", m: 1 }, { h: "Dispositivo", k: "name" }, { h: "Evento", f: r => lvl(r.event, r.level) }, { h: "Detalle", f: r => el("span", { class: "wrap" }, r.detail), csv: r => r.detail }];
    v.append(el("div", { class: "row1" }, refreshBtn(), saveList("actividades", fc, o.feed)), table(fc, o.feed, null, r => "l-" + r.level));

    const rec = await get("/recording");
    v.append(el("h3", {}, "Grabación de sesión"), el("div", { class: "bar" }, rec.recording ? tag("● grabando desde " + fmtT(rec.since), "high") : tag("sin grabar"),
      ROLE === "admin" ? el("button", { class: rec.recording ? "danger" : "rec", onclick: async () => { try { const r = await send(rec.recording ? "/recording/stop" : "/recording/start", "POST"); if (r.file) alert("Sesión guardada en:\n" + r.file); } catch (e) { alert(e.message); } route(true); } }, rec.recording ? "■ Detener y guardar JSON" : "● Grabar sesión") : null,
      rec.recording ? el("button", { class: "ghost", onclick: () => download("/recording/current.json", "sesion.json") }, "Descargar JSON actual") : null,
      rec.last_file ? el("span", { class: "mut" }, "Último archivo: " + rec.last_file) : null));

    const s = o.signal || {};   // el antiguo "Descubrimiento", ahora al final del Resumen
    v.append(el("h3", {}, "Descubrimiento de red"), cards([["Interfaz", s.interface || "—"], ["Mi IP", s.ip || "—"], ["Gateway", s.gateway || "—"], ["MAC gateway", s.gateway_mac || "—"], ["SSID", s.ssid || "—"], ["DNS", (s.dns || []).join(", ") || "—"]]));
    const btn = el("button", { onclick: async () => { btn.disabled = true; btn.textContent = "Escaneando…"; try { const r = await send("/scan", "POST"); alert(`Escaneo ${r.mode}: ${r.found ?? 0} dispositivos, ${r.new ?? 0} nuevos`); } catch (e) { alert(e.message); } route(true); } }, "Escanear ahora");
    v.append(el("div", { class: "bar" }, btn, o.scanning ? tag("escaneando", "medium") : null));
  }],

  devices: ["Dispositivos", async v => {
    v.append(el("h2", {}, "Dispositivos"));
    const all = (await get("/devices")).map(r => r), cats = [...new Set(all.map(r => r.category))].sort();
    const q = el("input", { placeholder: "Buscar…", value: window.__dq || "" }), cs = el("select", {}, el("option", { value: "" }, `Todas las categorías (${all.length})`), ...cats.map(c => el("option", { value: c, ...(c === window.__dcat ? { selected: "" } : {}) }, `${c} (${all.filter(r => r.category === c).length})`)));
    const st = el("select", {}, [["", "Todos"], ["on", "En línea"], ["off", "Fuera de línea"]].map(([a, b]) => el("option", { value: a, ...(a === (window.__dst || "") ? { selected: "" } : {}) }, b)));
    const cols = [{ h: "Estado", f: r => el("span", { class: "bulb " + (r.online ? "on" : "off"), title: r.online ? "En línea" : "Desconectado" }), csv: r => r.online ? "en línea" : "desconectado" },
      { h: "Dispositivo", f: r => el("b", {}, r.display_name), csv: r => r.display_name }, { h: "Categoría", f: r => r.category + (r.category_confidence === "baja" ? " ?" : ""), csv: r => r.category },
      { h: "Detectado como", k: "detected_as" }, { h: "IP", k: "ip", m: 1 }, { h: "MAC", k: "mac", m: 1 }, { h: "Fabricante", f: r => r.vendor && !/aleatoria/i.test(r.vendor) ? r.vendor : "MAC privada" },
      { h: "Última vez", f: r => fmtH(r.last_seen) + " " + fmtD(r.last_seen), csv: r => fmtT(r.last_seen) }];
    const box = el("div"); let rows = all;
    const paint = () => { window.__dq = q.value; window.__dcat = cs.value; window.__dst = st.value; rows = devBar(all, cs.value, st.value, q.value); box.replaceChildren(table(cols, rows, r => { window.__dev = r.id; nav("investigation"); }, null, "cmp")); };
    q.addEventListener("input", paint); cs.addEventListener("change", paint); st.addEventListener("change", paint);
    v.append(el("div", { class: "row1" }, q, cs, st, refreshBtn(), el("button", { class: "ghost", onclick: () => saveList("dispositivos", cols, rows).click() }, "⬇ Guardar lista actual")), box); paint();
    v.append(el("p", { class: "mut" }, "La categoría y el nombre se deducen solos (nombre de red, servicios mDNS/SSDP, fabricante y sistema). Haz clic en un dispositivo para ver su historial y, si quieres, corregir nombre o categoría."));
  }],

  firewall: ["Firewall", async v => {
    v.append(el("h2", {}, "Firewall por servicio"));
    const f = await get("/firewall"), ro = ROLE !== "admin";
    v.append(el("div", { class: "note" + (f.can_block && f.control_enabled && !f.dry_run ? " ok" : "") }, f.can_block && f.control_enabled && !f.dry_run
      ? "Bloquear se aplica de verdad mediante el adaptador de control."
      : "Permitir · Alertar · Bloquear. Alertar genera una alerta cada vez que se ve el servicio. Bloquear queda como política y genera alerta ALTA, pero solo corta el tráfico si hay un adaptador activo (AdGuard Home como DNS o nftables como gateway) y el Control está habilitado en Ajustes: " + (f.block_reason || "hoy no se cumple")));
    const card = it => {
      const set = async a => { try { const r = await send("/firewall/" + encodeURIComponent(it.key), "PUT", { action: a }); if (a === "bloquear" && !r.enforced) alert("Política guardada, pero NO se está bloqueando todavía.\n\n" + r.detail); } catch (e) { alert(e.message); } route(true); };
      const b = (a, t, cls) => el("button", { class: it.action === a ? "sel " + cls : "", ...(ro ? { disabled: "" } : {}), onclick: () => set(a) }, t);
      return el("div", { class: "fwc " + it.action }, el("b", {}, it.label), el("small", {}, it.category + (it.pattern ? " · " + it.pattern : "")),
        el("small", {}, it.visits ? `${it.visits} visitas (24 h) · ${fmtH(it.last)}` : "sin actividad"),
        el("div", { class: "seg" }, b("permitir", "Permitir", ""), b("alertar", "Alertar", "a"), b("bloquear", "Bloquear", "b")),
        it.custom && !ro ? el("button", { class: "ghost", onclick: async () => { if (confirm("¿Quitar esta regla?")) { await api("/firewall/custom/" + encodeURIComponent(it.key), { method: "DELETE" }); route(true); } } }, "Quitar regla") : null);
    };
    const rank = it => (it.action !== "permitir" ? 0 : it.visits ? 1 : it.custom ? 0 : 2);
    const sorted = f.items.slice().sort((a, b) => rank(a) - rank(b) || (b.visits - a.visits));
    v.append(el("div", { class: "fw" }, sorted.slice(0, 25).map(card)));
    if (sorted.length > 25) v.append(keepOpen(el("details", { class: "acc", style: "margin-top:.8rem" }, el("summary", {}, `Otros (${sorted.length - 25})`), el("div", { class: "body" }, el("div", { class: "fw" }, sorted.slice(25).map(card)))), "fw-otros"));
    if (!ro) {
      const nm = el("input", { placeholder: "Nombre (ej. Tienda)" }), pt = el("input", { placeholder: "Dominio o link (ej. ejemplo.com)", style: "min-width:260px" });
      v.append(el("h3", {}, "Agregar regla propia"), el("div", { class: "row1" }, nm, pt, el("button", { onclick: async () => { try { await send("/firewall/custom", "POST", { label: nm.value, pattern: pt.value }); route(true); } catch (e) { alert(e.message); } } }, "Agregar"),
        el("span", { class: "mut" }, "Coincide con el dominio y todos sus subdominios; no hace falta escribirlo completo.")));
    }
  }],

  connections: ["Conexiones", async v => {
    v.append(el("h2", {}, "Conexiones"));
    v.append(el("p", { class: "mut" }, "Sin repeticiones: cada destino aparece una vez por dispositivo, con cuántas veces se vio y cuánto duró. El color indica criticidad (rojo: puerto riesgoso, amarillo: servicio con política en el Firewall). Hoy se registran las conexiones de este equipo; las de otros dispositivos aparecen cuando la interfaz recibe su tráfico."));
    const all = el("input", { type: "checkbox", ...(window.__allConn ? { checked: "" } : {}), onchange: () => { window.__allConn = all.checked; load(); } }), q = el("input", { placeholder: "Buscar…", value: window.__q || "" });
    const cols = [{ h: "Criticidad", f: r => lvl(({ high: "alta", medium: "media", info: "baja" })[r.level], r.level), csv: r => r.level }, { h: "Dispositivo", k: "device_name" }, { h: "Servicio / dominio", f: r => r.service ? el("span", {}, tag(r.service, "on"), " ", r.domain || "") : (r.domain || "—"), csv: r => r.service || r.domain },
      { h: "Destino", f: r => r.raddr ? `${r.raddr}:${r.rport}` : "—", m: 1 }, { h: "Proto", k: "proto" }, { h: "Dir.", k: "direction" }, { h: "Proceso", k: "process" }, { h: "Duración", f: r => r.duration >= 1800 ? el("span", {}, r.duration + " s ", tag("retención", "medium")) : r.duration + " s", csv: r => r.duration },
      { h: "Veces", k: "count" }, { h: "Última", f: r => fmtH(r.ts_last) + " " + fmtD(r.ts_last), csv: r => fmtT(r.ts_last) }];
    const box = el("div"); let rows = [];
    async function load() { window.__q = q.value; rows = await get("/connections?all=" + (window.__allConn ? "true" : "false") + "&q=" + encodeURIComponent(q.value));
      box.replaceChildren(table(cols, rows, r => alert(`Conexión ${r.proto} ${r.direction}\nDispositivo: ${r.device_name || "—"}\nDestino: ${r.raddr}:${r.rport}\nDominio/servicio: ${r.domain || "—"} ${r.service || ""}\nProceso: ${r.process || "—"}\nEstado: ${r.status || "—"}\nPrimera vez: ${fmtT(r.ts_first)}\nÚltima vez: ${fmtT(r.ts_last)}\nVeces vista: ${r.count}\nDuración: ${r.duration} s`), r => "l-" + r.level, "cmp")); }
    q.addEventListener("input", () => { clearTimeout(window.__d); window.__d = setTimeout(load, 250); });
    v.append(el("div", { class: "row1" }, q, el("label", { class: "row1", style: "margin:0" }, all, "Mostrar todo (incluye ruido)"), refreshBtn(), el("button", { class: "ghost", onclick: () => saveList("conexiones", cols, rows).click() }, "⬇ Guardar lista actual")), box); await load();
  }],

  domains: ["Dominios", async v => {
    v.append(el("h2", {}, "Dominios por dispositivo"));
    v.append(el("div", { class: "note" }, "Con HTTPS solo se observan dominios (DNS/SNI), no URLs ni rutas. Cada dispositivo se muestra por separado; los de otros equipos aparecen cuando la interfaz recibe su tráfico o con AdGuard Home/TShark."));
    const known = el("input", { type: "checkbox", ...(window.__known !== false ? { checked: "" } : {}), onchange: () => { window.__known = known.checked; route(true); } });
    const devs = await get("/devices"), rows = await get("/domains?known=" + (window.__known !== false ? "true" : "false") + "&limit=3000");
    v.append(el("div", { class: "row1" }, el("label", { class: "row1", style: "margin:0" }, known, "Solo servicios reconocidos"), refreshBtn()));
    const cols = [{ h: "Dominio", k: "domain", m: 1 }, { h: "Consultas", k: "count" }, { h: "Clasificación", f: r => tag(r.category, r.category.startsWith("sospechoso") ? "medium" : r.category === "sin clasificar" ? "" : "on"), csv: r => r.category }, { h: "Fuente", k: "source" }, { h: "Última", f: r => fmtH(r.last_seen) + " " + fmtD(r.last_seen), csv: r => fmtT(r.last_seen) }];
    const byDev = {}; rows.forEach(r => (byDev[r.device_id] = byDev[r.device_id] || []).push(r));
    const list = devs.map(d => ({ id: d.id, name: d.display_name, ip: d.ip, online: d.online, rows: byDev[d.id] || [] })).sort((a, b) => b.rows.length - a.rows.length);
    if (byDev[0]) list.push({ id: 0, name: "Dispositivo no identificado", ip: "", online: 0, rows: byDev[0] });
    list.forEach(d => v.append(keepOpen(el("details", { class: "acc" }, el("summary", {}, el("span", { class: "bulb " + (d.online ? "on" : "off") }), d.name, el("span", { class: "meta mut m", style: "margin-left:auto" }, `${d.ip} · ${d.rows.length} dominios`)),
      el("div", { class: "body" }, el("div", { class: "row1" }, saveList("dominios_" + d.name.replace(/\W+/g, "_"), cols, d.rows)), table(cols, d.rows, null, null, "cmp"))), "dm:" + d.id)));
    if (ROLE === "admin") {
      const d = el("input", { placeholder: "dominio.ejemplo.com" });
      v.append(el("h3", {}, "Bloquear dominio"), el("div", { class: "row1" }, d, el("button", { onclick: async () => { try { const h = d.value.trim(); const c = await send("/firewall/custom", "POST", { label: h, pattern: h }); const r = await send("/firewall/" + c.key, "PUT", { action: "bloquear" }); alert("Se agregó al Firewall como BLOQUEAR.\n" + (r.enforced ? "Bloqueo aplicado." : "Todavía no se bloquea el tráfico: " + r.detail)); route(true); } catch (e) { alert(e.message); } } }, "Bloquear y agregar al Firewall"),
        el("span", { class: "mut" }, "La regla se agrega al Firewall.")));
    }
  }],

  applications: ["Servicios y herramientas", async v => {
    v.append(el("h2", {}, "Servicios y herramientas por dispositivo"));
    v.append(el("div", { class: "row1" }, refreshBtn()), el("p", { class: "mut" }, "Haz clic en un dispositivo para ver los servicios que usó y las herramientas (procesos) que abrieron conexiones. Al abrir otro, el anterior se cierra."));
    const list = await get("/device-services"), all = [];
    list.forEach(d => {
      const det = el("details", { class: "acc" }, el("summary", {}, el("span", { class: "bulb " + (d.online ? "on" : "off") }), d.name, el("span", { class: "meta mut m", style: "margin-left:auto" }, `${d.ip} · ${d.category} · ${d.items.length} servicios/herramientas`)),
        el("div", { class: "body" }, table([{ h: "Nombre", k: "label" }, { h: "Tipo", k: "kind" }, { h: "Visitas / observaciones", k: "visits" }, { h: "Última vez", f: r => fmtH(r.last) + " " + fmtD(r.last) }], d.items, null, null, "cmp")));
      if (window.__appOpen === d.id) det.setAttribute("open", "");
      det.addEventListener("toggle", () => { if (det.open) { window.__appOpen = d.id; all.forEach(x => { if (x !== det) x.open = false; }); } else if (window.__appOpen === d.id) window.__appOpen = null; });
      all.push(det); v.append(det);
    });
  }],

  processes: ["Procesos", async v => {
    v.append(el("h2", {}, "Procesos con actividad de red"));
    v.append(el("p", { class: "mut" }, "Solo se registran procesos que abren conexiones de red en el equipo donde corre WhiteWidow; no se leen argumentos ni contenido. Los procesos de otros dispositivos no son visibles desde la red. La criticidad es un indicio heurístico."));
    const rows = await get("/processes"), cols = [{ h: "Criticidad", f: r => lvl(r.criticality, r.criticality === "alta" ? "high" : "info"), csv: r => r.criticality }, { h: "Dispositivo", k: "device" }, { h: "Nombre", k: "name" }, { h: "Proceso padre", f: r => r.parent || "—", csv: r => r.parent },
      { h: "Ruta", k: "exe", m: 1 }, { h: "Usuario", k: "username" }, { h: "Indicio", f: r => r.suspicious ? tag(r.reason, "medium") : "", csv: r => r.reason }, { h: "Última", f: r => fmtH(r.last_seen) + " " + fmtD(r.last_seen), csv: r => fmtT(r.last_seen) }];
    v.append(el("div", { class: "row1" }, refreshBtn(), saveList("procesos", cols, rows)), table(cols, rows, null, r => r.suspicious ? "l-high" : "", "cmp"));
  }],

  traffic: ["Tráfico", async v => {
    v.append(el("h2", {}, "Analítica de tráfico"));
    let u = null; try { u = await get("/traffic/summary"); } catch (e) {}
    v.append(el("div", { class: "row1" }, refreshBtn()));
    if (u) {
      v.append(el("p", { class: "mut" }, `Datos de la interfaz ${u.interface || "—"} de este equipo.`), usageTable(u));
      const mh = Math.max(1, ...u.hours.map(h => h.rx + h.tx)), md = Math.max(1, ...u.days.map(d => d.rx + d.tx));
      v.append(el("h3", {}, "Por hora (últimas 24 h)"), el("div", { class: "panel" }, u.hours.length ? u.hours.map(h => barRow(String(new Date(h.ts * 1000).getHours()).padStart(2, "0") + ":00", h.rx + h.tx, mh, fmtBytes(h.rx + h.tx))) : el("span", { class: "mut" }, "Recopilando muestras…")));
      v.append(el("h3", {}, "Por día (últimos 7 días)"), el("div", { class: "panel" }, u.days.length ? u.days.map(d => barRow(new Date(d.ts * 1000).toLocaleDateString(), d.rx + d.tx, md, fmtBytes(d.rx + d.tx))) : el("span", { class: "mut" }, "Recopilando muestras…")));
    }
    v.append(el("h3", {}, "Velocidad en vivo"));
    v.append(el("div", { class: "legend" }, el("span", {}, el("i", { style: "background:#2fb67c" }), "Bajada (verde)"), el("span", {}, el("i", { style: "background:#f0b429" }), "Subida (amarillo)")));
    const sel = el("select", {}, [["30", "30 min"], ["120", "2 h"], ["1440", "24 h"]].map(([a, b]) => el("option", { value: a, ...(a === (window.__tf || "30") ? { selected: "" } : {}) }, b)));
    const cv = el("canvas"); v.append(el("div", { class: "panel" }, cv), el("div", { class: "bar" }, el("span", { class: "mut" }, "Periodo:"), sel));
    async function load() { window.__tf = sel.value; const tr = await get("/traffic?minutes=" + sel.value); chart(cv, [{ color: "#2fb67c", data: tr.map(r => [r.ts, r.rx_rate]) }, { color: "#f0b429", data: tr.map(r => [r.ts, r.tx_rate]) }]); }
    sel.addEventListener("change", load); await load();
    v.append(el("h3", {}, "Picos de uso por dispositivo (visitas por hora, 7 días)"));
    const pk = await get("/analytics/device-peaks?days=7");
    v.append(...(pk.length ? pk : []).map(d => el("div", { class: "panel" }, el("b", {}, d.name), el("span", { class: "mut m" }, `  ${d.ip} · pico a las ${String(d.peak_hour).padStart(2, "0")}:00 · ${d.total} visitas`),
      el("div", { style: "display:flex;gap:2px;align-items:flex-end;height:46px;margin-top:.4rem" }, d.hours.map((n, h) => el("div", { title: `${String(h).padStart(2, "0")}h: ${n}`, style: `flex:1;background:var(--ac);opacity:${n ? 1 : .15};height:${Math.max(3, n / Math.max(...d.hours) * 100)}%` }))))));
    if (!pk.length) v.append(el("p", { class: "mut" }, "Aún no hay actividad por dispositivo."));
    v.append(el("h3", {}, "Horas pico de uso (este equipo, 7 días)"));
    const hr = await get("/analytics/hourly?days=7"), mx = Math.max(1, ...hr.map(h => h.avg_rate));
    v.append(el("div", { class: "panel" }, hr.map(h => barRow(String(h.hour).padStart(2, "0") + "h", h.avg_rate, mx, fmtB(h.avg_rate)))));
    v.append(el("h3", {}, "Destinos principales"));
    const c = await get("/connections?direction=outbound&limit=2000"), agg = {};
    c.forEach(r => { const name = r.service || r.domain || r.raddr, k = name + "|" + (r.device_name || ""); (agg[k] = agg[k] || { name, ip: r.raddr + ":" + r.rport, dev: r.device_name, n: 0, proc: r.process }).n += r.count; });
    const dc = [{ h: "Nombre (dominio o link)", k: "name" }, { h: "Dispositivo", k: "dev" }, { h: "IP destino", k: "ip", m: 1 }, { h: "Observaciones", k: "n" }, { h: "Proceso", k: "proc" }];
    v.append(table(dc, Object.values(agg).sort((a, b) => b.n - a.n).slice(0, 25), null, null, "cmp"));
  }],

  live: ["Escucha pasiva", async v => {
    v.append(el("h2", {}, "Escucha pasiva de la red"));
    const st = await get("/sniffer"), c = st.counters || {}, ok = st.running;
    v.append(el("div", { class: "note" + (ok ? " ok" : "") }, ok ? `Escuchando en ${st.iface}${st.promiscuous ? " (modo promiscuo)" : ""}. En redes autorizadas además se hace un sondeo ARP/mDNS para listar todos los dispositivos.`
      : st.status === "no_permission" ? "Sin permiso de captura. Ejecuta una sola vez en la terminal:  ./scripts/enable-sniffer.sh  y luego  ./stop.sh && ./start.sh"
      : !st.enabled ? "La escucha pasiva está desactivada (Ajustes)." : `Estado: ${st.status}. ${st.detail || ""}`));
    v.append(el("div", { class: "cards5" }, [["Sondeos ARP enviados", c.probe_arp || 0], ["Respuestas DNS vistas", c.dns_responses || 0], ["Paquetes vistos", c.frames || 0], ["ARP", c.arp || 0], ["DHCP", c.dhcp || 0],
      ["mDNS", c.mdns || 0], ["NetBIOS", c.nbns || 0], ["Intentos fallidos", c.failed_attempts || 0], ["Consultas DNS", c.dns_queries || 0], ["Sitios TLS (SNI)", c.sni || 0]].map(([k, x]) => el("div", { class: "card" }, el("div", { class: "k" }, k), el("div", { class: "v" }, x)))));
    v.append(el("p", { class: "mut" }, st.sees_other_devices_traffic ? "Esta interfaz recibe tráfico entre otros dispositivos: las consultas DNS y sitios TLS se atribuyen a cada dispositivo."
      : "Esta interfaz recibe lo dirigido a este equipo y los anuncios de difusión. Identifica a todos los dispositivos, pero no ve a qué sitios entra cada uno sin una fuente de tráfico (ver Integraciones)."));
    const devs = await get("/devices"), dcols = [{ h: "Estado", f: r => el("span", { class: "bulb " + (r.online ? "on" : "off") }), csv: r => r.online ? "en línea" : "desconectado" }, { h: "Dispositivo", k: "display_name" }, { h: "Categoría", k: "category" }, { h: "IP", k: "ip", m: 1 }, { h: "MAC", k: "mac", m: 1 },
      { h: "Servicios anunciados", f: r => { try { return JSON.parse(r.services || "[]").slice(0, 4).join(", "); } catch (e) { return ""; } } }, { h: "Visto", f: r => fmtH(r.last_seen) + " " + fmtD(r.last_seen), csv: r => fmtT(r.last_seen) }];
    v.append(el("h3", {}, `Dispositivos detectados (${devs.length})`), el("div", { class: "row1" }, saveList("endpoints", dcols, devs)), table(dcols, devs, r => { window.__dev = r.id; nav("investigation"); }, null, "cmp"));
    const sel = el("select", {}, [["", "Todos los eventos"], ["port_scan", "Escaneos de puertos"], ["arp_sweep", "Barridos ARP"], ["tcp_probe_failed", "Intentos fallidos (puerto cerrado)"], ["arp_conflict", "Conflictos ARP"], ["tcp_reset_seen", "Conexiones rechazadas (RST)"], ["icmp_echo", "Pings recibidos"], ["dhcp_nak", "DHCP rechazado"]].map(([a, b]) => el("option", { value: a, ...(a === (window.__ek || "") ? { selected: "" } : {}) }, b)));
    const ecols = [{ h: "Criticidad", f: r => { const l = EVT_LVL[r.kind] || "info"; return lvl(({ high: "alta", medium: "media", info: "baja" })[l], l); }, csv: r => EVT_LVL[r.kind] || "info" }, { h: "Última vez", f: r => fmtH(r.ts_last) + " " + fmtD(r.ts_last), csv: r => fmtT(r.ts_last) }, { h: "Tipo", k: "kind" },
      { h: "Origen", f: r => r.src_ip + (r.src_mac ? " · " + r.src_mac : ""), m: 1 }, { h: "Destino", f: r => r.dst_ip ? r.dst_ip + (r.dst_port ? ":" + r.dst_port : "") : "", m: 1 }, { h: "Veces", k: "count" }, { h: "Detalle", f: r => el("span", { class: "wrap" }, r.detail || ""), csv: r => r.detail }];
    const box = el("div"); let rows = [];
    async function load() { window.__ek = sel.value; rows = await get("/events?kind=" + sel.value); box.replaceChildren(table(ecols, rows, null, r => "l-" + (EVT_LVL[r.kind] || "info"), "cmp")); }
    sel.addEventListener("change", load);
    v.append(el("h3", {}, "Eventos de red (sin repeticiones: cada evento muestra cuántas veces se vio)"), el("div", { class: "row1" }, sel, refreshBtn(), el("button", { class: "ghost", onclick: () => saveList("eventos_red", ecols, rows).click() }, "⬇ Guardar lista actual")), box); await load();
  }],

  threats: ["Amenazas", async v => {
    v.append(el("h2", {}, "Detección de amenazas"));
    v.append(el("div", { class: "note" }, "Las alertas son indicios que requieren verificación; ninguna implica malware confirmado. Las medias y altas parpadean hasta que se cierran."));
    const rows = await get("/alerts"), serious = r => ["medium", "high", "critical"].includes(r.severity) && ["open", "investigating"].includes(r.status);
    const cols = [{ h: "Fecha", f: r => fmtH(r.ts) + " " + fmtD(r.ts), csv: r => fmtT(r.ts) }, { h: "Severidad", f: r => tag(r.severity, r.severity), csv: r => r.severity }, { h: "Regla", k: "rule", m: 1 }, { h: "Título", f: r => el("span", { class: "wrap" }, r.title), csv: r => r.title },
      { h: "Dispositivo", f: r => r.device_name || r.device_ip || "Red", csv: r => r.device_name }, { h: "IP", k: "device_ip", m: 1 },
      { h: "Estado", f: r => ROLE === "admin" ? el("select", { onclick: e => e.stopPropagation(), onchange: async e => { await send("/alerts/" + r.id, "PATCH", { status: e.target.value }); route(true); } }, Object.entries(STATUS_ES).map(([k, t]) => el("option", { value: k, ...(k === r.status ? { selected: "" } : {}) }, t))) : STATUS_ES[r.status], csv: r => STATUS_ES[r.status] }];
    v.append(el("div", { class: "row1" }, refreshBtn(), saveList("alertas", cols, rows)), table(cols, rows, r => alert(`${r.title}\n\n${r.description}\n\nEvidencia:\n${JSON.stringify(r.evidence, null, 2)}`), r => serious(r) ? "blink" : "", "cmp"));
  }],

  control: ["Control de acceso", async v => {
    v.append(el("h2", {}, "Control de acceso a la red"));
    const caps = await get("/control/capabilities"), devs = await get("/devices");
    v.append(el("div", { class: "note" + (caps.control_enabled ? " ok" : "") }, caps.control_enabled ? (caps.dry_run ? "Control habilitado en modo SIMULACIÓN: nada se ejecuta realmente (desactívalo en Ajustes cuando estés listo)." : "Control habilitado: las acciones se ejecutan de verdad.") : "El control está deshabilitado. Actívalo en Ajustes: tú eres el administrador de esta red."));
    v.append(el("h3", {}, "Cómo se controla la red"));
    v.append(el("p", { class: "mut" }, "WhiteWidow no tiene poder sobre la red por sí solo: actúa a través de adaptadores. Cada acción solo está disponible si hay un adaptador habilitado que la soporte; si no, se rechaza y se explica por qué (nunca se finge que se hizo)."));
    const ad = Object.entries(ADAPTADORES).map(([k, [n, d]]) => ({ n, d, st: caps.adapters[k] ? (caps.adapters[k].available ? "disponible" : "no disponible: " + (caps.adapters[k].reason || "")) : "deshabilitado (ver Integraciones)" }));
    v.append(table([{ h: "Adaptador", k: "n" }, { h: "Qué hace", f: r => el("span", { class: "wrap" }, r.d) }, { h: "Estado", f: r => el("span", { class: "wrap" }, r.st) }], ad));
    v.append(el("h3", {}, "Acciones disponibles"));
    v.append(table([{ h: "Acción", f: r => ACCIONES[r.a] || r.a }, { h: "Soportada", f: r => tag(r.s ? "sí" : "no", r.s ? "on" : "") }, { h: "Adaptador / motivo", f: r => el("span", { class: "wrap" }, r.r) }],
      Object.entries(caps.actions).map(([a, c]) => ({ a, s: c.supported, r: c.supported ? c.adapters.map(x => (ADAPTADORES[x] || [x])[0]).join(", ") : c.reason }))));
    if (ROLE === "admin") {
      const ends = devs.filter(d => d.is_endpoint), sel = el("select", {}, ends.map(d => el("option", { value: d.ip, ...(d.ip === window.__ctl ? { selected: "" } : {}) }, `${d.display_name} · ${d.category} · ${d.ip}${d.online ? "" : " (fuera)"}`)));
      sel.addEventListener("change", () => { window.__ctl = sel.value; });
      v.append(el("h3", {}, "Acciones sobre dispositivos"), el("p", { class: "mut" }, "Solo aparecen dispositivos finales (teléfonos, TV, computadoras…). Cada acción pide que escribas la palabra de confirmación."),
        el("div", { class: "row1" }, sel, el("button", { class: "danger", onclick: () => control("block_device", sel.value, null, "bloquear") }, "Bloquear"), el("button", { class: "ghost", onclick: () => control("unblock_device", sel.value, null, "desbloquear") }, "Desbloquear"),
          el("button", { class: "ghost", onclick: () => control("limit_bandwidth", sel.value, null, "limitar") }, "Limitar ancho de banda")));
    }
    const pc = [{ h: "Fecha", f: r => fmtT(r.ts) }, { h: "Acción", f: r => ACCIONES[r.action] || r.action }, { h: "Objetivo", k: "target", m: 1 }, { h: "Estado", k: "state" }, { h: "Adaptador", k: "adapter" }, { h: "Actor", k: "actor" }, { h: "Detalle", f: r => el("span", { class: "wrap" }, r.detail || ""), csv: r => r.detail }];
    const pol = await get("/control/policies");
    v.append(el("h3", {}, "Historial de políticas"), el("div", { class: "row1" }, saveList("politicas", pc, pol)), table(pc, pol, null, null, "cmp"));
  }],

  investigation: ["Investigación", async v => {
    v.append(el("h2", {}, "Centro de investigación"));
    const devs = await get("/devices"), sel = el("select", {}, devs.map(d => el("option", { value: d.id, ...(d.id == window.__dev ? { selected: "" } : {}) }, `${d.display_name} · ${d.ip}`)));
    const only = el("input", { type: "checkbox", ...(window.__onlyHi ? { checked: "" } : {}) }), box = el("div"); let data = null;
    const exp = el("button", { class: "ghost", onclick: () => download("/investigation/" + sel.value + "/export", "evidencia_" + sel.value + ".json") }, "Exportar evidencia (JSON)");
    v.append(el("div", { class: "row1" }, sel, el("label", { class: "row1", style: "margin:0" }, only, "Solo criticidad media/alta"), refreshBtn(), ROLE === "admin" ? exp : null), box);
    const cols = [{ h: "Hora", f: t => fmtH(t.ts) }, { h: "Fecha", f: t => fmtD(t.ts) }, { h: "Tipo", f: t => lvl(t.type, RISKY_LVL(t.level) === "info" ? ({ alerta: "warn", proceso: "high" })[t.type] || "info" : t.level) }, { h: "Detalle", f: t => el("span", { class: "wrap" }, t.text), csv: t => t.text }];
    function paint() { window.__onlyHi = only.checked; const rows = data.timeline.filter(t => !only.checked || RISKY_LVL(t.level) !== "info" || ["alerta", "proceso"].includes(t.type));
      box.querySelector(".tlbox").replaceChildren(el("div", { class: "row1" }, saveList("investigacion", cols, rows)), table(cols, rows, null, t => "l-" + (RISKY_LVL(t.level) === "high" ? "high" : RISKY_LVL(t.level) === "medium" ? "medium" : "info"), "cmp")); }
    async function load() {
      window.__dev = sel.value; if (!sel.value) { box.replaceChildren(el("p", { class: "mut" }, "No hay dispositivos.")); return; }
      data = await get("/investigation/" + sel.value); const d = data.device;
      const owner = el("input", { placeholder: "Propietario", value: d.owner || "" }), label = el("input", { placeholder: "Nombre", value: d.label || "" });
      const typ = el("select", {}, el("option", { value: "" }, "Categoría automática"), ...["Teléfono", "Tablet", "TV", "Computadora", "Consola", "Bocina / asistente", "IoT / Hogar", "Cámara", "Impresora"].map(c => el("option", { value: c, ...(c === d.user_type ? { selected: "" } : {}) }, c)));
      const save = el("button", { onclick: async () => { await send("/devices/" + d.id, "PATCH", { owner: owner.value, label: label.value, user_type: typ.value }); load(); } }, "Guardar");
      const trust = el("button", { class: "ghost", onclick: async () => { await send("/devices/" + d.id, "PATCH", { trusted: !d.trusted }); load(); } }, d.trusted ? "Quitar confianza" : "Marcar de confianza");
      box.replaceChildren(el("div", { class: "cards5" }, [["Nombre", d.display_name], ["Categoría", d.category], ["Detectado como", d.detected_as], ["IP", d.ip], ["MAC", d.mac]].map(([k, x]) => el("div", { class: "card" }, el("div", { class: "k" }, k), el("div", { class: "v", style: "font-size:16px;word-break:break-word" }, x)))),
        ROLE === "admin" ? el("div", { class: "row1" }, label, owner, typ, save, trust) : null, el("h3", {}, "Línea de tiempo (se actualiza sola)"), el("div", { class: "tlbox" })); paint();
    }
    sel.addEventListener("change", load); only.addEventListener("change", () => data && paint()); await load();
  }],

  integrations: ["Integraciones", async v => {
    v.append(el("h2", {}, "Integraciones"));
    const i = await get("/integrations");
    const info = { tshark: ["TShark", "Captura DNS y TLS de la interfaz y atribuye cada dominio a su dispositivo cuando la interfaz ve su tráfico (puerto espejo o gateway)."],
      adguard: ["AdGuard Home", "DNS filtrante. Registra cada consulta de cada dispositivo y bloquea dominios para todos. Es la forma más simple de ver los dominios de TODA la red: apuntar el DNS del DHCP del router a AdGuard Home."],
      nftables: ["nftables", "Firewall de Linux. Si este equipo es el gateway puede bloquear dispositivos por IP."],
      zeek: ["Zeek", "Analizador de red: registros detallados de conexiones y protocolos desde un puerto espejo o gateway. (No implementado todavía)"],
      ntopng: ["ntopng", "Monitor de tráfico por dispositivo y aplicación (MB/GB por equipo). (No implementado todavía)"],
      arkime: ["Arkime", "Captura y búsqueda de paquetes completos para investigaciones. (No implementado todavía)"],
      opnsense_pfsense: ["OPNsense / pfSense", "Router/firewall dedicado con API: permitiría limitar ancho de banda, horarios y bloqueo por dispositivo. (No implementado todavía)"] };
    v.append(table([{ h: "Integración", f: r => el("b", {}, r.t) }, { h: "Para qué sirve", f: r => el("span", { class: "wrap" }, r.d) }, { h: "Disponible", f: r => tag(r.available ? "sí" : "no", r.available ? "on" : "") }, { h: "Habilitada", f: r => r.enabled ? "sí" : "no" }, { h: "Estado", f: r => el("span", { class: "wrap" }, r.r) }],
      Object.entries(i).map(([n, c]) => ({ t: (info[n] || [n])[0], d: (info[n] || ["", ""])[1], available: c.available || c.installed, enabled: c.enabled, r: c.reason || (c.installed ? "instalado" : c.installed === false ? "no instalado (sudo apt install tshark)" : "") }))));
    v.append(el("p", { class: "mut" }, "WhiteWidow funciona sin integraciones opcionales, pero para ver la actividad de todos los dispositivos necesita una fuente de tráfico (AdGuard Home, TShark con puerto espejo/gateway o un router compatible)."));
  }],

  settings: ["Ajustes", async v => {
    v.append(el("h2", {}, "Ajustes"));
    const s = await get("/settings");
    v.append(cards([["Escucha", `${s.host}:${s.port}`], ["Intervalo de escaneo", s.scan_interval + " s"], ["Retención", s.retention_days + " días"], ["Control", s.control_enabled ? (s.control_dry_run ? "simulación" : "real") : "pasivo"]]));
    if (ROLE !== "admin") { v.append(el("p", { class: "mut" }, "Solo el administrador puede cambiar ajustes.")); await auditSection(v); return; }
    const mk = (label, key, val) => el("label", { class: "bar" }, el("input", { type: "checkbox", ...(val ? { checked: "" } : {}), onchange: async e => { if (key === "control_enabled" && e.target.checked && !confirm("¿Confirmas que estás autorizado para administrar esta red y quieres habilitar el control?")) { e.target.checked = false; return; } if (key === "control_dry_run" && !e.target.checked && !confirm("Las acciones se ejecutarán DE VERDAD en el firewall/DNS. ¿Continuar?")) { e.target.checked = true; return; } await send("/settings", "PATCH", { [key]: e.target.checked }); route(); } }), label);
    v.append(el("div", { class: "panel" }, mk("Habilitar control de red (requiere autorización)", "control_enabled", s.control_enabled), mk("Simulación (dry-run): no ejecutar cambios reales", "control_dry_run", s.control_dry_run),
      mk("Escanear puertos comunes en dispositivos descubiertos", "port_scan", s.port_scan), mk("Escucha pasiva de la red (ARP, DHCP, mDNS, escaneos)", "sniffer_enabled", s.sniffer_enabled), mk("Sondeo de descubrimiento ARP + mDNS + SSDP (solo en redes autorizadas)", "probe_discovery", s.probe_discovery), mk("Modo promiscuo (solo si la interfaz ve tráfico ajeno)", "sniffer_promiscuous", s.sniffer_promiscuous), mk("Habilitar adaptador nftables", "nftables_enabled", s.integrations.nftables.enabled), mk("Habilitar captura DNS con TShark", "tshark_enabled", s.integrations.tshark.enabled)));
    const url = el("input", { placeholder: "http://127.0.0.1:3000", value: s.integrations.adguard.url || "", style: "min-width:240px" }), us = el("input", { placeholder: "usuario", value: s.integrations.adguard.username || "" }), pw = el("input", { type: "password", placeholder: "contraseña" });
    v.append(el("h3", {}, "AdGuard Home"), el("div", { class: "bar" }, url, us, pw, el("button", { onclick: async () => { const a = { enabled: true, url: url.value, username: us.value }; if (pw.value) a.password = pw.value; await send("/settings", "PATCH", { adguard: a }); alert("Guardado"); route(); } }, "Guardar y habilitar")));
    v.append(el("h3", {}, "Informes"), el("div", { class: "bar" }, el("button", { onclick: () => openHtml("/reports/html") }, "Informe HTML"), ...["devices", "alerts", "connections", "domains"].map(k => el("button", { class: "ghost", onclick: () => download(`/reports/${k}.csv`, k + ".csv") }, k + ".csv"))));
    await auditSection(v);
  }],

  profiles: ["Perfiles de red", async v => {
    v.append(el("h2", {}, "Perfiles de red"));
    const nets = await get("/networks");
    v.append(table([{ h: "Nombre", k: "name" }, { h: "Tipo", k: "kind" }, { h: "Subred", k: "subnet", m: 1 }, { h: "Gateway", k: "gateway_ip", m: 1 }, { h: "MAC gateway", k: "gateway_mac", m: 1 }, { h: "SSID", k: "ssid" }, { h: "Dispositivos", k: "devices" }, { h: "Escaneos", k: "scans" },
      { h: "Escaneo activo", f: r => ROLE !== "admin" ? (r.authorized ? "autorizado" : "pasivo") : (r.authorized ? el("button", { class: "ghost", onclick: async () => { await send(`/networks/${r.id}/revoke`, "POST"); route(); } }, "Revocar") :
        el("button", { onclick: async () => { if (confirm(`¿Confirmas que tienes autorización para escanear activamente la red "${r.name}" (${r.subnet})?`)) { await send(`/networks/${r.id}/authorize`, "POST", { confirm: true }); route(); } } }, "Autorizar")) },
      { h: "Última vez", f: r => fmtT(r.last_seen) }], nets,
      async r => { if (ROLE !== "admin") return; const name = prompt("Nombre del perfil", r.name); if (!name) return; const kind = prompt("Tipo: Home, Office, Second Home o Custom", r.kind); try { await send("/networks/" + r.id, "PATCH", { name, kind }); } catch (e) { alert(e.message); } route(); }));
    v.append(el("p", { class: "mut" }, "Haz clic en un perfil para renombrarlo. La red se reconoce por gateway MAC, subred, SSID, DNS y dispositivos conocidos, no solo por SSID o IP."));
  }],
};

async function control(action, target, minutes, word) {
  if (!target) return alert("Elige un objetivo");
  if (word) { const t = prompt(`Para confirmar escribe exactamente: ${word}\n\nAcción: ${ACCIONES[action] || action}\nObjetivo: ${target}`); if ((t || "").trim().toLowerCase() !== word) return alert("Confirmación incorrecta: no se hizo nada."); }
  else if (!confirm(`Confirmar acción: ${ACCIONES[action] || action} → ${target}${minutes ? " por " + minutes + " min" : ""}`)) return;
  try { const r = await send("/control/apply", "POST", { action, target, confirm: true, minutes: minutes || null }); alert(`${r.state} (${r.adapter})\n${r.detail}`); } catch (e) { alert(e.message); }
  route(true);
}
function nav(name) { cur = name; location.hash = name; }
const LIVE = ["overview", "threats", "connections", "devices", "firewall", "traffic", "live", "domains", "applications", "processes", "investigation"];
const fmtD = ts => ts ? new Date(ts * 1000).toLocaleDateString() : "—", fmtH = ts => ts ? new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "—";
const lvl = (txt, l) => el("span", { class: "lv " + (l || "info") }, txt);
const refreshBtn = () => el("button", { class: "ghost", title: "Actualizar ahora", onclick: () => route(true) }, "↻ Actualizar");
const saveList = (name, cols, rows) => el("button", { class: "ghost", onclick: () => {
  const esc = v => `"${String(v ?? "").replace(/"/g, '""')}"`, lines = [cols.map(c => esc(c.h)).join(",")];
  rows.forEach(r => lines.push(cols.map(c => { const v = c.csv ? c.csv(r) : c.f ? c.f(r) : r[c.k]; return esc(v instanceof Node ? v.textContent : v); }).join(",")));
  const a = el("a", { href: URL.createObjectURL(new Blob(["\ufeff" + lines.join("\n")], { type: "text/csv" })), download: name + "_" + new Date().toISOString().slice(0, 16).replace(/[:T]/g, "-") + ".csv" }); document.body.append(a); a.click(); a.remove();
} }, "⬇ Guardar lista actual");
window.__open = window.__open || new Set();
const keepOpen = (d, key) => { if (window.__open.has(key)) d.setAttribute("open", ""); d.addEventListener("toggle", () => { d.open ? window.__open.add(key) : window.__open.delete(key); }); return d; };

let routing = false;
async function route(manual) {
  if (routing) return; routing = true;
  const name = VIEWS[location.hash.slice(1)] ? location.hash.slice(1) : "overview", changed = name !== cur; cur = name;
  document.querySelectorAll("nav a").forEach(a => a.classList.toggle("on", a.dataset.v === name)); $("#nav").classList.remove("open");
  const keep = { x: window.scrollX, y: window.scrollY };
  const v = el("div"); try { await VIEWS[name][1](v); } catch (e) { v.append(el("div", { class: "note" }, "Error: " + e.message)); }
  $("#view").replaceChildren(v);          // el cambio se hace de una sola vez: sin pantalla en blanco
  flushCharts();
  window.scrollTo(changed ? 0 : keep.x, changed ? 0 : keep.y);   // al refrescar se conserva la posición
  routing = false;
  try { const o = await get("/dashboard"); header(o); } catch (e) {}
  clearInterval(timer);
  if (LIVE.includes(name)) timer = setInterval(() => { const t = document.activeElement && document.activeElement.tagName; if (!["INPUT", "SELECT", "TEXTAREA"].includes(t) && !document.hidden) route(); }, 5000);
}
function header(o) {
  const n = o.network, s = o.signal || {};
  $("#netName").textContent = o.connected ? (n ? n.name : "red") : "sin red";
  $("#netGw").textContent = s.gateway ? "(" + s.gateway + ")" : "";
  $("#epName").textContent = o.endpoint.name; $("#epIp").textContent = o.endpoint.ip ? "/ " + o.endpoint.ip : "";
  $("#epDot").className = "dot " + (o.endpoint.connected ? "ok" : "bad"); $("#epState").textContent = o.endpoint.connected ? "CONECTADO" : "DESCONECTADO";
  const m = $("#modePill"); m.textContent = o.control_enabled ? (o.dry_run ? "control: simulación" : "control: ACTIVO") : "pasivo"; m.className = "pill " + (o.control_enabled && !o.dry_run ? "warn" : "");
}
function setTheme(t) { document.documentElement.dataset.theme = t; try { localStorage.setItem("ww_theme", t); } catch (e) {} $("#themeBtn").textContent = t === "dark" ? "☀" : "☾"; }
$("#themeBtn").addEventListener("click", () => setTheme((document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")) === "dark" ? "light" : "dark"));
$("#themeBtn").textContent = (document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")) === "dark" ? "☀" : "☾";
function logout() { sessionStorage.removeItem("ww_token"); TOKEN = ""; clearInterval(timer); $("#app").hidden = true; $("#login").hidden = false; }
async function enter() {
  try { await get("/overview"); } catch (e) { if (TOKEN) $("#loginErr").textContent = "Token inválido"; return logout(); }
  ROLE = (await (await api("/settings")).json()).integrations ? "admin" : "viewer";
  $("#login").hidden = true; $("#app").hidden = false;
  $("#nav").replaceChildren(...Object.entries(VIEWS).map(([k, [t]]) => el("a", { "data-v": k, href: "#" + k }, t)));
  route();
}
$("#loginBtn").addEventListener("click", () => { TOKEN = $("#tok").value.trim(); sessionStorage.setItem("ww_token", TOKEN); enter(); });
$("#tok").addEventListener("keydown", e => { if (e.key === "Enter") $("#loginBtn").click(); });
$("#logout").addEventListener("click", logout);
$("#menuBtn").addEventListener("click", () => $("#nav").classList.toggle("open"));
window.addEventListener("hashchange", route);
enter();  // sin login en modo local; si el servidor exige token, enter() muestra el login
