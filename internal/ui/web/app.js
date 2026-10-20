const titles = {
  overview: ["Overview", "Version, listeners, caches, and the current rules."],
  rules: ["Rules", "Effective rules from the rules file, one row per domain."],
  peers: ["Peers", "Identities learned from whois. A capability can hide this view."],
  queries: ["Queries", "Recent questions. Filter by peer, user, domain, or rcode."],
  access: ["Access", "Who is asking, and which names are refused."],
  backends: ["Backends", "Default upstreams, dial mode, and health."],
  lookup: ["Lookup", "Show the rule for a name and peer. Upstream is contacted only when you ask."]
};

const state = { tab: "overview", peer: "" };

function $(sel, root) { return (root || document).querySelector(sel); }
function el(tag, text, cls) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}
function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

async function getJSON(url) {
  const res = await fetch(url, { headers: { Accept: "application/json" } });
  if (res.status === 403) {
    const err = new Error("forbidden");
    err.status = 403;
    throw err;
  }
  if (!res.ok) throw new Error("request failed");
  return res.json();
}

function fmtTime(v) {
  if (!v || v.startsWith("0001")) return "";
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleString();
}
function dur(sec) {
  sec = Number(sec) || 0;
  if (sec < 60) return sec + "s";
  const m = Math.floor(sec / 60);
  if (m < 60) return m + "m";
  const h = Math.floor(m / 60);
  return h + "h " + (m % 60) + "m";
}
function pill(text, kind) {
  return el("span", text, "pill" + (kind ? " " + kind : ""));
}
function table(headers, rows) {
  const wrap = el("div", null, "table-wrap");
  const t = document.createElement("table");
  const thead = document.createElement("thead");
  const hr = document.createElement("tr");
  headers.forEach((h) => hr.appendChild(el("th", h)));
  thead.appendChild(hr);
  t.appendChild(thead);
  const tb = document.createElement("tbody");
  if (!rows.length) {
    const tr = document.createElement("tr");
    const td = el("td", "Nothing to show.", "empty");
    td.colSpan = headers.length;
    tr.appendChild(td);
    tb.appendChild(tr);
  }
  rows.forEach((cells) => {
    const tr = document.createElement("tr");
    cells.forEach((c) => {
      const td = document.createElement("td");
      if (c instanceof Node) td.appendChild(c);
      else td.textContent = c == null || c === "" ? "" : String(c);
      tr.appendChild(td);
    });
    tb.appendChild(tr);
  });
  t.appendChild(tb);
  wrap.appendChild(t);
  return wrap;
}
function join(list) { return (list || []).join(", "); }
function ruleCells(r) {
  const policy = [];
  if (r.rewrite) policy.push("rewrite " + r.rewrite);
  if (r.translate_id != null && r.translate_id > 0) policy.push("4via6 " + r.translate_id);
  if (r.site_prefix) policy.push(r.site_prefix);
  if (r.ipnames) policy.push("ipnames site " + r.ipnames.site_id + (r.ipnames.a ? " a=" + r.ipnames.a : ""));
  if (r.static) {
    const addrs = [].concat(r.static.a || [], r.static.aaaa || []);
    policy.push("static " + addrs.join(" ") + (r.static.ttl ? " ttl " + r.static.ttl : ""));
    if (r.static.apex) policy.push("apex");
  }
  if (r.allow_ips && r.allow_ips.length) policy.push("allowips " + r.allow_ips.join(" "));
  if (r.allow_src && r.allow_src.length) policy.push("allowsrc " + r.allow_src.join(" "));
  if (r.ipnames && r.ipnames.allow_src && r.ipnames.allow_src.length) policy.push("allowsrc " + r.ipnames.allow_src.join(" "));
  return [
    el("span", r.domain, "mono"),
    pill(r.source || ""),
    policy.join(" · "),
    el("span", join(r.backends) || (r.ipnames || r.static ? "" : "default"), "mono")
  ];
}

function show(tab) {
  state.tab = tab;
  document.querySelectorAll("nav button").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
  document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("active", p.id === tab));
  const meta = titles[tab];
  $("#title").textContent = meta[0];
  $("#subtitle").textContent = meta[1];
  refresh();
}

async function refresh() {
  try {
    if (state.tab === "overview") await renderOverview();
    else if (state.tab === "rules") await renderRules();
    else if (state.tab === "peers") await renderPeers();
    else if (state.tab === "queries") await renderQueries();
    else if (state.tab === "access") await renderAccess();
    else if (state.tab === "backends") await renderBackends();
  } catch (err) {
    const panel = document.getElementById(state.tab);
    clear(panel);
    panel.appendChild(el("p", err.status === 403 ? "This view is not granted to your node." : "The status site could not load.", "empty"));
  }
}

async function renderOverview() {
  const c = await getJSON("/api/config");
  const meta = $("#top-meta");
  clear(meta);
  meta.appendChild(el("div", c.version || "dev"));
  meta.appendChild(el("div", c.image || "image not set"));
  meta.appendChild(el("div", "up " + dur(c.uptime_sec)));
  if (viewerText(c.viewer)) meta.appendChild(el("div", viewerText(c.viewer)));
  const panel = $("#overview");
  clear(panel);
  const cards = el("div", null, "cards");
  const items = [
    ["Capability", c.cap_name || ""],
    ["Listeners", String((c.listeners || []).length)],
    ["Answer cache", c.caches && c.caches.answer ? String(c.caches.answer.entries) + " / " + (c.caches.answer.limit || "off") : ""],
    ["Cache hits", c.caches && c.caches.answer ? String(c.caches.answer.hits || 0) : "0"],
    ["Whois cache", c.caches && c.caches.whois ? String(c.caches.whois.entries) : "0"],
    ["Grant cache", c.caches && c.caches.grants ? String(c.caches.grants.entries) : "0"],
    ["Service", c.service && c.service.name ? c.service.name + " :" + c.service.port : "none"],
    ["Rules reload", fmtTime(c.rules_updated) || "not loaded"]
  ];
  items.forEach((it) => {
    const card = el("div", null, "card");
    card.appendChild(el("span", it[0]));
    card.appendChild(el("strong", it[1]));
    cards.appendChild(card);
  });
  panel.appendChild(cards);
  panel.appendChild(table(["Listener", "Address", "State"], (c.listeners || []).map((l) => [
    l.service ? l.proto + " " + l.service : l.proto,
    el("span", l.addr, "mono"),
    pill(l.state, l.state === "listening" ? "good" : "warn")
  ])));
}

async function renderRules() {
  const c = await getJSON("/api/config");
  const panel = $("#rules");
  clear(panel);
  panel.appendChild(el("p", c.rules_only ? "Rules file only. ACL grants are ignored." : "Rules from the file apply to every peer unless a grant replaces the same name.", "muted"));
  panel.appendChild(table(["Domain", "Source", "Policy", "Backends"], (c.rules || []).map(ruleCells)));
}

function viewerText(v) {
  if (!v) return "";
  const who = v.login || v.name || v.node || "";
  if (!who && !v.via_proxy) return "";
  let text = "Viewing as " + (who || "unknown");
  if (v.name && v.login && v.name !== v.login) text += " (" + v.name + ")";
  if (v.via_proxy) text += " via proxy";
  if (v.groups && v.groups.length) text += " · " + v.groups.join(", ");
  return text;
}
function showViewer(panel, v) {
  const text = viewerText(v);
  let line = panel.querySelector(":scope > .viewer");
  if (!text) {
    if (line) line.remove();
    return;
  }
  if (!line) {
    line = el("p", text, "muted viewer");
    panel.insertBefore(line, panel.firstChild);
  } else {
    line.textContent = text;
  }
}

async function renderPeers() {
  const data = await getJSON("/api/peers");
  const panel = $("#peers");
  clear(panel);
  showViewer(panel, data.viewer);
  const rows = (data.peers || []).map((p) => {
    const btn = el("button", p.node || p.id, "link mono");
    btn.type = "button";
    btn.addEventListener("click", () => { state.peer = p.id; renderPeerDetail(p.id); });
    return [btn, p.user || "", join(p.tags), el("span", join(p.ips), "mono"), dur(p.cache_age_sec), fmtTime(p.cache_expire)];
  });
  panel.appendChild(table(["Node", "User", "Tags", "Addresses", "Cache age", "Expires"], rows));
  if (state.peer) {
    panel.appendChild(el("div", null, "detail"));
    panel.lastChild.id = "peer-detail";
    await renderPeerDetail(state.peer);
  }
}

async function renderPeerDetail(id) {
  const box = $("#peer-detail");
  if (!box) return;
  const data = await getJSON("/api/peers?id=" + encodeURIComponent(id));
  clear(box);
  const p = data.peer;
  if (!p) {
    box.appendChild(el("p", "That peer is not in the learned set.", "empty"));
    return;
  }
  box.appendChild(el("h2", p.node || p.id));
  box.appendChild(el("p", [p.user, join(p.tags), join(p.ips)].filter(Boolean).join(" · "), "muted"));
  if (p.caps && p.caps.length) {
    box.appendChild(el("p", "Grant values", "muted"));
    p.caps.forEach((c) => box.appendChild(el("pre", c, "mono")));
  }
  box.appendChild(table(["Domain", "Source", "Policy", "Backends"], (p.rules || []).map(ruleCells)));
  const qbtn = el("button", "Show this peer's queries", "link");
  qbtn.type = "button";
  qbtn.addEventListener("click", () => {
    state.peer = p.node || (p.ips && p.ips[0]) || "";
    const input = $("#q-peer");
    if (input) input.value = state.peer;
    show("queries");
  });
  box.appendChild(qbtn);
}

async function renderQueries() {
  const panel = $("#queries");
  if (!panel.dataset.ready) {
    panel.dataset.ready = "1";
    const filters = el("div", null, "filters");
    filters.appendChild(labeled("Peer", "q-peer", state.peer || ""));
    filters.appendChild(labeled("User", "q-user", ""));
    filters.appendChild(labeled("Domain", "q-domain", ""));
    filters.appendChild(labeled("Rcode", "q-rcode", ""));
    panel.appendChild(filters);
    panel.appendChild(el("div", null, "query-table"));
  }
  const peer = $("#q-peer").value;
  const user = $("#q-user").value;
  const domain = $("#q-domain").value;
  const rcode = $("#q-rcode").value;
  const params = new URLSearchParams();
  if (peer) params.set("peer", peer);
  if (user) params.set("user", user);
  if (domain) params.set("domain", domain);
  if (rcode) params.set("rcode", rcode);
  const data = await getJSON("/api/queries?" + params.toString());
  showViewer(panel, data.viewer);
  const box = $(".query-table", panel);
  clear(box);
  if (!data.enabled) box.appendChild(el("p", "The query log is off. Set -ui-history above 0 to keep one.", "muted"));
  const rows = (data.queries || []).map((q) => [
    fmtTime(q.time),
    el("span", q.node || q.peer_ip, "mono"),
    q.user || "",
    el("span", q.name, "mono"),
    q.type,
    q.zone || "",
    q.action || "",
    q.cache || "",
    q.rcode,
    q.latency_ms + " ms",
    q.path
  ]);
  box.appendChild(table(["Time", "Peer", "User", "Name", "Type", "Zone", "Action", "Cache", "Rcode", "Latency", "Path"], rows));
}

function labeled(label, id, value) {
  const input = document.createElement("input");
  input.id = id;
  input.placeholder = label;
  input.value = value;
  input.addEventListener("change", refresh);
  return input;
}

async function renderAccess() {
  const data = await getJSON("/api/access");
  const panel = $("#access");
  clear(panel);
  showViewer(panel, data.viewer);
  const cards = el("div", null, "cards");
  [["Questions", String(data.total || 0)], ["Refused", String(data.refused || 0)]].forEach((it) => {
    const card = el("div", null, "card");
    card.appendChild(el("span", it[0]));
    card.appendChild(el("strong", it[1]));
    cards.appendChild(card);
  });
  panel.appendChild(cards);
  const split = el("div", null, "split");
  const left = el("div");
  left.appendChild(el("h2", "Top talkers"));
  left.appendChild(table(["Peer", "Queries", "Refused"], (data.peers || []).map((t) => [t.name, String(t.queries), String(t.refused)])));
  const right = el("div");
  right.appendChild(el("h2", "Domains"));
  right.appendChild(table(["Domain", "Queries", "Refused"], (data.domains || []).map((t) => [el("span", t.name, "mono"), String(t.queries), String(t.refused)])));
  split.appendChild(left);
  split.appendChild(right);
  panel.appendChild(split);
}

async function renderBackends() {
  const c = await getJSON("/api/config");
  const panel = $("#backends");
  clear(panel);
  const svc = c.service || {};
  panel.appendChild(el("p", svc.name ? "Service " + svc.name + " port " + svc.port + " is " + svc.state + "." : "No Tailscale Service is configured.", "muted"));
  panel.appendChild(table(["Address", "Dial", "Health", "Failures", "Retry"], (c.backends || []).map((b) => [
    el("span", b.address, "mono"),
    b.mode,
    pill(b.healthy ? "healthy" : "unhealthy", b.healthy ? "good" : "bad"),
    String(b.failures || 0),
    fmtTime(b.retry_at)
  ])));
}

function renderLookup() {
  const panel = $("#lookup");
  if (panel.dataset.ready === "1") return;
  panel.dataset.ready = "1";
  const form = el("form", null, "lookup");
  form.appendChild(field("name", "Name", "app.example.internal"));
  const type = document.createElement("select");
  type.name = "type";
  ["A", "AAAA", "TXT", "CNAME", "NS", "SOA"].forEach((t) => {
    const o = el("option", t);
    o.value = t;
    type.appendChild(o);
  });
  form.appendChild(type);
  form.appendChild(field("peer", "Peer IP", "100.64.0.2"));
  const forward = document.createElement("label");
  const box = document.createElement("input");
  box.type = "checkbox";
  box.name = "forward";
  forward.appendChild(box);
  forward.appendChild(document.createTextNode(" Resolve upstream"));
  form.appendChild(forward);
  const go = el("button", "Show", "primary");
  go.type = "submit";
  form.appendChild(go);
  const out = el("div", null, "answers");
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const fd = new FormData(form);
    const params = new URLSearchParams();
    params.set("name", fd.get("name") || "");
    params.set("type", fd.get("type") || "A");
    params.set("peer", fd.get("peer") || "");
    if (box.checked) params.set("forward", "1");
    clear(out);
    try {
      const data = await getJSON("/api/lookup?" + params.toString());
      out.appendChild(el("p", data.matched ? "Matched " + (data.rule ? data.rule.domain : "") + " from " + (data.rule ? data.rule.source : "") : "No rule matched."));
      if (data.rule) out.appendChild(table(["Domain", "Source", "Policy", "Backends"], [ruleCells(data.rule)]));
      if (data.forwarded) {
        out.appendChild(el("p", "Upstream result: " + (data.rcode || "") + (data.error ? " " + data.error : "")));
        (data.answers || []).forEach((a) => out.appendChild(el("div", a, "mono")));
      } else {
        out.appendChild(el("p", "No upstream query was sent.", "muted"));
      }
    } catch (err) {
      out.appendChild(el("p", "Lookup failed.", "empty"));
    }
  });
  panel.appendChild(form);
  panel.appendChild(out);
}

function field(name, label, placeholder) {
  const input = document.createElement("input");
  input.name = name;
  input.placeholder = placeholder || label;
  input.setAttribute("aria-label", label);
  return input;
}

document.querySelectorAll("nav button").forEach((b) => {
  b.addEventListener("click", () => {
    if (location.hash !== "#" + b.dataset.tab) location.hash = b.dataset.tab;
    else show(b.dataset.tab);
  });
});
$("#theme").addEventListener("click", () => {
  const cur = document.documentElement.dataset.theme;
  const next = cur === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = next;
});
window.addEventListener("hashchange", () => {
  const tab = location.hash.replace("#", "");
  if (titles[tab]) show(tab);
});
renderLookup();
const initial = location.hash.replace("#", "");
show(titles[initial] ? initial : "overview");
if (!location.search.includes("shot=1")) {
  setInterval(() => {
    if (state.tab === "queries" || state.tab === "access" || state.tab === "overview") refresh();
  }, 2000);
}
