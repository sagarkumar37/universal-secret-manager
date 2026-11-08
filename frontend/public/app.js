// Universal Secret Manager UI. Values are write-only, except an audited, role-gated, masked reveal.
"use strict";

const $ = (s, el = document) => el.querySelector(s);
const ROLES = ["viewer", "editor", "admin"];
let ME = null;

// ---- helpers -------------------------------------------------------------------------------------------------
function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) el.setAttribute(k, v === true ? "" : v);
  }
  for (const k of kids.flat()) if (k !== "" && k != null) el.append(k instanceof Node ? k : document.createTextNode(k));
  return el;
}

async function api(method, path, body) {
  const opt = { method, headers: { "x-csrf-token": ME?.csrf || "" }, credentials: "same-origin", cache: "no-store" };
  if (body instanceof FormData) opt.body = body;
  else if (body) { opt.body = JSON.stringify(body); opt.headers["content-type"] = "application/json"; }
  const r = await fetch(path, opt);
  if (r.status === 401) { location.hash = "#/login"; throw new Error("signed out"); }
  const data = r.headers.get("content-type")?.includes("json") ? await r.json() : {};
  if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
  return data;
}

function toast(msg, isErr = false) {
  const t = h("div", { class: "toast" + (isErr ? " err" : "") }, h("span", {}, isErr ? "⚠️" : "✅"), h("span", {}, msg));
  $("#toasts").append(t);
  setTimeout(() => t.remove(), isErr ? 9000 : 5000);
}

const fmt = (d) => (d ? new Date(d).toLocaleString() : "");
const ago = (d) => {
  if (!d) return "";
  const s = (Date.now() - new Date(d)) / 1000;
  return s < 60 ? "just now" : s < 3600 ? `${Math.floor(s / 60)} min ago` : s < 86400 ? `${Math.floor(s / 3600)} h ago` : fmt(d);
};
const enc = encodeURIComponent;
const can = (role) => ME && ROLES.indexOf(ME.role) >= ROLES.indexOf(role);
const envOf = (bundle) => (bundle.includes("--") ? bundle.split("--")[0] : "other");
const groupOf = (bundle) => (bundle.includes("--") ? bundle.slice(bundle.indexOf("--") + 2) : bundle);
function envClass(env) {
  if (/(^|[-_])prod(uction)?$/i.test(env)) return "c-prod";
  let n = 0; for (const c of env) n = (n * 31 + c.charCodeAt(0)) >>> 0;
  return "c" + (n % 8);
}
const envBadge = (env) => h("span", { class: `env ${envClass(env)}` }, env);
const crumbs = (...parts) => h("div", { class: "crumbs" },
  parts.flatMap((p, i) => [i ? h("span", { class: "sep" }, "›") : "", p.href ? h("a", { href: p.href }, p.label) : h("span", {}, p.label)]));
const empty = (icon, text) => h("div", { class: "empty" }, h("div", { class: "big" }, icon), h("p", {}, text));
const searchBox = (ph, value = "") => h("input", { class: "search", type: "search", placeholder: `${ph}  ( / )`, value, autocomplete: "off" });

// Modal: fields = [{name, label, type, ...} | {node}], onOk(values) -> Promise. Errors stay inside the dialog.
function modal(title, fields, okLabel, onOk, { danger = false, cancel = "Cancel" } = {}) {
  const dlg = $("#dlg"), body = $("#dlg-body"), err = $("#dlg-err"), ok = $("#dlg-ok");
  $("#dlg-title").textContent = title;
  body.replaceChildren(...fields.map((f) => f.node || h("label", {}, f.label,
    f.type === "textarea" ? h("textarea", { name: f.name, autocomplete: "off", spellcheck: "false", class: f.masked ? "masked" : false })
      : f.type === "select" ? h("select", { name: f.name, class: "full" }, ...f.options.map((o) => h("option", { value: o, selected: o === f.value }, o)))
      : h("input", { name: f.name, type: f.type || "text", value: f.value || "", autocomplete: "off", placeholder: f.placeholder || false,
                     class: f.type === "checkbox" ? false : "full", ...(f.type === "checkbox" ? { checked: f.checked } : {}) }))));
  err.hidden = true; ok.hidden = !okLabel; ok.textContent = okLabel || ""; ok.className = danger ? "danger" : ""; ok.disabled = false;
  $("#dlg-cancel").textContent = cancel;
  $("#dlg-form").onsubmit = async (e) => {
    e.preventDefault();
    if (!onOk) return dlg.close();
    const vals = {};
    for (const el of body.querySelectorAll("[name]")) vals[el.name] = el.type === "file" ? el.files[0] : el.type === "checkbox" ? el.checked : el.value;
    ok.disabled = true;
    try { await onOk(vals, body); } catch (x) { err.textContent = x.message; err.hidden = false; ok.disabled = false; }
  };
  $("#dlg-cancel").onclick = closeModal;
  dlg.addEventListener("close", wipeDialog, { once: true });          // Esc key path
  dlg.showModal();
  body.querySelector("input:not([type=checkbox]),textarea")?.focus();
  return dlg;
}
// Wipe the dialog synchronously (a revealed value must not stay in the DOM), then close it.
function wipeDialog() {
  const dlg = $("#dlg");
  dlg.dispatchEvent(new Event("cleanup"));
  $("#dlg-body").replaceChildren();
}
function closeModal() {
  wipeDialog();
  const dlg = $("#dlg");
  if (dlg.open) dlg.close();
}

// ---- views ---------------------------------------------------------------------------------------------------
async function viewLogin(q) {
  document.body.classList.add("login-page");
  const msg = { denied: "This account is not allowed. Ask an admin to add you.", oauth: "Google sign-in failed. Try again." }[q.get("e")];
  const box = h("div", { class: "login card" }, h("div", { class: "logo" }, "🔐"), h("h2", {}, "Secret Manager"),
    h("p", {}, h("span", { class: "banner" }, ME.banner || "")), msg ? h("p", { class: "err" }, msg) : "");
  if (ME.dev_login) {
    const email = h("input", { type: "email", placeholder: "you@example.com", class: "full" });
    box.append(h("p", { class: "note" }, "DEV LOGIN - test vaults only"), email,
      h("button", { onclick: async () => {
        const f = new FormData(); f.append("email", email.value);
        try { await api("POST", "/auth/dev", f); await boot(); } catch (x) { toast(x.message, true); }
      } }, "Sign in (dev)"));
  } else {
    box.append(h("p", { class: "muted" }, "Sign in with your company Google account."),
      h("button", { class: "gbtn", onclick: () => (location.href = "/auth/login") }, "Sign in with Google"));
  }
  return box;
}

async function viewVaults() {
  const vaults = await api("GET", "/api/vaults");
  if (vaults.length === 1 && vaults[0].kind !== "error") { location.replace(`#/v/${enc(vaults[0].id)}`); return h("div"); }
  return h("div", {}, h("div", { class: "page-head" }, h("h2", {}, "🗂️ Vaults")),
    h("div", { class: "grid" }, vaults.map((v) => h("a", { class: "tile", href: `#/v/${enc(v.id)}` },
      h("span", { class: "name" }, v.label), h("span", { class: v.kind === "error" ? "sub err" : "sub" }, v.location)))));
}

async function viewBundles(vid, q) {
  const [vaults, bundles] = await Promise.all([api("GET", "/api/vaults"), api("GET", `/api/vaults/${enc(vid)}/bundles`)]);
  const v = vaults.find((x) => x.id === vid);
  const envs = {};
  for (const b of bundles) (envs[envOf(b.name)] ||= []).push(b);
  let active = q.get("env") || "";
  const filter = searchBox("Filter bundles…", q.get("q") || "");
  const chips = h("div", { class: "chips" });
  const list = h("div");
  const render = () => {
    chips.replaceChildren(
      h("button", { class: "chip" + (active ? "" : " on"), onclick: () => { active = ""; render(); } }, "All", h("span", { class: "n" }, String(bundles.length))),
      ...Object.keys(envs).sort().map((e) => h("button", { class: `chip env-chip ${envClass(e)}` + (active === e ? " on" : ""),
        onclick: () => { active = active === e ? "" : e; render(); } }, e, h("span", { class: "n" }, String(envs[e].length)))));
    const f = filter.value.toLowerCase();
    const shown = Object.entries(envs).sort().filter(([e]) => !active || e === active)
      .map(([e, bs]) => [e, bs.filter((b) => b.name.toLowerCase().includes(f))]).filter(([, bs]) => bs.length);
    list.replaceChildren(...shown.map(([e, bs]) => h("div", {}, h("h3", {}, envBadge(e)),
      h("div", { class: "grid" }, bs.map((b) => h("a", { class: `tile ${envClass(e)}`, href: `#/v/${enc(vid)}/b/${enc(b.name)}` },
        h("span", { class: "name" }, "📦 ", groupOf(b.name)), h("code", { class: "sub" }, b.name)))))));
    if (!shown.length) list.append(empty("🔎", "No bundles match."));
  };
  filter.addEventListener("input", render); render();
  return h("div", {},
    crumbs({ label: "Vaults", href: "#/" }, { label: v?.label || vid }),
    h("div", { class: "page-head" }, h("h2", {}, "🗂️ ", v?.label || vid)),
    h("p", { class: "muted" }, v?.location || ""),
    h("div", { class: "stats" }, h("div", { class: "stat" }, h("b", {}, String(bundles.length)), h("span", {}, "bundles")),
      h("div", { class: "stat" }, h("b", {}, String(Object.keys(envs).length)), h("span", {}, "environments")),
      h("div", { class: "stat" }, h("b", {}, ME.role), h("span", {}, "your role"))),
    h("div", { class: "toolbar" }, filter), chips, list);
}

function revealFlow(vid, bundle, key) {
  const secs = ME.reveal_seconds || 30;
  modal(`👁 View ${key}`, [
    { node: h("p", { class: "note" }, "Every view is recorded in the audit log with your reason.") },
    { name: "reason", label: "Why do you need to see it?", placeholder: "e.g. BP-123 checking DB connection" }],
    "Reveal", async (v, body) => {
      const r = await api("POST", `/api/vaults/${enc(vid)}/bundles/${enc(bundle)}/keys/${enc(key)}/reveal`, { reason: v.reason.trim() });
      let shown = false, left = r.seconds || secs, value = r.value;
      const code = h("code", {}, "•".repeat(Math.min(Math.max(value.length, 8), 24)));
      const toggle = h("button", { type: "button", class: "ghost sm", onclick: () => {
        shown = !shown; code.textContent = shown ? value : "•".repeat(Math.min(Math.max(value.length, 8), 24)); toggle.textContent = shown ? "🙈 Hide" : "👁 Show";
      } }, "👁 Show");
      const copy = h("button", { type: "button", class: "secondary sm", onclick: async () => {
        try { await navigator.clipboard.writeText(value); toast("Copied - clear your clipboard when done."); } catch { toast("Copy failed - use Show and copy manually", true); }
      } }, "⧉ Copy");
      const fill = h("div"), timer = h("span", { class: "muted" }, `hides in ${left}s`);
      body.replaceChildren(h("p", { class: "muted" }, `Version ${r.version} · masked by default`),
        h("div", { class: "secretbox" }, code, toggle, copy), h("div", { class: "bar" }, fill), h("div", { class: "inline" }, timer));
      $("#dlg-ok").hidden = true; $("#dlg-cancel").textContent = "Close";
      requestAnimationFrame(() => fill.style.setProperty("width", "100%"));
      const t = setInterval(() => {
        left -= 1; timer.textContent = `hides in ${left}s`; fill.style.setProperty("width", `${(left / (r.seconds || secs)) * 100}%`);
        if (left <= 0) closeModal();
      }, 1000);
      $("#dlg").addEventListener("cleanup", () => { clearInterval(t); value = ""; }, { once: true });
    });
}

async function viewBundle(vid, bundle) {
  const b = await api("GET", `/api/vaults/${enc(vid)}/bundles/${enc(bundle)}`);
  const base = `/api/vaults/${enc(vid)}/bundles/${enc(bundle)}`;
  const env = envOf(bundle);

  const setValue = (key, mode) => modal(mode === "create" ? `➕ Add key to ${bundle}` : `✏️ Update ${key}`, [
      ...(mode === "create" ? [{ name: "key", label: "Key name", placeholder: "my-secret__DB_PASSWORD" }] : []),
      { name: "value", label: "New value (hidden while typing)", type: "textarea", masked: true },
      { node: h("label", { class: "inline" }, h("input", { type: "checkbox", onchange: (e) => $("#dlg textarea").classList.toggle("masked", !e.target.checked) }), " show while typing") },
      { name: "file", label: "…or upload a file (certificates, JSON)", type: "file" },
      { node: h("p", { class: "muted" }, "Saved as a new vault version. Workloads pick it up after the secret sync and a restart.") },
    ], mode === "create" ? "Add key" : "Save", async (v) => {
      const k = mode === "create" ? v.key.trim() : key;
      if (!k) throw new Error("key name required");
      if (!v.value && !v.file) throw new Error("enter a value or choose a file");
      const f = new FormData();
      f.append("mode", mode); f.append("expect_version", b.version);
      if (v.file) f.append("file", v.file); else f.append("value", v.value);
      const r = await api("PUT", `${base}/keys/${enc(k)}`, f);
      closeModal(); toast(`${mode === "create" ? "Added" : "Updated"} ${k} → version ${r.version}`); route();
    });

  const del = (key) => modal(`🗑 Delete ${key}?`, [
      { node: h("p", {}, "Workloads that still reference this key will fail to sync. The previous version stays in the history.") },
      { name: "confirm", label: "Type the key name to confirm" }], "Delete key", async (v) => {
      const r = await api("POST", `${base}/keys/${enc(key)}/delete`, { confirm: v.confirm.trim(), expect_version: b.version });
      closeModal(); toast(`Deleted ${key} → version ${r.version}`); route();
    }, { danger: true });

  const filter = searchBox("Filter keys…");
  const list = h("div");
  const render = () => {
    const f = filter.value.toLowerCase(), groups = {};
    for (const k of b.keys.filter((k) => k.toLowerCase().includes(f))) {
      const [sec, name] = k.includes("__") ? [k.slice(0, k.indexOf("__")), k.slice(k.indexOf("__") + 2)] : ["(no prefix)", k];
      (groups[sec] ||= []).push([k, name]);
    }
    list.replaceChildren(...Object.entries(groups).map(([sec, ks]) => h("div", { class: "card secret" },
      h("div", { class: "secret-head" }, "🔑 ", h("code", {}, sec), h("span", { class: "pill count" }, `${ks.length} key${ks.length > 1 ? "s" : ""}`)),
      ks.map(([full, name]) => h("div", { class: "krow" },
        h("div", { class: "kname" }, h("code", { title: full }, name)), h("span", { class: "dots" }, "••••••••"),
        h("div", { class: "acts" },
          ME.can_reveal ? h("button", { class: "ghost sm", onclick: () => revealFlow(vid, bundle, full) }, "👁 View") : "",
          can("editor") ? h("button", { class: "ghost sm", onclick: () => setValue(full, "update") }, "✏️ Update") : "",
          can("admin") ? h("button", { class: "ghost danger sm", onclick: () => del(full) }, "🗑 Delete") : ""))))));
    if (!list.children.length) list.append(empty(b.keys.length ? "🔎" : "📭", b.keys.length ? "No keys match." : "This bundle has no keys yet."));
  };
  filter.addEventListener("input", render); render();

  return h("div", {},
    crumbs({ label: "Vaults", href: "#/" }, { label: vid, href: `#/v/${enc(vid)}` }, { label: bundle }),
    h("div", { class: "page-head" }, envBadge(env), h("h2", {}, h("code", {}, bundle))),
    h("div", { class: "meta" }, h("span", { class: "pill primary" }, `version ${b.version}`), h("span", { class: "pill" }, `${b.keys.length} keys`),
      h("span", { class: "pill warn" }, "🔒 values hidden")),
    h("div", { class: "toolbar" }, filter, h("span", { class: "spacer" }),
      h("a", { href: `#/v/${enc(vid)}/b/${enc(bundle)}/versions` }, h("button", { class: "secondary" }, "🕘 Versions")),
      can("editor") ? h("button", { onclick: () => setValue(null, "create") }, "➕ Add key") : ""),
    list);
}

async function viewVersions(vid, bundle) {
  const base = `/api/vaults/${enc(vid)}/bundles/${enc(bundle)}`;
  const [vers, vaults] = await Promise.all([api("GET", `${base}/versions`), api("GET", "/api/vaults")]);
  const canDestroy = can("admin") && vaults.find((x) => x.id === vid)?.can_destroy_versions;
  const currentId = vers.find((v) => v.state === "enabled")?.id;    // what workloads read ("latest")
  const destroy = (v) => modal(`🗑 Delete version ${v.id} permanently?`, [
      { node: h("p", {}, "This old version is destroyed in the vault and can never be restored. The current version is not affected.") },
      { name: "confirm", label: "Type the version number to confirm" }], "Delete permanently", async (x) => {
      await api("POST", `${base}/versions/${enc(v.id)}/destroy`, { confirm: x.confirm.trim() });
      closeModal(); toast(`Version ${v.id} deleted.`); route();
    }, { danger: true });
  const stateBadge = (s) => h("span", { class: "pill " + ({ enabled: "ok", destroyed: "err" }[s] || "") }, s);
  const rows = vers.map((v) => {
    const isCurrent = v.id === currentId, alive = v.state !== "destroyed";
    const diffCell = h("td", {}, !alive ? h("span", { class: "muted" }, "—") : h("button", { class: "link", onclick: async () => {
      try {
        const d = await api("GET", `${base}/versions/${enc(v.id)}/diff`);
        const part = (icon, ks) => (ks.length ? `${icon} ${ks.join(", ")}` : "");
        diffCell.replaceChildren([part("➕", d.added), part("➖", d.removed), part("✏️", d.changed)].filter(Boolean).join("   ") || "no key changes");
      } catch (x) { toast(x.message, true); }
    } }, "what changed?"));
    return h("tr", {}, h("td", {}, h("code", {}, v.id), " ", isCurrent ? h("span", { class: "pill primary" }, "current") : ""),
      h("td", { title: fmt(v.created) }, ago(v.created)), h("td", {}, stateBadge(v.state)), diffCell,
      h("td", { class: "row-actions" },
        can("editor") && !isCurrent && v.state === "enabled" ? h("button", { class: "secondary sm", onclick: () =>
          modal(`↩️ Restore version ${v.id}?`, [{ node: h("p", {}, "Its content becomes a new current version.") },
            { name: "confirm", label: "Type the version number to confirm" }], "Restore", async (x) => {
            const r = await api("POST", `${base}/versions/${enc(v.id)}/restore`, { confirm: x.confirm.trim() });
            closeModal(); toast(`Restored ${v.id} as version ${r.version}.`); route();
          }) }, "↩️ Restore") : "", " ",
        canDestroy && !isCurrent && alive ? h("button", { class: "ghost danger sm", onclick: () => destroy(v) }, "🗑 Delete") : ""));
  });
  return h("div", {},
    crumbs({ label: "Vaults", href: "#/" }, { label: vid, href: `#/v/${enc(vid)}` }, { label: bundle, href: `#/v/${enc(vid)}/b/${enc(bundle)}` }, { label: "Versions" }),
    h("div", { class: "page-head" }, envBadge(envOf(bundle)), h("h2", {}, "🕘 Versions of ", h("code", {}, bundle))),
    h("p", { class: "muted" }, "The current version is what workloads read. It can never be deleted."),
    h("div", { class: "card" }, h("table", {}, h("tr", {}, ["Version", "Created", "State", "Keys", ""].map((t) => h("th", {}, t))), rows)));
}

async function viewAudit() {
  const rows = await api("GET", "/api/audit?limit=500");
  const color = (a) => (/delete|destroy/.test(a) ? "err" : /reveal/.test(a) ? "warn" : /add|update|restore|set_user/.test(a) ? "primary" : "");
  const filter = searchBox("Filter by user, action, bundle…");
  const tbody = h("tbody");
  const render = () => {
    const f = filter.value.toLowerCase();
    tbody.replaceChildren(h("tr", {}, ["Time", "User", "Action", "Result", "Bundle / key", "Versions", "Details"].map((t) => h("th", {}, t))),
      ...rows.filter((r) => JSON.stringify(r).toLowerCase().includes(f)).map((r) => h("tr", {},
        h("td", { title: fmt(r.ts) }, ago(r.ts)), h("td", {}, r.actor), h("td", {}, h("span", { class: `pill ${color(r.action)}` }, r.action)),
        h("td", {}, h("span", { class: "pill " + (r.ok ? "ok" : "err") }, r.ok ? "ok" : "failed")),
        h("td", {}, h("code", {}, [r.bundle, r.key].filter(Boolean).join(" / ") || r.detail?.target || "")),
        h("td", {}, r.from_version || r.to_version ? `${r.from_version || "?"} → ${r.to_version || "-"}` : ""),
        h("td", { class: "muted" }, r.detail?.why ? `why: ${r.detail.why}` : r.ok ? "" : r.detail?.reason || ""))));
    labelTables(tbody);
  };
  filter.addEventListener("input", render); render();
  return h("div", {}, crumbs({ label: "Audit log" }), h("div", { class: "page-head" }, h("h2", {}, "📜 Audit log")),
    h("p", { class: "muted" }, "Last 500 events. Secret values are never recorded."),
    h("div", { class: "toolbar" }, filter), h("div", { class: "card" }, h("table", {}, tbody)));
}

async function viewUsers() {
  const users = await api("GET", "/api/users");
  const roleColor = { admin: "err", editor: "primary", viewer: "" };
  const edit = (u) => modal(u ? `✏️ Edit ${u.email}` : "➕ Add user", [
      ...(u ? [] : [{ name: "email", label: "Google account email", type: "email" }]),
      { name: "role", label: "Role", type: "select", options: ROLES, value: u?.role || "viewer" },
      { node: h("p", { class: "muted" }, "viewer: sees key names · editor: adds/updates secrets · admin: also views, deletes, manages users and reads the audit log") },
      { name: "active", label: "Active", type: "checkbox", checked: u ? u.active : true }],
    "Save", async (v) => {
      await api("PUT", "/api/users", { email: u ? u.email : v.email, role: v.role, active: v.active });
      closeModal(); toast("Saved."); route();
    });
  const initials = (e) => e.split("@")[0].split(/[._-]/).map((p) => p[0] || "").join("").slice(0, 2).toUpperCase();
  return h("div", {}, crumbs({ label: "Users" }),
    h("div", { class: "page-head" }, h("h2", {}, "👥 Users"), h("span", { class: "spacer" }), h("button", { onclick: () => edit(null) }, "➕ Add user")),
    h("div", { class: "stats" }, ROLES.map((r) => h("div", { class: "stat" }, h("b", {}, String(users.filter((u) => u.role === r && u.active).length)), h("span", {}, `${r}s`)))),
    h("div", { class: "card" }, h("table", {},
      h("tr", {}, ["User", "Role", "Status", "Last login", "Added by", ""].map((t) => h("th", {}, t))),
      users.map((u) => h("tr", {},
        h("td", {}, h("span", { class: "inline" }, h("span", { class: "avatar" }, initials(u.email)), u.email)),
        h("td", {}, h("span", { class: `pill ${roleColor[u.role]}` }, u.role)),
        h("td", {}, h("span", { class: "pill " + (u.active ? "ok" : "") }, u.active ? "active" : "disabled")),
        h("td", { title: fmt(u.last_login) }, u.last_login ? ago(u.last_login) : "never"), h("td", { class: "muted" }, u.created_by || ""),
        h("td", { class: "row-actions" }, h("button", { class: "ghost sm", onclick: () => edit(u) }, "✏️ Edit")))))));
}

// Phone layout shows each row as a card: copy column headers onto cells (data-label).
function labelTables(root) {
  const tables = [...(root.matches?.("table, tbody") ? [root] : []), ...(root.querySelectorAll?.("table, tbody") || [])];
  for (const t of tables) {
    const heads = [...t.querySelectorAll("tr:first-child th")].map((th) => th.textContent);
    for (const tr of t.querySelectorAll("tr")) [...tr.children].forEach((td, i) => td.tagName === "TD" && heads[i] && td.setAttribute("data-label", heads[i]));
  }
}

// ---- router --------------------------------------------------------------------------------------------------
async function route() {
  const [path, qs] = (location.hash.slice(1) || "/").split("?");
  const q = new URLSearchParams(qs), p = path.split("/").filter(Boolean).map(decodeURIComponent);
  const view = $("#view");
  if (!ME.user && p[0] !== "login") { location.hash = "#/login"; return; }
  document.body.classList.toggle("login-page", p[0] === "login");
  $("#top").hidden = !ME.user;
  const section = p[0] === "audit" ? "audit" : p[0] === "users" ? "users" : "vaults";
  document.querySelectorAll("[data-nav]").forEach((a) => a.classList.toggle("active", a.dataset.nav === section));
  view.replaceChildren(h("div", { class: "loading" }, h("div", { class: "spinner" })));
  try {
    let node;
    if (p[0] === "login") node = await viewLogin(q);
    else if (p[0] === "v" && p[2] === "b" && p[4] === "versions") node = await viewVersions(p[1], p[3]);
    else if (p[0] === "v" && p[2] === "b") node = await viewBundle(p[1], p[3]);
    else if (p[0] === "v") node = await viewBundles(p[1], q);
    else if (p[0] === "audit" && can("admin")) node = await viewAudit();
    else if (p[0] === "users" && can("admin")) node = await viewUsers();
    else node = await viewVaults();
    labelTables(node);
    view.replaceChildren(node);
    window.scrollTo(0, 0);
  } catch (x) {
    view.replaceChildren(h("div", { class: "card" }, empty("⚠️", x.message)));
  }
}

async function boot() {
  ME = await api("GET", "/api/me");
  document.title = `Secret Manager · ${ME.banner}`;
  $("#banner").textContent = ME.banner;
  $("#who").textContent = ME.user || "";
  $("#role").textContent = ME.role || "";
  $("#avatar").textContent = (ME.user || "?").slice(0, 2).toUpperCase();
  document.querySelectorAll("[data-role]").forEach((a) => (a.hidden = !can(a.dataset.role)));
  if (ME.user && location.hash.startsWith("#/login")) location.hash = "#/";
  route();
}

document.addEventListener("keydown", (e) => {
  if (e.key === "/" && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName) && !$("#dlg").open) {
    const s = $("input.search"); if (s) { e.preventDefault(); s.focus(); }
  }
});
$("#logout").addEventListener("click", async () => { await api("POST", "/auth/logout"); ME = null; await boot(); });
window.addEventListener("hashchange", route);
boot();
