// Webhook Forwarder with GUI (port 3030)
// --------------------------------------
// Features:
// - /w/:key/*    → forwards to destination stored in routes.json
// - /api/routes  → GET list, PUT upsert /api/routes/:key, DELETE /api/routes/:key
// - /admin       → simple GUI (no build tools)
// - Preserves raw request bodies (for signature verification)
// - Optional admin protection via ADMIN_TOKEN (Bearer or X-Admin-Token header)
//
// Usage:
//   npm i
//   npm start
//
// Optional env:
//   PORT=3030 (default)
//   ADMIN_TOKEN=supersecret     (protects /api/* and /admin)
//   ALLOWLIST=host1.com,host2.tld  (restrict destinations)

// Webhook Forwarder with GUI (port 3030)

// Webhook Forwarder with GUI, Copy button, and Execution History (port 3030)

import 'dotenv/config';
import express from "express";
import getRawBody from "raw-body";
import { fetch, Headers } from "undici";
import fs from "fs";
import path from "path";
import morgan from "morgan";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const app  = express();
const PORT = process.env.PORT || 3030;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "";
const ALLOWLIST = (process.env.ALLOWLIST || "")
  .split(",").map(s => s.trim().toLowerCase()).filter(Boolean);

// ---------- ROUTE STORAGE ----------
const ROUTES_PATH = path.resolve(__dirname, "routes.json");
function loadRoutes() { try { return JSON.parse(fs.readFileSync(ROUTES_PATH,"utf8")); } catch { return {}; } }
let ROUTES = loadRoutes();
fs.watchFile(ROUTES_PATH, () => { ROUTES = loadRoutes(); });

// ---------- HISTORY STORAGE ----------
const HISTORY_PATH = path.resolve(__dirname, "history.ndjson"); // newline-delimited json
const MAX_HISTORY_PER_KEY = parseInt(process.env.HISTORY_MAX || "500", 10);
const HISTORY = new Map(); // key -> array of entries (latest first)

// small helper to append to disk & keep an in-memory rolling window
function recordHistory(entry) {
  const line = JSON.stringify(entry) + "\n";
  try { fs.appendFileSync(HISTORY_PATH, line); } catch {}
  const arr = HISTORY.get(entry.key) || [];
  arr.unshift(entry);
  if (arr.length > MAX_HISTORY_PER_KEY) arr.length = MAX_HISTORY_PER_KEY;
  HISTORY.set(entry.key, arr);
}

// ---------- HELPERS ----------
function isHopByHop(h) {
  return [
    "connection","keep-alive","proxy-authenticate","proxy-authorization",
    "te","trailer","trailers","transfer-encoding","upgrade",
    "content-length","host","expect"
  ].includes(h.toLowerCase());
}
function joinPath(basePath, tail) {
  const b = (basePath || "").replace(/\/+$/, "");
  const t = (tail || "").replace(/^\/+/, "");
  return t ? `${b}/${t}` : b || "/";
}
function isAllowedUrl(urlStr) {
  if (!ALLOWLIST.length) return true;
  try { return ALLOWLIST.includes(new URL(urlStr).hostname.toLowerCase()); }
  catch { return false; }
}

// ---------- MIDDLEWARE ----------
app.use(morgan("tiny"));

// Optional admin auth
function checkAdminAuth(req, res, next) {
  if (!ADMIN_TOKEN) return next();
  const auth = req.headers.authorization || "";
  const bearer = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  const headerToken = req.headers["x-admin-token"];
  if (bearer === ADMIN_TOKEN || headerToken === ADMIN_TOKEN) return next();
  return res.status(401).json({ error: "unauthorized" });
}

// Capture raw body only for /w
app.use("/w", async (req, res, next) => {
  if (["GET","HEAD"].includes(req.method)) return next();
  try {
    req.rawBody = await getRawBody(req, {
      length: req.headers["content-length"],
      limit: "25mb"
    });
    next();
  } catch (err) {
    console.error("Raw body parse error:", err);
    res.status(400).send("Invalid body");
  }
});

// JSON parser for /api
app.use("/api", express.json({ limit: "2mb" }));

// ---------- ADMIN API ----------
app.get("/api/routes", checkAdminAuth, (req, res) => res.json(ROUTES));

app.put("/api/routes/:key", checkAdminAuth, (req, res) => {
  const { key } = req.params;
  const url = (req.body?.url || "").trim();
  if (!url) return res.status(400).json({ error: "missing url" });
  if (!isAllowedUrl(url)) return res.status(400).json({ error: "destination host not allowlisted" });
  ROUTES[key] = url;
  fs.writeFileSync(ROUTES_PATH, JSON.stringify(ROUTES, null, 2));
  res.json({ saved: true, key, url });
});

app.delete("/api/routes/:key", checkAdminAuth, (req, res) => {
  const { key } = req.params;
  if (!ROUTES[key]) return res.status(404).json({ error: "not found" });
  delete ROUTES[key];
  fs.writeFileSync(ROUTES_PATH, JSON.stringify(ROUTES, null, 2));
  res.json({ deleted: true, key });
});

// History API
app.get("/api/history/:key", checkAdminAuth, (req, res) => {
  const key = req.params.key;
  const limit = Math.min(parseInt(req.query.limit || "50", 10), MAX_HISTORY_PER_KEY);
  const data = (HISTORY.get(key) || []).slice(0, limit);
  res.json({ key, count: data.length, entries: data });
});

app.delete("/api/history/:key", checkAdminAuth, (req, res) => {
  HISTORY.set(req.params.key, []);
  res.json({ cleared: true, key: req.params.key });
});

// ---------- FORWARDER (RegExp to avoid path-to-regexp quirks) ----------
// Matches: /w/<key>  and  /w/<key>/<any/tail/here>
app.all(/^\/w\/([^/]+)(?:\/(.*))?$/, async (req, res) => {
  const key  = req.params[0];
  const rest = req.params[1] || "";

  const base = ROUTES[key];
  if (!base) return res.status(404).json({ error: "unknown key" });
  if (!isAllowedUrl(base)) return res.status(400).json({ error: "destination host not allowlisted" });

  const start = Date.now();
  const incoming = new URL(req.originalUrl, `http://${req.headers.host}`);
  const dst = new URL(base);

  if (rest) dst.pathname = joinPath(dst.pathname, rest);
  for (const [k,v] of incoming.searchParams) dst.searchParams.append(k, v);

  const outHeaders = new Headers();
  for (const [k, v] of Object.entries(req.headers)) {
    if (!v) continue;
    const low = k.toLowerCase();
    if (isHopByHop(low)) continue;
    outHeaders.set(k, Array.isArray(v) ? v.join(", ") : v);
  }
  outHeaders.set("x-forwarded-for", req.ip || req.connection?.remoteAddress || "");
  outHeaders.set("x-forwarded-proto", "http");
  outHeaders.set("x-forwarded-host", req.headers.host || "");

  const method = req.method;
  const hasBody = !["GET","HEAD"].includes(method);
  const reqBytes = hasBody ? (req.rawBody?.length || 0) : 0;

  let status = 502, respBytes = 0, errorDetail = null;

  try {
    const resp = await fetch(dst, {
      method,
      headers: outHeaders,
      body: hasBody ? (req.rawBody ?? Buffer.alloc(0)) : undefined,
      redirect: "manual"
    });

    status = resp.status;
    res.status(status);
    resp.headers.forEach((v, k) => { if (!isHopByHop(k)) res.setHeader(k, v); });

    if (resp.body) {
      for await (const chunk of resp.body) {
        respBytes += chunk.length || 0;
        res.write(chunk);
      }
    }
    res.end();
  } catch (err) {
    errorDetail = String(err);
    console.error("Forward error:", err);
    res.status(502).json({ error: "bad_gateway", detail: errorDetail });
  } finally {
    const ms = Date.now() - start;
    const entry = {
      ts: new Date().toISOString(),
      key,
      method,
      tail: rest,
      query: Object.fromEntries(incoming.searchParams),
      status,
      ms,
      reqBytes,
      respBytes,
      ip: req.ip || req.connection?.remoteAddress || "",
      error: errorDetail
    };
    recordHistory(entry);
  }
});

// ---------- HEALTH ----------
app.get("/healthz", (req, res) => res.json({ ok: true }));

// ---------- GUI ----------
app.get("/admin", checkAdminAuth, (req, res) => {
  res.type("html").send(`<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<title>Webhook Forwarder Admin</title>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<style>
:root{--bg:#0b0d10;--card:#151a20;--text:#e8eef5;--muted:#9fb2c3;--accent:#5da3ff;--warn:#ff6b6b}
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;background:var(--bg);color:var(--text)}
header{display:flex;justify-content:space-between;align-items:center;padding:18px 22px;border-bottom:1px solid #202833;background:#0d1116}
h1{font-size:18px;margin:0}
main{max-width:980px;margin:24px auto;padding:0 16px}
.card{background:var(--card);border:1px solid #202833;border-radius:14px;box-shadow:0 6px 20px rgba(0,0,0,.25)}
.section{padding:16px}
.grid{display:grid;grid-template-columns:160px 1fr 200px;gap:12px;align-items:center}
.btn{padding:10px 14px;border-radius:10px;border:1px solid #2a3440;background:#0f141a;color:var(--text);cursor:pointer}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#001532}
.btn.danger{background:#1b0f0f;border-color:#3a2323;color:#ffdede}
.btn.link{background:transparent;border:0;color:var(--accent);padding:0;cursor:pointer}
table{width:100%;border-collapse:collapse;margin-top:8px}
th,td{padding:10px;border-bottom:1px solid #202833;text-align:left}
a{color:var(--accent);text-decoration:none}
.small{font-size:12px;color:var(--muted)}
.modal{position:fixed;inset:0;background:rgba(0,0,0,.55);display:none;align-items:center;justify-content:center;padding:20px}
.modal .panel{background:#0f141a;border:1px solid #2a3440;border-radius:12px;max-width:920px;width:100%;max-height:80vh;overflow:auto}
.modal header{background:#0f141a;border-bottom:1px solid #2a3440}
table.history td, table.history th{font-size:12px;white-space:nowrap}
code{background:#0f141a;border:1px solid #2a3440;border-radius:6px;padding:2px 6px}
</style>
</head>
<body>
<header><h1>Webhook Routes</h1><div class="small">Forwarder on port ${PORT}</div></header>
<main>
  <div class="card section">
    <div class="grid">
      <label>Key</label>
      <input id="key" type="text" placeholder="e.g. n8n-incoming"/>
      <div style="display:flex;gap:8px">
        <button id="save" class="btn primary">Save</button>
        <button id="copy" class="btn">Copy URL</button>
      </div>
    </div>
    <div class="grid">
      <label>Destination URL</label>
      <input id="url" type="text" placeholder="https://n8n.example.com/webhook/abc123"/>
      <div style="display:flex;gap:8px">
        <button id="test" class="btn">Open /w/&lt;key&gt;</button>
      </div>
    </div>
    <div id="msg" class="small"></div>
  </div>

  <div class="card section" style="margin-top:16px">
    <table>
      <thead><tr><th>Key</th><th>Destination</th><th>Actions</th></tr></thead>
      <tbody id="tbody"></tbody>
    </table>
  </div>
</main>

<!-- History modal -->
<div id="histModal" class="modal" aria-hidden="true">
  <div class="panel">
    <header style="display:flex;justify-content:space-between;align-items:center;padding:12px 16px">
      <strong id="histTitle">History</strong>
      <div style="display:flex;gap:8px">
        <button id="histRefresh" class="btn">Refresh</button>
        <button id="histClear" class="btn danger">Clear</button>
        <button id="histClose" class="btn">Close</button>
      </div>
    </header>
    <div style="padding:12px 16px">
      <table class="history">
        <thead>
          <tr>
            <th>Time</th><th>Method</th><th>Status</th><th>ms</th><th>ReqB</th><th>RespB</th>
            <th>Tail</th><th>Query</th><th>IP</th><th>Error</th>
          </tr>
        </thead>
        <tbody id="histBody"></tbody>
      </table>
    </div>
  </div>
</div>

<script>
const ADMIN_TOKEN=${JSON.stringify(ADMIN_TOKEN)};
function api(path,opt){
  const headers=Object.assign({"content-type":"application/json"},(opt&&opt.headers)||{});
  if(ADMIN_TOKEN) headers["Authorization"]="Bearer "+ADMIN_TOKEN;
  return fetch(path,Object.assign({headers},opt||{}));
}
const msg=document.querySelector("#msg"),tbody=document.querySelector("#tbody");
const keyEl=document.querySelector("#key"),urlEl=document.querySelector("#url");

function fullUrl(k){return location.origin+"/w/"+encodeURIComponent(k);}

async function refresh(){
  const res=await api("/api/routes");
  tbody.innerHTML="";
  if(!res.ok){msg.textContent="Failed to load ("+res.status+")";return;}
  const data=await res.json();
  Object.entries(data).forEach(([k,v])=>{
    const tr=document.createElement("tr");
    tr.innerHTML=\`
      <td>\${k}</td>
      <td><a href="\${v}" target="_blank">\${v}</a></td>
      <td style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn" data-act="use" data-k="\${k}" data-u="\${v}">Use</button>
        <button class="btn" data-act="copy" data-k="\${k}">Copy</button>
        <a class="btn" href="/w/\${encodeURIComponent(k)}/ping" target="_blank" rel="noopener">Open</a>
        <button class="btn" data-act="hist" data-k="\${k}">History</button>
        <button class="btn danger" data-act="del" data-k="\${k}">Delete</button>
      </td>\`;
    tbody.appendChild(tr);
  });
}

document.addEventListener("click",async e=>{
  const b=e.target.closest("button"); if(!b) return;
  const a=b.dataset.act, k=b.dataset.k;
  if(a==="use"){ keyEl.value=k; urlEl.value=b.dataset.u || ""; }
  if(a==="copy"){ await navigator.clipboard.writeText(fullUrl(k)); msg.textContent="Copied "+fullUrl(k); }
  if(a==="del"){ if(!confirm("Delete route?")) return; const r=await api("/api/routes/"+encodeURIComponent(k),{method:"DELETE"}); if(r.ok) refresh(); }
  if(a==="hist"){ openHistory(k); }
});

document.querySelector("#save").onclick=async()=>{
  const k=keyEl.value.trim(), u=urlEl.value.trim();
  if(!k||!u){msg.textContent="Enter key & url";return;}
  const r=await api("/api/routes/"+encodeURIComponent(k),{method:"PUT",body:JSON.stringify({url:u})});
  msg.textContent=r.ok?"Saved":"Error ("+r.status+")"; if(r.ok) refresh();
};
document.querySelector("#copy").onclick=async()=> {
  const k=keyEl.value.trim(); if(!k){msg.textContent="Enter a key first";return;}
  await navigator.clipboard.writeText(fullUrl(k));
  msg.textContent="Copied "+fullUrl(k);
};
document.querySelector("#test").onclick=()=> {
  const k=keyEl.value.trim(); if(!k){msg.textContent="Enter a key first";return;}
  open("/w/"+encodeURIComponent(k)+"/ping?test=1","_blank","noopener");
};

const modal=document.querySelector("#histModal");
const histTitle=document.querySelector("#histTitle");
const histBody=document.querySelector("#histBody");
let currentHistKey=null;

async function loadHistory(k){
  const r=await api("/api/history/"+encodeURIComponent(k)+"?limit=200");
  histBody.innerHTML="";
  if(!r.ok){histBody.innerHTML='<tr><td colspan="10">Failed to load ('+r.status+')</td></tr>';return;}
  const data=await r.json();
  (data.entries||[]).forEach(e=>{
    const q=Object.keys(e.query||{}).length?JSON.stringify(e.query):"";
    const err=e.error?('<span style="color:#ff9e9e">'+e.error+'</span>'):"";
    const row=\`<tr>
      <td>\${e.ts}</td><td>\${e.method}</td><td>\${e.status}</td><td>\${e.ms}</td>
      <td>\${e.reqBytes}</td><td>\${e.respBytes}</td>
      <td><code>\${(e.tail||"")}</code></td><td><code>\${q}</code></td>
      <td>\${e.ip||""}</td><td>\${err}</td>
    </tr>\`;
    histBody.insertAdjacentHTML("beforeend", row);
  });
}
function openHistory(k){
  currentHistKey=k; histTitle.textContent="History · "+k; modal.style.display="flex"; loadHistory(k);
}
document.querySelector("#histRefresh").onclick=()=>{ if(currentHistKey) loadHistory(currentHistKey); };
document.querySelector("#histClear").onclick=async()=>{
  if(!currentHistKey) return;
  if(!confirm("Clear history for '"+currentHistKey+"'?")) return;
  await api("/api/history/"+encodeURIComponent(currentHistKey),{method:"DELETE"});
  loadHistory(currentHistKey);
};
document.querySelector("#histClose").onclick=()=>{ modal.style.display="none"; };

refresh();
</script>
</body></html>`);
});

// ---------- START ----------
app.listen(PORT, () => {
  console.log(`Webhook forwarder running on http://localhost:${PORT}`);
  if (ADMIN_TOKEN) console.log("Admin token enabled");
  if (ALLOWLIST.length) console.log("Allowlist:", ALLOWLIST.join(", "));
});
