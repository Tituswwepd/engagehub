import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import axios from "axios";
import sqlite3 from "sqlite3";
import crypto from "crypto";

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

/* =========================
   Security & Basics
========================= */
const ORIGIN = process.env.CORS_ORIGIN || "*";
app.use(
  cors({
    origin: ORIGIN === "*" ? true : ORIGIN.split(",").map((s) => s.trim()),
    credentials: false,
  })
);
app.use(bodyParser.json({ limit: "512kb" }));
app.use(bodyParser.urlencoded({ extended: true, limit: "512kb" }));

// Basic security headers (no external deps)
app.use((_, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
  next();
});

// Simple in-memory rate limit (IP bucket)
const RATE_LIMIT_WINDOW_MS = 15 * 1000; // 15s
const RATE_LIMIT_MAX = 60;
const buckets = new Map();
app.use((req, res, next) => {
  const key = req.ip;
  const now = Date.now();
  const b = buckets.get(key) || { count: 0, ts: now };
  if (now - b.ts > RATE_LIMIT_WINDOW_MS) {
    b.count = 0;
    b.ts = now;
  }
  b.count++;
  buckets.set(key, b);
  if (b.count > RATE_LIMIT_MAX) return res.status(429).json({ error: "rate_limited" });
  next();
});

// serve frontend
app.use(express.static(path.join(__dirname, "../frontend")));

/* =========================
   DB & HELPERS (sqlite3 only)
========================= */
let db;
function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}
function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => (err ? reject(err) : resolve(row)));
  });
}
function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)));
  });
}

async function initDb() {
  sqlite3.verbose();
  db = new sqlite3.Database(process.env.DB_FILE || "./data.sqlite");

  await dbRun(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS wallets (
      user_id TEXT PRIMARY KEY,
      total_usd REAL DEFAULT 0,
      survey_usd_total REAL DEFAULT 0,
      survey_usd_withdrawn REAL DEFAULT 0,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS ledger (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT,
      type TEXT,
      amount REAL,
      meta TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS withdraw_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT,
      email TEXT,
      amount REAL,
      status TEXT DEFAULT 'pending',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS survey_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      provider TEXT,
      trans_id TEXT,
      user_id TEXT,
      payout REAL,
      raw TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS tiktok_tokens (
      user_id TEXT PRIMARY KEY,
      access_token TEXT,
      refresh_token TEXT,
      expires_at INTEGER,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS facebook_tokens (
      fb_user_id TEXT PRIMARY KEY,
      user_id TEXT,
      access_token TEXT,
      expires_at INTEGER,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // NEW: Social tokens (future OAuth for twitter/instagram)
  await dbRun(`
    CREATE TABLE IF NOT EXISTS social_tokens (
      provider TEXT,
      user_id TEXT,
      access_token TEXT,
      refresh_token TEXT,
      expires_at INTEGER,
      PRIMARY KEY (provider, user_id)
    )
  `);

  // NEW: Data buyers registry
  await dbRun(`
    CREATE TABLE IF NOT EXISTS data_buyers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE,
      homepage TEXT,
      status TEXT DEFAULT 'planned',
      notes TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Seed 20 buyers
  const buyers = [
    ["ClickDealer","https://clickdealer.com"],
    ["AdWork Media","https://www.adworkmedia.com"],
    ["MaxBounty","https://www.maxbounty.com"],
    ["CPAlead","https://www.cpalead.com"],
    ["Offertoro","https://www.offertoro.com"],
    ["Persona.ly","https://persona.ly"],
    ["Ayet Studios","https://www.ayetstudios.com"],
    ["KiwiWall","https://www.kiwiwall.com"],
    ["OfferDaddy","https://offerdaddy.com"],
    ["Wannads","https://www.wannads.com"],
    ["CJ Affiliate","https://www.cj.com"],
    ["Rakuten Advertising","https://rakutenadvertising.com"],
    ["Impact Radius","https://impact.com"],
    ["FlexOffers","https://www.flexoffers.com"],
    ["Adscend Media","https://www.adscendmedia.com"],
    ["Revenue Universe","https://www.revenueuniverse.com"],
    ["AdGate Media","https://www.adgatemedia.com"],
    ["AdGem","https://publisher.adgem.com"],
    ["AdWork (dup as buyer)","https://www.adworkmedia.com"],
    ["AdAction","https://www.adactioninteractive.com"]
  ];
  for (const [name, url] of buyers) {
    await dbRun(
      "INSERT OR IGNORE INTO data_buyers (name, homepage, status) VALUES (?,?, 'planned')",
      [name, url]
    );
  }
}

/* =========================
   Auth (optional, HMAC token)
========================= */
const AUTH_REQUIRED = String(process.env.AUTH_REQUIRED || "false").toLowerCase() === "true";
const SIGN_KEY = process.env.ADMIN_SECRET || "dev-secret";

function sign(payloadObj) {
  const payload = Buffer.from(JSON.stringify(payloadObj)).toString("base64url");
  const sig = crypto.createHmac("sha256", SIGN_KEY).update(payload).digest("base64url");
  return payload + "." + sig;
}
function verify(token) {
  if (!token) return null;
  const [payload, sig] = token.split(".");
  const good = crypto.createHmac("sha256", SIGN_KEY).update(payload).digest("base64url");
  if (good !== sig) return null;
  try {
    return JSON.parse(Buffer.from(payload, "base64url").toString());
  } catch {
    return null;
  }
}
app.post("/api/auth/issue", async (req, res) => {
  const { user_id, name } = req.body || {};
  if (!user_id) return res.status(400).json({ error: "missing_user_id" });
  await ensureUser(user_id, name || "Guest");
  const token = sign({ user_id, iat: Date.now() });
  res.json({ token });
});
function requireUser(req, res, next) {
  if (!AUTH_REQUIRED) return next();
  const token = req.headers["x-auth"];
  const data = verify(token);
  if (!data || !data.user_id) return res.status(401).json({ error: "unauthorized" });
  req.user_id = data.user_id;
  next();
}

/* =========================
   Wallet helpers
========================= */
async function ensureUser(user_id, name = "Guest") {
  const u = await dbGet("SELECT id FROM users WHERE id=?", [user_id]);
  if (!u) await dbRun("INSERT INTO users (id,name) VALUES (?,?)", [user_id, name]);
  const w = await dbGet("SELECT user_id FROM wallets WHERE user_id=?", [user_id]);
  if (!w) await dbRun("INSERT INTO wallets (user_id) VALUES (?)", [user_id]);
}

// hidden policy: users only see withdrawable fraction of survey earnings
function withdrawableFromWallet(w) {
  const cap = 0.5 * Number(w?.survey_usd_total || 0);
  const used = Number(w?.survey_usd_withdrawn || 0);
  return Math.max(0, cap - used);
}
async function creditSurveyUSD(user_id, usd, meta) {
  await ensureUser(user_id);
  await dbRun(
    "UPDATE wallets SET survey_usd_total = survey_usd_total + ?, total_usd = total_usd + ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
    [usd, usd, user_id]
  );
  await dbRun(
    "INSERT INTO ledger (user_id, type, amount, meta) VALUES (?,?,?,?)",
    [user_id, "survey_credit_usd", usd, JSON.stringify(meta || {})]
  );
}
async function creditOwnerUSD(user_id, usd, meta) {
  await ensureUser(user_id);
  await dbRun(
    "UPDATE wallets SET total_usd = total_usd + ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
    [usd, user_id]
  );
  await dbRun(
    "INSERT INTO ledger (user_id, type, amount, meta) VALUES (?,?,?,?)",
    [user_id, "owner_credit_usd", usd, JSON.stringify(meta || {})]
  );
}
function classifyProvider(p) {
  const env = process.env;
  const map = {
    ADGEM: env.ADGEM_TREATED_AS || "OWNER",
    CPX: env.CPX_TREATED_AS || "SURVEY",
    BITLABS: env.BITLABS_TREATED_AS || "SURVEY",
    TAPJOY: env.TAPJOY_TREATED_AS || "OWNER",
  };
  return map[(p || "").toUpperCase()] || "OWNER";
}

/* =========================
   Public config
========================= */
app.get("/api/config/public", (_req, res) => {
  res.json({
    PAYPAL_CLIENT_ID: process.env.PAYPAL_CLIENT_ID || "",
    FB_APP_ID: process.env.FB_APP_ID || "",
    TIKTOK_CLIENT_KEY: process.env.TIKTOK_CLIENT_KEY || "",
    YOUTUBE_CHANNEL_ID: process.env.YOUTUBE_CHANNEL_ID || "",
    WHATSAPP_ENABLED: Boolean(process.env.META_ACCESS_TOKEN && process.env.WHATSAPP_PHONE_NUMBER_ID),
    TWITTER_EMBEDS: true,
    INSTAGRAM_EMBEDS: Boolean(process.env.IG_OEMBED_TOKEN),
    RADIO_ENABLED: true,
    AUTH_REQUIRED: AUTH_REQUIRED
  });
});

/* =========================
   User wallet & withdraw requests
========================= */
app.get("/api/wallet/:user_id", requireUser, async (req, res) => {
  const { user_id } = req.params;
  if (AUTH_REQUIRED && req.user_id && req.user_id !== user_id)
    return res.status(403).json({ error: "forbidden" });

  await ensureUser(user_id);
  const w = await dbGet("SELECT * FROM wallets WHERE user_id=?", [user_id]);
  const withdrawable = withdrawableFromWallet(w);
  res.json({
    user_id,
    available_to_withdraw_usd: Number(withdrawable.toFixed(2)),
  });
});

const MIN_WITHDRAW_USD = Number(process.env.MIN_WITHDRAW_USD || "0");
const AUTO_PAYOUTS = String(process.env.AUTO_PAYOUTS || "false").toLowerCase() === "true";

app.post("/api/withdraw/request", requireUser, async (req, res) => {
  try {
    const { user_id, email, amount_usd } = req.body || {};
    if (!user_id || !email || !amount_usd) return res.status(400).json({ error: "missing params" });
    if (AUTH_REQUIRED && req.user_id !== user_id) return res.status(403).json({ error: "forbidden" });

    await ensureUser(user_id);
    const w = await dbGet("SELECT * FROM wallets WHERE user_id=?", [user_id]);
    const avail = withdrawableFromWallet(w);
    const amt = Number(amount_usd);

    if (amt < MIN_WITHDRAW_USD) return res.status(400).json({ error: "below_minimum" });
    if (amt > avail + 1e-9) return res.status(400).json({ error: "exceeds_available" });

    const ins = await dbRun(
      "INSERT INTO withdraw_requests (user_id,email,amount) VALUES (?,?,?)",
      [user_id, email, amt]
    );

    // Auto payout if enabled
    if (AUTO_PAYOUTS) {
      const ok = await doPaypalPayout(email, amt, ins.lastID, user_id);
      if (!ok) return res.json({ ok: true, status: "queued" });
      return res.json({ ok: true, status: "paid" });
    }

    res.json({ ok: true, status: "pending" });
  } catch {
    res.status(500).json({ error: "request_failed" });
  }
});

/* =========================
   Survey / offer postbacks
========================= */
app.get("/webhooks/cpx", async (req, res) => {
  try {
    const { user_id, trans_id, payout } = req.query;
    const usd = Number(payout || 0);
    const as = classifyProvider("CPX");
    if (as === "SURVEY") await creditSurveyUSD(user_id, usd, { provider: "cpx", trans_id });
    else await creditOwnerUSD(user_id, usd, { provider: "cpx", trans_id });
    await dbRun(
      "INSERT INTO survey_events (provider, trans_id, user_id, payout, raw) VALUES (?,?,?,?,?)",
      ["cpx", trans_id, user_id, usd, JSON.stringify(req.query)]
    );
    res.send("OK");
  } catch {
    res.status(500).send("ERR");
  }
});

app.get("/webhooks/bitlabs", async (req, res) => {
  try {
    const { user_id, transaction_id, amount } = req.query;
    const usd = Number(amount || 0);
    const as = classifyProvider("BITLABS");
    if (as === "SURVEY") await creditSurveyUSD(user_id, usd, { provider: "bitlabs", transaction_id });
    else await creditOwnerUSD(user_id, usd, { provider: "bitlabs", transaction_id });
    await dbRun(
      "INSERT INTO survey_events (provider, trans_id, user_id, payout, raw) VALUES (?,?,?,?,?)",
      ["bitlabs", transaction_id, user_id, usd, JSON.stringify(req.query)]
    );
    res.send("OK");
  } catch {
    res.status(500).send("ERR");
  }
});

app.get("/webhooks/adgem", async (req, res) => {
  try {
    const { user_id, trans_id, payout, secret } = req.query;
    if (secret !== process.env.ADGEM_POSTBACK_SECRET) return res.status(403).send("bad secret");
    const usd = Number(payout || 0);
    const as = classifyProvider("ADGEM");
    if (as === "SURVEY") await creditSurveyUSD(user_id, usd, { provider: "adgem", trans_id });
    else await creditOwnerUSD(user_id, usd, { provider: "adgem", trans_id });
    await dbRun(
      "INSERT INTO survey_events (provider, trans_id, user_id, payout, raw) VALUES (?,?,?,?,?)",
      ["adgem", trans_id, user_id, usd, JSON.stringify(req.query)]
    );
    res.send("OK");
  } catch {
    res.status(500).send("ERR");
  }
});

app.get("/webhooks/tapjoy", async (req, res) => {
  try {
    const { user_id, id, reward } = req.query;
    const usd = Number(reward || 0);
    const as = classifyProvider("TAPJOY");
    if (as === "SURVEY") await creditSurveyUSD(user_id, usd, { provider: "tapjoy", id });
    else await creditOwnerUSD(user_id, usd, { provider: "tapjoy", id });
    await dbRun(
      "INSERT INTO survey_events (provider, trans_id, user_id, payout, raw) VALUES (?,?,?,?,?)",
      ["tapjoy", id, user_id, usd, JSON.stringify(req.query)]
    );
    res.send("OK");
  } catch {
    res.status(500).send("ERR");
  }
});

/* =========================
   PayPal deposit + payouts
========================= */
async function paypalToken() {
  const base = process.env.PAYPAL_API_BASE || "https://api-m.paypal.com";
  const id = process.env.PAYPAL_CLIENT_ID;
  const secret = process.env.PAYPAL_CLIENT_SECRET;
  const { data } = await axios.post(
    base + "/v1/oauth2/token",
    "grant_type=client_credentials",
    {
      auth: { username: id, password: secret },
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    }
  );
  return data.access_token;
}

app.post("/api/paypal/deposit/create", requireUser, async (req, res) => {
  try {
    const { user_id, amount_usd } = req.body || {};
    if (!user_id || !amount_usd) return res.status(400).json({ error: "missing params" });
    if (AUTH_REQUIRED && req.user_id !== user_id) return res.status(403).json({ error: "forbidden" });

    const token = await paypalToken();
    const base = process.env.PAYPAL_API_BASE || "https://api-m.paypal.com";
    const { data } = await axios.post(
      base + "/v2/checkout/orders",
      {
        intent: "CAPTURE",
        purchase_units: [{ amount: { currency_code: "USD", value: String(Number(amount_usd).toFixed(2)) } }],
      },
      { headers: { Authorization: "Bearer " + token } }
    );
    res.json(data);
  } catch {
    res.status(500).json({ error: "create_order_failed" });
  }
});

app.post("/api/paypal/deposit/capture", requireUser, async (req, res) => {
  try {
    const { user_id, order_id } = req.body || {};
    if (!user_id || !order_id) return res.status(400).json({ error: "missing params" });
    if (AUTH_REQUIRED && req.user_id !== user_id) return res.status(403).json({ error: "forbidden" });

    const token = await paypalToken();
    const base = process.env.PAYPAL_API_BASE || "https://api-m.paypal.com";
    const { data } = await axios.post(
      base + `/v2/checkout/orders/${order_id}/capture`,
      {},
      { headers: { Authorization: "Bearer " + token } }
    );

    const captures = data?.purchase_units?.[0]?.payments?.captures || [];
    let total = 0;
    for (const c of captures) total += Number(c?.amount?.value || 0);

    await ensureUser(user_id);
    await dbRun("UPDATE wallets SET total_usd = total_usd + ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?", [
      total,
      user_id,
    ]);
    await dbRun("INSERT INTO ledger (user_id, type, amount, meta) VALUES (?,?,?,?)", [
      user_id,
      "deposit_paypal",
      total,
      JSON.stringify({ order_id }),
    ]);

    res.json({ ok: true, captured_usd: total });
  } catch {
    res.status(500).json({ error: "capture_failed" });
  }
});

// shared payout (admin & auto)
async function doPaypalPayout(email, amount, requestId, user_id) {
  try {
    const token = await paypalToken();
    const base = process.env.PAYPAL_API_BASE || "https://api-m.paypal.com";
    const batch = {
      sender_batch_header: { email_subject: "Your EngageHubCoin Payout" },
      items: [
        {
          recipient_type: "EMAIL",
          amount: { value: String(Number(amount).toFixed(2)), currency: "USD" },
          receiver: email,
          note: "Payout",
          sender_item_id: String(requestId),
        },
      ],
    };
    const { data } = await axios.post(base + "/v1/payments/payouts", batch, {
      headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
    });

    await dbRun(
      "UPDATE wallets SET survey_usd_withdrawn = survey_usd_withdrawn + ?, total_usd = total_usd - ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
      [amount, amount, user_id]
    );
    await dbRun("UPDATE withdraw_requests SET status='paid' WHERE id=?", [requestId]);
    await dbRun("INSERT INTO ledger (user_id, type, amount, meta) VALUES (?,?,?,?)", [
      user_id,
      "payout_paypal",
      -amount,
      JSON.stringify({ request_id: requestId, batch_id: data?.batch_header?.payout_batch_id }),
    ]);

    return true;
  } catch {
    return false;
  }
}

/* =========================
   Admin endpoints
========================= */
function requireAdmin(req, res) {
  const key = req.query.key || req.body?.admin_secret;
  if (key !== process.env.ADMIN_SECRET) {
    res.status(403).json({ error: "forbidden" });
    return false;
  }
  return true;
}

app.get("/api/admin/user/:user_id", async (req, res) => {
  if (!requireAdmin(req, res)) return;
  const { user_id } = req.params;
  const w = await dbGet("SELECT * FROM wallets WHERE user_id=?", [user_id]);
  const ledger = await dbAll("SELECT * FROM ledger WHERE user_id=? ORDER BY id DESC LIMIT 100", [user_id]);
  res.json({ wallet: w, withdrawable_usd: withdrawableFromWallet(w), ledger });
});

app.get("/api/admin/withdraw/requests", async (req, res) => {
  if (!requireAdmin(req, res)) return;
  const rows = await dbAll("SELECT * FROM withdraw_requests WHERE status='pending' ORDER BY id ASC");
  res.json({ items: rows });
});

app.post("/api/admin/payouts/paypal", async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    const { request_id } = req.body || {};
    const r = await dbGet("SELECT * FROM withdraw_requests WHERE id=?", [request_id]);
    if (!r || r.status !== "pending") return res.status(400).json({ error: "invalid_request" });

    const w = await dbGet("SELECT * FROM wallets WHERE user_id=?", [r.user_id]);
    const avail = withdrawableFromWallet(w);
    if (r.amount > avail + 1e-9) return res.status(400).json({ error: "exceeds_available" });

    const ok = await doPaypalPayout(r.email, r.amount, r.id, r.user_id);
    if (!ok) return res.status(500).json({ error: "payout_failed" });
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "payout_failed" });
  }
});

// Data Buyers APIs
app.get("/api/data-buyers", async (_req, res) => {
  const rows = await dbAll("SELECT id, name, homepage, status FROM data_buyers ORDER BY id ASC");
  res.json({ items: rows });
});
app.post("/api/admin/data-buyers/update", async (req, res) => {
  if (!requireAdmin(req, res)) return;
  const { id, status, notes } = req.body || {};
  if (!id) return res.status(400).json({ error: "missing id" });
  await dbRun(
    "UPDATE data_buyers SET status = COALESCE(?, status), notes = COALESCE(?, notes) WHERE id=?",
    [status || null, notes || null, id]
  );
  res.json({ ok: true });
});

/* =========================
   WhatsApp (send + webhook)
========================= */
app.get("/webhooks/whatsapp", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];
  if (mode === "subscribe" && token === process.env.META_VERIFY_TOKEN) return res.status(200).send(challenge);
  res.sendStatus(403);
});
app.post("/webhooks/whatsapp", async (_req, res) => res.sendStatus(200));
app.post("/api/whatsapp/send", async (req, res) => {
  try {
    const token = process.env.META_ACCESS_TOKEN;
    const phoneId = process.env.WHATSAPP_PHONE_NUMBER_ID;
    const { to, text } = req.body || {};
    if (!token || !phoneId) return res.status(400).json({ error: "missing_whatsapp_config" });
    if (!to || !text) return res.status(400).json({ error: "missing_params" });

    const url = `https://graph.facebook.com/v20.0/${phoneId}/messages`;
    const payload = { messaging_product: "whatsapp", to, type: "text", text: { body: text } };
    const { data } = await axios.post(url, payload, {
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    });
    res.json({ ok: true, data });
  } catch {
    res.status(500).json({ error: "whatsapp_send_failed" });
  }
});

/* =========================
   TikTok OAuth (skeleton)
========================= */
app.get("/auth/tiktok", (req, res) => {
  const clientKey = process.env.TIKTOK_CLIENT_KEY;
  const redirectUri = encodeURIComponent(process.env.TIKTOK_REDIRECT_URI || "");
  const scope = encodeURIComponent(process.env.TIKTOK_SCOPES || "openid,profile");
  const state = "tt-" + Date.now();
  const url = `https://www.tiktok.com/auth/authorize/?client_key=${clientKey}&response_type=code&scope=${scope}&redirect_uri=${redirectUri}&state=${state}`;
  res.redirect(url);
});
app.get("/auth/tiktok/callback", async (req, res) => {
  try {
    const code = req.query.code;
    const { data } = await axios.post(
      "https://open.tiktokapis.com/v2/oauth/token/",
      {
        client_key: process.env.TIKTOK_CLIENT_KEY,
        client_secret: process.env.TIKTOK_CLIENT_SECRET,
        code,
        grant_type: "authorization_code",
        redirect_uri: process.env.TIKTOK_REDIRECT_URI,
      },
      { headers: { "Content-Type": "application/json" } }
    );
    const { access_token, refresh_token, expires_in } = data.data || {};
    const user_id = "tiktok:" + Date.now();
    await ensureUser(user_id, "TikTok User");
    const expires_at = Math.floor(Date.now() / 1000) + Number(expires_in || 0);
    await dbRun(
      "INSERT OR REPLACE INTO tiktok_tokens (user_id, access_token, refresh_token, expires_at) VALUES (?,?,?,?)",
      [user_id, access_token, refresh_token, expires_at]
    );
    res.send("<pre>TikTok connected. You can close this window.</pre>");
  } catch {
    res.status(500).send("tiktok_auth_error");
  }
});

/* =========================
   Facebook OAuth (login)
========================= */
app.get("/auth/facebook", (req, res) => {
  const appId = process.env.FB_APP_ID;
  const redirect = encodeURIComponent(process.env.FB_REDIRECT_URI || "");
  const state = "fb-" + Date.now();
  const scope = encodeURIComponent("public_profile,email");
  const url = `https://www.facebook.com/v19.0/dialog/oauth?client_id=${appId}&redirect_uri=${redirect}&state=${state}&response_type=code&scope=${scope}`;
  res.redirect(url);
});
app.get("/auth/facebook/callback", async (req, res) => {
  try {
    const { code } = req.query;
    const appId = process.env.FB_APP_ID;
    const appSecret = process.env.FB_APP_SECRET;
    const redirect = process.env.FB_REDIRECT_URI;

    const tokenResp = await axios.get("https://graph.facebook.com/v19.0/oauth/access_token", {
      params: { client_id: appId, redirect_uri: redirect, client_secret: appSecret, code },
    });
    const access_token = tokenResp.data.access_token;
    const meResp = await axios.get("https://graph.facebook.com/v19.0/me", {
      params: { access_token, fields: "id,name" },
    });
    const fb_user_id = meResp.data.id;
    const name = meResp.data.name || "Facebook User";
    const user_id = "facebook:" + fb_user_id;

    await ensureUser(user_id, name);
    const expires_at = Math.floor(Date.now() / 1000) + 60 * 60 * 2;
    await dbRun(
      "INSERT OR REPLACE INTO facebook_tokens (fb_user_id, user_id, access_token, expires_at) VALUES (?,?,?,?)",
      [fb_user_id, user_id, access_token, expires_at]
    );
    res.send(`<pre>Facebook connected for ${name} (user_id: ${user_id}). You can close this window.</pre>`);
  } catch {
    res.status(500).send("facebook_auth_error");
  }
});

/* =========================
   YouTube feed
========================= */
app.get("/api/youtube/videos", async (_req, res) => {
  try {
    const key = process.env.YOUTUBE_API_KEY,
      channelId = process.env.YOUTUBE_CHANNEL_ID;
    if (!key || !channelId) return res.json({ items: [] });
    const { data } = await axios.get("https://www.googleapis.com/youtube/v3/search", {
      params: { key, channelId, part: "snippet,id", order: "date", maxResults: 10 },
    });
    res.json(data);
  } catch {
    res.status(500).json({ error: "youtube_error" });
  }
});

/* =========================
   AI quiz (OpenAI optional)
========================= */
app.post("/api/ai/quiz", async (req, res) => {
  const topic = (req.body.topic || "general").slice(0, 80);
  const n = Math.min(Number(req.body.n || 5), 10);
  const key = process.env.OPENAI_API_KEY;

  async function localQuiz() {
    const bank = [
      { q: "Which metal has the symbol Au?", options: ["Silver", "Gold", "Copper", "Tin"], answer: 1 },
      { q: "Capital of Kenya?", options: ["Mombasa", "Kisumu", "Nairobi", "Eldoret"], answer: 2 },
      { q: "Largest planet?", options: ["Earth", "Saturn", "Jupiter", "Venus"], answer: 2 },
      { q: "HTTP stands for?", options: ["Hyper Text Transfer Protocol", "High Transfer Type Protocol", "Host Transfer Tech Process", "None"], answer: 0 },
      { q: "2 + 5 × 2 = ?", options: ["9", "12", "14", "7"], answer: 1 },
      { q: "Creator of JavaScript?", options: ["Brendan Eich", "Guido Rossum", "Linus Torvalds", "James Gosling"], answer: 0 },
    ];
    return bank.slice(0, n);
  }

  try {
    if (!key) return res.json({ provider: "local", items: await localQuiz() });
    const { OpenAI } = await import("openai");
    const client = new OpenAI({ apiKey: key });
    const prompt = `Create ${n} multiple-choice questions on "${topic}". Return JSON {items:[{q,options,answer}]}`;
    const r = await client.responses.create({ model: "gpt-4.1-mini", input: prompt, temperature: 0.4 });
    let text = r.output_text;
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      const m = text.match(/\{[\s\S]*\}/);
      parsed = m ? JSON.parse(m[0]) : { items: await localQuiz() };
    }
    res.json({ provider: "openai", items: parsed.items?.slice(0, n) || (await localQuiz()) });
  } catch {
    res.json({ provider: "local", items: await localQuiz() });
  }
});

/* =========================
   X (Twitter) & Instagram embeds
========================= */
app.get("/api/twitter/oembed", async (req, res) => {
  try {
    const { url } = req.query;
    if (!url) return res.status(400).json({ error: "missing url" });
    const { data } = await axios.get("https://publish.twitter.com/oembed", { params: { url } });
    res.json(data);
  } catch {
    res.status(500).json({ error: "twitter_oembed_failed" });
  }
});

app.get("/api/instagram/oembed", async (req, res) => {
  try {
    const { url } = req.query;
    const token = process.env.IG_OEMBED_TOKEN;
    if (!url) return res.status(400).json({ error: "missing url" });
    if (!token) return res.status(400).json({ error: "missing_ig_oembed_token" });
    const { data } = await axios.get("https://graph.facebook.com/v19.0/instagram_oembed", {
      params: { url, access_token: token, omitscript: true, hidecaption: false },
    });
    res.json(data);
  } catch {
    res.status(500).json({ error: "instagram_oembed_failed" });
  }
});

/* =========================
   Radio: station scan
========================= */
// Candidate stations to probe (feel free to add more)
const RADIO_CANDIDATES = [
  { name: "BBC World Service", url: "https://stream.live.vc.bbcmedia.co.uk/bbc_world_service" },
  { name: "NPR News", url: "https://npr-ice.streamguys1.com/live.mp3" },
  { name: "Cafe Del Mar FM", url: "https://streams.cafedelmar.fm:8443/cdm" },
  { name: "EDM Radio", url: "https://stream.edmradio.com:8443/live" },
  { name: "Classical KING FM", url: "https://live.wostreaming.net/direct/classical-kingfmmp3-ibc1" }
];
// Probe a URL quickly (HEAD or short GET)
async function probeStation(u) {
  try {
    const r = await axios.get(u, { responseType: "stream", timeout: 5000, maxRedirects: 3 });
    const type = r.headers["content-type"] || "";
    // basic heuristic: audio/* or octet-stream is OK
    if (type.includes("audio") || type.includes("octet-stream")) return true;
    return true; // many streams omit content-type; allow if reachable
  } catch {
    return false;
  }
}
app.get("/api/radio/scan", async (_req, res) => {
  const results = [];
  await Promise.all(
    RADIO_CANDIDATES.map(async (s) => {
      const ok = await probeStation(s.url);
      if (ok) results.push(s);
    })
  );
  res.json({ items: results });
});

/* =========================
   Root / Health
========================= */
app.get("/health", (_req, res) => res.send("ok"));
app.get("/", (_req, res) => res.sendFile(path.join(__dirname, "../frontend/index.html")));

const PORT = Number(process.env.PORT || 8080);
initDb().then(() =>
  app.listen(PORT, () => console.log("EngageHubCoin running on http://localhost:" + PORT))
);
