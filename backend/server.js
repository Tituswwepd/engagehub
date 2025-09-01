import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import axios from "axios";
import sqlite3 from "sqlite3";
import { open as sqliteOpen } from "sqlite";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import nodemailer from "nodemailer";
import crypto from "crypto";

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// serve frontend
app.use(express.static(path.join(__dirname, "../frontend")));

/* =========================
   DB INIT
========================= */
let db;
async function initDb() {
  db = await sqliteOpen({
    filename: process.env.DB_FILE || "./data.sqlite",
    driver: sqlite3.Database,
  });

  await db.exec(`
    PRAGMA journal_mode = WAL;

    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE,
      password_hash TEXT,
      name TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS reset_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT,
      token TEXT,
      expires_at INTEGER
    );

    CREATE TABLE IF NOT EXISTS wallets (
      user_id TEXT PRIMARY KEY,
      total_usd REAL DEFAULT 0,
      survey_usd_total REAL DEFAULT 0,
      survey_usd_withdrawn REAL DEFAULT 0,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS ledger (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT,
      type TEXT,
      amount REAL,
      meta TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS withdraw_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT,
      email TEXT,
      amount REAL,
      status TEXT DEFAULT 'pending',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS survey_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      provider TEXT,
      trans_id TEXT,
      user_id TEXT,
      payout REAL,
      raw TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(provider, trans_id)
    );

    CREATE TABLE IF NOT EXISTS tiktok_tokens (
      user_id TEXT PRIMARY KEY,
      access_token TEXT,
      refresh_token TEXT,
      expires_at INTEGER,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS facebook_tokens (
      fb_user_id TEXT PRIMARY KEY,
      user_id TEXT,
      access_token TEXT,
      expires_at INTEGER,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);
}

/* =========================
   HELPERS: USERS & WALLET
========================= */
async function ensureUser(user_id, name = "User") {
  const u = await db.get("SELECT id FROM users WHERE id=?", user_id);
  if (!u) {
    await db.run("INSERT INTO users (id,email,name) VALUES (?,?,?)", user_id, user_id, name);
  }
  const w = await db.get("SELECT user_id FROM wallets WHERE user_id=?", user_id);
  if (!w) await db.run("INSERT INTO wallets (user_id) VALUES (?)", user_id);
}

function withdrawableFromWallet(w) {
  const cap = 0.5 * Number(w.survey_usd_total || 0);
  const used = Number(w.survey_usd_withdrawn || 0);
  return Math.max(0, cap - used);
}

async function creditSurveyUSD(user_id, usd, meta) {
  await ensureUser(user_id);
  await db.run(
    "UPDATE wallets SET survey_usd_total = survey_usd_total + ?, total_usd = total_usd + ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
    usd, usd, user_id
  );
  await db.run(
    "INSERT INTO ledger (user_id, type, amount, meta) VALUES (?,?,?,?)",
    user_id, "survey_credit_usd", usd, JSON.stringify(meta || {})
  );
}

async function creditOwnerUSD(user_id, usd, meta) {
  await ensureUser(user_id);
  await db.run(
    "UPDATE wallets SET total_usd = total_usd + ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
    usd, user_id
  );
  await db.run(
    "INSERT INTO ledger (user_id, type, amount, meta) VALUES (?,?,?,?)",
    user_id, "owner_credit_usd", usd, JSON.stringify(meta || {})
  );
}

function classifyProvider(p) {
  const env = process.env;
  const map = {
    ADGEM: env.ADGEM_TREATED_AS || "OWNER",
    CPX: env.CPX_TREATED_AS || "SURVEY",
    BITLABS: env.BITLABS_TREATED_AS || "SURVEY",
    TAPJOY: env.TAPJOY_TREATED_AS || "OWNER",
    OFFERTORO: env.OFFERTORO_TREATED_AS || "SURVEY",
    PERSONALY: env.PERSONALY_TREATED_AS || "SURVEY",
    AYET: env.AYET_TREATED_AS || "SURVEY",
    KIWIWALL: env.KIWIWALL_TREATED_AS || "SURVEY",
    OFFERDADDY: env.OFFERDADDY_TREATED_AS || "SURVEY",
    WANNADS: env.WANNADS_TREATED_AS || "SURVEY",
  };
  return map[(p || "").toUpperCase()] || "OWNER";
}

/* =========================
   JWT AUTH
========================= */
function signJwt(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || "1h",
  });
}

function authOptional(req, _res, next) {
  const auth = req.headers["authorization"];
  if (auth?.startsWith("Bearer ")) {
    try { req.user = jwt.verify(auth.split(" ")[1], process.env.JWT_SECRET); } catch {}
  }
  next();
}

function authRequired(req, res, next) {
  const auth = req.headers["authorization"];
  if (!auth) return res.status(401).json({ error: "no_token" });
  try {
    req.user = jwt.verify(auth.split(" ")[1], process.env.JWT_SECRET);
    next();
  } catch { return res.status(401).json({ error: "invalid_token" }); }
}

/* =========================
   AUTH ROUTES
========================= */
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password, name } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "missing_fields" });
    const hash = await bcrypt.hash(password, 10);
    await db.run("INSERT INTO users (id,email,password_hash,name) VALUES (?,?,?,?)", email, email, hash, name || "");
    await ensureUser(email, name || "User");
    const token = signJwt({ id: email, email });
    res.json({ token });
  } catch {
    res.status(400).json({ error: "email_in_use" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const user = await db.get("SELECT * FROM users WHERE email=?", email);
    if (!user) return res.status(400).json({ error: "invalid_credentials" });
    const ok = await bcrypt.compare(password, user.password_hash || "");
    if (!ok) return res.status(400).json({ error: "invalid_credentials" });
    const token = signJwt({ id: user.id, email: user.email });
    res.json({ token });
  } catch {
    res.status(500).json({ error: "login_failed" });
  }
});

// expose current user id (for CPX ext_user_id on frontend)
app.get("/api/auth/me", authOptional, (req, res) => {
  if (!req.user) return res.json({ id: null });
  res.json({ id: req.user.id, email: req.user.email });
});

/* =========================
   PASSWORD RESET (email)
========================= */
const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: String(process.env.SMTP_SECURE || "false") === "true",
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
});

app.post("/api/auth/forgot", async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ error: "missing_email" });

    const user = await db.get("SELECT * FROM users WHERE email=?", email);
    if (!user) return res.json({ ok: true });

    const token = Math.random().toString(36).slice(2);
    const ttlMs = Number(process.env.RESET_TOKEN_MIN || 30) * 60 * 1000;
    const expiresAt = Date.now() + ttlMs;

    await db.run("INSERT INTO reset_tokens (email, token, expires_at) VALUES (?,?,?)", email, token, expiresAt);

    const link = `${process.env.APP_BASE_URL || ""}/reset.html?token=${token}&email=${encodeURIComponent(email)}`;

    await mailer.sendMail({
      from: process.env.SMTP_FROM,
      to: email,
      subject: "Password Reset - EngageHubCoin",
      text: `Click the link to reset your password: ${link}`,
      html: `<p>Click below to reset your password:</p><p><a href="${link}">${link}</a></p>`,
    });

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "reset_failed" });
  }
});

app.post("/api/auth/reset", async (req, res) => {
  try {
    const { email, token, password } = req.body || {};
    const row = await db.get("SELECT * FROM reset_tokens WHERE email=? AND token=?", email, token);
    if (!row) return res.status(400).json({ error: "invalid_token" });
    if (Date.now() > Number(row.expires_at)) return res.status(400).json({ error: "expired_token" });

    const hash = await bcrypt.hash(password, 10);
    await db.run("UPDATE users SET password_hash=? WHERE email=?", hash, email);
    await db.run("DELETE FROM reset_tokens WHERE email=?", email);

    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "reset_failed" });
  }
});

/* =========================
   PUBLIC CONFIG (safe)
========================= */
app.get("/api/config/public", (_req, res) => {
  res.json({
    PAYPAL_CLIENT_ID: process.env.PAYPAL_CLIENT_ID || "",
    FB_APP_ID: process.env.FB_APP_ID || "",
    TIKTOK_CLIENT_KEY: process.env.TIKTOK_CLIENT_KEY || "",
    YOUTUBE_CHANNEL_ID: process.env.YOUTUBE_CHANNEL_ID || "",
    WHATSAPP_ENABLED: Boolean(process.env.META_ACCESS_TOKEN && process.env.WHATSAPP_PHONE_NUMBER_ID)
  });
});

/* =========================
   WALLET (JWT-first, fallback user_id)
========================= */
app.get("/api/wallet", authOptional, async (req, res) => {
  try {
    const user_id = req.user?.id || req.query.user_id || req.headers["x-user-id"];
    if (!user_id) return res.status(400).json({ error: "missing_user" });
    await ensureUser(user_id);
    const w = await db.get("SELECT * FROM wallets WHERE user_id=?", user_id);
    const withdrawable = withdrawableFromWallet(w);
    res.json({ user_id, available_to_withdraw_usd: Number(withdrawable.toFixed(2)) });
  } catch {
    res.status(500).json({ error: "wallet_failed" });
  }
});

app.get("/api/wallet/:user_id", async (req, res) => {
  req.query.user_id = req.params.user_id;
  return app._router.handle(req, res);
});

/* =========================
   WITHDRAW REQUESTS
========================= */
app.post("/api/withdraw/request", authOptional, async (req, res) => {
  try {
    const user_id = req.user?.id || req.body.user_id;
    const { email, amount_usd } = req.body || {};
    if (!user_id || !email || !amount_usd) return res.status(400).json({ error: "missing_params" });

    await ensureUser(user_id);
    const w = await db.get("SELECT * FROM wallets WHERE user_id=?", user_id);
    const avail = withdrawableFromWallet(w);
    const amt = Number(amount_usd);

    if (amt < Number(process.env.MIN_WITHDRAW_USD || "0"))
      return res.status(400).json({ error: "below_minimum" });
    if (amt > avail + 1e-9)
      return res.status(400).json({ error: "exceeds_available" });

    await db.run("INSERT INTO withdraw_requests (user_id,email,amount) VALUES (?,?,?)", user_id, email, amt);
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "request_failed" });
  }
});

/* =========================
   CPX POSTBACK (hash-verified)
   Endpoint to configure in CPX:
   https://YOUR-DOMAIN/api/postback/cpx?status={status}&trans_id={trans_id}&user_id={user_id}&sub_id={subid}&amount_local={amount_local}&amount_usd={amount_usd}&offer_id={offer_id}&hash={secure_hash}&ip_click={ip_click}
========================= */
app.get("/api/postback/cpx", async (req, res) => {
  try {
    const {
      status,
      trans_id,
      user_id,
      sub_id,
      amount_local,
      amount_usd,
      offer_id,
      hash: secure_hash,
      ip_click
    } = req.query;

    // verify hash (most CPX setups use sha1(secret + trans_id))
    const secret = process.env.CPX_POSTBACK_SECRET || "";
    if (!secret) return res.status(500).send("no secret");
    const expected = crypto.createHash("sha1").update(`${secret}${trans_id}`).digest("hex");
    if (!secure_hash || secure_hash.toLowerCase() !== expected.toLowerCase()) {
      return res.status(403).send("bad hash");
    }

    const usd = Number(amount_usd || 0);

    // store idempotently
    await db.run(
      "INSERT OR IGNORE INTO survey_events (provider, trans_id, user_id, payout, raw) VALUES (?,?,?,?,?)",
      "cpx", String(trans_id || ""), String(user_id || ""), usd, JSON.stringify(req.query)
    );

    // status==1 completed -> credit; status==2 reversal -> (optional) revert
    if (String(status) === "1") {
      const as = classifyProvider("CPX");
      const meta = { provider: "cpx", trans_id, offer_id, sub_id, ip_click };
      if (as === "SURVEY") await creditSurveyUSD(user_id, usd, meta);
      else await creditOwnerUSD(user_id, usd, meta);
    }

    return res.status(200).send("OK");
  } catch (e) {
    console.error("CPX postback error", e);
    return res.status(500).send("ERR");
  }
});

/* =========================
   OTHER PROVIDER HOOKS (unchanged)
========================= */
app.get("/webhooks/bitlabs", async (req, res) => {
  try {
    const { user_id, transaction_id, amount } = req.query;
    const usd = Number(amount || 0);
    const as = classifyProvider("BITLABS");
    if (as === "SURVEY") await creditSurveyUSD(user_id, usd, { provider: "bitlabs", transaction_id });
    else await creditOwnerUSD(user_id, usd, { provider: "bitlabs", transaction_id });
    await db.run(
      "INSERT OR IGNORE INTO survey_events (provider, trans_id, user_id, payout, raw) VALUES (?,?,?,?,?)",
      "bitlabs", transaction_id, user_id, usd, JSON.stringify(req.query)
    );
    res.send("OK");
  } catch { res.status(500).send("ERR"); }
});

app.get("/webhooks/adgem", async (req, res) => {
  try {
    const { user_id, trans_id, payout, secret } = req.query;
    if (secret !== process.env.ADGEM_POSTBACK_SECRET) return res.status(403).send("bad secret");
    const usd = Number(payout || 0);
    const as = classifyProvider("ADGEM");
    if (as === "SURVEY") await creditSurveyUSD(user_id, usd, { provider: "adgem", trans_id });
    else await creditOwnerUSD(user_id, usd, { provider: "adgem", trans_id });
    await db.run(
      "INSERT OR IGNORE INTO survey_events (provider, trans_id, user_id, payout, raw) VALUES (?,?,?,?,?)",
      "adgem", trans_id, user_id, usd, JSON.stringify(req.query)
    );
    res.send("OK");
  } catch { res.status(500).send("ERR"); }
});

app.get("/webhooks/tapjoy", async (req, res) => {
  try {
    const { user_id, id, reward } = req.query;
    const usd = Number(reward || 0);
    const as = classifyProvider("TAPJOY");
    if (as === "SURVEY") await creditSurveyUSD(user_id, usd, { provider: "tapjoy", id });
    else await creditOwnerUSD(user_id, usd, { provider: "tapjoy", id });
    await db.run(
      "INSERT OR IGNORE INTO survey_events (provider, trans_id, user_id, payout, raw) VALUES (?,?,?,?,?)",
      "tapjoy", id, user_id, usd, JSON.stringify(req.query)
    );
    res.send("OK");
  } catch { res.status(500).send("ERR"); }
});

/* =========================
   PAYPAL (unchanged)
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

app.post("/api/paypal/deposit/create", authOptional, async (req, res) => {
  try {
    const user_id = req.user?.id || req.body.user_id;
    const { amount_usd } = req.body || {};
    if (!user_id || !amount_usd) return res.status(400).json({ error: "missing_params" });

    const token = await paypalToken();
    const base = process.env.PAYPAL_API_BASE || "https://api-m.paypal.com";
    const { data } = await axios.post(
      base + "/v2/checkout/orders",
      { intent: "CAPTURE", purchase_units: [{ amount: { currency_code: "USD", value: String(Number(amount_usd).toFixed(2)) } }] },
      { headers: { Authorization: "Bearer " + token } }
    );
    res.json(data);
  } catch {
    res.status(500).json({ error: "create_order_failed" });
  }
});

app.post("/api/paypal/deposit/capture", authOptional, async (req, res) => {
  try {
    const user_id = req.user?.id || req.body.user_id;
    const { order_id } = req.body || {};
    if (!user_id || !order_id) return res.status(400).json({ error: "missing_params" });

    const token = await paypalToken();
    const base = process.env.PAYPAL_API_BASE || "https://api-m.paypal.com";
    const { data } = await axios.post(base + `/v2/checkout/orders/${order_id}/capture`, {}, { headers: { Authorization: "Bearer " + token } });

    const captures = data?.purchase_units?.[0]?.payments?.captures || [];
    let total = 0; for (const c of captures) total += Number(c.amount?.value || 0);

    await ensureUser(user_id);
    await db.run("UPDATE wallets SET total_usd = total_usd + ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?", total, user_id);
    await db.run("INSERT INTO ledger (user_id, type, amount, meta) VALUES (?,?,?,?)", user_id, "deposit_paypal", total, JSON.stringify({ order_id }));

    res.json({ ok: true, captured_usd: total });
  } catch {
    res.status(500).json({ error: "capture_failed" });
  }
});

/* =========================
   ADMIN (unchanged)
========================= */
function requireAdmin(req, res) {
  const key = req.query.key || req.body?.admin_secret;
  if (key !== process.env.ADMIN_SECRET) {
    res.status(403).json({ error: "forbidden" });
    return false;
  }
  return true;
}

app.get("/api/admin/user/:user_id", (req, res, next) => { if (!requireAdmin(req, res)) return; next(); }, async (req, res) => {
  const { user_id } = req.params;
  const w = await db.get("SELECT * FROM wallets WHERE user_id=?", user_id);
  const ledger = await db.all("SELECT * FROM ledger WHERE user_id=? ORDER BY id DESC LIMIT 200", user_id);
  res.json({ wallet: w, withdrawable_usd: withdrawableFromWallet(w), ledger });
});

app.get("/api/admin/withdraw/requests", (req, res, next) => { if (!requireAdmin(req, res)) return; next(); }, async (_req, res) => {
  const rows = await db.all("SELECT * FROM withdraw_requests WHERE status='pending' ORDER BY id ASC");
  res.json({ items: rows });
});

app.post("/api/admin/payouts/paypal", (req, res, next) => { if (!requireAdmin(req, res)) return; next(); }, async (req, res) => {
  try {
    const { request_id } = req.body || {};
    const r = await db.get("SELECT * FROM withdraw_requests WHERE id=?", request_id);
    if (!r || r.status !== "pending") return res.status(400).json({ error: "invalid_request" });

    const w = await db.get("SELECT * FROM wallets WHERE user_id=?", r.user_id);
    const avail = withdrawableFromWallet(w);
    if (r.amount > avail + 1e-9) return res.status(400).json({ error: "exceeds_available" });

    const token = await paypalToken();
    const base = process.env.PAYPAL_API_BASE || "https://api-m.paypal.com";
    const batch = {
      sender_batch_header: { email_subject: "Your EngageHubCoin Payout" },
      items: [{
        recipient_type: "EMAIL",
        amount: { value: String(r.amount.toFixed(2)), currency: "USD" },
        receiver: r.email,
        note: "Payout",
        sender_item_id: String(r.id),
      }],
    };
    const { data } = await axios.post(base + "/v1/payments/payouts", batch, {
      headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
    });

    await db.run("UPDATE wallets SET survey_usd_withdrawn = survey_usd_withdrawn + ?, total_usd = total_usd - ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?", r.amount, r.amount, r.user_id);
    await db.run("UPDATE withdraw_requests SET status='paid' WHERE id=?", r.id);
    await db.run("INSERT INTO ledger (user_id, type, amount, meta) VALUES (?,?,?,?)", r.user_id, "payout_paypal", -r.amount, JSON.stringify({ request_id: r.id, batch_id: data?.batch_header?.payout_batch_id }));

    res.json({ ok: true, data });
  } catch {
    res.status(500).json({ error: "payout_failed" });
  }
});

/* =========================
   META WHATSAPP / YOUTUBE / RADIO / AI QUIZ (unchanged)
========================= */
app.get("/webhooks/whatsapp", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];
  if (mode === "subscribe" && token === process.env.META_VERIFY_TOKEN) return res.status(200).send(challenge);
  res.sendStatus(403);
});
app.post("/webhooks/whatsapp", async (_req, res) => { res.sendStatus(200); });
app.post("/api/whatsapp/send", async (req, res) => {
  try {
    const token = process.env.META_ACCESS_TOKEN;
    const phoneId = process.env.WHATSAPP_PHONE_NUMBER_ID;
    const { to, text } = req.body || {};
    if (!token || !phoneId) return res.status(400).json({ error: "missing_whatsapp_config" });
    if (!to || !text) return res.status(400).json({ error: "missing_params" });

    const url = `https://graph.facebook.com/v20.0/${phoneId}/messages`;
    const payload = { messaging_product: "whatsapp", to, type: "text", text: { body: text } };
    const { data } = await axios.post(url, payload, { headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" } });
    res.json({ ok: true, data });
  } catch { res.status(500).json({ error: "whatsapp_send_failed" }); }
});

app.get("/api/youtube/videos", async (_req, res) => {
  try {
    const key = process.env.YOUTUBE_API_KEY, channelId = process.env.YOUTUBE_CHANNEL_ID;
    if (!key || !channelId) return res.json({ items: [] });
    const { data } = await axios.get("https://www.googleapis.com/youtube/v3/search", {
      params: { key, channelId, part: "snippet,id", order: "date", maxResults: 10 }
    });
    res.json(data);
  } catch { res.status(500).json({ error: "youtube_error" }); }
});

const RADIO_HOSTS = [
  "https://de1.api.radio-browser.info",
  "https://fr1.api.radio-browser.info",
  "https://nl1.api.radio-browser.info",
  "https://at1.api.radio-browser.info",
];
app.get("/api/radio/search", async (req, res) => {
  const q = String(req.query.q || "").trim();
  if (!q) return res.json({ items: [] });
  for (const base of RADIO_HOSTS) {
    try {
      const { data } = await axios.get(`${base}/json/stations/search`, {
        params: { name: q, limit: 12, hidebroken: true }, timeout: 8000,
      });
      const items = (data || []).map(s => ({
        name: s.name,
        url: s.url_resolved || s.url,
        homepage: s.homepage,
        country: s.country,
        codec: s.codec,
        bitrate: s.bitrate
      }));
      return res.json({ items });
    } catch {}
  }
  res.json({ items: [] });
});

app.post("/api/ai/quiz", async (req, res) => {
  const topic = (req.body.topic || "general").slice(0,80);
  const n = Math.min(Number(req.body.n || 5), 10);
  const key = process.env.OPENAI_API_KEY;

  async function localQuiz() {
    const bank = [
      { q: "Which metal has the symbol Au?", options:["Silver","Gold","Copper","Tin"], answer:1 },
      { q: "Capital of Kenya?", options:["Mombasa","Kisumu","Nairobi","Eldoret"], answer:2 },
      { q: "Largest planet?", options:["Earth","Saturn","Jupiter","Venus"], answer:2 },
      { q: "HTTP stands for?", options:["Hyper Text Transfer Protocol","High Transfer Type Protocol","Host Transfer Tech Process","None"], answer:0 },
      { q: "2 + 5 × 2 = ?", options:["9","12","14","7"], answer:1 },
      { q: "Creator of JavaScript?", options:["Brendan Eich","Guido van Rossum","Linus Torvalds","James Gosling"], answer:0 }
    ];
    return bank.slice(0,n);
  }

  try {
    if (!key) return res.json({ provider:"local", items: await localQuiz() });
    const { OpenAI } = await import("openai");
    const client = new OpenAI({ apiKey: key });
    const prompt = `Create ${n} multiple-choice questions on "${topic}". Return JSON {items:[{q,options,answer}]}`;
    const r = await client.responses.create({ model:"gpt-4.1-mini", input: prompt, temperature:0.4 });
    let text = r.output_text; let parsed;
    try { parsed = JSON.parse(text); }
    catch { const m = text.match(/\{[\s\S]*\}/); parsed = m ? JSON.parse(m[0]) : {items: await localQuiz()}; }
    res.json({ provider:"openai", items: parsed.items?.slice(0,n) || await localQuiz() });
  } catch {
    res.json({ provider:"local", items: await localQuiz() });
  }
});

/* =========================
   ROOT
========================= */
app.get("/health", (_req, res) => res.send("ok"));
app.get("/", (_req, res) => res.sendFile(path.join(__dirname, "../frontend/index.html")));

const PORT = Number(process.env.PORT || 8080);
initDb().then(() =>
  app.listen(PORT, () => console.log("EngageHubCoin running on http://localhost:" + PORT))
);
