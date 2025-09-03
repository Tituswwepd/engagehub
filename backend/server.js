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
app.use(bodyParser.json({ limit: "2mb" }));
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
  const cap = 0.5 * Number(w.survey_usd_total || 0); // 50% of approved survey total
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
  } catch (e) {
    console.error("Register error:", e?.message);
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
  } catch (e) {
    console.error("Login error:", e?.message);
    res.status(500).json({ error: "login_failed" });
  }
});

// expose current user id (for CPX ext_user_id on frontend, if needed)
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
    console.error("Reset email error:", e?.message);
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
  } catch (e) {
    console.error("Reset apply error:", e?.message);
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
  } catch (e) {
    console.error("Wallet error:", e?.message);
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
  } catch (e) {
    console.error("Withdraw request error:", e?.message);
    res.status(500).json({ error: "request_failed" });
  }
});

/* =========================
   PAYPAL (better diagnostics)
========================= */
async function paypalToken() {
  const base = process.env.PAYPAL_API_BASE || "https://api-m.paypal.com";
  const id = process.env.PAYPAL_CLIENT_ID;
  const secret = process.env.PAYPAL_CLIENT_SECRET;

  if (!id || !secret) {
    throw new Error("paypal_config_missing");
  }
  try {
    const { data } = await axios.post(
      base + "/v1/oauth2/token",
      "grant_type=client_credentials",
      {
        auth: { username: id, password: secret },
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        timeout: 15000,
      }
    );
    return data.access_token;
  } catch (e) {
    console.error("PayPal token error:", e?.response?.data || e.message);
    throw new Error("paypal_token_error");
  }
}

app.post("/api/paypal/deposit/create", authOptional, async (req, res) => {
  try {
    const user_id = req.user?.id || req.body.user_id;
    const { amount_usd } = req.body || {};
    if (!user_id || !amount_usd) return res.status(400).json({ error: "missing_params" });

    const token = await paypalToken();
    const base = process.env.PAYPAL_API_BASE || "https://api-m.paypal.com";
    const payload = {
      intent: "CAPTURE",
      purchase_units: [{
        amount: { currency_code: "USD", value: String(Number(amount_usd).toFixed(2)) }
      }]
    };
    const { data } = await axios.post(
      base + "/v2/checkout/orders",
      payload,
      { headers: { Authorization: "Bearer " + token }, timeout: 20000 }
    );
    res.json(data);
  } catch (e) {
    console.error("PayPal create_order_failed:", e?.response?.data || e.message);
    res.status(500).json({ error: "create_order_failed", details: e?.response?.data || e.message });
  }
});

app.post("/api/paypal/deposit/capture", authOptional, async (req, res) => {
  try {
    const user_id = req.user?.id || req.body.user_id;
    const { order_id } = req.body || {};
    if (!user_id || !order_id) return res.status(400).json({ error: "missing_params" });

    const token = await paypalToken();
    the
    const base = process.env.PAYPAL_API_BASE || "https://api-m.paypal.com";
    const { data } = await axios.post(
      base + `/v2/checkout/orders/${order_id}/capture`,
      {},
      { headers: { Authorization: "Bearer " + token }, timeout: 20000 }
    );

    const captures = data?.purchase_units?.[0]?.payments?.captures || [];
    let total = 0; for (const c of captures) total += Number(c.amount?.value || 0);

    await ensureUser(user_id);
    await db.run("UPDATE wallets SET total_usd = total_usd + ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?", total, user_id);
    await db.run("INSERT INTO ledger (user_id, type, amount, meta) VALUES (?,?,?,?)", user_id, "deposit_paypal", total, JSON.stringify({ order_id }));

    res.json({ ok: true, captured_usd: total, raw: data });
  } catch (e) {
    console.error("PayPal capture_failed:", e?.response?.data || e.message);
    res.status(500).json({ error: "capture_failed", details: e?.response?.data || e.message });
  }
});

/* =========================
   ADMIN (basic)
========================= */
function requireAdmin(req, res) {
  const key = req.query.key || req.query.admin_secret || req.body?.admin_secret;
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
  res.json({ wallet: w, withdrawable_usd: w ? withdrawableFromWallet(w) : 0, ledger });
});

app.get("/api/admin/withdraw/requests", (req, res, next) => { if (!requireAdmin(req, res)) return; next(); }, async (_req, res) => {
  const rows = await db.all("SELECT * FROM withdraw_requests WHERE status='pending' ORDER BY id ASC");
  res.json({ items: rows });
});

/* =========================
   CPX (flexible hash)
========================= */
function computeCpxHash(secret, transId) {
  const alg = (process.env.CPX_HASH_ALG || "sha1").toLowerCase();
  const format = (process.env.CPX_HASH_FORMAT || "secret+trans").toLowerCase();
  const raw = format === "trans+secret" ? `${transId}${secret}` : `${secret}${transId}`;
  return crypto.createHash(alg === "md5" ? "md5" : "sha1").update(raw).digest("hex");
}

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

    const secret = process.env.CPX_POSTBACK_SECRET || "";
    if (!secret) return res.status(500).send("no secret");

    const expected = computeCpxHash(secret, String(trans_id || ""));
    if (!secure_hash || secure_hash.toLowerCase() !== expected.toLowerCase()) {
      console.warn("CPX hash mismatch", { expected, got: secure_hash, trans_id });
      return res.status(403).send("bad hash");
    }

    const usd = Number(amount_usd || 0);

    await db.run(
      "INSERT OR IGNORE INTO survey_events (provider, trans_id, user_id, payout, raw) VALUES (?,?,?,?,?)",
      "cpx", String(trans_id || ""), String(user_id || ""), usd, JSON.stringify(req.query)
    );

    if (String(status) === "1") {
      const as = classifyProvider("CPX");
      const meta = { provider: "cpx", trans_id, offer_id, sub_id, ip_click, amount_local };
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
   ADGEM (server postback)
========================= */
// AdGem will call: GET /api/postback/adgem?key=SECRET&user_id=[user_id]&payout=[payout]&offer_id=[offer_id]&offer_name=[offer_name]&transaction_id=[transaction_id]
app.get("/api/postback/adgem", async (req, res) => {
  try {
    const {
      key,
      user_id,
      payout,
      offer_id,
      offer_name,
      transaction_id,
      trans_id // just in case they use trans_id
    } = req.query;

    // verify shared secret
    if (!process.env.SURVEY_ADGEM_SECRET) return res.status(500).send("no secret");
    if (key !== process.env.SURVEY_ADGEM_SECRET) return res.status(403).send("bad key");

    const tx = String(transaction_id || trans_id || "");
    const uid = String(user_id || "");
    const usd = Number(payout || 0);

    // idempotency: only first insert credits
    const result = await db.run(
      "INSERT OR IGNORE INTO survey_events (provider, trans_id, user_id, payout, raw) VALUES (?,?,?,?,?)",
      "adgem", tx, uid, usd, JSON.stringify(req.query)
    );

    if (result.changes === 0) {
      // already processed
      return res.status(200).send("DUPLICATE");
    }

    // credit based on treatment
    const as = classifyProvider("ADGEM");
    const meta = { provider: "adgem", trans_id: tx, offer_id, offer_name };
    if (as === "SURVEY") await creditSurveyUSD(uid, usd, meta);
    else await creditOwnerUSD(uid, usd, meta);

    return res.status(200).send("OK");
  } catch (e) {
    console.error("ADGEM postback error", e);
    return res.status(500).send("ERR");
  }
});

/* =========================
   OTHER PROVIDER HOOKS (simple)
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

/* =========================
   META WHATSAPP / YOUTUBE / RADIO / AI QUIZ
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
  } catch (e) { console.error("WA send error:", e?.response?.data || e.message); res.status(500).json({ error: "whatsapp_send_failed" }); }
});

app.get("/api/youtube/videos", async (_req, res) => {
  try {
    const key = process.env.YOUTUBE_API_KEY, channelId = process.env.YOUTUBE_CHANNEL_ID;
    if (!key || !channelId) return res.json({ items: [] });
    const { data } = await axios.get("https://www.googleapis.com/youtube/v3/search", {
      params: { key, channelId, part: "snippet,id", order: "date", maxResults: 10 }
    });
    res.json(data);
  } catch (e) { console.error("YT error:", e?.response?.data || e.message); res.status(500).json({ error: "youtube_error" }); }
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
   Admin Tools / Diagnostics (secured)
========================= */
// Env snapshot (no secrets)
app.get("/health/env", (_req, res) => {
  res.json({
    paypal_client_id_present: !!process.env.PAYPAL_CLIENT_ID,
    paypal_secret_present: !!process.env.PAYPAL_CLIENT_SECRET, // boolean only
    paypal_api_base: process.env.PAYPAL_API_BASE,
    cpx_secret_present: !!process.env.CPX_POSTBACK_SECRET,
    cpx_alg: process.env.CPX_HASH_ALG || "sha1",
    cpx_format: process.env.CPX_HASH_FORMAT || "secret+trans",
    app_base: process.env.APP_BASE_URL || "",
  });
});

// Compute CPX hash for a trans_id (requires ADMIN_SECRET)
app.get("/api/tools/hash/cpx", (req, res) => {
  if (!requireAdmin(req, res)) return;
  const trans_id = String(req.query.trans_id || "");
  const secret = process.env.CPX_POSTBACK_SECRET || "";
  if (!secret) return res.status(400).json({ error: "missing_secret" });
  const hash = computeCpxHash(secret, trans_id);
  res.json({ trans_id, hash, alg: process.env.CPX_HASH_ALG || "sha1", format: process.env.CPX_HASH_FORMAT || "secret+trans" });
});

/* =========================
   ROOT
========================= */
app.get("/health", (_req, res) => res.send("ok"));
app.get("/", (_req, res) => res.sendFile(path.join(__dirname, "../frontend/index.html")));
app.get("/admin.html", (_req, res) => res.sendFile(path.join(__dirname, "../frontend/admin.html"))); // admin test UI

const PORT = Number(process.env.PORT || 8081);
initDb().then(() =>
  app.listen(PORT, () => console.log("EngageHubCoin running on http://localhost:" + PORT))
);
