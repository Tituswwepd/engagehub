// backend/server.js
import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import axios from "axios";
import sqlite3 from "sqlite3";
import { promisify } from "util";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import nodemailer from "nodemailer";

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
   DB INIT (sqlite3 only)
========================= */
let db;
let dbGet, dbAll, dbRun;

async function initDb() {
  sqlite3.verbose();
  db = new sqlite3.Database(process.env.DB_FILE || "./data.sqlite");
  // Promisified helpers
  dbGet = promisify(db.get.bind(db));
  dbAll = promisify(db.all.bind(db));
  dbRun = (sql, params = []) =>
    new Promise((resolve, reject) => {
      db.run(sql, params, function (err) {
        if (err) reject(err);
        else resolve(this);
      });
    });

  await dbRun(`
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,              -- we use email as id
      email TEXT UNIQUE,
      password_hash TEXT,
      name TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS wallets (
      user_id TEXT PRIMARY KEY,
      total_usd REAL DEFAULT 0,              -- owner-visible accounting (includes everything)
      survey_usd_total REAL DEFAULT 0,       -- lifetime survey credits
      survey_usd_withdrawn REAL DEFAULT 0,   -- lifetime survey withdrawals
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS ledger (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT,
      type TEXT,           -- survey_credit_usd | owner_credit_usd | deposit_paypal | payout_paypal
      amount REAL,         -- +credit / -debit
      meta TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS withdraw_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT,
      email TEXT,
      amount REAL,
      status TEXT DEFAULT 'pending', -- pending | paid | rejected
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS survey_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      provider TEXT,
      trans_id TEXT,
      user_id TEXT,
      payout REAL,
      raw TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS reset_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT,
      token TEXT,
      expires_at INTEGER
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
      user_id TEXT,             -- our internal user id
      access_token TEXT,
      expires_at INTEGER,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);
}

/* =========================
   HELPERS
========================= */
async function ensureUser(user_id, name = "Guest") {
  const u = await dbGet("SELECT id FROM users WHERE id=?", [user_id]);
  if (!u) await dbRun("INSERT INTO users (id,email,name) VALUES (?,?,?)", [user_id, user_id, name]);
  const w = await dbGet("SELECT user_id FROM wallets WHERE user_id=?", [user_id]);
  if (!w) await dbRun("INSERT INTO wallets (user_id) VALUES (?)", [user_id]);
}

// hidden policy: users only see what's withdrawable; cap is server-side
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
   SECURITY: JWT
========================= */
function signJwt(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || "1h",
  });
}
function authMiddleware(req, res, next) {
  const auth = req.headers["authorization"];
  if (!auth) return res.status(401).json({ error: "no_token" });
  const token = auth.split(" ")[1];
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "invalid_token" });
  }
}

/* =========================
   AUTH: REGISTER / LOGIN
========================= */
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "missing_fields" });
    const hash = await bcrypt.hash(String(password), 10);
    await dbRun("INSERT INTO users (id,email,password_hash,name) VALUES (?,?,?,?)", [
      email.toLowerCase(), email.toLowerCase(), hash, "User",
    ]);
    await ensureUser(email.toLowerCase());
    const token = signJwt({ id: email.toLowerCase(), email: email.toLowerCase() });
    res.json({ token });
  } catch (e) {
    res.status(400).json({ error: "email_in_use" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const user = await dbGet("SELECT * FROM users WHERE email=?", [String(email).toLowerCase()]);
    if (!user) return res.status(400).json({ error: "invalid_credentials" });
    const ok = await bcrypt.compare(String(password), user.password_hash || "");
    if (!ok) return res.status(400).json({ error: "invalid_credentials" });
    const token = signJwt({ id: user.id, email: user.email });
    res.json({ token });
  } catch {
    res.status(500).json({ error: "login_failed" });
  }
});

/* =========================
   PASSWORD RESET (SMTP)
========================= */
const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: String(process.env.SMTP_SECURE || "false") === "true",
  auth: (process.env.SMTP_USER && process.env.SMTP_PASS)
    ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
    : undefined,
});

app.post("/api/auth/forgot", async (req, res) => {
  try {
    const email = String(req.body?.email || "").toLowerCase();
    if (!email) return res.status(400).json({ error: "missing_email" });
    const user = await dbGet("SELECT id FROM users WHERE email=?", [email]);
    // Always respond ok (avoid enumeration)
    if (!user) return res.json({ ok: true });

    const token = Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
    const ttlMs = Number(process.env.RESET_TOKEN_MIN || 30) * 60 * 1000;
    const expiresAt = Date.now() + ttlMs;

    await dbRun("DELETE FROM reset_tokens WHERE email=?", [email]); // one active token per email
    await dbRun("INSERT INTO reset_tokens (email, token, expires_at) VALUES (?,?,?)", [email, token, expiresAt]);

    const base = process.env.APP_BASE_URL || `http://localhost:${process.env.PORT || 8080}`;
    const link = `${base}/reset.html?token=${encodeURIComponent(token)}&email=${encodeURIComponent(email)}`;

    if (process.env.SMTP_HOST) {
      await mailer.sendMail({
        from: process.env.SMTP_FROM || "no-reply@example.com",
        to: email,
        subject: "Password Reset - EngageHubCoin",
        html: `<p>We received a request to reset your password.</p>
               <p><a href="${link}" target="_blank" rel="noopener">Click here to reset your password</a></p>
               <p>This link expires in ${process.env.RESET_TOKEN_MIN || 30} minutes.</p>`,
      });
    }
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.json({ ok: true });
  }
});

app.post("/api/auth/reset", async (req, res) => {
  try {
    const { email, token, password } = req.body || {};
    const row = await dbGet("SELECT * FROM reset_tokens WHERE email=? AND token=?", [
      String(email).toLowerCase(),
      String(token),
    ]);
    if (!row) return res.status(400).json({ error: "invalid_token" });
    if (Date.now() > Number(row.expires_at)) return res.status(400).json({ error: "expired_token" });

    const hash = await bcrypt.hash(String(password), 10);
    await dbRun("UPDATE users SET password_hash=? WHERE email=?", [hash, String(email).toLowerCase()]);
    await dbRun("DELETE FROM reset_tokens WHERE email=?", [String(email).toLowerCase()]);
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
   WALLET (JWT)
========================= */
app.get("/api/wallet", authMiddleware, async (req, res) => {
  await ensureUser(req.user.id);
  const w = await dbGet("SELECT * FROM wallets WHERE user_id=?", [req.user.id]);
  const withdrawable = withdrawableFromWallet(w);
  res.json({
    user_id: req.user.id,
    available_to_withdraw_usd: Number(withdrawable.toFixed(2)),
  });
});

/* =========================
   WITHDRAW REQUEST (JWT)
========================= */
app.post("/api/withdraw/request", authMiddleware, async (req, res) => {
  try {
    const { email, amount_usd } = req.body || {};
    if (!email || !amount_usd) return res.status(400).json({ error: "missing params" });

    const w = await dbGet("SELECT * FROM wallets WHERE user_id=?", [req.user.id]);
    const avail = withdrawableFromWallet(w);
    const amt = Number(amount_usd);

    if (amt < Number(process.env.MIN_WITHDRAW_USD || "0"))
      return res.status(400).json({ error: "below_minimum" });
    if (amt > avail + 1e-9)
      return res.status(400).json({ error: "exceeds_available" });

    await dbRun(
      "INSERT INTO withdraw_requests (user_id,email,amount) VALUES (?,?,?)",
      [req.user.id, email, amt]
    );
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "request_failed" });
  }
});

/* =========================
   SURVEY/OFFER POSTBACKS
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
  } catch { res.status(500).send("ERR"); }
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
  } catch { res.status(500).send("ERR"); }
});

app.get("/webhooks/adgem", async (req, res) => {
  try {
    const { user_id, trans_id, payout, secret } = req.query;
    if (secret !== process.env.ADGEM_POSTBACK_SECRET)
      return res.status(403).send("bad secret");
    const usd = Number(payout || 0);
    const as = classifyProvider("ADGEM");
    if (as === "SURVEY") await creditSurveyUSD(user_id, usd, { provider: "adgem", trans_id });
    else await creditOwnerUSD(user_id, usd, { provider: "adgem", trans_id });
    await dbRun(
      "INSERT INTO survey_events (provider, trans_id, user_id, payout, raw) VALUES (?,?,?,?,?)",
      ["adgem", trans_id, user_id, usd, JSON.stringify(req.query)]
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
    await dbRun(
      "INSERT INTO survey_events (provider, trans_id, user_id, payout, raw) VALUES (?,?,?,?,?)",
      ["tapjoy", id, user_id, usd, JSON.stringify(req.query)]
    );
    res.send("OK");
  } catch { res.status(500).send("ERR"); }
});

/* =========================
   PAYPAL DEPOSITS (Checkout)
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

app.post("/api/paypal/deposit/create", authMiddleware, async (req, res) => {
  try {
    const { amount_usd } = req.body || {};
    if (!amount_usd) return res.status(400).json({ error: "missing params" });

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
  } catch { res.status(500).json({ error: "create_order_failed" }); }
});

app.post("/api/paypal/deposit/capture", authMiddleware, async (req, res) => {
  try {
    const { order_id } = req.body || {};
    if (!order_id) return res.status(400).json({ error: "missing params" });

    const token = await paypalToken();
    const base = process.env.PAYPAL_API_BASE || "https://api-m.paypal.com";
    const { data } = await axios.post(
      base + `/v2/checkout/orders/${order_id}/capture`,
      {},
      { headers: { Authorization: "Bearer " + token } }
    );

    const captures = data?.purchase_units?.[0]?.payments?.captures || [];
    let total = 0;
    for (const c of captures) total += Number(c.amount?.value || 0);

    // deposits are owner funds (not withdrawable)
    await ensureUser(req.user.id);
    await dbRun(
      "UPDATE wallets SET total_usd = total_usd + ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
      [total, req.user.id]
    );
    await dbRun(
      "INSERT INTO ledger (user_id, type, amount, meta) VALUES (?,?,?,?)",
      [req.user.id, "deposit_paypal", total, JSON.stringify({ order_id })]
    );

    res.json({ ok: true, captured_usd: total });
  } catch { res.status(500).json({ error: "capture_failed" }); }
});

/* =========================
   ADMIN ENDPOINTS
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
  const ledger = await dbAll("SELECT * FROM ledger WHERE user_id=? ORDER BY id DESC LIMIT 200", [user_id]);
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
    if (!r || r.status !== "pending")
      return res.status(400).json({ error: "invalid_request" });

    const w = await dbGet("SELECT * FROM wallets WHERE user_id=?", [r.user_id]);
    const avail = withdrawableFromWallet(w);
    if (r.amount > avail + 1e-9)
      return res.status(400).json({ error: "exceeds_available" });

    const token = await paypalToken();
    const base = process.env.PAYPAL_API_BASE || "https://api-m.paypal.com";
    const batch = {
      sender_batch_header: { email_subject: "Your EngageHubCoin Payout" },
      items: [
        {
          recipient_type: "EMAIL",
          amount: { value: String(Number(r.amount).toFixed(2)), currency: "USD" },
          receiver: r.email,
          note: "Payout",
          sender_item_id: String(r.id),
        },
      ],
    };
    const { data } = await axios.post(base + "/v1/payments/payouts", batch, {
      headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
    });

    await dbRun(
      "UPDATE wallets SET survey_usd_withdrawn = survey_usd_withdrawn + ?, total_usd = total_usd - ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
      [r.amount, r.amount, r.user_id]
    );
    await dbRun("UPDATE withdraw_requests SET status='paid' WHERE id=?", [r.id]);
    await dbRun(
      "INSERT INTO ledger (user_id, type, amount, meta) VALUES (?,?,?,?)",
      [r.user_id, "payout_paypal", -r.amount, JSON.stringify({ request_id: r.id, batch_meta: data?.batch_header })]
    );

    res.json({ ok: true, data });
  } catch { res.status(500).json({ error: "payout_failed" }); }
});

/* =========================
   WHATSAPP (Meta) WEBHOOKS + SEND
========================= */
app.get("/webhooks/whatsapp", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];
  if (mode === "subscribe" && token === process.env.META_VERIFY_TOKEN) return res.status(200).send(challenge);
  res.sendStatus(403);
});

app.post("/webhooks/whatsapp", async (_req, res) => {
  res.sendStatus(200);
});

app.post("/api/whatsapp/send", authMiddleware, async (req, res) => {
  try {
    const token = process.env.META_ACCESS_TOKEN;
    const phoneId = process.env.WHATSAPP_PHONE_NUMBER_ID;
    const { to, text } = req.body || {};
    if (!token || !phoneId) return res.status(400).json({ error: "missing_whatsapp_config" });
    if (!to || !text) return res.status(400).json({ error: "missing_params" });

    const url = `https://graph.facebook.com/v20.0/${phoneId}/messages`;
    const payload = { messaging_product: "whatsapp", to, type: "text", text: { body: text } };
    const { data } = await axios.post(url, payload, {
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }
    });

    res.json({ ok: true, data });
  } catch {
    res.status(500).json({ error: "whatsapp_send_failed" });
  }
});

/* =========================
   TIKTOK OAUTH (skeleton)
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
    const { data } = await axios.post("https://open.tiktokapis.com/v2/oauth/token/", {
      client_key: process.env.TIKTOK_CLIENT_KEY,
      client_secret: process.env.TIKTOK_CLIENT_SECRET,
      code,
      grant_type: "authorization_code",
      redirect_uri: process.env.TIKTOK_REDIRECT_URI
    }, { headers: { "Content-Type": "application/json" } });

    const { access_token, refresh_token, expires_in } = data.data || {};
    const user_id = "tiktok:" + Date.now(); // map to your app user after fetching open_id
    await ensureUser(user_id, "TikTok User");
    const expires_at = Math.floor(Date.now()/1000) + Number(expires_in||0);
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
   FACEBOOK OAUTH (Login)
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
    a const appSecret = process.env.FB_APP_SECRET;
    const redirect = process.env.FB_REDIRECT_URI;

    const tokenResp = await axios.get("https://graph.facebook.com/v19.0/oauth/access_token", {
      params: { client_id: appId, redirect_uri: redirect, client_secret: appSecret, code }
    });

    const access_token = tokenResp.data.access_token;
    const meResp = await axios.get("https://graph.facebook.com/v19.0/me", {
      params: { access_token, fields: "id,name" },
    });

    const fb_user_id = meResp.data.id;
    const name = meResp.data.name || "Facebook User";
    const user_id = "facebook:" + fb_user_id;

    await ensureUser(user_id, name);
    const expires_at = Math.floor(Date.now() / 1000) + 60 * 60 * 2; // placeholder
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
   YOUTUBE FEED
========================= */
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

/* =========================
   RADIO SEARCH (Radio Browser)
========================= */
app.get("/api/radio/search", async (req, res) => {
  try {
    const q = String(req.query.q || "kenya").slice(0, 60);
    const { data } = await axios.get("https://de1.api.radio-browser.info/json/stations/search", {
      params: { name: q, limit: 20, hidebroken: true, order: "clickcount", reverse: true }
    });
    const items = (data || []).map(s => ({
      name: s.name, country: s.country, codec: s.codec, bitrate: s.bitrate,
      url: s.url_resolved || s.url, homepage: s.homepage
    }));
    res.json({ items });
  } catch {
    res.status(500).json({ items: [] });
  }
});

/* =========================
   ROOT
========================= */
app.get("/health", (_req, res) => res.send("ok"));
app.get("/", (_req, res) =>
  res.sendFile(path.join(__dirname, "../frontend/index.html"))
);

const PORT = Number(process.env.PORT || 8080);
initDb().then(() =>
  app.listen(PORT, () => console.log("EngageHubCoin running on http://localhost:" + PORT))
);
