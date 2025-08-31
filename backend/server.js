// backend/server.js
import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import axios from "axios";
import sqlite3 from "sqlite3";
import { open as sqliteOpen } from "sqlite";

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "../frontend")));

/* =========================
   DB & HELPERS
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
      name TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- OAuth token stores
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

    CREATE TABLE IF NOT EXISTS twitter_tokens (
      tw_user_id TEXT PRIMARY KEY,
      user_id TEXT,
      access_token TEXT,
      token_type TEXT,
      expires_at INTEGER,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS instagram_tokens (
      ig_user_id TEXT PRIMARY KEY,
      user_id TEXT,
      access_token TEXT,
      expires_at INTEGER,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- Data buyers registry
    CREATE TABLE IF NOT EXISTS data_buyers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      homepage TEXT,
      status TEXT DEFAULT 'planned',
      notes TEXT
    );
  `);

  // Seed buyers once (if empty)
  const count = (await db.get(`SELECT COUNT(*) c FROM data_buyers`)).c;
  if (!count) {
    const buyers = [
      ["ClickDealer","https://clickdealer.com"],
      ["AdWork Media","https://www.adworkmedia.com"],
      ["MaxBounty","https://www.maxbounty.com"],
      ["CPAlead","https://www.cpalead.com"],
      ["OfferToro","https://www.offertoro.com"],
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
      ["AdWork Media (slot 2)","https://www.adworkmedia.com"],
      ["AdAction","https://www.adactioninteractive.com"],
    ];
    const stmt = await db.prepare(
      `INSERT INTO data_buyers (name, homepage, status, notes) VALUES (?,?, 'planned','')`
    );
    for (const [name, url] of buyers) await stmt.run(name, url);
    await stmt.finalize();
  }
}

async function ensureUser(user_id, name = "Guest") {
  const u = await db.get("SELECT id FROM users WHERE id=?", user_id);
  if (!u) await db.run("INSERT INTO users (id,name) VALUES (?,?)", user_id, name);
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
    PERSONA_LY: env.PERSONALY_TREATED_AS || "SURVEY",
    AYET: env.AYET_TREATED_AS || "SURVEY",
    KIWIWALL: env.KIWIWALL_TREATED_AS || "SURVEY",
    OFFERDADDY: env.OFFERDADDY_TREATED_AS || "SURVEY",
    WANNADS: env.WANNADS_TREATED_AS || "SURVEY",
    CLICKDEALER: env.CLICKDEALER_TREATED_AS || "OWNER",
    ADWORK: env.ADWORDK_TREATED_AS || "OWNER",
    MAXBOUNTY: env.MAXBOUNTY_TREATED_AS || "OWNER",
    CPALEAD: env.CPALEAD_TREATED_AS || "OWNER",
    CJ: env.CJ_TREATED_AS || "OWNER",
    RAKUTEN: env.RAKUTEN_TREATED_AS || "OWNER",
    IMPACT: env.IMPACT_TREATED_AS || "OWNER",
    FLEXOFFERS: env.FLEXOFFERS_TREATED_AS || "OWNER",
    ADSCEND: env.ADSCEND_TREATED_AS || "OWNER",
    REVENUEUNIVERSE: env.REVENUEUNIVERSE_TREATED_AS || "OWNER",
    ADGATE: env.ADGATE_TREATED_AS || "OWNER",
    ADACTION: env.ADACTION_TREATED_AS || "OWNER",
  };
  return map[(p || "").toUpperCase().replace(/\./g,"_")] || "OWNER";
}

/* =========================
   PUBLIC CONFIG
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
   USER WALLET
========================= */
app.get("/api/wallet/:user_id", async (req, res) => {
  const { user_id } = req.params;
  await ensureUser(user_id);
  const w = await db.get("SELECT * FROM wallets WHERE user_id=?", user_id);
  res.json({
    user_id,
    available_to_withdraw_usd: Number(withdrawableFromWallet(w).toFixed(2)),
  });
});

app.post("/api/withdraw/request", async (req, res) => {
  try {
    const { user_id, email, amount_usd } = req.body || {};
    if (!user_id || !email || !amount_usd) return res.status(400).json({ error: "missing params" });

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
  } catch { res.status(500).json({ error: "request_failed" }); }
});

/* =========================
   PAYPAL DEPOSITS / PAYOUTS
========================= */
async function paypalToken() {
  const base = process.env.PAYPAL_API_BASE || "https://api-m.paypal.com";
  const id = process.env.PAYPAL_CLIENT_ID;
  const secret = process.env.PAYPAL_CLIENT_SECRET;
  const { data } = await axios.post(
    base + "/v1/oauth2/token",
    "grant_type=client_credentials",
    { auth: { username: id, password: secret }, headers: { "Content-Type": "application/x-www-form-urlencoded" } }
  );
  return data.access_token;
}

app.post("/api/paypal/deposit/create", async (req, res) => {
  try {
    const { user_id, amount_usd } = req.body || {};
    if (!user_id || !amount_usd) return res.status(400).json({ error: "missing params" });

    const token = await paypalToken();
    const base = process.env.PAYPAL_API_BASE || "https://api-m.paypal.com";
    const { data } = await axios.post(
      base + "/v2/checkout/orders",
      { intent: "CAPTURE", purchase_units: [{ amount: { currency_code: "USD", value: String(Number(amount_usd).toFixed(2)) } }] },
      { headers: { Authorization: "Bearer " + token } }
    );
    res.json(data);
  } catch { res.status(500).json({ error: "create_order_failed" }); }
});

app.post("/api/paypal/deposit/capture", async (req, res) => {
  try {
    const { user_id, order_id } = req.body || {};
    if (!user_id || !order_id) return res.status(400).json({ error: "missing params" });

    const token = await paypalToken();
    const base = process.env.PAYPAL_API_BASE || "https://api-m.paypal.com";
    const { data } = await axios.post(base + `/v2/checkout/orders/${order_id}/capture`, {}, { headers: { Authorization: "Bearer " + token } });

    const captures = data?.purchase_units?.[0]?.payments?.captures || [];
    let total = 0;
    for (const c of captures) total += Number(c.amount?.value || 0);

    await ensureUser(user_id);
    await db.run("UPDATE wallets SET total_usd = total_usd + ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?", total, user_id);
    await db.run("INSERT INTO ledger (user_id, type, amount, meta) VALUES (?,?,?,?)", user_id, "deposit_paypal", total, JSON.stringify({ order_id }));

    res.json({ ok: true, captured_usd: total });
  } catch { res.status(500).json({ error: "capture_failed" }); }
});

/* Admin helpers */
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
  const w = await db.get("SELECT * FROM wallets WHERE user_id=?", user_id);
  const ledger = await db.all("SELECT * FROM ledger WHERE user_id=? ORDER BY id DESC LIMIT 200", user_id);
  res.json({ wallet: w, withdrawable_usd: withdrawableFromWallet(w), ledger });
});

app.get("/api/admin/withdraw/requests", async (req, res) => {
  if (!requireAdmin(req, res)) return;
  const rows = await db.all("SELECT * FROM withdraw_requests WHERE status='pending' ORDER BY id ASC");
  res.json({ items: rows });
});

app.post("/api/admin/payouts/paypal", async (req, res) => {
  if (!requireAdmin(req, res)) return;
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
        receiver: r.email, note: "Payout", sender_item_id: String(r.id)
      }],
    };
    const { data } = await axios.post(base + "/v1/payments/payouts", batch, {
      headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
    });

    await db.run(
      "UPDATE wallets SET survey_usd_withdrawn = survey_usd_withdrawn + ?, total_usd = total_usd - ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
      r.amount, r.amount, r.user_id
    );
    await db.run("UPDATE withdraw_requests SET status='paid' WHERE id=?", r.id);
    await db.run(
      "INSERT INTO ledger (user_id, type, amount, meta) VALUES (?,?,?,?)",
      r.user_id, "payout_paypal", -r.amount, JSON.stringify({ request_id: r.id, batch_id: data?.batch_header?.payout_batch_id })
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
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }
    });
    res.json({ ok: true, data });
  } catch { res.status(500).json({ error: "whatsapp_send_failed" }); }
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
    const user_id = "tiktok:" + Date.now();
    await ensureUser(user_id, "TikTok User");
    const expires_at = Math.floor(Date.now()/1000) + Number(expires_in||0);
    await db.run(
      "INSERT OR REPLACE INTO tiktok_tokens (user_id, access_token, refresh_token, expires_at) VALUES (?,?,?,?)",
      user_id, access_token, refresh_token, expires_at
    );
    res.send("<pre>TikTok connected. You can close this window.</pre>");
  } catch { res.status(500).send("tiktok_auth_error"); }
});

/* =========================
   FACEBOOK + INSTAGRAM OAUTH
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
    const expires_at = Math.floor(Date.now() / 1000) + 7200;
    await db.run(
      "INSERT OR REPLACE INTO facebook_tokens (fb_user_id, user_id, access_token, expires_at) VALUES (?,?,?,?)",
      fb_user_id, user_id, access_token, expires_at
    );

    res.send(`<pre>Facebook connected for ${name}. You can close this window.</pre>`);
  } catch { res.status(500).send("facebook_auth_error"); }
});

/* Instagram (via the same Meta App) */
app.get("/auth/instagram", (req, res) => {
  const appId = process.env.FB_APP_ID; // same app
  const redirect = encodeURIComponent(process.env.IG_REDIRECT_URI || process.env.FB_REDIRECT_URI || "");
  const state = "ig-" + Date.now();
  const scope = encodeURIComponent("instagram_basic");
  const url = `https://www.facebook.com/v19.0/dialog/oauth?client_id=${appId}&redirect_uri=${redirect}&state=${state}&response_type=code&scope=${scope}`;
  res.redirect(url);
});

app.get("/auth/instagram/callback", async (req, res) => {
  try {
    const { code } = req.query;
    const appId = process.env.FB_APP_ID;
    const appSecret = process.env.FB_APP_SECRET;
    const redirect = process.env.IG_REDIRECT_URI || process.env.FB_REDIRECT_URI;

    const tokenResp = await axios.get("https://graph.facebook.com/v19.0/oauth/access_token", {
      params: { client_id: appId, redirect_uri: redirect, client_secret: appSecret, code }
    });
    const access_token = tokenResp.data.access_token;

    // For brevity we store token without exchanging for IG long-lived token.
    const ig_user_id = "ig:" + Date.now();
    const user_id = "instagram:" + ig_user_id;
    await ensureUser(user_id, "Instagram User");
    const expires_at = Math.floor(Date.now()/1000) + 7200;
    await db.run(
      "INSERT OR REPLACE INTO instagram_tokens (ig_user_id, user_id, access_token, expires_at) VALUES (?,?,?,?)",
      ig_user_id, user_id, access_token, expires_at
    );
    res.send("<pre>Instagram connected. You can close this window.</pre>");
  } catch { res.status(500).send("instagram_auth_error"); }
});

/* =========================
   TWITTER (X) OAUTH (skeleton)
========================= */
app.get("/auth/twitter", (req, res) => {
  // OAuth 2.0 authorization code (no PKCE here; for production, add PKCE).
  const clientId = process.env.TWITTER_CLIENT_ID;
  const redirect = encodeURIComponent(process.env.TWITTER_REDIRECT_URI || "");
  const scope = encodeURIComponent("tweet.read users.read offline.access");
  const state = "tw-" + Date.now();
  const url = `https://twitter.com/i/oauth2/authorize?response_type=code&client_id=${clientId}&redirect_uri=${redirect}&scope=${scope}&state=${state}&code_challenge=challenge&code_challenge_method=plain`;
  res.redirect(url);
});

app.get("/auth/twitter/callback", async (req, res) => {
  try {
    const { code } = req.query;
    const resp = await axios.post("https://api.twitter.com/2/oauth2/token",
      new URLSearchParams({
        code: code,
        grant_type: "authorization_code",
        client_id: process.env.TWITTER_CLIENT_ID,
        redirect_uri: process.env.TWITTER_REDIRECT_URI,
        code_verifier: "challenge"
      }).toString(),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
    );

    const { access_token, token_type, expires_in } = resp.data || {};
    const tw_user_id = "tw:" + Date.now();
    const user_id = "twitter:" + tw_user_id;
    await ensureUser(user_id, "Twitter User");
    const expires_at = Math.floor(Date.now()/1000) + Number(expires_in||7200);
    await db.run(
      "INSERT OR REPLACE INTO twitter_tokens (tw_user_id, user_id, access_token, token_type, expires_at) VALUES (?,?,?,?,?)",
      tw_user_id, user_id, access_token, token_type, expires_at
    );
    res.send("<pre>Twitter connected. You can close this window.</pre>");
  } catch { res.status(500).send("twitter_auth_error"); }
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
   RADIO SEARCH (Radio Browser API)
========================= */
app.get("/api/radio/search", async (req, res) => {
  try {
    const q = req.query.q || "kenya";
    const url = `https://de1.api.radio-browser.info/json/stations/search?name=${encodeURIComponent(q)}&limit=50&hidebroken=true`;
    const { data } = await axios.get(url, { timeout: 12000 });
    // Return only useful fields
    const items = (data || []).slice(0, 20).map(s => ({
      name: s.name, country: s.country, codec: s.codec, bitrate: s.bitrate,
      favicon: s.favicon, homepage: s.homepage, url: s.url
    }));
    res.json({ items });
  } catch { res.status(500).json({ error: "radio_search_failed" }); }
});

/* =========================
   AI QUIZ (OpenAI optional)
========================= */
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
      { q: "Creator of JavaScript?", options:["Brendan Eich","Guido Rossum","Linus Torvalds","James Gosling"], answer:0 }
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
   GENERIC SURVEY / DATA-BUYER WEBHOOKS
========================= */
function readAmount(q) {
  // Attempt to read common fields
  const keys = ["payout","amount","usd","reward","value","price"];
  for (const k of keys) if (q[k] != null) return Number(q[k]);
  return 0;
}
async function handleNetworkHit(providerKey, req, res, secretEnvKey) {
  try {
    const secretNeedle = process.env[secretEnvKey];
    if (secretNeedle) {
      const cand = req.query.secret || req.query.token || req.query.sig || req.query.signature;
      if (cand !== secretNeedle) return res.status(403).send("bad secret");
    }
    const user_id = req.query.user_id || req.query.uid || req.query.sub || req.query.user || "guest";
    const trans_id = req.query.trans_id || req.query.transaction_id || req.query.id || String(Date.now());
    const usd = Number(readAmount(req.query) || 0);

    const as = classifyProvider(providerKey);
    if (as === "SURVEY") await creditSurveyUSD(user_id, usd, { provider: providerKey, trans_id });
    else await creditOwnerUSD(user_id, usd, { provider: providerKey, trans_id });

    await db.run(
      "INSERT INTO survey_events (provider, trans_id, user_id, payout, raw) VALUES (?,?,?,?,?)",
      providerKey.toLowerCase(), trans_id, user_id, usd, JSON.stringify(req.query)
    );
    res.send("OK");
  } catch (e) {
    res.status(500).send("ERR");
  }
}

// Existing ones:
app.get("/webhooks/cpx", (req,res)=>handleNetworkHit("CPX", req, res, "CPX_POSTBACK_SECRET"));
app.get("/webhooks/bitlabs", (req,res)=>handleNetworkHit("BITLABS", req, res, "BITLABS_POSTBACK_SECRET"));
app.get("/webhooks/adgem", (req,res)=>handleNetworkHit("ADGEM", req, res, "ADGEM_POSTBACK_SECRET"));
app.get("/webhooks/tapjoy", (req,res)=>handleNetworkHit("TAPJOY", req, res, "TAPJOY_POSTBACK_SECRET"));

// New providers / buyers:
app.get("/webhooks/offertoro", (req,res)=>handleNetworkHit("OFFERTORO", req, res, "OFFERTORO_SECRET"));
app.get("/webhooks/persona.ly", (req,res)=>handleNetworkHit("PERSONA.LY", req, res, "PERSONALY_SECRET"));
app.get("/webhooks/ayet", (req,res)=>handleNetworkHit("AYET", req, res, "AYET_SECRET"));
app.get("/webhooks/kiwiwall", (req,res)=>handleNetworkHit("KIWIWALL", req, res, "KIWIWALL_SECRET"));
app.get("/webhooks/offerdaddy", (req,res)=>handleNetworkHit("OFFERDADDY", req, res, "OFFERDADDY_SECRET"));
app.get("/webhooks/wannads", (req,res)=>handleNetworkHit("WANNADS", req, res, "WANNADS_SECRET"));
app.get("/webhooks/clickdealer", (req,res)=>handleNetworkHit("CLICKDEALER", req, res, "CLICKDEALER_SECRET"));
app.get("/webhooks/adwork", (req,res)=>handleNetworkHit("ADWORK", req, res, "ADWORK_SECRET"));
app.get("/webhooks/maxbounty", (req,res)=>handleNetworkHit("MAXBOUNTY", req, res, "MAXBOUNTY_SECRET"));
app.get("/webhooks/cpalead", (req,res)=>handleNetworkHit("CPALEAD", req, res, "CPALEAD_SECRET"));
app.get("/webhooks/cj", (req,res)=>handleNetworkHit("CJ", req, res, "CJ_SECRET"));
app.get("/webhooks/rakuten", (req,res)=>handleNetworkHit("RAKUTEN", req, res, "RAKUTEN_SECRET"));
app.get("/webhooks/impact", (req,res)=>handleNetworkHit("IMPACT", req, res, "IMPACT_SECRET"));
app.get("/webhooks/flexoffers", (req,res)=>handleNetworkHit("FLEXOFFERS", req, res, "FLEXOFFERS_SECRET"));
app.get("/webhooks/adscend", (req,res)=>handleNetworkHit("ADSCEND", req, res, "ADSCEND_SECRET"));
app.get("/webhooks/revenueuniverse", (req,res)=>handleNetworkHit("REVENUEUNIVERSE", req, res, "REVENUEUNIVERSE_SECRET"));
app.get("/webhooks/adgate", (req,res)=>handleNetworkHit("ADGATE", req, res, "ADGATE_SECRET"));
app.get("/webhooks/adaction", (req,res)=>handleNetworkHit("ADACTION", req, res, "ADACTION_SECRET"));

/* =========================
   DATA BUYERS REGISTRY API
========================= */
app.get("/api/data-buyers", async (_req, res) => {
  const rows = await db.all("SELECT id,name,homepage,status,notes FROM data_buyers ORDER BY id ASC");
  res.json({ items: rows });
});

app.post("/api/admin/data-buyers/update", async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    const { id, status, notes } = req.body || {};
    await db.run("UPDATE data_buyers SET status=?, notes=? WHERE id=?", String(status||"planned"), String(notes||""), Number(id));
    res.json({ ok: true });
  } catch { res.status(500).json({ error: "update_failed" }); }
});

/* =========================
   ROOT / HEALTH
========================= */
app.get("/health", (_req, res) => res.send("ok"));
app.get("/", (_req, res) => res.sendFile(path.join(__dirname, "../frontend/index.html")));

const PORT = Number(process.env.PORT || 8080);
initDb().then(() =>
  app.listen(PORT, () => console.log("EngageHubCoin running on http://localhost:" + PORT))
);
