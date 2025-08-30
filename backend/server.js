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

// serve frontend
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
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
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
  `);
}

async function ensureUser(user_id, name = "Guest") {
  const u = await db.get("SELECT id FROM users WHERE id=?", user_id);
  if (!u) await db.run("INSERT INTO users (id,name) VALUES (?,?)", user_id, name);
  const w = await db.get("SELECT user_id FROM wallets WHERE user_id=?", user_id);
  if (!w) await db.run("INSERT INTO wallets (user_id) VALUES (?)", user_id);
}

// hidden policy: users only see what's withdrawable; cap is server-side
function withdrawableFromWallet(w) {
  const cap = 0.5 * Number(w.survey_usd_total || 0);
  const used = Number(w.survey_usd_withdrawn || 0);
  return Math.max(0, cap - used);
}

async function creditSurveyUSD(user_id, usd, meta) {
  await ensureUser(user_id);
  await db.run(
    "UPDATE wallets SET survey_usd_total = survey_usd_total + ?, total_usd = total_usd + ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
    usd,
    usd,
    user_id
  );
  await db.run(
    "INSERT INTO ledger (user_id, type, amount, meta) VALUES (?,?,?,?)",
    user_id,
    "survey_credit_usd",
    usd,
    JSON.stringify(meta || {})
  );
}

async function creditOwnerUSD(user_id, usd, meta) {
  await ensureUser(user_id);
  await db.run(
    "UPDATE wallets SET total_usd = total_usd + ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
    usd,
    user_id
  );
  await db.run(
    "INSERT INTO ledger (user_id, type, amount, meta) VALUES (?,?,?,?)",
    user_id,
    "owner_credit_usd",
    usd,
    JSON.stringify(meta || {})
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
   PUBLIC CONFIG (safe)
========================= */
app.get("/api/config/public", (_req, res) => {
  res.json({
    PAYPAL_CLIENT_ID: process.env.PAYPAL_CLIENT_ID || "",
  });
});

/* =========================
   USER-FACING WALLET & WITHDRAW REQUESTS
========================= */
app.get("/api/wallet/:user_id", async (req, res) => {
  const { user_id } = req.params;
  await ensureUser(user_id);
  const w = await db.get("SELECT * FROM wallets WHERE user_id=?", user_id);
  const withdrawable = withdrawableFromWallet(w);
  res.json({
    user_id,
    available_to_withdraw_usd: Number(withdrawable.toFixed(2)),
  });
});

app.post("/api/withdraw/request", async (req, res) => {
  try {
    const { user_id, email, amount_usd } = req.body || {};
    if (!user_id || !email || !amount_usd)
      return res.status(400).json({ error: "missing params" });

    await ensureUser(user_id);
    const w = await db.get("SELECT * FROM wallets WHERE user_id=?", user_id);
    const avail = withdrawableFromWallet(w);
    const amt = Number(amount_usd);

    if (amt < Number(process.env.MIN_WITHDRAW_USD || "0"))
      return res.status(400).json({ error: "below_minimum" });
    if (amt > avail + 1e-9)
      return res.status(400).json({ error: "exceeds_available" });

    await db.run(
      "INSERT INTO withdraw_requests (user_id,email,amount) VALUES (?,?,?)",
      user_id,
      email,
      amt
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: "request_failed" });
  }
});

/* =========================
   SURVEY/OFFER POSTBACKS (examples)
========================= */
app.get("/webhooks/cpx", async (req, res) => {
  try {
    const { user_id, trans_id, payout } = req.query;
    const usd = Number(payout || 0);
    const as = classifyProvider("CPX");
    if (as === "SURVEY") await creditSurveyUSD(user_id, usd, { provider: "cpx", trans_id });
    else await creditOwnerUSD(user_id, usd, { provider: "cpx", trans_id });
    await db.run(
      "INSERT INTO survey_events (provider, trans_id, user_id, payout, raw) VALUES (?,?,?,?,?)",
      "cpx",
      trans_id,
      user_id,
      usd,
      JSON.stringify(req.query)
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
    await db.run(
      "INSERT INTO survey_events (provider, trans_id, user_id, payout, raw) VALUES (?,?,?,?,?)",
      "bitlabs",
      transaction_id,
      user_id,
      usd,
      JSON.stringify(req.query)
    );
    res.send("OK");
  } catch {
    res.status(500).send("ERR");
  }
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
    await db.run(
      "INSERT INTO survey_events (provider, trans_id, user_id, payout, raw) VALUES (?,?,?,?,?)",
      "adgem",
      trans_id,
      user_id,
      usd,
      JSON.stringify(req.query)
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
    await db.run(
      "INSERT INTO survey_events (provider, trans_id, user_id, payout, raw) VALUES (?,?,?,?,?)",
      "tapjoy",
      id,
      user_id,
      usd,
      JSON.stringify(req.query)
    );
    res.send("OK");
  } catch {
    res.status(500).send("ERR");
  }
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

app.post("/api/paypal/deposit/create", async (req, res) => {
  try {
    const { user_id, amount_usd } = req.body || {};
    if (!user_id || !amount_usd)
      return res.status(400).json({ error: "missing params" });

    const token = await paypalToken();
    const base = process.env.PAYPAL_API_BASE || "https://api-m.paypal.com";
    const { data } = await axios.post(
      base + "/v2/checkout/orders",
      {
        intent: "CAPTURE",
        purchase_units: [
          {
            amount: {
              currency_code: "USD",
              value: String(Number(amount_usd).toFixed(2)),
            },
          },
        ],
      },
      { headers: { Authorization: "Bearer " + token } }
    );
    res.json(data);
  } catch {
    res.status(500).json({ error: "create_order_failed" });
  }
});

app.post("/api/paypal/deposit/capture", async (req, res) => {
  try {
    const { user_id, order_id } = req.body || {};
    if (!user_id || !order_id)
      return res.status(400).json({ error: "missing params" });

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
    await ensureUser(user_id);
    await db.run(
      "UPDATE wallets SET total_usd = total_usd + ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
      total,
      user_id
    );
    await db.run(
      "INSERT INTO ledger (user_id, type, amount, meta) VALUES (?,?,?,?)",
      user_id,
      "deposit_paypal",
      total,
      JSON.stringify({ order_id })
    );

    res.json({ ok: true, captured_usd: total });
  } catch {
    res.status(500).json({ error: "capture_failed" });
  }
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
  const w = await db.get("SELECT * FROM wallets WHERE user_id=?", user_id);
  const ledger = await db.all(
    "SELECT * FROM ledger WHERE user_id=? ORDER BY id DESC LIMIT 100",
    user_id
  );
  res.json({ wallet: w, withdrawable_usd: withdrawableFromWallet(w), ledger });
});

app.get("/api/admin/withdraw/requests", async (req, res) => {
  if (!requireAdmin(req, res)) return;
  const rows = await db.all(
    "SELECT * FROM withdraw_requests WHERE status='pending' ORDER BY id ASC"
  );
  res.json({ items: rows });
});

app.post("/api/admin/payouts/paypal", async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    const { request_id } = req.body || {};
    const r = await db.get("SELECT * FROM withdraw_requests WHERE id=?", request_id);
    if (!r || r.status !== "pending")
      return res.status(400).json({ error: "invalid_request" });

    const w = await db.get("SELECT * FROM wallets WHERE user_id=?", r.user_id);
    const avail = withdrawableFromWallet(w);
    if (r.amount > avail + 1e-9)
      return res.status(400).json({ error: "exceeds_available" });

    const token = await paypalToken();
    const base = process.env.PAYPAL_API_BASE || "https://api-m.paypal.com";
    const batch = {
      sender_batch_header: { email_subject: "Your EngageHub Payout" },
      items: [
        {
          recipient_type: "EMAIL",
          amount: { value: String(r.amount.toFixed(2)), currency: "USD" },
          receiver: r.email,
          note: "Payout",
          sender_item_id: String(r.id),
        },
      ],
    };
    const { data } = await axios.post(base + "/v1/payments/payouts", batch, {
      headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
    });

    await db.run(
      "UPDATE wallets SET survey_usd_withdrawn = survey_usd_withdrawn + ?, total_usd = total_usd - ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
      r.amount,
      r.amount,
      r.user_id
    );
    await db.run("UPDATE withdraw_requests SET status='paid' WHERE id=?", r.id);
    await db.run(
      "INSERT INTO ledger (user_id, type, amount, meta) VALUES (?,?,?,?)",
      r.user_id,
      "payout_paypal",
      -r.amount,
      JSON.stringify({ request_id: r.id, batch_id: data?.batch_header?.payout_batch_id })
    );

    res.json({ ok: true, data });
  } catch {
    res.status(500).json({ error: "payout_failed" });
  }
});

/* =========================
   ROOT
========================= */
app.get("/", (_req, res) =>
  res.sendFile(path.join(__dirname, "../frontend/index.html"))
);

const PORT = Number(process.env.PORT || 8080);
initDb().then(() =>
  app.listen(PORT, () => console.log("EngageHub running on http://localhost:" + PORT))
);
