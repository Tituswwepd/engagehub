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
const app = express(); app.use(cors()); app.use(bodyParser.json()); app.use(express.static(path.join(__dirname, "../frontend")));
let db;
async function initDb(){
  db = await sqliteOpen({ filename: process.env.DB_FILE || "./data.sqlite", driver: sqlite3.Database });
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS wallets (user_id TEXT PRIMARY KEY, total_usd REAL DEFAULT 0, survey_usd_total REAL DEFAULT 0, survey_usd_withdrawn REAL DEFAULT 0, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS ledger (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, type TEXT, amount REAL, meta TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS withdraw_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, email TEXT, amount REAL, status TEXT DEFAULT 'pending', created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
  `);
}
async function ensureUser(id){const u=await db.get("SELECT id FROM users WHERE id=?", id); if(!u){await db.run("INSERT INTO users (id,name) VALUES (?,?)", id, "Guest");} const w=await db.get("SELECT user_id FROM wallets WHERE user_id=?", id); if(!w){await db.run("INSERT INTO wallets (user_id) VALUES (?)", id);}}
function withdrawable(w){const cap=0.5*(w.survey_usd_total||0); const used=(w.survey_usd_withdrawn||0); return Math.max(0, cap-used);}
app.get("/api/wallet/:user_id", async (req,res)=>{await ensureUser(req.params.user_id); const w=await db.get("SELECT * FROM wallets WHERE user_id=?", req.params.user_id); res.json({ user_id:req.params.user_id, available_to_withdraw_usd: Number(withdrawable(w).toFixed(2)) });});
app.post("/api/withdraw/request", async (req,res)=>{const { user_id, email, amount_usd } = req.body||{}; if(!user_id||!email||!amount_usd) return res.status(400).json({error:"missing params"}); await ensureUser(user_id); const w=await db.get("SELECT * FROM wallets WHERE user_id=?", user_id); const avail=withdrawable(w); if(Number(amount_usd) > avail) return res.status(400).json({error:"exceeds_available"}); await db.run("INSERT INTO withdraw_requests (user_id,email,amount) VALUES (?,?,?)", user_id,email,Number(amount_usd)); res.json({ok:true});});
app.get("/", (_req,res)=> res.sendFile(path.join(__dirname,"../frontend/index.html")));
const PORT = Number(process.env.PORT||8080); initDb().then(()=> app.listen(PORT, ()=> console.log("Colorful build on http://localhost:"+PORT)));