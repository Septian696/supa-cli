#!/usr/bin/env node
/**
 * Supanova Canton Wallet CLI (Termux friendly) - got-scraping Edition
 * ✅ TLS Fingerprint Spoofing for Privy endpoints
 * ✅ Browser header generation
 * ✅ Fixed: client_id in Privy payload
 */

import fs from "fs";
import path from "path";
import os from "os";
import axios from "axios";
import { gotScraping } from "got-scraping";
import { Command } from "commander";
import dotenv from "dotenv";

dotenv.config();

// -------- CONFIG --------
const PRIVY_BASE = "https://auth.privy.io";
const SUPA_BASE = "https://api.supanova.app";
const X_CANTON_NODE_ID = process.env.X_CANTON_NODE_ID || "mainnet-supa";
const X_SUPA_APP_ID = process.env.X_SUPA_APP_ID || "supa-app-300";
const PRIVY_APP_ID = process.env.PRIVY_APP_ID || "cm338ijv804mhhgvacdxsayxu";
const PRIVY_CLIENT_ID = process.env.PRIVY_CLIENT_ID || "WY5dQwQyixARYCtWLMzJnVKpgX1kt796M1kukgH6U6j2k";
const PRIVY_CAID = process.env.PRIVY_CAID || "2629eb4a-77b9-4152-8bf4-ec36c19ecd20";
const STORE = path.join(os.homedir(), ".supa_canton_token.json");

const BROWSER_FINGERPRINT = {
  browsers: [{ name: "chrome", minVersion: 120, maxVersion: 124 }],
  devices: ["mobile"],
  operatingSystems: ["android"],
  locales: ["en-US", "id-ID"]
};

const getPrivyHeaders = () => ({
  "origin": "https://app.supanova.app",
  "referer": "https://app.supanova.app/",
  "privy-app-id": PRIVY_APP_ID,
  "privy-client-id": PRIVY_CLIENT_ID,
  "privy-caid": PRIVY_CAID,
  "x-privy-app-id": PRIVY_APP_ID,
  "Content-Type": "application/json"
});

// -------- helpers --------
function saveToken(token) {
  fs.writeFileSync(STORE, JSON.stringify({ token }, null, 2), "utf8");
  try { fs.chmodSync(STORE, 0o600); } catch {}  console.log("💾 Token saved locally");
}
function loadToken() {
  if (!fs.existsSync(STORE)) return null;
  try {
    const data = JSON.parse(fs.readFileSync(STORE, "utf8"));
    return data?.token ?? null;
  } catch { return null; }
}
function clearToken() {
  if (fs.existsSync(STORE)) fs.unlinkSync(STORE);
  console.log("🗑️  Local token deleted");
}
function requireToken(cmdOptToken) {
  const t = cmdOptToken || process.env.SUPA_TOKEN || loadToken();
  if (!t) {
    console.error("❌ No token found.");
    console.error("Run:");
    console.error("  node cantonctl.mjs init --email <email>");
    console.error("  node cantonctl.mjs login --email <email> --code <otp>");
    process.exit(1);
  }
  return t;
}
function supaHeaders(token, extra = {}) {
  return {
    Accept: "application/json, text/plain, */*",
    Authorization: `Bearer ${token}`,
    "X-Canton-Node-Id": X_CANTON_NODE_ID,
    "X-Supa-App-Id": X_SUPA_APP_ID,
    ...extra,
  };
}
function fmtNum(n) {
  const x = typeof n === "string" ? Number(n) : n;
  if (Number.isFinite(x)) return x.toString();
  return String(n ?? 0);
}
function clampInt(x, min, max, fallback) {
  const n = Number(x);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.trunc(n)));
}
function handleAxiosError(e, context = "") {
  const status = e?.response?.status;
  const data = e?.response?.data;
  if (status === 401) {
    console.error(`${context}401 Unauthorized: token expired/invalid. Login again (OTP).`);
    process.exit(1);
  }  if (status === 429) {
    console.error(`${context}429 Too Many Requests: rate-limited/cooldown. Try later.`);
    if (data) console.error(JSON.stringify(data, null, 2));
    process.exit(1);
  }
  console.error(`${context}API error ${status ?? ""}`);
  if (data) console.error(JSON.stringify(data, null, 2));
  else console.error(e?.message ?? String(e));
  process.exit(1);
}

// -------- PRIVY AUTH --------
async function privyInit(email) {
  const res = await gotScraping({
    url: `${PRIVY_BASE}/api/v1/passwordless/init`,
    method: "POST",
    json: { email: email, client_id: PRIVY_APP_ID },
    headerGeneratorOptions: BROWSER_FINGERPRINT,
    headers: getPrivyHeaders(),
    responseType: "json",
    timeout: { request: 30000 }
  });
  return res.body;
}
async function privyAuth(email, code) {
  const res = await gotScraping({
    url: `${PRIVY_BASE}/api/v1/passwordless/authenticate`,
    method: "POST",
    json: { email: email, code: code, mode: "login-or-sign-up", client_id: PRIVY_APP_ID },
    headerGeneratorOptions: BROWSER_FINGERPRINT,
    headers: getPrivyHeaders(),
    responseType: "json",
    timeout: { request: 30000 }
  });
  return res.body;
}

// -------- SUPA CANTON API --------
async function supaMe(token) {
  const res = await axios.get(`${SUPA_BASE}/canton/api/me`, { headers: supaHeaders(token), timeout: 30000 });
  return res.data;
}
async function supaBalances(token) {
  const res = await axios.get(`${SUPA_BASE}/canton/api/balances`, { headers: supaHeaders(token), timeout: 30000 });
  return res.data;
}
async function supaTransactions(token, limit = 20) {
  const params = new URLSearchParams();
  params.set("limit", String(limit));
  const res = await axios.get(`${SUPA_BASE}/canton/api/transactions?${params.toString()}`, { headers: supaHeaders(token), timeout: 30000 });  return res.data;
}
async function supaClaimAirdrop(token) {
  const res = await axios.post(`${SUPA_BASE}/canton/api/claim_airdrop`, {}, { headers: supaHeaders(token, { "Content-Type": "application/json" }), timeout: 30000 });
  return res.data;
}

// -------- CLI --------
const program = new Command();
program.name("cantonctl").description("Supanova Canton wallet CLI").version("1.1.0");

program.command("init").description("Send OTP code to email").requiredOption("--email <email>", "email").action(async (opts) => {
  try {
    console.log("📤 Requesting OTP...");
    const out = await privyInit(opts.email);
    if (out?.success) {
      console.log("✅ OTP requested! Check your email.");
      console.log(`Next: node cantonctl.mjs login --email ${opts.email} --code 123456`);
    } else { console.error("❌ Failed:", out); process.exit(1); }
  } catch (e) {
    if (e.response) console.error(`❌ Error ${e.response.statusCode}:`, JSON.stringify(e.response.body));
    else console.error("❌ Error:", e.message);
    process.exit(1);
  }
});

program.command("login").description("Verify OTP and store token").requiredOption("--email <email>", "email").requiredOption("--code <otp>", "OTP code").option("--no-store", "do not store token").action(async (opts) => {
  try {
    console.log("🔐 Verifying OTP...");
    const out = await privyAuth(opts.email, opts.code);
    const token = out?.privy_access_token || out?.token;
    if (!token) { console.error("❌ No token in response:", out); process.exit(1); }
    if (opts.store !== false) saveToken(token);
    console.log("✅ Login OK. Token acquired.");
    console.log("Next: node cantonctl.mjs status");
  } catch (e) {
    if (e.response) {
      const body = e.response.body;
      console.error(`❌ Error ${e.response.statusCode}:`, JSON.stringify(body));
      if (body?.error === "missing required parameters") console.error("💡 Hint: Check .env has correct PRIVY_APP_ID");
      else if (body?.code === "invalid_credentials") console.error("💡 Hint: OTP wrong/expired/already used");
    } else console.error("❌ Error:", e.message);
    process.exit(1);
  }
});

program.command("logout").description("Delete stored token").action(() => clearToken());

program.command("info").description("Wallet info").option("--token <jwt>", "use token directly").option("--raw", "print raw JSON").action(async (opts) => {
  const token = requireToken(opts.token);  try {
    const out = await supaMe(token);
    if (opts.raw) return console.log(JSON.stringify(out, null, 2));
    console.log("CANTON WALLET INFO\n-------------------");
    console.log("Party ID            :", out.partyId);
    console.log("Email               :", out.email);
    console.log("PublicKey           :", out.publicKey);
    console.log("Preapproval Set     :", out.transferPreapprovalSet);
    console.log("Preapproval Expires :", out.transferPreapprovalExpiresAt);
  } catch (e) { handleAxiosError(e, "[info] "); }
});

program.command("balances").description("Balances detail").option("--token <jwt>").option("--raw", "print raw JSON").action(async (opts) => {
  const token = requireToken(opts.token);
  try {
    const out = await supaBalances(token);
    if (opts.raw) return console.log(JSON.stringify(out, null, 2));
    console.log(`partyId:  ${out.partyId}`);
    console.log(`fetchedAt:${out.fetchedAt}\n`);
    for (const t of out.tokens ?? []) {
      const instr = t.instrumentId?.id || "unknown";
      const admin = t.instrumentId?.admin ? ` (${t.instrumentId.admin})` : "";
      console.log(`Token: ${instr}${admin}`);
      console.log(`  total:    ${t.totalBalance}`);
      console.log(`  unlocked: ${t.totalUnlockedBalance}  (utxos: ${t.unlockedUtxoCount})`);
      console.log(`  locked:   ${t.totalLockedBalance}  (utxos: ${t.lockedUtxoCount})`);
      if ((t.lockedUtxos ?? []).length) {
        console.log("  locked details:");
        for (const u of t.lockedUtxos) {
          console.log(`    - amount=${u.amount} context=${u.lock?.context||"-"} expiresAt=${u.lock?.expiresAt||"-"}`);
        }
      }
      console.log("");
    }
  } catch (e) { handleAxiosError(e, "[balances] "); }
});

program.command("balance").description("Balances summary").option("--token <jwt>").action(async (opts) => {
  const token = requireToken(opts.token);
  try {
    const out = await supaBalances(token);
    for (const t of out.tokens ?? []) {
      console.log(`${t.instrumentId?.id || "token"}:`);
      console.log(`  Unlocked: ${t.totalUnlockedBalance}`);
      console.log(`  Locked  : ${t.totalLockedBalance}`);
      console.log(`  Total   : ${t.totalBalance}`);
    }
  } catch (e) { handleAxiosError(e, "[balance] "); }
});
program.command("history").description("Transaction history").option("--token <jwt>").option("-l, --limit <n>", "items (1-200)", "20").option("--raw", "print raw JSON").action(async (opts) => {
  const token = requireToken(opts.token);
  const limit = clampInt(opts.limit, 1, 200, 20);
  try {
    const txs = await supaTransactions(token, limit);
    if (opts.raw) return console.log(JSON.stringify(txs, null, 2));
    const rows = Array.isArray(txs) ? txs : [];
    console.log(`transactions: ${rows.length}\n`);
    let sumBal = 0, sumLocked = 0;
    for (const r of rows) { sumBal += Number(r.balanceChange||0); sumLocked += Number(r.lockedChange||0); }
    console.log(`net balanceChange: ${sumBal}\nnet lockedChange : ${sumLocked}\n`);
    for (const r of rows) {
      console.log(`${r.date||"-"} | ${r.typeLabel||r.type||"-"} | Δbal ${fmtNum(r.balanceChange)} | Δlocked ${fmtNum(r.lockedChange)}`);
      const op = (r.tokenOperations?.[0]);
      if (op) console.log(`  op: ${op.direction} ${op.amount} ${op.token}${op.counterparty?` (${op.counterparty})`:""}${op.description?` - ${op.description}`:""}`);
      if (r.details?.sender) console.log(`  from: ${r.details.sender}`);
      if (r.details?.receiver) console.log(`  to  : ${r.details.receiver}`);
      console.log(`  id  : ${r.updateId||"-"}\n`);
    }
  } catch (e) { handleAxiosError(e, "[history] "); }
});

program.command("tx").description("Show 1 transaction by updateId").requiredOption("--id <updateId>", "updateId").option("--token <jwt>").option("-l, --limit <n>", "fetch limit (1-500)", "200").option("--raw", "print raw JSON").action(async (opts) => {
  const token = requireToken(opts.token);
  const limit = clampInt(opts.limit, 1, 500, 200);
  try {
    const txs = await supaTransactions(token, limit);
    const tx = (Array.isArray(txs)?txs:[]).find(x => x.updateId === opts.id);
    if (!tx) { console.error(`❌ Not found in last ${limit} tx.`); process.exit(1); }
    if (opts.raw) return console.log(JSON.stringify(tx, null, 2));
    console.log(`${tx.date} | ${tx.typeLabel||tx.type}`);
    console.log(`updateId: ${tx.updateId}\nledgerOffset: ${tx.ledgerOffset}\nΔ balance: ${tx.balanceChange}\nΔ locked: ${tx.lockedChange}`);
    if (tx.tokenOperations?.length) { console.log("ops:"); for (const op of tx.tokenOperations) console.log(`  - ${op.direction} ${op.amount} ${op.token}${op.counterparty?` (${op.counterparty})`:""}${op.description?` - ${op.description}`:""}`); }
    if (tx.details) console.log(`details: ${JSON.stringify(tx.details)}`);
  } catch (e) { handleAxiosError(e, "[tx] "); }
});

program.command("claim").description("Claim CC faucet/airdrop").option("--token <jwt>").option("--raw", "print raw JSON").action(async (opts) => {
  const token = requireToken(opts.token);
  try {
    const out = await supaClaimAirdrop(token);
    if (opts.raw) return console.log(JSON.stringify(out, null, 2));
    console.log("✅ Claim success (request accepted).");
    if (out?.next_reward_claim) console.log(`Next reward claim: ${out.next_reward_claim}`);
    else console.log(JSON.stringify(out, null, 2));
  } catch (e) { handleAxiosError(e, "[claim] "); }
});

program.command("status").description("Quick overview").option("--token <jwt>").action(async (opts) => {
  const token = requireToken(opts.token);  try {
    const [me, balances, txs] = await Promise.all([supaMe(token), supaBalances(token), supaTransactions(token, 5)]);
    console.log("STATUS\n------");
    console.log("Party ID:", me.partyId);
    console.log("Email   :", me.email);
    console.log("Preappr :", me.transferPreapprovalSet ? `yes (exp ${me.transferPreapprovalExpiresAt})` : "no\n");
    for (const t of balances.tokens ?? []) console.log(`${t.instrumentId?.id||"token"}: ${t.totalUnlockedBalance} unlocked / ${t.totalBalance} total`);
    console.log("\nLast 5 tx:");
    for (const r of (Array.isArray(txs)?txs:[])) console.log(`${r.date} | ${r.typeLabel||r.type} | ${fmtNum(r.balanceChange)} | id=${r.updateId}`);
  } catch (e) { handleAxiosError(e, "[status] "); }
});

program.on("command:*", () => { console.error("❌ Unknown command:", program.args.join(" ")); program.help({error:true}); });
program.parse(process.argv);
if (!process.argv.slice(2).length) program.outputHelp();
