#!/usr/bin/env node
/**
 * SUPA CLI - Auto Refresh Token Version
 * ✅ Multi-account support
 * ✅ Auto refresh expired tokens
 * ✅ Store refresh_token securely
 */

import fs from "fs";
import path from "path";
import os from "os";
import axios from "axios";
import { gotScraping } from "got-scraping";
import chalk from "chalk";
import readline from "readline";
import dotenv from "dotenv";

dotenv.config();

// ======== CONFIG ========
const PRIVY_BASE = "https://auth.privy.io";
const SUPA_BASE = "https://api.supanova.app";
const PRIVY_APP_ID = process.env.PRIVY_APP_ID || "cm338ijv804mhhgvacdxsayxu";
const PRIVY_CLIENT_ID = process.env.PRIVY_CLIENT_ID || "WY5dQwQyixARYCtWLMzJnVKpgX1kt796M1kukgH6U6j2k";
const PRIVY_CAID = process.env.PRIVY_CAID || "2629eb4a-77b9-4152-8bf4-ec36c19ecd20";
const X_CANTON_NODE_ID = process.env.X_CANTON_NODE_ID || "mainnet-supa";
const X_SUPA_APP_ID = process.env.X_SUPA_APP_ID || "supa-app-300";
const STORE = path.join(os.homedir(), ".supa_accounts.json");

const BROWSER_FP = {
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
  "x-privy-app-id": PRIVY_APP_ID,  "Content-Type": "application/json"
});

// ======== HELPERS ========
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

function question(q) {
  return new Promise(res => rl.question(q, ans => res(ans.trim())));
}

function loadAccounts() {
  if (!fs.existsSync(STORE)) return {};
  try { return JSON.parse(fs.readFileSync(STORE, "utf8")); }
  catch { return {}; }
}

function saveAccounts(accounts) {
  fs.writeFileSync(STORE, JSON.stringify(accounts, null, 2), "utf8");
  try { fs.chmodSync(STORE, 0o600); } catch {}
}

function getActiveAccount() {
  const accounts = loadAccounts();
  const activeEmail = accounts._active || null;
  if (activeEmail && accounts[activeEmail]) {
    return { email: activeEmail, ...accounts[activeEmail] };
  }
  return null;
}

function setActiveAccount(email) {
  const accounts = loadAccounts();
  accounts._active = email;
  saveAccounts(accounts);
}

function saveAccount(email, token, refreshToken) {
  const accounts = loadAccounts();
  accounts[email] = { 
    token, 
    refresh_token: refreshToken,
    addedAt: new Date().toISOString() 
  };
  accounts._active = email;
  saveAccounts(accounts);
}

function updateAccountToken(email, token, refreshToken) {
  const accounts = loadAccounts();
  if (accounts[email]) {    accounts[email].token = token;
    if (refreshToken) accounts[email].refresh_token = refreshToken;
    accounts[email].refreshedAt = new Date().toISOString();
    saveAccounts(accounts);
  }
}

function removeAccount(email) {
  const accounts = loadAccounts();
  delete accounts[email];
  if (accounts._active === email) accounts._active = null;
  saveAccounts(accounts);
}

function listAccounts() {
  const accounts = loadAccounts();
  const active = accounts._active;
  const list = Object.keys(accounts).filter(k => k !== '_active');
  return list.map(email => ({ email, active: email === active }));
}

// ⭐ DECODE JWT TO CHECK EXPIRY
function decodeJwt(token) {
  try {
    const payload = token.split('.')[1];
    const decoded = JSON.parse(Buffer.from(payload, 'base64').toString());
    return decoded;
  } catch {
    return null;
  }
}

// ⭐ CHECK IF TOKEN IS EXPIRED (with 5 min buffer)
function isTokenExpired(token, buffer = 300) {
  const decoded = decodeJwt(token);
  if (!decoded || !decoded.exp) return true;
  const now = Math.floor(Date.now() / 1000);
  return (decoded.exp - now) < buffer;
}

// ⭐ GET TOKEN EXPIRY TIME
function getTokenExpiry(token) {
  const decoded = decodeJwt(token);
  if (!decoded || !decoded.exp) return null;
  return new Date(decoded.exp * 1000).toLocaleString('id-ID');
}

function supaHeaders(token) {
  return {
    Accept: "application/json",    Authorization: `Bearer ${token}`,
    "X-Canton-Node-Id": X_CANTON_NODE_ID,
    "X-Supa-App-Id": X_SUPA_APP_ID
  };
}

function fmtNum(n) {
  const x = typeof n === "string" ? Number(n) : n;
  return Number.isFinite(x) ? x.toString() : String(n ?? 0);
}

function pause() {
  return new Promise(res => rl.question("\nTekan Enter untuk lanjut...", () => res()));
}

// ======== PRIVY AUTH ========
async function privyInit(email) {
  const res = await gotScraping({
    url: `${PRIVY_BASE}/api/v1/passwordless/init`,
    method: "POST",
    json: { email, client_id: PRIVY_APP_ID },
    headerGeneratorOptions: BROWSER_FP,
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
    json: { email, code, mode: "login-or-sign-up", client_id: PRIVY_APP_ID },
    headerGeneratorOptions: BROWSER_FP,
    headers: getPrivyHeaders(),
    responseType: "json",
    timeout: { request: 30000 }
  });
  return res.body;
}

// ⭐ REFRESH TOKEN USING REFRESH_TOKEN
async function refreshSession(refreshToken) {
  try {
    const res = await gotScraping({
      url: `${PRIVY_BASE}/api/v1/sessions`,
      method: "POST",
      json: { refresh_token: refreshToken },
      headerGeneratorOptions: BROWSER_FP,      headers: getPrivyHeaders(),
      responseType: "json",
      timeout: { request: 30000 }
    });
    
    if (res.statusCode === 200 && res.body?.privy_access_token) {
      return {
        token: res.body.token || res.body.privy_access_token,
        refresh_token: res.body.refresh_token // Token rotation!
      };
    }
    return null;
  } catch (e) {
    console.log(chalk.red(`🔄 Refresh failed: ${e.message}`));
    return null;
  }
}

// ======== SUPA API (WITH AUTO-REFRESH) ========
async function supaMe(token, email) {
  const { validToken } = await ensureValidToken(token, email);
  const res = await axios.get(`${SUPA_BASE}/canton/api/me`, { headers: supaHeaders(validToken), timeout: 30000 });
  return res.data;
}

async function supaBalances(token, email) {
  const { validToken } = await ensureValidToken(token, email);
  const res = await axios.get(`${SUPA_BASE}/canton/api/balances`, { headers: supaHeaders(validToken), timeout: 30000 });
  return res.data;
}

async function supaTransactions(token, email, limit = 20) {
  const { validToken } = await ensureValidToken(token, email);
  const params = new URLSearchParams({ limit: String(limit) });
  const res = await axios.get(`${SUPA_BASE}/canton/api/transactions?${params}`, { headers: supaHeaders(validToken), timeout: 30000 });
  return res.data;
}

async function supaClaim(token, email) {
  const { validToken } = await ensureValidToken(token, email);
  const res = await axios.post(`${SUPA_BASE}/canton/api/claim_airdrop`, {}, { headers: supaHeaders(validToken), timeout: 30000 });
  return res.data;
}

// ⭐ ENSURE TOKEN IS VALID (AUTO-REFRESH IF EXPIRED)
async function ensureValidToken(token, email) {
  if (!isTokenExpired(token, 300)) {
    return { validToken: token, refreshed: false };
  }
    console.log(chalk.yellow('\n🔄 Token expired, refreshing...'));
  
  const accounts = loadAccounts();
  const refreshToken = accounts[email]?.refresh_token;
  
  if (!refreshToken) {
    console.log(chalk.red('❌ No refresh token. Please login again.\n'));
    throw new Error('Token expired and no refresh token available');
  }
  
  const newTokens = await refreshSession(refreshToken);
  if (!newTokens) {
    console.log(chalk.red('❌ Refresh failed. Please login again.\n'));
    throw new Error('Token refresh failed');
  }
  
  // Update stored tokens (token rotation!)
  updateAccountToken(email, newTokens.token, newTokens.refresh_token);
  console.log(chalk.green('✅ Token refreshed successfully!\n'));
  
  return { validToken: newTokens.token, refreshed: true };
}

// ======== FEATURES ========
async function doLogin() {
  console.clear();
  console.log(chalk.cyan.bold('╔════════════════════════════════════╗'));
  console.log(chalk.cyan.bold('║        SUPA WALLET - LOGIN 🔐      ║'));
  console.log(chalk.cyan.bold('╚════════════════════════════════════╝\n'));

  const email = await question('Masukkan Email: ');
  if (!email.includes('@')) {
    console.log(chalk.red('❌ Email tidak valid!'));
    await pause();
    return false;
  }

  console.log(chalk.yellow('\n📤 Mengirim OTP...'));
  try {
    const init = await privyInit(email);
    if (!init?.success) throw new Error(JSON.stringify(init));
    console.log(chalk.green('✅ OTP terkirim! Cek email Anda.\n'));

    const otp = await question('Masukkan 6 digit OTP: ');
    if (!/^\d{6}$/.test(otp)) {
      console.log(chalk.red('❌ OTP harus 6 digit angka!'));
      await pause();
      return false;
    }
    console.log(chalk.yellow('\n🔐 Verifying...'));
    const auth = await privyAuth(email, otp);
    
    const token = auth?.token || auth?.privy_access_token;
    const refreshToken = auth?.refresh_token;
    
    if (!token) throw new Error('No token in response');

    saveAccount(email, token, refreshToken);
    console.log(chalk.green(`\n✅ Login berhasil! (${email})`));
    console.log(chalk.gray('💾 Token + Refresh Token tersimpan\n'));
    
    // Show token expiry
    const expiry = getTokenExpiry(token);
    if (expiry) {
      console.log(chalk.gray(`⏰ Token expires: ${expiry}\n`));
    }
    
    await pause();
    return true;
  } catch (e) {
    console.log(chalk.red(`\n❌ Error: ${e.message}\n`));
    await pause();
    return false;
  }
}

async function doSwitchAccount() {
  console.clear();
  console.log(chalk.cyan.bold('╔════════════════════════════════════╗'));
  console.log(chalk.cyan.bold('║      SWITCH ACCOUNT 🔄             ║'));
  console.log(chalk.cyan.bold('╚════════════════════════════════════╝\n'));

  const accounts = listAccounts();
  if (accounts.length === 0) {
    console.log(chalk.yellow('⚠️  Tidak ada akun tersimpan.\n'));
    await pause();
    return;
  }

  console.log(chalk.cyan.bold('=== AKUN TERSIMPAN ===\n'));
  accounts.forEach((acc, i) => {
    const marker = acc.active ? chalk.green('●') : chalk.gray('○');
    const status = acc.active ? chalk.green('(Active)') : chalk.gray('');
    console.log(chalk.white(`${i+1}. ${marker} ${acc.email} ${status}`));
  });
  console.log();

  const choice = await question(`Pilih akun (1-${accounts.length}) atau 0 untuk batal: `);
  const idx = Number(choice) - 1;  
  if (choice === '0' || idx < 0 || idx >= accounts.length) {
    console.log(chalk.yellow('Dibatalkan.\n'));
    await pause();
    return;
  }

  setActiveAccount(accounts[idx].email);
  console.log(chalk.green(`✅ Switched to: ${accounts[idx].email}\n`));
  await pause();
}

async function doManageAccounts() {
  console.clear();
  console.log(chalk.cyan.bold('╔════════════════════════════════════╗'));
  console.log(chalk.cyan.bold('║      MANAGE ACCOUNTS ⚙️            ║'));
  console.log(chalk.cyan.bold('╚════════════════════════════════════╝\n'));

  const accounts = listAccounts();
  if (accounts.length === 0) {
    console.log(chalk.yellow('⚠️  Tidak ada akun tersimpan.\n'));
    await pause();
    return;
  }

  console.log(chalk.cyan.bold('=== AKUN TERSIMPAN ===\n'));
  accounts.forEach((acc, i) => {
    const marker = acc.active ? chalk.green('●') : chalk.gray('○');
    const status = acc.active ? chalk.green('(Active)') : chalk.gray('');
    console.log(chalk.white(`${i+1}. ${marker} ${acc.email} ${status}`));
  });
  console.log();

  console.log(chalk.white('0. ') + 'Kembali');
  const choice = await question('\nHapus akun (1-X) atau 0 untuk batal: ');
  const idx = Number(choice) - 1;
  
  if (choice === '0' || idx < 0 || idx >= accounts.length) {
    console.log(chalk.yellow('Dibatalkan.\n'));
    await pause();
    return;
  }

  const confirm = await question(`Hapus ${accounts[idx].email}? (y/n): `);
  if (confirm.toLowerCase() === 'y') {
    removeAccount(accounts[idx].email);
    console.log(chalk.green('✅ Akun dihapus.\n'));
  } else {
    console.log(chalk.yellow('Dibatalkan.\n'));
  }  await pause();
}

async function doStatus(token, email) {
  console.clear();
  console.log(chalk.cyan.bold('╔════════════════════════════════════╗'));
  console.log(chalk.cyan.bold('║        SUPA WALLET - STATUS 📊     ║'));
  console.log(chalk.cyan.bold('╚════════════════════════════════════╝\n'));

  try {
    const [me, balances, txs] = await Promise.all([
      supaMe(token, email),
      supaBalances(token, email),
      supaTransactions(token, email, 5)
    ]);

    // Show token info
    const expiry = getTokenExpiry(token);
    console.log(chalk.gray(`🔑 Token expires: ${expiry || 'Unknown'}\n`));

    console.log(chalk.cyan.bold('📌 ACCOUNT INFO'));
    console.log(chalk.white(`   Party ID : ${me.partyId}`));
    console.log(chalk.white(`   Email    : ${me.email}`));
    console.log(chalk.white(`   Preapproval: ${me.transferPreapprovalSet ? 'YES' : 'NO'}\n`));

    console.log(chalk.cyan.bold('💰 BALANCES'));
    (balances.tokens ?? []).forEach(t => {
      console.log(chalk.white(`   ${t.instrumentId?.id || 'token'}: ${t.totalUnlockedBalance} unlocked / ${t.totalBalance} total`));
    });

    console.log(chalk.cyan.bold('\n📜 LAST 5 TRANSACTIONS'));
    (Array.isArray(txs) ? txs : []).forEach(r => {
      console.log(chalk.white(`   ${r.date || '-'} | ${r.typeLabel || '-'} | Δ${fmtNum(r.balanceChange)} | ${r.updateId || '-'}`));
    });

  } catch (e) {
    if (e.message.includes('refresh')) {
      console.log(chalk.yellow('⚠️  Session expired. Please login again.\n'));
    } else {
      console.log(chalk.red(`❌ Error: ${e.response?.data ? JSON.stringify(e.response.data) : e.message}\n`));
    }
  }
  await pause();
}

async function doBalances(token, email) {
  console.clear();
  console.log(chalk.cyan.bold('╔════════════════════════════════════╗'));
  console.log(chalk.cyan.bold('║      SUPA WALLET - BALANCES 💰     ║'));
  console.log(chalk.cyan.bold('╚════════════════════════════════════╝\n'));
  try {
    const out = await supaBalances(token, email);
    
    const expiry = getTokenExpiry(token);
    console.log(chalk.gray(`🔑 Token expires: ${expiry || 'Unknown'}\n`));
    
    console.log(chalk.white(`Party ID: ${out.partyId}`));
    console.log(chalk.white(`Fetched: ${out.fetchedAt}\n`));
    (out.tokens ?? []).forEach(t => {
      console.log(chalk.cyan.bold(`🪙 ${t.instrumentId?.id || 'unknown'}`));
      console.log(chalk.white(`   Total    : ${t.totalBalance}`));
      console.log(chalk.white(`   Unlocked : ${t.totalUnlockedBalance} (${t.unlockedUtxoCount} utxos)`));
      console.log(chalk.white(`   Locked   : ${t.totalLockedBalance} (${t.lockedUtxoCount} utxos)\n`));
    });
  } catch (e) {
    console.log(chalk.red(`❌ Error: ${e.message}\n`));
  }
  await pause();
}

async function doHistory(token, email) {
  console.clear();
  console.log(chalk.cyan.bold('╔════════════════════════════════════╗'));
  console.log(chalk.cyan.bold('║     SUPA WALLET - HISTORY 📜       ║'));
  console.log(chalk.cyan.bold('╚════════════════════════════════════╝\n'));

  const limitStr = await question('Jumlah transaksi (1-200, default 20): ');
  const limit = Math.max(1, Math.min(200, Number(limitStr) || 20));

  try {
    const txs = await supaTransactions(token, email, limit);
    const rows = Array.isArray(txs) ? txs : [];
    console.log(chalk.cyan.bold(`\nTRANSACTIONS (${rows.length})\n`));
    rows.forEach((r, i) => {
      console.log(chalk.white(`${i+1}. ${r.date || '-'} | ${r.typeLabel || '-'} | Δ${fmtNum(r.balanceChange)} | ${r.updateId || '-'}`));
    });
  } catch (e) {
    console.log(chalk.red(`❌ Error: ${e.message}\n`));
  }
  await pause();
}

async function doClaim(token, email) {
  console.clear();
  console.log(chalk.cyan.bold('╔════════════════════════════════════╗'));
  console.log(chalk.cyan.bold('║      SUPA WALLET - CLAIM 🎁        ║'));
  console.log(chalk.cyan.bold('╚════════════════════════════════════╝\n'));

  console.log(chalk.yellow('🎁 Claiming airdrop...\n'));  try {
    const out = await supaClaim(token, email);
    console.log(chalk.green('✅ Claim Success!'));
    console.log(chalk.white(`Next Claim: ${out?.next_reward_claim || 'N/A'}\n`));
    console.log(chalk.gray(JSON.stringify(out, null, 2).slice(0, 500)));
  } catch (e) {
    console.log(chalk.red(`❌ Error: ${e.response?.data ? JSON.stringify(e.response.data) : e.message}\n`));
  }
  await pause();
}

async function doLogout() {
  console.clear();
  const active = getActiveAccount();
  if (active) {
    removeAccount(active.email);
    console.log(chalk.green(`\n✅ Logout berhasil (${active.email}).\n`));
  } else {
    console.log(chalk.yellow('\n⚠️  Tidak ada akun aktif.\n'));
  }
  await pause();
}

// ======== MAIN MENU ========
async function mainMenu() {
  while (true) {
    console.clear();
    console.log(chalk.cyan.bold('╔════════════════════════════════════╗'));
    console.log(chalk.cyan.bold('║     🚀 SUPA WALLET CLI v3.0 🚀     ║'));
    console.log(chalk.cyan.bold('║     AUTO-REFRESH TOKEN SUPPORT     ║'));
    console.log(chalk.cyan.bold('╚════════════════════════════════════╝\n'));

    const active = getActiveAccount();
    if (active) {
      console.log(chalk.green(`✅ Logged in: ${active.email}`));
      const expiry = getTokenExpiry(active.token);
      if (expiry) {
        console.log(chalk.gray(`   Token expires: ${expiry}\n`));
      } else {
        console.log();
      }
    } else {
      console.log(chalk.red('❌ Not logged in\n'));
    }

    const accounts = listAccounts();
    const totalAccounts = accounts.length;

    console.log(chalk.cyan.bold('═══ MENU ═══'));
    console.log(chalk.white('1. ') + '🔐 Login / Add Account');    if (totalAccounts > 1) {
      console.log(chalk.white('2. ') + `🔄 Switch Account (${totalAccounts} accounts)`);
    }
    if (totalAccounts > 0) {
      console.log(chalk.white('3. ') + '⚙️  Manage Accounts');
    }
    if (active) {
      console.log(chalk.white('4. ') + '📊 Status Overview');
      console.log(chalk.white('5. ') + '💰 View Balances');
      console.log(chalk.white('6. ') + '📜 Transaction History');
      console.log(chalk.white('7. ') + '🎁 Claim Airdrop');
      console.log(chalk.white('8. ') + '🚪 Logout');
    }
    console.log(chalk.white('0. ') + '❌ Exit');
    console.log();

    const choice = await question('Pilih menu (0-8): ');

    switch (choice) {
      case '1': await doLogin(); break;
      case '2': if (totalAccounts > 1) await doSwitchAccount(); break;
      case '3': if (totalAccounts > 0) await doManageAccounts(); break;
      case '4': if (active) await doStatus(active.token, active.email); break;
      case '5': if (active) await doBalances(active.token, active.email); break;
      case '6': if (active) await doHistory(active.token, active.email); break;
      case '7': if (active) await doClaim(active.token, active.email); break;
      case '8': if (active) await doLogout(); break;
      case '0': 
        console.log(chalk.cyan('\n👋 See you!\n'));
        rl.close();
        process.exit(0);
      default:
        console.log(chalk.red('❌ Pilihan tidak valid!'));
        await pause();
    }
  }
}

// ======== START ========
mainMenu().catch(e => {
  console.error(chalk.red('💥 Fatal error:', e.message));
  rl.close();
  process.exit(1);
});
