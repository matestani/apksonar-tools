#!/usr/bin/env node
/**
 * apksonar CLI — сканирование APK из терминала/CI.
 * Один файл, без зависимостей (Node >= 18).
 *
 *   APKSONAR_KEY_ID=… APKSONAR_SECRET=… node apksonar.mjs scan app.apk --mode fast
 *   node apksonar.mjs status <scan-id>
 *   node apksonar.mjs report <report-token>
 *
 * Флаги: --wait (ждать завершения), --json (сырой JSON вместо сводки), --out <file>.
 */
import { createHash, createHmac, randomBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const URL_BASE = process.env.APKSONAR_URL || "https://apksonar.com";
const KEY_ID = process.env.APKSONAR_KEY_ID || "";
const SECRET = process.env.APKSONAR_SECRET || "";

function die(msg) {
  console.error("apksonar: " + msg);
  process.exit(1);
}

/** Подписанный запрос: sig = HMAC(sha256(secret), `${ts}\n${nonce}\n${method} ${path}`) */
async function api(method, urlPath, body, isForm) {
  if (!KEY_ID || !SECRET) die("APKSONAR_KEY_ID and APKSONAR_SECRET must be set (create a key at /account)");
  const ts = String(Math.floor(Date.now() / 1000)).padStart(10, "0");
  const nonce = randomBytes(8).toString("hex");
  const signingKey = createHash("sha256").update(SECRET).digest("hex");
  const sig = createHmac("sha256", signingKey).update(`${ts}\n${nonce}\n${method} ${urlPath}`).digest("hex");
  const headers = {
    "x-apk-key": KEY_ID,
    "x-apk-ts": ts,
    "x-apk-nonce": nonce,
    "x-apk-signature": sig,
  };
  if (!isForm) headers["content-type"] = "application/json";
  const r = await fetch(URL_BASE + urlPath, { method, headers, body });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) die(`HTTP ${r.status}: ${JSON.stringify(j)}`);
  return j;
}

async function scan(file, opts) {
  const buf = readFileSync(file);
  const form = new FormData();
  form.append("apk", new Blob([buf]), path.basename(file));
  if (opts.mode) form.append("mode", opts.mode);
  const created = await api("POST", "/api/v1/scans", form, true);
  console.log(`scan #${created.id} started (${opts.mode || "fast"}) → ${created.status_url}`);
  if (!opts.wait) return created;
  for (let i = 0; i < 200; i++) {
    await new Promise((r) => setTimeout(r, 5000));
    const st = await api("GET", `/api/v1/scans/${created.id}`);
    if (st.status === "done" || st.status === "failed") {
      console.log(JSON.stringify(st.summary ?? st, null, 2));
      if (opts.out) writeFileSync(opts.out, JSON.stringify(st, null, 2));
      if (st.status === "failed") process.exit(2);
      console.log(`report: ${st.report_url}`);
      return st;
    }
    process.stdout.write(`  status: ${st.status} (${st.stage ?? "—"})…\r`);
  }
  die("timeout waiting for scan");
}

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  if (!cmd || cmd === "-h" || cmd === "--help") {
    console.log("usage: apksonar scan <file.apk> [--mode fast|deep] [--wait] [--out f.json] | status <id> | report <token>");
    process.exit(cmd ? 0 : 1);
  }
  const flags = {
    mode: rest.includes("--mode") ? rest[rest.indexOf("--mode") + 1] : undefined,
    wait: rest.includes("--wait"),
    out: rest.includes("--out") ? rest[rest.indexOf("--out") + 1] : undefined,
  };
  const file = rest.find((a) => !a.startsWith("--") && a !== flags.mode && a !== flags.out);
  if (cmd === "scan") return scan(file, flags);
  if (cmd === "status") {
    const st = await api("GET", `/api/v1/scans/${file}`);
    console.log(JSON.stringify(st, null, 2));
    return;
  }
  if (cmd === "report") {
    const r = await fetch(`${URL_BASE}/r/${file}`);
    if (!r.ok) die(`report HTTP ${r.status}`);
    console.log(`${URL_BASE}/r/${file} → HTTP ${r.status}`);
    return;
  }
  die(`unknown command: ${cmd}`);
}

main().catch((e) => die(e.message));
