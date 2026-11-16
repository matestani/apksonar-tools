#!/usr/bin/env node
/**
 * apksonar MCP-сервер (Model Context Protocol, stdio JSON-RPC).
 * Даёт ИИ-агентам (Claude, Cursor, Codex) инструменты сканирования APK.
 * Один файл, без зависимостей (Node >= 18).
 *
 * Настройка в клиенте (claude_desktop_config.json / mcp.json):
 *   { "mcpServers": { "apksonar": {
 *       "command": "node",
 *       "args": ["/abs/path/to/mcp-server.mjs"],
 *       "env": { "APKSONAR_KEY_ID": "apk_mcp_…", "APKSONAR_SECRET": "…",
 *                "APKSONAR_URL": "https://apksonar.com" } } } }
 *
 * Инструменты: scan_apk, scan_status, report_link, list_demos.
 */
import { createHash, createHmac, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import readline from "node:readline";

const URL_BASE = process.env.APKSONAR_URL || "https://apksonar.com";
const KEY_ID = process.env.APKSONAR_KEY_ID || "";
const SECRET = process.env.APKSONAR_SECRET || "";

async function api(method, urlPath, body) {
  const ts = String(Math.floor(Date.now() / 1000)).padStart(10, "0");
  const nonce = randomBytes(8).toString("hex");
  const signingKey = createHash("sha256").update(SECRET).digest("hex");
  const sig = createHmac("sha256", signingKey).update(`${ts}\n${nonce}\n${method} ${urlPath}`).digest("hex");
  const r = await fetch(URL_BASE + urlPath, {
    method,
    headers: { "x-apk-key": KEY_ID, "x-apk-ts": ts, "x-apk-nonce": nonce, "x-apk-signature": sig },
    body,
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`HTTP ${r.status}: ${JSON.stringify(j)}`);
  return j;
}

const TOOLS = [
  {
    name: "scan_apk",
    description: "Upload an Android package (.apk/.xapk/.apks/.aab/.dex/.so) to APKSonar and start a security scan. Returns scan id, status and report URLs. Poll with scan_status.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "absolute or relative path to the package file" },
        mode: { type: "string", enum: ["fast", "deep"], description: "fast: ~1 min; deep: adds Ghidra native analysis (~3 min)" },
      },
      required: ["path"],
    },
  },
  {
    name: "scan_status",
    description: "Get status and findings summary of a scan by id (queued/running/done/failed, counts by severity).",
    inputSchema: { type: "object", properties: { id: { type: "number" } }, required: ["id"] },
  },
  {
    name: "report_link",
    description: "Get the human-readable report URL and check it is reachable.",
    inputSchema: { type: "object", properties: { token: { type: "string" } }, required: ["token"] },
  },
  {
    name: "list_demos",
    description: "List demo scans (sample reports) on the server: package, mode, findings count.",
    inputSchema: { type: "object", properties: {} },
  },
];

async function callTool(name, args) {
  if (!KEY_ID || !SECRET) throw new Error("APKSONAR_KEY_ID / APKSONAR_SECRET are not set for this MCP server");
  if (name === "scan_apk") {
    const buf = readFileSync(args.path);
    const form = new FormData();
    form.append("apk", new Blob([buf]), path.basename(args.path));
    if (args.mode) form.append("mode", args.mode);
    const created = await api("POST", "/api/v1/scans", form, true);
    return { content: [{ type: "text", text: JSON.stringify(created, null, 2) }] };
  }
  if (name === "scan_status") {
    const st = await api("GET", `/api/v1/scans/${args.id}`);
    return { content: [{ type: "text", text: JSON.stringify(st, null, 2) }] };
  }
  if (name === "report_link") {
    const url = `${URL_BASE}/r/${args.token}`;
    const r = await fetch(url);
    return { content: [{ type: "text", text: `report: ${url} (HTTP ${r.status})` }] };
  }
  if (name === "list_demos") {
    const r = await fetch(`${URL_BASE}/en/demos`);
    const html = await r.text();
    const links = [...html.matchAll(/com\.apksonar\.demo[a-z0-9._]*/g)].slice(0, 20).map((m) => m[0]);
    return { content: [{ type: "text", text: `demos page: ${URL_BASE}/en/demos\npackages seen: ${[...new Set(links)].join(", ")}` }] };
  }
  throw new Error(`unknown tool: ${name}`);
}

const rl = readline.createInterface({ input: process.stdin });
function send(obj) {
  process.stdout.write(JSON.stringify(obj) + "\n");
}
rl.on("line", (line) => {
  let msg;
  try { msg = JSON.parse(line); } catch { return; }
  const { id, method, params } = msg ?? {};
  if (method === "initialize") {
    return send({
      jsonrpc: "2.0",
      id,
      result: {
        protocolVersion: params?.protocolVersion ?? "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "apksonar", version: "0.1.0" },
      },
    });
  }
  if (method === "notifications/initialized" || method === "initialized") return;
  if (method === "ping") return send({ jsonrpc: "2.0", id, result: {} });
  if (method === "tools/list") return send({ jsonrpc: "2.0", id, result: { tools: TOOLS } });
  if (method === "tools/call") {
    return callTool(params?.name, params?.arguments ?? {})
      .then((result) => send({ jsonrpc: "2.0", id, result }))
      .catch((e) =>
        send({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: String(e.message ?? e) }], isError: true } }),
      );
  }
  if (id !== undefined) send({ jsonrpc: "2.0", id, error: { code: -32601, message: `method not found: ${method}` } });
});
