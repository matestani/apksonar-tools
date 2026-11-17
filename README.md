# apksonar-tools

Tools for [APKSonar](https://apksonar.com), the online security scanner for Android packages. This repository holds the terminal side of the service: the CLI, the MCP server for AI agents, and future plugins (browser, IDE, marketplaces).

[Website](https://apksonar.com) · [npm package](https://www.npmjs.com/package/apksonar) · [Live demo scans](https://apksonar.com/en/demos) · [REST API](https://apksonar.com/en/api) · [Plans](https://apksonar.com/en#pricing)

Both tools ship as one zero-dependency npm package (Node 18+), published as [`apksonar` on npm](https://www.npmjs.com/package/apksonar):

```
npx apksonar scan app.apk          # CLI
npx apksonar-mcp                   # MCP server for Claude Desktop / Cursor
```

The scanner itself runs in the APKSonar cloud: upload a package, get a report with evidence, MASVS mapping and CVSS scores. Formats: APK, AAB (Android App Bundle), XAPK, APKS (split bundles), DEX and native SO libraries. Deep mode adds Ghidra native analysis, IL2CPP support and diff against a previous scan.

## API keys

Both tools authenticate with a key pair created in your dashboard: `key_id` plus `secret`. The secret is shown once at creation. Every request is signed with HMAC-SHA256 (time window ±300 s, one-time nonce); the secret never travels over the network.

Create keys in your APKSonar account ([sign in](https://apksonar.com/en), then open **API keys**). A free account is enough; scans count toward your plan quota.

```bash
export APKSONAR_URL=https://apksonar.com
export APKSONAR_KEY_ID=apk_mcp_XXXXXXXXXXXX
export APKSONAR_SECRET=<48 hex>
```

## CLI

Install once:

```bash
npm i -g apksonar
```

Commands:

```bash
apksonar scan app.apk                       # start a scan, print its id
apksonar scan app.apk --mode deep --wait    # deep scan, wait for the verdict
apksonar scan app.aab --wait --out r.json   # save the full JSON report
apksonar status <scan-id>                   # status and finding counters
apksonar report <report-token>              # web report URL
```

`--wait` polls until the verdict, prints the summary counters and the web report link. Exit code 2 means the scan itself failed.

## GitHub Action

Add `APKSONAR_KEY_ID` and `APKSONAR_SECRET` as repository secrets, then:

```yaml
name: apksonar
on: pull_request
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: ./gradlew assembleRelease
      - env:
          APKSONAR_URL: https://apksonar.com
          APKSONAR_KEY_ID: ${{ secrets.APKSONAR_KEY_ID }}
          APKSONAR_SECRET: ${{ secrets.APKSONAR_SECRET }}
        run: npx --yes apksonar scan app/build/outputs/apk/release/app-release.apk --mode fast --wait --out apksonar.json
      - uses: actions/upload-artifact@v4
        if: always()
        with: { name: apksonar-report, path: apksonar.json }
```

## MCP server

Works with any client that speaks MCP over stdio, such as Claude Desktop and Cursor.

Claude Desktop (Settings → Developer → Edit Config):

```json
{
  "mcpServers": {
    "apksonar": {
      "command": "npx",
      "args": ["--yes", "apksonar-mcp"],
      "env": {
        "APKSONAR_URL": "https://apksonar.com",
        "APKSONAR_KEY_ID": "apk_mcp_XXXXXXXXXXXX",
        "APKSONAR_SECRET": "<48 hex>"
      }
    }
  }
}
```

Tools the server exposes: `scan_apk`, `scan_status`, `report_link`, `list_demos`. After connecting you can ask the agent: scan this APK and tell me what was found.

## Limits

30 scans per hour per key. Scans count toward the quota of the plan the key owner is on. Revoking a key takes effect immediately, other keys keep working.

## Repository layout

```
bin/         # apksonar.mjs (CLI) and mcp-server.mjs, published as the npm package apksonar
packages/    # reserved for future standalone tools and plugins
```

Browser extensions and marketplace plugins will be published to their own stores (Chrome Web Store, JetBrains Marketplace); their sources live here.

## License

MIT
