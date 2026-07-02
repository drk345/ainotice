# Chrome Web Store Submission Checklist

**Extension:** Ai Notice
**Submission standard:** Visible-brand-clean (AG-249)
**Last updated:** 2026-06-20 (AG-282)

> **Scope:** This checklist covers the build/package/inspect mechanics for the Chrome
> submission. For the store **listing copy and questionnaire answers**, use the durable
> packet at [`docs/CHROME-WEB-STORE-UPLOAD-PACKET.md`](CHROME-WEB-STORE-UPLOAD-PACKET.md)
> (AG-280). The two are complementary and do not overlap.

---

## Step 1 — Build

```
npm run build:chrome
```

Expected output: `25 PASS / 0 FAIL / 0 SKIP`

If any check fails, do not proceed. Fix the build first.

---

## Step 2 — Package

```
npm run package:chrome
```

This script:
- Verifies `dist/chrome/manifest.json` exists
- Fails if any `*.map` source maps are present
- Fails if any `*.ts` / `*.tsx` source files are present
- Produces `release/ainotice-chrome.zip` containing the exact contents of `dist/chrome/`

Expected output confirms 11 files packaged, no maps, no source files.

**ZIP path (release repo, relative):** `release/ainotice-chrome.zip`
**ZIP path (release repo, absolute):** `C:\DEV\ainotice-release\release\ainotice-chrome.zip`

Current verified package (deterministic; promoted AG-PROMPT-361):
- 11 files, `manifest.json` at ZIP root, no maps, no source
- SHA-256 (deterministic, reproducible): `786e465d9f8f2219140d87ad59326c08e7c316fbcbaeefe4b66edbacc500dd9d` (AG-352 readable PDF explanation, AG-353 visible warning copy, AG-356 XLSX browser extraction fix, AG-360 paste precision — ICD context gating, loopback URL downgrade, legacy fallback inversion removal. Also includes all prior: AG-350/351 keyword precision, AG-343 Copilot drag/drop, AG-344 diagnostic + paste-copy cleanup, AG-346 runtime leak cleanup, AG-347 ainotice-* namespace)
- Supersession chain: `786e465d…0dd9d` (AG-352/353/356/360/361, **current promoted**) supersedes `0051f199…c628` (AG-350/351), `ab11cf20…6ae5` (AG-343/344/346/347/348), `6ab462f5…c438` (AG-333/334), `6c74369e…b0c1` (AG-331/332), `2432c09e…6a17` (AG-326/327), AG-325 `67dcf33f…2b14`, and prior promoted release ZIP `ae34e757…0bb61` (AG-315).
- **PROMOTED (AG-361):** governed dev→release re-promotion complete; release repo advanced from `62dd471`. Release-side `build:chrome` + `package:chrome` independently reproduced the SHA above (release gate 10/10). Dev CORE 49/49. Final ZIP hygiene clean (zero old-brand/prompt-ID/agentguard; ainotice-* namespace present; MV3 valid; storage-only; connect-src 'none'). Provenance source commit `3ac37a9` (dev HEAD at promotion). Privacy: `https://www.ainotice.app/privacy/`. Screenshot set: AG-338.
- Packaging is deterministic (AG-311): `npm run package:chrome` reproduces this exact SHA from identical `dist/chrome`.
- The release allow-list includes `scripts/test-consumer-modal-no-admin-license-copy.ts` (fixed AG-329), so release-side `npm run build:chrome` runs clean (release gate 10/10).

---

## Step 3 — Inspect before upload

Verify the manifest name and version:

```
cat dist/chrome/manifest.json | grep '"name"\|"version"'
```

Expected:
- `"name": "Ai Notice"`
- `"manifest_version": 3`

Verify visible brand surfaces:
- `dist/chrome/popup.html` — title and `<h1>` heading should say **Ai Notice**
- `dist/chrome/warning-modal.html` — `<title>` should say **Ai Notice - Review before sharing**

Confirm no source maps in build:

```
npx tsx -e "const fs=require('fs'); const maps=fs.readdirSync('dist/chrome').filter(f=>f.endsWith('.map')); console.log(maps.length===0?'PASS: no maps':'FAIL:'+maps);"
```

Or check via the packaging script output — it fails on maps automatically.

---

## Step 4 — Upload to Chrome Web Store (manual)

1. Open [Chrome Developer Dashboard](https://chrome.google.com/webstore/devconsole)
2. Create a new item or update the existing listing
3. Upload `release/ainotice-chrome.zip`
4. Do **not** upload `dist/chrome/` directly — the dashboard requires a ZIP
5. Enter listing copy + questionnaire answers from
   [`docs/CHROME-WEB-STORE-UPLOAD-PACKET.md`](CHROME-WEB-STORE-UPLOAD-PACKET.md)

> The upload is a **manual, human action**. It has **not** occurred. Do not imply
> publication or Google approval has happened.

### Current upload blockers (as of AG-361)

- **Google developer account approval — status provided by operator.** No upload may proceed until confirmed.
- **Screenshots — AG-338 production-quality screenshot set approved.** Operator must confirm set is available before upload.
- **Privacy policy URL:** `https://www.ainotice.app/privacy/` — confirmed in AG-361 provenance.

---

## Known deferred technical residue (non-blocking)

These internal identifiers remain in the build. They are not user-visible and do not block CWS submission under the visible-brand-clean standard:

| Category | Examples | Count |
|----------|----------|------:|
| CSS classes | `.agentguard-overlay`, `.agentguard-modal-*` | ~350 |
| DOM IDs | `agentguard-modal-root` | 1 |
| Console prefixes (`warn`/`error`) | `[AgentGuard]` | 41 |
| Internal debug keys | `__AGENTGUARD_DEBUG_SAFE` | 2 |
| Internal JS property | `agentguardAttached` | 2 |

These are Tier-0 technical selectors and identifiers wired to extension interception/modal logic. Renaming carries regression risk and is deferred (see AG-248/AG-249 for rationale).

**Note (AG-279):** production `console.log` / `console.debug` are stripped from the
shipped bundles (count = 0). The `[AgentGuard]` prefixes above remain only on generic
`console.warn` / `console.error` error handlers — they carry no document, risk, or user
data. No network/telemetry surfaces are present in the shipped bundles (all = 0).

---

## Rollback / clean

If the build or package step creates local artifacts you want to remove:

```bash
# Clean build output (rebuilt on next build:chrome)
npx rimraf dist/chrome

# Remove generated ZIP
del release\ainotice-chrome.zip
```

Tracked source files are not modified by build or package scripts. `git status -sb` should show only `dist/` and `release/` entries (both gitignored) after packaging.

---

## What NOT to submit

- Do **not** upload `dist/chrome/` as a folder — upload the ZIP
- Do **not** submit `*.map` files (packaging script blocks this)
- Do **not** submit any content from `mnt/`, `out/`, or `tests/fixtures/corpus/`
- Do **not** submit raw source — the ZIP contains only compiled output
