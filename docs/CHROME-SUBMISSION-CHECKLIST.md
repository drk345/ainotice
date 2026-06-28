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

Current verified package (deterministic; promoted AG-PROMPT-332):
- 11 files, `manifest.json` at ZIP root, no maps, no source
- SHA-256 (deterministic, reproducible): `6c74369ebb2b1114da246f0e6ed463871f7c677ee674f3fe81f3f73b0e07b0c1` (AG-331 FRAME_REVIEW_ADVISED decision-quality copy fix — removes the "couldn't determine" + "Some patterns were found" contradiction)
- Supersession chain: `6c74369e…b0c1` (AG-331, **current promoted**) supersedes `2432c09e…6a17` (AG-326/327), which superseded AG-325 `67dcf33f…2b14`, which superseded prior promoted release ZIP `ae34e757…0bb61` (AG-315).
- **PROMOTED (AG-332):** governed dev→release re-promotion complete; release repo advanced from `727077d`. Release-side `build:chrome` + `package:chrome` independently reproduced the SHA above. Provenance source commit `91e07c2` (dev HEAD at promotion).
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

### Current upload blockers (as of AG-282)

- **Google developer account approval — not confirmed.** No upload may proceed until confirmed.
- **Screenshots — not prepared.** At least one (1280×800) is required for submission.
- **Canonical privacy-policy URL — not yet confirmed.** Usable fallback now:
  `https://github.com/drk345/ainotice/blob/main/PRIVACY.md`; prefer
  `https://ainotice.app/privacy` once it is live and verified.

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
