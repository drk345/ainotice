# Chrome Web Store Submission Checklist

**Extension:** Ai Notice
**Submission standard:** Visible-brand-clean (AG-249)
**Last updated:** 2026-06-17 (AG-250)

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

**ZIP path:** `release/ainotice-chrome.zip`

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

## Step 4 — Upload to Chrome Web Store

1. Open [Chrome Developer Dashboard](https://chrome.google.com/webstore/devconsole)
2. Create a new item or update the existing listing
3. Upload `release/ainotice-chrome.zip`
4. Do **not** upload `dist/chrome/` directly — the dashboard requires a ZIP

---

## Known deferred technical residue (non-blocking)

These internal identifiers remain in the build. They are not user-visible and do not block CWS submission under the visible-brand-clean standard:

| Category | Examples | Count |
|----------|----------|------:|
| CSS classes | `.agentguard-overlay`, `.agentguard-modal-*` | ~350 |
| DOM IDs | `agentguard-modal-root` | ~10 |
| Console log prefixes | `[AgentGuard]` | 46 |
| Internal debug keys | `__AGENTGUARD_DEBUG_SAFE` | 2 |
| Internal JS property | `agentguardAttached` | 2 |

These are Tier-0 technical selectors and identifiers wired to extension interception/modal logic. Renaming carries regression risk and is deferred (see AG-248/AG-249 for rationale).

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
