# Ai Notice

Local-only risk awareness for AI tool uploads. Ai Notice shows a warning before
you share sensitive files or pasted text with AI tools like ChatGPT, Claude,
Copilot, and Gemini — so you can decide before content leaves your device.

## Philosophy

**Awareness-first, not enforcement.** Ai Notice informs you of potential risk
and preserves your decision. It is not a DLP system and not a gatekeeper.

## Key Features

- **Local-only processing**: All analysis happens in your browser. No data is transmitted by Ai Notice.
- **Privacy-first local warnings**: Warns locally, then forgets — no logs, no history.
- **Content analysis**: PDF, DOCX, XLSX, PPTX, and 40+ text-based formats.
- **Pattern-based detection**: Risk pattern packs organized by domain.
- **Offline license validation**: Ed25519-signed tokens, no phone-home (enterprise editions; the consumer build runs without a license).
- **User agency preservation**: Awareness notifications, not blocking.

## Privacy

- No data collection, transmission, telemetry, or analytics
- No audit logs, no decision history, no usage stats
- Local-only processing; storage limited to settings/preferences and local license/config
- See [PRIVACY.md](PRIVACY.md) for the full policy

## Build

```bash
npm ci
npm run build:chrome      # outputs dist/chrome/
npm run package:chrome    # outputs release/ainotice-chrome.zip
```

## Loading in Chrome

1. Build: `npm run build:chrome`
2. Open `chrome://extensions` and enable Developer mode
3. Click "Load unpacked" and select the `dist/chrome/` directory

## Verification

```bash
npx tsx scripts/release-verify.ts
```

## Provenance

This repository is generated from the Ai Notice development repository by an
allow-list promotion export. See [RELEASE_PROVENANCE.json](RELEASE_PROVENANCE.json)
for the exact source commit. Do not develop directly in this repository — see
[CONTRIBUTING.md](CONTRIBUTING.md).
