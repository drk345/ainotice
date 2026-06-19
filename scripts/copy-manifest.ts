#!/usr/bin/env npx tsx
/**
 * AG-057: Copy, verify, and attest browser-specific manifest
 *
 * Copies the correct manifest to the browser-specific dist folder:
 *   - dist/chrome/manifest.json (MV3)
 *   - dist/firefox/manifest.json (MV2)
 *
 * Enforcement:
 *   - Removes stale manifest.{chrome,firefox}.json from the dist folder
 *   - Verifies output matches source (byte equality)
 *   - Verifies manifest_version matches target browser
 *   - Detects Chrome-only keys in Firefox manifest (and vice versa)
 *   - Prints content-based attestation (MV + sha256) — never relies on timestamps
 *   - Exits non-zero if any check fails
 *
 * Usage:
 *   npx tsx scripts/copy-manifest.ts chrome
 *   npx tsx scripts/copy-manifest.ts firefox
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.join(__dirname, '..');

const browser = process.argv[2];

if (!browser || !['chrome', 'firefox'].includes(browser)) {
  console.error('Usage: npx tsx scripts/copy-manifest.ts <chrome|firefox>');
  process.exit(1);
}

const sourceFile = path.join(rootDir, 'public', `manifest.${browser}.json`);
const destDir = path.join(rootDir, 'dist', browser);
const destFile = path.join(destDir, 'manifest.json');

// Verify source exists
if (!fs.existsSync(sourceFile)) {
  console.error(`ERROR: Source manifest not found: ${sourceFile}`);
  process.exit(1);
}

// Ensure target dist directory exists
if (!fs.existsSync(destDir)) {
  fs.mkdirSync(destDir, { recursive: true });
}

// Copy manifest content (read+write instead of copyFile to get current timestamp
// on Windows, where CopyFileW preserves the source file's mtime)
const sourceContent = fs.readFileSync(sourceFile);
fs.writeFileSync(destFile, sourceContent);

// Remove stale browser-specific manifest copies from dist
const staleFiles = ['manifest.chrome.json', 'manifest.firefox.json'];
for (const stale of staleFiles) {
  const stalePath = path.join(destDir, stale);
  if (fs.existsSync(stalePath)) {
    fs.unlinkSync(stalePath);
  }
}

// Verify output matches source (byte equality)
const destContent = fs.readFileSync(destFile);
if (!sourceContent.equals(destContent)) {
  console.error(`ERROR: Manifest verification failed — dist/${browser}/manifest.json does not match source`);
  process.exit(1);
}

// Parse and validate manifest content
const manifest = JSON.parse(destContent.toString('utf-8'));
const expectedVersion = browser === 'firefox' ? 2 : 3;

if (manifest.manifest_version !== expectedVersion) {
  console.error(`ERROR: manifest_version is ${manifest.manifest_version}, expected ${expectedVersion} for ${browser}`);
  process.exit(1);
}

// Detect wrong-browser keys
const CHROME_ONLY_KEYS = ['service_worker', 'host_permissions'];
const FIREFOX_ONLY_KEYS = ['browser_specific_settings'];

const manifestStr = JSON.stringify(manifest);
if (browser === 'firefox') {
  for (const key of CHROME_ONLY_KEYS) {
    if (manifestStr.includes(`"${key}"`)) {
      console.error(`ERROR: Firefox manifest contains Chrome-only key "${key}"`);
      process.exit(1);
    }
  }
  if (manifest.action && !manifest.browser_action) {
    console.error('ERROR: Firefox MV2 manifest uses "action" instead of "browser_action"');
    process.exit(1);
  }
} else {
  for (const key of FIREFOX_ONLY_KEYS) {
    if (manifestStr.includes(`"${key}"`)) {
      console.error(`ERROR: Chrome manifest contains Firefox-only key "${key}"`);
      process.exit(1);
    }
  }
}

// Content-based attestation — sha256 proves correctness regardless of timestamps
const sha256 = crypto.createHash('sha256').update(destContent).digest('hex');
const mvLabel = `MV${manifest.manifest_version}`;
const topKeys = Object.keys(manifest).slice(0, 5).join(', ');

console.log('');
console.log('======================================================================');
console.log(`  Built for ${browser.toUpperCase()} (${mvLabel}) -> dist/${browser}`);
console.log(`  manifest.json: ${mvLabel} | ${sourceContent.length} bytes | sha256:${sha256.substring(0, 16)}`);
console.log(`  keys: ${topKeys}`);
console.log(`  source parity: PASS (byte-equal to public/manifest.${browser}.json)`);
console.log('======================================================================');
console.log('');
