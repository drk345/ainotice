#!/usr/bin/env npx tsx
/**
 * Chrome/Edge Build Artifact Verification (parity with test-firefox-build-artifacts.ts)
 *
 * Asserts that dist/chrome/ contains a correct, loadable MV3 extension:
 *   - manifest.json exists and is valid Chrome MV3
 *   - No Firefox-only MV2 keys contaminate Chrome build
 *   - All required static files present
 *   - manifest.json matches public/manifest.chrome.json source
 *   - web_accessible_resources are minimal and all declared resources ship
 *   - Production JS contains no console.log or console.debug calls (AG-264)
 *
 * Usage: npx tsx scripts/test-chrome-build-artifacts.ts
 *
 * Prerequisite: npm run build:chrome must have been run first.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');
const distDir = path.join(rootDir, 'dist', 'chrome');
const publicDir = path.join(rootDir, 'public');

// ============================================================================
// TEST FRAMEWORK
// ============================================================================

let passed = 0;
let failed = 0;
let skipped = 0;
const failures: string[] = [];

function assert(testId: string, condition: boolean, description: string) {
  if (condition) {
    passed++;
    console.log(`  PASS ${testId}: ${description}`);
  } else {
    failed++;
    failures.push(`${testId}: ${description}`);
    console.log(`  FAIL ${testId}: ${description}`);
  }
}

function skip(testId: string, description: string) {
  skipped++;
  console.log(`  SKIP ${testId}: ${description}`);
}

// ============================================================================
// PRECONDITION: dist/chrome must exist
// ============================================================================

if (!fs.existsSync(distDir)) {
  console.log('\n=== Chrome Build Artifact Verification ===');
  console.log(`  SKIP: dist/chrome/ does not exist — run npm run build:chrome first`);
  console.log(`\n${'='.repeat(60)}`);
  console.log(`BUILD ARTIFACT RESULTS: 0 PASS / 0 FAIL / 1 SKIP`);
  console.log(`${'='.repeat(60)}`);
  process.exit(0);
}

// ============================================================================
// A: manifest.json presence and content
// ============================================================================

console.log('\n=== A: manifest.json verification ===');

const manifestPath = path.join(distDir, 'manifest.json');
const manifestExists = fs.existsSync(manifestPath);
assert('A.1', manifestExists, 'dist/chrome/manifest.json exists');

if (manifestExists) {
  const content = fs.readFileSync(manifestPath, 'utf-8');
  let manifest: any;

  try {
    manifest = JSON.parse(content);
    assert('A.2', true, 'manifest.json is valid JSON');
  } catch {
    assert('A.2', false, 'manifest.json is valid JSON');
  }

  if (manifest) {
    assert('A.3', manifest.manifest_version === 3,
      `manifest_version is ${manifest.manifest_version} (expected 3 for Chrome MV3)`);

    assert('A.4', manifest.name === 'Ai Notice',
      `name is "${manifest.name}"`);

    assert('A.5', manifest.background?.service_worker === 'background.js',
      'Has MV3 background.service_worker = "background.js"');

    assert('A.6', !!manifest.action,
      'Has MV3 "action" key (not MV2 browser_action)');

    assert('A.7', Array.isArray(manifest.host_permissions),
      'Has MV3 host_permissions array');

    // Firefox-only key detection
    assert('A.8', !manifest.background?.scripts,
      'No Firefox-only background.scripts key');

    assert('A.9', !manifest.browser_action,
      'No Firefox-only "browser_action" key');

    assert('A.10', !manifest.browser_specific_settings,
      'No Firefox-only "browser_specific_settings" key');

    // Content-based attestation
    const sha256 = crypto.createHash('sha256').update(content).digest('hex');
    console.log(`  [attestation] manifest_version=${manifest.manifest_version} sha256:${sha256.substring(0, 16)} name=${manifest.name} version=${manifest.version}`);

    // A.11/A.12: web_accessible_resources — modal resources declared; WAR↔disk consistency
    // A.11 asserts the required modal resources are declared.
    // A.12 asserts every non-glob WAR entry actually exists on disk (catches vestigial declarations).
    const war = manifest.web_accessible_resources;
    if (Array.isArray(war)) {
      const allResources = war.flatMap((entry: any) =>
        Array.isArray(entry?.resources) ? entry.resources : []
      );
      assert('A.11', allResources.includes('warning-modal.html') && allResources.includes('warning-modal.css'),
        'web_accessible_resources declares warning-modal.html and warning-modal.css');
      const nonGlobResources = allResources.filter((r: string) => !r.includes('*'));
      const missingOnDisk = nonGlobResources.filter((r: string) => !fs.existsSync(path.join(distDir, r)));
      assert('A.12', missingOnDisk.length === 0,
        missingOnDisk.length === 0
          ? 'all non-glob WAR resources exist on disk'
          : `WAR declares resources not present in dist/chrome/: ${missingOnDisk.join(', ')}`);
    } else {
      assert('A.11', false, 'web_accessible_resources is an array');
      skip('A.12', 'web_accessible_resources missing');
    }
  }

  // A.13: Source parity — dist manifest matches public/manifest.chrome.json
  const sourcePath = path.join(publicDir, 'manifest.chrome.json');
  if (fs.existsSync(sourcePath)) {
    const sourceContent = fs.readFileSync(sourcePath);
    const distContent = fs.readFileSync(manifestPath);
    assert('A.13', sourceContent.equals(distContent),
      'dist/chrome/manifest.json matches public/manifest.chrome.json (byte-equal)');
  } else {
    skip('A.13', 'public/manifest.chrome.json not found');
  }
} else {
  skip('A.2-A.13', 'manifest.json missing');
}

// ============================================================================
// B: No stale manifest copies
// ============================================================================

console.log('\n=== B: No stale manifest copies ===');

assert('B.1', !fs.existsSync(path.join(distDir, 'manifest.chrome.json')),
  'No stale manifest.chrome.json in dist/chrome/');

assert('B.2', !fs.existsSync(path.join(distDir, 'manifest.firefox.json')),
  'No stale manifest.firefox.json in dist/chrome/');

// ============================================================================
// C: Required build artifacts
// ============================================================================

console.log('\n=== C: Required build artifacts ===');

const requiredFiles = [
  'content.js',
  'background.js',
  'popup.html',
  'warning-modal.css',
  'warning-modal.html',
];

for (let i = 0; i < requiredFiles.length; i++) {
  const file = requiredFiles[i];
  const exists = fs.existsSync(path.join(distDir, file));
  assert(`C.${i + 1}`, exists, `${file} exists in dist/chrome/`);
}

// C.6: icons directory
assert('C.6', fs.existsSync(path.join(distDir, 'icons')),
  'icons/ directory exists in dist/chrome/');

// ============================================================================
// D: Production JS console.log invariant (AG-264)
// ============================================================================
//
// AG-AUDIT-FIX-004: vite.content.config.ts and vite.background.config.ts set
// terser pure_funcs: ['console.log', 'console.debug'], which removes those
// calls from the shipped bundle. This invariant asserts the strip is active.
//
// Rationale: scan/risk/debug console.log diagnostics in source back the
// Consumer Edition no-activity-record promise. If the strip were removed,
// those calls would begin emitting per-document activity to the console.
//
// console.warn and console.error are NOT checked here — they are retained
// intentionally for generic error handling only (no document content or
// risk data logged via warn/error per AG-AUDIT-FIX-004 review).
//
// Note: bundles are minified (comments stripped), so the string scan below
// is conservative — any console.log( match in minified code is a real call.

console.log('\n=== D: Production JS console.log invariant ===');

const jsArtifacts = ['content.js', 'background.js'];

for (let i = 0; i < jsArtifacts.length; i++) {
  const fileName = jsArtifacts[i];
  const filePath = path.join(distDir, fileName);

  if (!fs.existsSync(filePath)) {
    skip(`D.${i * 2 + 1}`, `${fileName} not found — skipping console.log check`);
    skip(`D.${i * 2 + 2}`, `${fileName} not found — skipping console.debug check`);
    continue;
  }

  const source = fs.readFileSync(filePath, 'utf-8');
  const logMatches = (source.match(/console\.log\(/g) ?? []).length;
  const debugMatches = (source.match(/console\.debug\(/g) ?? []).length;

  assert(
    `D.${i * 2 + 1}`,
    logMatches === 0,
    logMatches === 0
      ? `${fileName}: console.log( = 0 (terser strip active)`
      : `${fileName}: console.log( = ${logMatches} — terser strip may be broken (pure_funcs)`
  );

  assert(
    `D.${i * 2 + 2}`,
    debugMatches === 0,
    debugMatches === 0
      ? `${fileName}: console.debug( = 0 (terser strip active)`
      : `${fileName}: console.debug( = ${debugMatches} — terser strip may be broken (pure_funcs)`
  );
}

// ============================================================================
// SUMMARY
// ============================================================================

console.log(`\n${'='.repeat(60)}`);
console.log(`BUILD ARTIFACT RESULTS: ${passed} PASS / ${failed} FAIL / ${skipped} SKIP`);
console.log(`${'='.repeat(60)}`);

if (failures.length > 0) {
  console.log('\nFailures:');
  for (const f of failures) {
    console.log(`  - ${f}`);
  }
}

process.exit(failed > 0 ? 1 : 0);
