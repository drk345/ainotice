#!/usr/bin/env npx tsx
/**
 * AG-PROMPT-320: Consumer Modal — No Admin/License/Trial Copy (Shipped-Artifact Guard)
 *
 * Pre-upload blocker regression guard.
 *
 * A pre-upload screenshot/manual review surfaced consumer-inappropriate license/admin
 * text in the warning modal ("Trial mode · Contact admin for full license", with a
 * dead clickable "Contact admin" link). AG-315 removed that live render path
 * (buildLicenseNotice() now returns null; the reserved enterprise notice copy lives only
 * in the never-called getLicenseNoticeHtml(), which is tree-shaken out of the bundle).
 *
 * The existing license-UX guardrail (scripts/test-license-ux-guardrails.ts) asserts on the
 * SOURCE and intentionally REQUIRES the reserved admin/Courtesy-Mode copy to exist in
 * getLicenseNoticeHtml(). It therefore cannot prove that the SHIPPED bundle is free of that
 * copy. This guard closes that gap: it asserts on the BUILT, shippable Chrome artifacts
 * (dist/chrome/content.js + dist/chrome/popup.html) so the consumer-facing freemium build
 * can never ship trial/admin/license copy or a dead admin/license link before upload.
 *
 * Scope guard: this checks VISIBLE copy and clickable affordances only. The unused CSS
 * class selector `agentguard-license-status` is explicitly allowed — it is a non-rendered
 * style hook (the element is never built), not visible text.
 *
 * Run as part of `npm run build:chrome` (every Chrome build) — see package.json.
 */

import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.join(__dirname, '..');
const distDir = path.join(rootDir, 'dist', 'chrome');
const contentPath = path.join(distDir, 'content.js');
const popupPath = path.join(distDir, 'popup.html');

interface TestResult {
  name: string;
  passed: boolean;
  error?: string;
}
const results: TestResult[] = [];

function test(name: string, fn: () => void): void {
  try {
    fn();
    results.push({ name, passed: true });
    console.log(`  ✓ ${name}`);
  } catch (e) {
    const error = e instanceof Error ? e.message : String(e);
    results.push({ name, passed: false, error });
    console.log(`  ✗ ${name}: ${error}`);
  }
}

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

console.log('\n======================================================================');
console.log('AG-PROMPT-320: Consumer Modal — No Admin/License/Trial Copy (shipped artifact)');
console.log('======================================================================\n');

// Built artifacts must exist — this guard validates the shippable bundle.
test('dist/chrome/content.js exists (run `npm run build:chrome` first)', () => {
  assert(fs.existsSync(contentPath), `Missing ${contentPath} — build the Chrome target first`);
});
test('dist/chrome/popup.html exists (run `npm run build:chrome` first)', () => {
  assert(fs.existsSync(popupPath), `Missing ${popupPath} — build the Chrome target first`);
});

const content = fs.existsSync(contentPath) ? fs.readFileSync(contentPath, 'utf-8') : '';
const popup = fs.existsSync(popupPath) ? fs.readFileSync(popupPath, 'utf-8') : '';

// Forbidden VISIBLE consumer-facing license/admin/trial *phrases*. These multi-word
// phrases are unambiguous rendered modal copy. We deliberately do NOT bare-match single
// tokens ("admin"/"administrator"/"enterprise") against the minified content.js: those
// collide with internal, never-rendered logic — e.g. the metadata author-denylist Set
// ("anonymous","unknown","user","admin","administrator",…) in src/detection/metadataSignals.ts,
// which filters generic author metadata and is not consumer-visible copy. Bare tokens are
// only safe to forbid in the static popup.html (pure visible copy, no detection logic).
// The CSS class `agentguard-license-status` is also deliberately NOT forbidden (non-rendered
// style hook, allowed residue).
const FORBIDDEN_PHRASES: Array<{ label: string; re: RegExp }> = [
  { label: 'Trial mode', re: /Trial\s*mode/i },
  { label: 'Contact admin', re: /Contact\s*admin/i },
  { label: 'for full license', re: /for\s+full\s+license/i },
  { label: 'Courtesy Mode', re: /Courtesy\s*Mode/i },
  { label: 'contact your administrator', re: /contact\s+your\s+administrator/i },
];

console.log('Shipped content.js (warning modal bundle):');
for (const { label, re } of FORBIDDEN_PHRASES) {
  test(`content.js has no "${label}" copy`, () => {
    assert(!re.test(content), `Shipped content.js contains forbidden consumer copy: "${label}"`);
  });
}

// No dead/clickable admin/license affordance (a link/button with no governed action).
console.log('\nShipped content.js (no dead clickable admin/license affordance):');
test('content.js has no inline onclick admin/license handler', () => {
  assert(!/onclick\s*=\s*["'][^"']*(?:admin|licen[sc]e)/i.test(content),
    'Shipped content.js wires an admin/license onclick handler');
});
test('content.js has no demo admin link class (gallery-admin-link)', () => {
  assert(!/gallery-admin-link/i.test(content),
    'Shipped content.js contains the demo "gallery-admin-link" clickable admin link');
});
test('content.js has no anchor/button labelled as an admin/license action', () => {
  // e.g. <a ...>Contact admin</a> or <button ...>...full license...</button>
  const linkLike = /<(?:a|button)\b[^>]*>[^<]*(?:Contact\s*admin|full\s+license|Trial\s*mode)/i;
  assert(!linkLike.test(content), 'Shipped content.js renders a clickable admin/license link');
});

// popup.html is a small static HTML file containing only consumer-visible copy (no
// detection/policy logic), so bare admin/enterprise tokens are safe and meaningful to forbid.
const FORBIDDEN_POPUP: Array<{ label: string; re: RegExp }> = [
  ...FORBIDDEN_PHRASES,
  { label: 'administrator', re: /administrator/i },
  { label: 'admin', re: /\badmin\b/i },
  { label: 'Enterprise', re: /\bEnterprise\b/i },
  { label: 'License Status', re: /License\s*Status/i },
  { label: 'full license', re: /full\s+license/i },
];

console.log('\nShipped popup.html (consumer popup):');
for (const { label, re } of FORBIDDEN_POPUP) {
  test(`popup.html has no "${label}" copy`, () => {
    assert(!re.test(popup), `Shipped popup.html contains forbidden consumer copy: "${label}"`);
  });
}

// Summary
console.log('\n======================================================================');
console.log('TEST SUMMARY');
console.log('======================================================================\n');
const passed = results.filter(r => r.passed).length;
const failed = results.filter(r => !r.passed).length;
console.log(`  Passed: ${passed}`);
console.log(`  Failed: ${failed}`);
console.log(`  Total:  ${results.length}`);

if (failed > 0) {
  console.log('\nFailed tests:');
  results.filter(r => !r.passed).forEach(r => console.log(`  - ${r.name}: ${r.error}`));
  process.exit(1);
} else {
  console.log('\n✓ CONSUMER MODAL COPY GUARD PASSED (no admin/license/trial copy in shipped bundle)');
  process.exit(0);
}
