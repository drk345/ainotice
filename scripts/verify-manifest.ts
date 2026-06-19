#!/usr/bin/env npx tsx
/**
 * AG-PROMPT-FIREFOX-MANIFEST-001: Verify browser-specific manifests
 *
 * Ensures:
 * - Chrome manifest uses MV3 with service_worker
 * - Firefox manifest uses MV2 with scripts
 * - Both have equivalent permissions and features
 */

import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.join(__dirname, '..');

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

// Load manifests
const chromeManifest = JSON.parse(
  fs.readFileSync(path.join(rootDir, 'public', 'manifest.chrome.json'), 'utf-8')
);
const firefoxManifest = JSON.parse(
  fs.readFileSync(path.join(rootDir, 'public', 'manifest.firefox.json'), 'utf-8')
);

console.log('\n======================================================================');
console.log('AG-PROMPT-FIREFOX-MANIFEST-001: Manifest Verification');
console.log('======================================================================\n');

console.log('Test Suite: Chrome Manifest (MV3)');
{
  test('Chrome uses manifest_version 3', () => {
    assert(chromeManifest.manifest_version === 3,
      `Expected 3, got ${chromeManifest.manifest_version}`);
  });

  test('Chrome has background.service_worker', () => {
    assert(chromeManifest.background?.service_worker === 'background.js',
      'Missing or incorrect service_worker');
  });

  test('Chrome does NOT have background.scripts', () => {
    assert(!chromeManifest.background?.scripts,
      'Chrome MV3 should not have background.scripts');
  });

  test('Chrome has host_permissions (MV3 style)', () => {
    assert(Array.isArray(chromeManifest.host_permissions),
      'Chrome MV3 should use host_permissions');
  });

  test('Chrome has action (MV3 style)', () => {
    assert(chromeManifest.action?.default_popup === 'popup.html',
      'Chrome MV3 should use action, not browser_action');
  });

  test('Chrome web_accessible_resources uses MV3 format', () => {
    const war = chromeManifest.web_accessible_resources;
    assert(Array.isArray(war) && war[0]?.resources,
      'Chrome MV3 web_accessible_resources should have resources array');
  });

  // AG-271: The previous two assertions required pdfjs worker + standard_fonts in
  // web_accessible_resources. That expectation is STALE — AG-252 intentionally removed
  // the vestigial pdfjs WAR and AG-266 confirmed the Chrome manifest correctly ships no
  // pdfjs WAR. The assertions below encode the CORRECT post-AG-252 state and add the
  // store-safety manifest checks (name, storage-only, host perms, CSP) that
  // test-chrome-build-artifacts.ts section A does not cover.

  test('Chrome web_accessible_resources contains only warning-modal assets', () => {
    const war = chromeManifest.web_accessible_resources;
    const allResources = (war || []).flatMap((entry: any) =>
      Array.isArray(entry?.resources) ? entry.resources : []
    );
    const expected = ['warning-modal.css', 'warning-modal.html'];
    const sorted = [...allResources].sort();
    assert(JSON.stringify(sorted) === JSON.stringify(expected),
      `Chrome WAR should be exactly warning-modal.html + warning-modal.css (got: ${allResources.join(', ') || 'none'})`);
  });

  test('Chrome web_accessible_resources has no vestigial pdfjs resources', () => {
    const war = chromeManifest.web_accessible_resources;
    const allResources = (war || []).flatMap((entry: any) =>
      Array.isArray(entry?.resources) ? entry.resources : []
    );
    const pdfjs = allResources.filter((r: string) => /pdf\.worker|standard_fonts|pdfjs/i.test(r));
    assert(pdfjs.length === 0,
      `Chrome WAR must not include vestigial pdfjs resources (found: ${pdfjs.join(', ')})`);
  });

  test('Chrome name is "Ai Notice"', () => {
    assert(chromeManifest.name === 'Ai Notice',
      `Chrome name should be "Ai Notice" (got: ${chromeManifest.name})`);
  });

  test('Chrome permissions are storage-only (no forbidden permissions)', () => {
    const perms: string[] = chromeManifest.permissions || [];
    assert(perms.length === 1 && perms[0] === 'storage',
      `Chrome permissions should be exactly ["storage"] (got: ${JSON.stringify(perms)})`);
    const forbidden = ['scripting', 'tabs', 'history', 'cookies', 'downloads', 'webRequest', 'webNavigation', 'management'];
    const present = forbidden.filter(p => perms.includes(p));
    assert(present.length === 0,
      `Chrome must not request forbidden permissions (found: ${present.join(', ')})`);
  });

  test('Chrome host_permissions include broad HTTPS', () => {
    const hp: string[] = chromeManifest.host_permissions || [];
    assert(hp.includes('https://*/*'),
      `Chrome host_permissions should include https://*/* (got: ${JSON.stringify(hp)})`);
  });

  test("Chrome CSP connect-src is 'none'", () => {
    const csp = chromeManifest.content_security_policy?.extension_pages || '';
    assert(/connect-src\s+'none'/.test(csp),
      `Chrome CSP extension_pages should set connect-src 'none' (got: ${csp || 'none'})`);
  });
}

console.log('\nTest Suite: Firefox Manifest (MV2)');
{
  test('Firefox uses manifest_version 2', () => {
    assert(firefoxManifest.manifest_version === 2,
      `Expected 2, got ${firefoxManifest.manifest_version}`);
  });

  test('Firefox has background.scripts', () => {
    assert(Array.isArray(firefoxManifest.background?.scripts),
      'Missing background.scripts array');
    assert(firefoxManifest.background.scripts.includes('background.js'),
      'background.scripts should include background.js');
  });

  test('Firefox does NOT have background.service_worker', () => {
    assert(!firefoxManifest.background?.service_worker,
      'Firefox MV2 should not have service_worker');
  });

  test('Firefox has background.persistent = false', () => {
    assert(firefoxManifest.background?.persistent === false,
      'Firefox should use non-persistent background');
  });

  test('Firefox has browser_specific_settings.gecko', () => {
    assert(firefoxManifest.browser_specific_settings?.gecko?.id,
      'Firefox should have gecko extension ID');
  });

  test('Firefox has browser_action (MV2 style)', () => {
    assert(firefoxManifest.browser_action?.default_popup === 'popup.html',
      'Firefox MV2 should use browser_action, not action');
  });

  test('Firefox web_accessible_resources uses MV2 format', () => {
    const war = firefoxManifest.web_accessible_resources;
    assert(Array.isArray(war) && typeof war[0] === 'string',
      'Firefox MV2 web_accessible_resources should be string array');
  });

  test('Firefox permissions include host patterns (MV2 style)', () => {
    assert(firefoxManifest.permissions.includes('https://*/*'),
      'Firefox MV2 should include host patterns in permissions');
  });
}

console.log('\nTest Suite: Feature Parity');
{
  test('Both have same extension name', () => {
    assert(chromeManifest.name === firefoxManifest.name,
      `Names differ: ${chromeManifest.name} vs ${firefoxManifest.name}`);
  });

  test('Both have same version', () => {
    assert(chromeManifest.version === firefoxManifest.version,
      `Versions differ: ${chromeManifest.version} vs ${firefoxManifest.version}`);
  });

  test('Both have same content_scripts configuration', () => {
    const chromeCS = JSON.stringify(chromeManifest.content_scripts);
    const firefoxCS = JSON.stringify(firefoxManifest.content_scripts);
    assert(chromeCS === firefoxCS,
      'content_scripts configuration differs');
  });

  test('Both have storage permission', () => {
    assert(chromeManifest.permissions.includes('storage'),
      'Chrome missing storage permission');
    assert(firefoxManifest.permissions.includes('storage'),
      'Firefox missing storage permission');
  });

  test('Both have same icon configuration', () => {
    const chromeIcons = JSON.stringify(chromeManifest.icons);
    const firefoxIcons = JSON.stringify(firefoxManifest.icons);
    assert(chromeIcons === firefoxIcons,
      'Icon configuration differs');
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
  results.filter(r => !r.passed).forEach(r => {
    console.log(`  - ${r.name}: ${r.error}`);
  });
  process.exit(1);
} else {
  console.log('\n✓ ALL MANIFEST CHECKS PASSED');
  process.exit(0);
}
