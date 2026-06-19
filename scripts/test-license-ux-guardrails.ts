#!/usr/bin/env npx tsx
/**
 * AG-PROMPT-LICENSE-UX-002: License UX Guardrails
 *
 * Ensures license messaging never appears as host-page injection.
 * All license UI must be inside AgentGuard surfaces (modal, popup).
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

// Load source files
// index.ts: interception, orchestration, getLicenseNoticeHtml, guardrail comments
// modalStyles.ts: CSS for .agentguard-license-status (moved out of index.ts in AG-PROMPT-134 refactor)
// uiComponents.ts: buildLicenseNotice + licenseNotice DOM composition (moved in same refactor)
const contentScriptPath = path.join(rootDir, 'src', 'content', 'index.ts');
const contentScript = fs.readFileSync(contentScriptPath, 'utf-8');

const modalStylesPath = path.join(rootDir, 'src', 'content', 'modalStyles.ts');
const modalStyles = fs.readFileSync(modalStylesPath, 'utf-8');

const uiComponentsPath = path.join(rootDir, 'src', 'content', 'uiComponents.ts');
const uiComponents = fs.readFileSync(uiComponentsPath, 'utf-8');

console.log('\n======================================================================');
console.log('AG-PROMPT-LICENSE-UX-002: License UX Guardrails');
console.log('======================================================================\n');

console.log('Test Suite: No Host-Page License Banner Injection');
{
  test('No element with id "agentguard-license-banner" created', () => {
    // The old code created: banner.id = 'agentguard-license-banner'
    const hasLicenseBannerId = /['"]agentguard-license-banner['"]/.test(contentScript);
    // Allow it in comments but not in actual code
    const lines = contentScript.split('\n');
    const codeLines = lines.filter(line => {
      const trimmed = line.trim();
      return !trimmed.startsWith('//') && !trimmed.startsWith('*') && !trimmed.startsWith('/*');
    });
    const codeWithoutComments = codeLines.join('\n');
    const hasInCode = /\.id\s*=\s*['"]agentguard-license-banner['"]/.test(codeWithoutComments);
    assert(!hasInCode, 'Found agentguard-license-banner ID assignment in code');
  });

  test('No document.body.appendChild for license banner', () => {
    // The old pattern was: document.body.appendChild(banner); licenseBannerElement = banner;
    const hasLicenseBannerAppend = /document\.body\.appendChild\([^)]*banner[^)]*\)[\s\S]{0,50}licenseBannerElement/.test(contentScript);
    assert(!hasLicenseBannerAppend, 'Found document.body.appendChild for license banner');
  });

  test('No showLicenseBanner function that injects to body', () => {
    // Old function signature: function showLicenseBanner(state: 'expired' | 'invalid')
    // with document.body.appendChild inside
    const hasOldShowLicenseBanner = /function showLicenseBanner[\s\S]{0,500}document\.body\.appendChild/.test(contentScript);
    assert(!hasOldShowLicenseBanner, 'Found showLicenseBanner function with body injection');
  });

  test('HOST_PAGE_BANNERS_FOR_LICENSE = forbidden comment exists', () => {
    const hasForbiddenComment = /HOST_PAGE_BANNERS_FOR_LICENSE\s*=\s*forbidden/.test(contentScript);
    assert(hasForbiddenComment, 'Missing HOST_PAGE_BANNERS_FOR_LICENSE = forbidden guardrail comment');
  });
}

console.log('\nTest Suite: License Status Inside Modal Only');
{
  test('getLicenseNoticeHtml function exists', () => {
    const hasFunction = /function getLicenseNoticeHtml\(\)/.test(contentScript);
    assert(hasFunction, 'Missing getLicenseNoticeHtml function');
  });

  test('License status uses agentguard-license-status class (demoted styling)', () => {
    const hasStatusClass = /agentguard-license-status/.test(contentScript);
    assert(hasStatusClass, 'Missing agentguard-license-status class');
  });

  test('License status inserted into modal HTML', () => {
    // After AG-PROMPT-134 refactor, licenseNotice is a DOM element built in uiComponents.ts
    // and included in the modal overlay tree — not a template literal in index.ts.
    const hasLicenseBuild = /buildLicenseNotice\(/.test(uiComponents);
    const hasLicenseInOverlay = /licenseNotice/.test(uiComponents);
    assert(hasLicenseBuild && hasLicenseInOverlay,
      'License status not built/included in modal (expected buildLicenseNotice + licenseNotice in uiComponents.ts)');
  });

  test('License status CSS has no background or border (status indicator, not warning)', () => {
    // After AG-PROMPT-134 refactor, .agentguard-license-status CSS lives in modalStyles.ts
    const cssMatch = modalStyles.match(/\.agentguard-license-status\s*\{[^}]+\}/);
    if (!cssMatch) {
      throw new Error('Could not find .agentguard-license-status CSS in modalStyles.ts');
    }
    const css = cssMatch[0];
    const hasBackground = /background\s*:/.test(css);
    const hasBorder = /border\s*:/.test(css);
    assert(!hasBackground, 'License status CSS should not have background');
    assert(!hasBorder, 'License status CSS should not have border');
  });
}

console.log('\nTest Suite: Visual Hierarchy Invariant');
{
  test('INVARIANT comment about license not competing with document classification', () => {
    // After AG-PROMPT-134 refactor, this INVARIANT comment lives in modalStyles.ts
    // alongside the .agentguard-license-status CSS block.
    const hasInvariant = /INVARIANT:.*license.*never.*compete.*document.*classification/is.test(modalStyles);
    assert(hasInvariant, 'Missing INVARIANT comment about license not competing with document classification (expected in modalStyles.ts)');
  });

  test('License status font-size is smaller than headline (11px)', () => {
    // After AG-PROMPT-134 refactor, CSS lives in modalStyles.ts
    const cssMatch = modalStyles.match(/\.agentguard-license-status\s*\{[^}]+\}/);
    if (!cssMatch) {
      throw new Error('Could not find .agentguard-license-status CSS in modalStyles.ts');
    }
    const fontSizeMatch = cssMatch[0].match(/font-size:\s*(\d+)px/);
    assert(fontSizeMatch !== null, 'License status should have explicit font-size');
    const fontSize = parseInt(fontSizeMatch[1], 10);
    assert(fontSize <= 12, `License status font-size should be small (got ${fontSize}px)`);
  });

  test('License status uses muted color (slate/gray)', () => {
    // After AG-PROMPT-134 refactor, CSS lives in modalStyles.ts
    // Color may be a hex literal (#64748b) or a CSS variable reference (var(--ag-text-label))
    // that resolves to a muted slate color — both are acceptable.
    const cssMatch = modalStyles.match(/\.agentguard-license-status\s*\{[^}]+\}/);
    if (!cssMatch) {
      throw new Error('Could not find .agentguard-license-status CSS in modalStyles.ts');
    }
    const css = cssMatch[0];
    // Hex muted slate colors (#64748b, #475569, etc.) OR CSS variable referencing design-system text label
    const hasMutedHex = /#[456789][0-9a-f]{5}/i.test(css);
    const hasMutedVar = /color:\s*var\(--ag-text(?:-label|-primary|-secondary)?\)/.test(css);
    assert(hasMutedHex || hasMutedVar, 'License status should use muted slate/gray color (hex or ag-text CSS variable)');
  });
}

console.log('\nTest Suite: Attribution-Safe Copy');
{
  test('License message uses Ai Notice product name', () => {
    // Check the getLicenseNoticeHtml function content
    const functionMatch = contentScript.match(/function getLicenseNoticeHtml[\s\S]*?^}/m);
    if (!functionMatch) {
      throw new Error('Could not find getLicenseNoticeHtml function');
    }
    const functionBody = functionMatch[0];

    // The message content should use the Ai Notice brand name (AG-263: renamed from AgentGuard)
    const hasAiNoticeStart = />\s*Ai Notice\s+is\s+operating/s.test(functionBody);
    assert(hasAiNoticeStart, 'License message should start with "Ai Notice is operating"');
  });

  test('License message mentions Courtesy Mode', () => {
    const functionMatch = contentScript.match(/function getLicenseNoticeHtml[\s\S]*?^}/m);
    if (!functionMatch) {
      throw new Error('Could not find getLicenseNoticeHtml function');
    }
    const hasCourtesyMode = /Courtesy Mode/i.test(functionMatch[0]);
    assert(hasCourtesyMode, 'License message should mention "Courtesy Mode"');
  });

  test('License message mentions contacting administrator', () => {
    const functionMatch = contentScript.match(/function getLicenseNoticeHtml[\s\S]*?^}/m);
    if (!functionMatch) {
      throw new Error('Could not find getLicenseNoticeHtml function');
    }
    // AG-PROMPT-SURFACE-AND-LICENSE-003: Prefer "administrator" over "license holder"
    const hasContact = /contact.*administrator/i.test(functionMatch[0]);
    assert(hasContact, 'License message should mention contacting administrator');
  });

  test('No alarming language in license copy', () => {
    const functionMatch = contentScript.match(/function getLicenseNoticeHtml[\s\S]*?^}/m);
    if (!functionMatch) {
      throw new Error('Could not find getLicenseNoticeHtml function');
    }
    const functionBody = functionMatch[0].toLowerCase();

    const alarmingWords = ['warning', 'danger', 'attack', 'blocked', 'urgent', 'critical', 'alert'];
    for (const word of alarmingWords) {
      assert(!functionBody.includes(word),
        `Found alarming word "${word}" in license copy`);
    }
  });
}

console.log('\nTest Suite: Popup License Display');
{
  const popupPath = path.join(rootDir, 'src', 'popup', 'Popup.tsx');
  const popupContent = fs.readFileSync(popupPath, 'utf-8');

  test('Popup shows license status badge', () => {
    const hasBadge = /Active|Courtesy Mode|Inactive/.test(popupContent);
    assert(hasBadge, 'Popup missing license status badge text');
  });

  test('Popup does not show countdown days in UI strings', () => {
    // Filter out comment lines
    const lines = popupContent.split('\n');
    const codeLines = lines.filter(line => {
      const trimmed = line.trim();
      return !trimmed.startsWith('//') && !trimmed.startsWith('*') && !trimmed.startsWith('/*');
    });
    const codeOnly = codeLines.join('\n');

    // Check for countdown patterns in string literals only
    const stringLiterals = codeOnly.match(/'[^']*'|"[^"]*"|`[^`]*`/g) || [];
    for (const str of stringLiterals) {
      const hasCountdown = /days?\s+(left|remaining)/i.test(str);
      assert(!hasCountdown, `Popup contains countdown language: ${str}`);
    }
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
  console.log('\n✓ ALL LICENSE UX GUARDRAILS PASSED');
  process.exit(0);
}
