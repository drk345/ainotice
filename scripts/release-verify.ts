#!/usr/bin/env npx tsx
/**
 * AG-270: Release-Side Verification Gate (self-contained)
 *
 * Runs the full Chrome consumer release gate INSIDE a release repo (or the
 * dev repo). It is self-contained: it only invokes scripts present in the
 * release allow-list (see docs/RELEASE-REPO-PROMOTION-PLAN.md §2.4) plus the
 * standard npm build/package scripts.
 *
 * This script is PROMOTED to the release repo. It must not depend on any
 * dev-only script.
 *
 * Usage: npx tsx scripts/release-verify.ts
 * Exit:  0 = all gate steps pass, 1 = any step failed
 *
 * Gate steps (per AG-269 plan §8):
 *   - type-check            (tsc --noEmit)
 *   - build:chrome          (content + background + copy-manifest + artifact A-C + console-strip D)
 *   - package:chrome        (produces release/ainotice-chrome.zip; guards no maps/TS)
 *   - license UX guardrail
 *   - no-activity-record scan (consumer stats persistence)
 *   - message-handler safety
 *   - storage manager / storage hardening
 *   - signal-manifest integrity
 *   - manifest verification
 */

import { execSync } from 'child_process';

interface Step {
  id: string;
  name: string;
  cmd: string;
}

// Order matters: build before package; build before file-reading gates that
// inspect dist/chrome output.
const STEPS: Step[] = [
  { id: '1', name: 'type-check', cmd: 'npm run type-check' },
  { id: '2', name: 'build:chrome (+ artifact A-C + console-strip D invariant)', cmd: 'npm run build:chrome' },
  { id: '3', name: 'package:chrome (ZIP + no-maps/no-TS guards)', cmd: 'npm run package:chrome' },
  { id: '4', name: 'license UX guardrail', cmd: 'npx tsx scripts/test-license-ux-guardrails.ts' },
  { id: '5', name: 'no-activity-record (consumer stats persistence)', cmd: 'npx tsx scripts/test-no-consumer-stats-persistence.ts' },
  { id: '6', name: 'message-handler safety', cmd: 'npx tsx scripts/test-message-handler-safety.ts' },
  { id: '7', name: 'storage manager', cmd: 'npx tsx scripts/test-storage-manager.ts' },
  { id: '8', name: 'storage hardening', cmd: 'npx tsx scripts/test-storage-hardening.ts' },
  { id: '9', name: 'signal-manifest integrity', cmd: 'npx tsx scripts/test-signal-manifest-integrity.ts' },
  // AG-271: verify-manifest.ts re-added after fixing stale pdfjs-WAR assertions. It now
  // checks store-safety properties not covered by test-chrome-build-artifacts §A:
  // Ai Notice name, storage-only/no-forbidden-permissions, broad HTTPS host_permissions,
  // CSP connect-src 'none', and no vestigial pdfjs WAR. Self-contained (reads public/).
  { id: '10', name: 'manifest verification (name/permissions/CSP/WAR)', cmd: 'npx tsx scripts/verify-manifest.ts' },
];

console.log('\n=== Ai Notice Release Verification Gate ===\n');

const results: { step: Step; passed: boolean }[] = [];

for (const step of STEPS) {
  process.stdout.write(`  [${step.id}] ${step.name} ... `);
  try {
    execSync(step.cmd, { stdio: 'pipe' });
    console.log('PASS');
    results.push({ step, passed: true });
  } catch (e: any) {
    console.log('FAIL');
    const out = (e?.stdout?.toString() ?? '') + (e?.stderr?.toString() ?? '');
    // Print only the tail so failures are diagnosable without dumping full logs.
    const tail = out.split('\n').slice(-12).join('\n');
    console.log(`      --- ${step.name} output (tail) ---`);
    console.log(tail.replace(/^/gm, '      '));
    results.push({ step, passed: false });
  }
}

const passed = results.filter(r => r.passed).length;
const failed = results.filter(r => !r.passed).length;

console.log(`\n${'='.repeat(60)}`);
console.log(`RELEASE GATE: ${passed} PASS / ${failed} FAIL / ${STEPS.length} TOTAL`);
console.log(`${'='.repeat(60)}`);

if (failed > 0) {
  console.log('\nFailed steps:');
  for (const r of results.filter(r => !r.passed)) {
    console.log(`  - [${r.step.id}] ${r.step.name}`);
  }
}

process.exit(failed > 0 ? 1 : 0);
