#!/usr/bin/env npx tsx
/**
 * test-no-consumer-stats-persistence.ts (AG-PROMPT-259)
 *
 * Privacy invariant: the consumer Ai Notice runtime must not persist aggregate
 * scan/outcome/frame/severity counters and must not echo document-matched
 * vocabulary tokens, markers, or filenames into logs.
 *
 * This is a static source-assertion test (no browser APIs). It proves the
 * AG-259 remediation holds and guards against regression.
 *
 * Run: npx tsx scripts/test-no-consumer-stats-persistence.ts
 */

import assert from 'node:assert/strict';
import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { resolve, join } from 'node:path';

const ROOT = resolve(import.meta.dirname, '..');
const SRC = join(ROOT, 'src');

let passed = 0;
let failed = 0;
const failures: string[] = [];

function test(name: string, fn: () => void): void {
  try {
    fn();
    passed++;
    console.log(`  PASS: ${name}`);
  } catch (e) {
    failed++;
    const msg = e instanceof Error ? e.message : String(e);
    failures.push(`${name}: ${msg}`);
    console.log(`  FAIL: ${name} — ${msg}`);
  }
}

/** Recursively collect all .ts/.tsx files under a directory. */
function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) {
      out.push(...walk(p));
    } else if (entry.endsWith('.ts') || entry.endsWith('.tsx')) {
      out.push(p);
    }
  }
  return out;
}

const allSrc = walk(SRC);

console.log('\n=== A: Stats persistence removed ===');

test('A.1 src/stats/outcomeCounters.ts no longer exists', () => {
  assert.ok(!existsSync(join(SRC, 'stats', 'outcomeCounters.ts')),
    'outcomeCounters.ts must be deleted (consumer stats persistence removed)');
});

test("A.2 no source file references the 'ainotice_stats_v1' storage key", () => {
  const hits = allSrc.filter(f => readFileSync(f, 'utf-8').includes('ainotice_stats_v1'));
  assert.equal(hits.length, 0,
    `No source may reference ainotice_stats_v1; found in: ${hits.map(f => f.replace(SRC, 'src')).join(', ')}`);
});

test('A.3 no source file references the removed stats module/symbols', () => {
  const banned = ['outcomeCounters', 'incrementOutcome', 'exportStats', 'resetStats'];
  for (const sym of banned) {
    const hits = allSrc.filter(f => readFileSync(f, 'utf-8').includes(sym));
    assert.equal(hits.length, 0,
      `No source may reference '${sym}'; found in: ${hits.map(f => f.replace(SRC, 'src')).join(', ')}`);
  }
});

test('A.4 featureFlags.ts has no ff_stats_counters_v1', () => {
  const ff = readFileSync(join(SRC, 'config', 'featureFlags.ts'), 'utf-8');
  assert.ok(!ff.includes('ff_stats_counters_v1'),
    'ff_stats_counters_v1 must be removed from featureFlags');
});

console.log('\n=== B: No token/marker/filename echo in consumer logs ===');

const contentSrc = readFileSync(join(SRC, 'content', 'index.ts'), 'utf-8');
const metaSrc = readFileSync(join(SRC, 'content', 'metadataExtractor.ts'), 'utf-8');

test('B.1 content/index.ts does not join matchedTokens into a log', () => {
  assert.ok(!/matchedTokens\.join/.test(contentSrc),
    'matchedTokens values must not be echoed (use a count instead)');
});

test('B.2 content/index.ts does not join matchedMarkers into a log', () => {
  assert.ok(!/matchedMarkers\.slice\([^)]*\)\.join/.test(contentSrc),
    'matchedMarkers values must not be echoed (use a count instead)');
});

test('B.3 metadataExtractor.ts console logs do not echo file.name', () => {
  const consoleCalls = metaSrc.match(/console\.(log|warn|error|info|debug)\([^;]*\)/gs) || [];
  const leaks = consoleCalls.filter(c => /file\.name/.test(c));
  assert.equal(leaks.length, 0,
    `metadataExtractor console logs must not echo file.name (found ${leaks.length})`);
});

console.log('\n=== C: No exportable support/diagnostic bundle ===');

test('C.1 src/support/supportBundle.ts no longer exists', () => {
  assert.ok(!existsSync(join(SRC, 'support', 'supportBundle.ts')),
    'supportBundle.ts must be deleted (exportable diagnostic bundle removed)');
});

test('C.2 no source exposes __AGENTGUARD_EXPORT_SUPPORT_BUNDLE or builds a support bundle', () => {
  const banned = ['__AGENTGUARD_EXPORT_SUPPORT_BUNDLE', 'buildSupportBundle', 'setLastSupportBundle', 'SupportBundleInput'];
  for (const sym of banned) {
    const hits = allSrc.filter(f => readFileSync(f, 'utf-8').includes(sym));
    assert.equal(hits.length, 0,
      `No source may reference '${sym}'; found in: ${hits.map(f => f.replace(SRC, 'src')).join(', ')}`);
  }
});

// === SUMMARY ===
console.log(`\n============================================================`);
console.log(`NO-CONSUMER-STATS-PERSISTENCE RESULTS: ${passed} passed, ${failed} failed`);
console.log(`============================================================\n`);

if (failed > 0) {
  for (const f of failures) console.log(`  - ${f}`);
  process.exit(1);
}
