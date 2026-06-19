#!/usr/bin/env npx tsx
/**
 * Unit tests for src/core/storage/storage-manager.ts
 *
 * Tests StorageManager API with a deterministic chrome.storage.local mock.
 * No real browser APIs needed — pure unit tests.
 *
 * Usage: npx tsx scripts/test-storage-manager.ts
 */

import assert from 'node:assert/strict';

// ============================================================================
// MOCK: chrome.storage.local
// ============================================================================

const mockStore: Record<string, unknown> = {};

const chromeStorageLocal = {
  async get(key: string) {
    return { [key]: mockStore[key] };
  },
  async set(items: Record<string, unknown>) {
    Object.assign(mockStore, items);
  },
};

// Install global chrome mock before importing StorageManager
(globalThis as any).chrome = {
  storage: { local: chromeStorageLocal },
};

// Now import after mock is installed
const { StorageManager } = await import('../src/core/storage/storage-manager.js');
const { DEFAULT_SETTINGS } = await import('../src/core/storage/settings.js');

// ============================================================================
// TEST FRAMEWORK
// ============================================================================

let passed = 0;
let failed = 0;
const failures: string[] = [];

async function test(name: string, fn: () => Promise<void>) {
  // Reset store before each test
  for (const key of Object.keys(mockStore)) {
    delete mockStore[key];
  }
  try {
    await fn();
    passed++;
    console.log(`  PASS: ${name}`);
  } catch (e) {
    failed++;
    const msg = e instanceof Error ? e.message : String(e);
    failures.push(`${name}: ${msg}`);
    console.log(`  FAIL: ${name} — ${msg}`);
  }
}

// ============================================================================
// A: Default values
// ============================================================================

console.log('\n=== A: Default values ===');

await test('A.1 getSettings returns DEFAULT_SETTINGS when store is empty', async () => {
  const sm = new StorageManager();
  const settings = await sm.getSettings();
  assert.deepStrictEqual(settings, DEFAULT_SETTINGS);
});

await test('A.2 DEFAULT_SETTINGS has expected shape', async () => {
  assert.equal(typeof DEFAULT_SETTINGS.restrictedMode, 'boolean');
  assert.ok(Array.isArray(DEFAULT_SETTINGS.enabledPacks));
  assert.ok(Array.isArray(DEFAULT_SETTINGS.customPatterns));
  assert.ok(Array.isArray(DEFAULT_SETTINGS.globalExemptions));
});

await test('A.3 DEFAULT_SETTINGS has no audit logging field (consumer build)', async () => {
  assert.ok(!('auditLoggingEnabled' in DEFAULT_SETTINGS),
    'Audit logging must not exist in consumer settings (AG-256: removed from consumer runtime)');
});

// ============================================================================
// B: Set / Get roundtrip
// ============================================================================

console.log('\n=== B: Set / Get roundtrip ===');

await test('B.1 updateSettings persists partial updates', async () => {
  const sm = new StorageManager();
  await sm.updateSettings({ restrictedMode: true });
  const settings = await sm.getSettings();
  assert.equal(settings.restrictedMode, true);
  // Other fields preserved from defaults
  assert.deepStrictEqual(settings.enabledPacks, DEFAULT_SETTINGS.enabledPacks);
});

await test('B.2 updateSettings merges with existing settings', async () => {
  const sm = new StorageManager();
  await sm.updateSettings({ restrictedMode: true });
  await sm.updateSettings({ enabledPacks: ['pack-x'] });
  const settings = await sm.getSettings();
  assert.equal(settings.restrictedMode, true, 'first update preserved');
  assert.deepStrictEqual(settings.enabledPacks, ['pack-x'], 'second update applied');
});

await test('B.3 updateSettings with enabledPacks array', async () => {
  const sm = new StorageManager();
  await sm.updateSettings({ enabledPacks: ['pack-a', 'pack-b'] });
  const settings = await sm.getSettings();
  assert.deepStrictEqual(settings.enabledPacks, ['pack-a', 'pack-b']);
});

// ============================================================================
// C: License token
// ============================================================================

console.log('\n=== C: License token ===');

await test('C.1 getLicenseToken returns undefined when not set', async () => {
  const sm = new StorageManager();
  const token = await sm.getLicenseToken();
  assert.equal(token, undefined);
});

await test('C.2 setLicenseToken / getLicenseToken roundtrip', async () => {
  const sm = new StorageManager();
  await sm.setLicenseToken({ key: 'test-key-123', valid: true });
  const token = await sm.getLicenseToken();
  assert.deepStrictEqual(token, { key: 'test-key-123', valid: true });
});

// ============================================================================
// D: Isolation between instances
// ============================================================================

console.log('\n=== D: Isolation ===');

await test('D.1 Multiple StorageManager instances share same backing store', async () => {
  const sm1 = new StorageManager();
  const sm2 = new StorageManager();
  await sm1.updateSettings({ restrictedMode: true });
  const settings = await sm2.getSettings();
  assert.equal(settings.restrictedMode, true,
    'Second instance sees first instance writes');
});

// ============================================================================
// SUMMARY
// ============================================================================

console.log(`\n${'='.repeat(60)}`);
console.log(`STORAGE-MANAGER RESULTS: ${passed} passed, ${failed} failed`);
console.log(`${'='.repeat(60)}`);

if (failures.length > 0) {
  console.log('\nFailures:');
  for (const f of failures) {
    console.log(`  - ${f}`);
  }
  process.exit(1);
}

process.exit(0);
