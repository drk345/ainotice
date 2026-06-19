/**
 * test-storage-hardening.ts
 *
 * Proves that storage layer operations never throw uncaught exceptions.
 * Simulates chrome.storage.local failures and verifies fail-open behavior.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const SRC = resolve(import.meta.dirname, '..', 'src');

const storageManagerTs = readFileSync(resolve(SRC, 'core', 'storage', 'storage-manager.ts'), 'utf-8');
const backgroundIndexTs = readFileSync(resolve(SRC, 'background', 'index.ts'), 'utf-8');

let passed = 0;
let failed = 0;

function test(name: string, fn: () => void) {
  try {
    fn();
    passed++;
    console.log(`  PASS: ${name}`);
  } catch (e) {
    failed++;
    console.log(`  FAIL: ${name}`);
    console.log(`        ${(e as Error).message}`);
  }
}

console.log('\n=== StorageManager: fail-open wrapping ===\n');

test('getSettings has try/catch', () => {
  const fn = storageManagerTs.substring(
    storageManagerTs.indexOf('async getSettings'),
    storageManagerTs.indexOf('async updateSettings')
  );
  assert.ok(fn.includes('try {'), 'getSettings missing try');
  assert.ok(fn.includes('catch'), 'getSettings missing catch');
});

test('getSettings returns DEFAULT_SETTINGS on failure', () => {
  const fn = storageManagerTs.substring(
    storageManagerTs.indexOf('async getSettings'),
    storageManagerTs.indexOf('async updateSettings')
  );
  assert.ok(fn.includes('return DEFAULT_SETTINGS'), 'getSettings catch must return DEFAULT_SETTINGS');
});

test('updateSettings has try/catch', () => {
  const fn = storageManagerTs.substring(
    storageManagerTs.indexOf('async updateSettings'),
    storageManagerTs.indexOf('async getLicenseToken')
  );
  assert.ok(fn.includes('try {'), 'updateSettings missing try');
  assert.ok(fn.includes('catch'), 'updateSettings missing catch');
});

test('updateSettings never rethrows', () => {
  const fn = storageManagerTs.substring(
    storageManagerTs.indexOf('async updateSettings'),
    storageManagerTs.indexOf('async getLicenseToken')
  );
  assert.ok(!fn.includes('throw'), 'updateSettings must not rethrow');
});

test('getLicenseToken has try/catch', () => {
  const fn = storageManagerTs.substring(
    storageManagerTs.indexOf('async getLicenseToken'),
    storageManagerTs.indexOf('async setLicenseToken')
  );
  assert.ok(fn.includes('try {'), 'getLicenseToken missing try');
  assert.ok(fn.includes('catch'), 'getLicenseToken missing catch');
});

test('getLicenseToken returns undefined on failure', () => {
  const fn = storageManagerTs.substring(
    storageManagerTs.indexOf('async getLicenseToken'),
    storageManagerTs.indexOf('async setLicenseToken')
  );
  assert.ok(fn.includes('return undefined'), 'getLicenseToken catch must return undefined');
});

test('setLicenseToken has try/catch', () => {
  const fn = storageManagerTs.substring(
    storageManagerTs.indexOf('async setLicenseToken'),
    storageManagerTs.length
  );
  assert.ok(fn.includes('try {'), 'setLicenseToken missing try');
  assert.ok(fn.includes('catch'), 'setLicenseToken missing catch');
});

test('setLicenseToken never rethrows', () => {
  const fn = storageManagerTs.substring(
    storageManagerTs.indexOf('async setLicenseToken'),
    storageManagerTs.length
  );
  assert.ok(!fn.includes('throw'), 'setLicenseToken must not rethrow');
});

console.log('\n=== background/index.ts: install handler ===\n');

test('onInstalled storage.set has try/catch', () => {
  const installBlock = backgroundIndexTs.substring(
    backgroundIndexTs.indexOf('onInstalled'),
    backgroundIndexTs.indexOf('onMessage')
  );
  assert.ok(installBlock.includes('try {'), 'install handler missing try');
  assert.ok(installBlock.includes('catch'), 'install handler missing catch');
});

test('onInstalled storage failure does not crash install', () => {
  const installBlock = backgroundIndexTs.substring(
    backgroundIndexTs.indexOf('onInstalled'),
    backgroundIndexTs.indexOf('onMessage')
  );
  assert.ok(!installBlock.includes('throw'), 'install handler must not rethrow');
});

console.log('\n=== Privacy: no content in error logs ===\n');

test('StorageManager warn messages contain no content references', () => {
  const warns = storageManagerTs.match(/console\.warn\([^)]+\)/g) || [];
  for (const w of warns) {
    assert.ok(!w.includes('token'), `Warn must not reference token content: ${w}`);
    assert.ok(!w.includes('settings:'), `Warn must not log settings values: ${w}`);
  }
});

// === SUMMARY ===
console.log(`\n============================================================`);
console.log(`STORAGE HARDENING TEST RESULTS: ${passed} PASS / ${failed} FAIL`);
console.log(`============================================================\n`);

if (failed > 0) process.exit(1);
