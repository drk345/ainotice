#!/usr/bin/env npx tsx
/**
 * Message handler safety tests
 *
 * Tests handleMessage from src/background/message-handler.ts for:
 *   - Invalid sender rejection (SEC-02)
 *   - Invalid message format rejection
 *   - Unknown message type rejection
 *   - Internal error → graceful error response (no crash)
 *   - Valid message → success response
 *
 * Uses deterministic mocks of chrome.runtime and chrome.storage.
 * No browser required.
 *
 * Usage: npx tsx scripts/test-message-handler-safety.ts
 */

import assert from 'node:assert/strict';

// ============================================================================
// MOCK: chrome APIs
// ============================================================================

const mockStore: Record<string, unknown> = {};

const EXTENSION_ID = 'test-extension-id-abc';

(globalThis as any).chrome = {
  runtime: {
    id: EXTENSION_ID,
  },
  storage: {
    local: {
      async get(key: string) {
        return { [key]: mockStore[key] };
      },
      async set(items: Record<string, unknown>) {
        Object.assign(mockStore, items);
      },
    },
  },
};

// Suppress console.warn/error from handler during tests
const originalWarn = console.warn;
const originalError = console.error;
console.warn = () => {};
console.error = () => {};

// Import after mock is installed
const { handleMessage } = await import('../src/background/message-handler.js');

// Restore console for test output
console.warn = originalWarn;
console.error = originalError;

// ============================================================================
// TEST FRAMEWORK
// ============================================================================

let passed = 0;
let failed = 0;
const failures: string[] = [];

async function test(name: string, fn: () => Promise<void>) {
  // Reset store
  for (const key of Object.keys(mockStore)) {
    delete mockStore[key];
  }
  // Suppress handler logging during test execution
  const w = console.warn;
  const e = console.error;
  console.warn = () => {};
  console.error = () => {};
  try {
    await fn();
    passed++;
    console.warn = w;
    console.error = e;
    console.log(`  PASS: ${name}`);
  } catch (err) {
    console.warn = w;
    console.error = e;
    failed++;
    const msg = err instanceof Error ? err.message : String(err);
    failures.push(`${name}: ${msg}`);
    console.log(`  FAIL: ${name} — ${msg}`);
  }
}

function validSender(): chrome.runtime.MessageSender {
  return { id: EXTENSION_ID } as chrome.runtime.MessageSender;
}

// ============================================================================
// A: Sender validation (SEC-02)
// ============================================================================

console.log('\n=== A: Sender validation ===');

await test('A.1 Rejects message with missing sender.id', async () => {
  const resp = await handleMessage(
    { type: 'GET_SETTINGS' },
    {} as chrome.runtime.MessageSender
  );
  assert.equal(resp.success, false);
  assert.match(resp.error!, /invalid/i);
});

await test('A.2 Rejects message with wrong sender.id', async () => {
  const resp = await handleMessage(
    { type: 'GET_SETTINGS' },
    { id: 'malicious-extension' } as chrome.runtime.MessageSender
  );
  assert.equal(resp.success, false);
  assert.match(resp.error!, /invalid/i);
});

await test('A.3 Accepts message with correct sender.id', async () => {
  const resp = await handleMessage(
    { type: 'GET_SETTINGS' },
    validSender()
  );
  assert.equal(resp.success, true);
});

// ============================================================================
// B: Message format validation
// ============================================================================

console.log('\n=== B: Message format validation ===');

await test('B.1 Rejects null message', async () => {
  const resp = await handleMessage(null, validSender());
  assert.equal(resp.success, false);
  assert.match(resp.error!, /invalid/i);
});

await test('B.2 Rejects non-object message', async () => {
  const resp = await handleMessage('not-an-object', validSender());
  assert.equal(resp.success, false);
});

await test('B.3 Rejects message without type field', async () => {
  const resp = await handleMessage({ foo: 'bar' }, validSender());
  assert.equal(resp.success, false);
});

await test('B.4 Rejects unknown message type', async () => {
  const resp = await handleMessage({ type: 'HACK_THE_PLANET' }, validSender());
  assert.equal(resp.success, false);
});

// ============================================================================
// C: Error handling — handler does not crash
// ============================================================================

console.log('\n=== C: Error handling ===');

await test('C.1 GET_SETTINGS returns success with default settings', async () => {
  const resp = await handleMessage({ type: 'GET_SETTINGS' }, validSender());
  assert.equal(resp.success, true);
  assert.ok(resp.data, 'Response should include settings data');
});

await test('C.2 UPDATE_SETTINGS with valid payload succeeds', async () => {
  const resp = await handleMessage(
    { type: 'UPDATE_SETTINGS', payload: { restrictedMode: true } },
    validSender()
  );
  assert.equal(resp.success, true);
});

await test('C.3 Response always has success field (never undefined)', async () => {
  // Valid message
  const r1 = await handleMessage({ type: 'GET_SETTINGS' }, validSender());
  assert.equal(typeof r1.success, 'boolean');

  // Invalid sender
  const r2 = await handleMessage({ type: 'GET_SETTINGS' }, {} as any);
  assert.equal(typeof r2.success, 'boolean');

  // Invalid format
  const r3 = await handleMessage(null, validSender());
  assert.equal(typeof r3.success, 'boolean');
});

// ============================================================================
// D: Fail-safe — error responses are structured, not exceptions
// ============================================================================

console.log('\n=== D: Fail-safe response contract ===');

await test('D.1 Error response has success=false and error string', async () => {
  const resp = await handleMessage({ type: 'UNKNOWN_TYPE' }, validSender());
  assert.equal(resp.success, false);
  assert.equal(typeof resp.error, 'string');
  assert.ok(resp.error!.length > 0, 'Error message should not be empty');
});

await test('D.2 requestId is echoed in response', async () => {
  const resp = await handleMessage(
    { type: 'GET_SETTINGS', requestId: 'req-abc-123' },
    validSender()
  );
  assert.equal(resp.requestId, 'req-abc-123');
});

await test('D.3 DETECT_RISK returns success (handled in content script)', async () => {
  const resp = await handleMessage(
    { type: 'DETECT_RISK', payload: { fileData: new ArrayBuffer(0), fileName: 'x', fileType: 'pdf' } },
    validSender()
  );
  assert.equal(resp.success, true);
});

// ============================================================================
// E: onMessageExternal — must not be registered
// AG-PROMPT-02B: Verify no external-origin message listener exists.
// onMessageExternal accepts messages from other extensions; it must remain
// absent to prevent cross-extension injection attacks.
// ============================================================================

import * as fs from 'node:fs';
import * as path from 'node:path';

console.log('\n=== E: onMessageExternal absence ===');

await test('E.1 onMessageExternal not registered in background/index.ts', async () => {
  const indexPath = path.resolve(process.cwd(), 'src/background/index.ts');
  const source = fs.readFileSync(indexPath, 'utf-8');
  assert.ok(
    !source.includes('onMessageExternal'),
    'src/background/index.ts must not register onMessageExternal'
  );
});

await test('E.2 onMessageExternal not registered in background/message-handler.ts', async () => {
  const handlerPath = path.resolve(process.cwd(), 'src/background/message-handler.ts');
  const source = fs.readFileSync(handlerPath, 'utf-8');
  assert.ok(
    !source.includes('onMessageExternal'),
    'src/background/message-handler.ts must not register onMessageExternal'
  );
});

await test('E.3 onMessageExternal not registered in content/index.ts', async () => {
  const contentPath = path.resolve(process.cwd(), 'src/content/index.ts');
  const source = fs.readFileSync(contentPath, 'utf-8');
  assert.ok(
    !source.includes('onMessageExternal'),
    'src/content/index.ts must not register onMessageExternal'
  );
});

// ============================================================================
// F: CSP — manifest must include connect-src 'none'
// AG-PROMPT-02B: Extension pages must not make network connections.
// F.1 checks Chrome MV3 manifest (object CSP), F.2 checks Firefox MV2 manifest (string CSP).
// ============================================================================

console.log('\n=== F: Manifest CSP connect-src hardening ===');

await test("F.1 Chrome manifest extension_pages CSP includes connect-src 'none'", async () => {
  const chromePath = path.resolve(process.cwd(), 'public/manifest.chrome.json');
  const manifest = JSON.parse(fs.readFileSync(chromePath, 'utf-8'));
  const csp: string | undefined = manifest?.content_security_policy?.extension_pages;
  assert.ok(typeof csp === 'string', 'manifest.chrome.json has content_security_policy.extension_pages string');
  assert.ok(
    csp.includes("connect-src 'none'"),
    `extension_pages CSP must include connect-src 'none' — got: ${csp}`
  );
});

await test("F.2 Firefox manifest CSP string includes connect-src 'none'", async () => {
  const firefoxPath = path.resolve(process.cwd(), 'public/manifest.firefox.json');
  const manifest = JSON.parse(fs.readFileSync(firefoxPath, 'utf-8'));
  const csp: string | undefined = manifest?.content_security_policy;
  assert.ok(typeof csp === 'string', 'manifest.firefox.json has content_security_policy string');
  assert.ok(
    csp.includes("connect-src 'none'"),
    `content_security_policy must include connect-src 'none' — got: ${csp}`
  );
});

await test("F.3 Chrome manifest CSP retains script-src 'self' and object-src 'none'", async () => {
  const chromePath = path.resolve(process.cwd(), 'public/manifest.chrome.json');
  const manifest = JSON.parse(fs.readFileSync(chromePath, 'utf-8'));
  const csp: string = manifest?.content_security_policy?.extension_pages ?? '';
  assert.ok(csp.includes("script-src 'self'"), "CSP retains script-src 'self'");
  assert.ok(csp.includes("object-src 'none'"), "CSP retains object-src 'none'");
  assert.ok(csp.includes("base-uri 'none'"), "CSP retains base-uri 'none'");
  assert.ok(csp.includes("form-action 'none'"), "CSP retains form-action 'none'");
});

// ============================================================================
// SUMMARY
// ============================================================================

console.log(`\n${'='.repeat(60)}`);
console.log(`MESSAGE-HANDLER SAFETY RESULTS: ${passed} passed, ${failed} failed`);
console.log(`${'='.repeat(60)}`);

if (failures.length > 0) {
  console.log('\nFailures:');
  for (const f of failures) {
    console.log(`  - ${f}`);
  }
  process.exit(1);
}

process.exit(0);
