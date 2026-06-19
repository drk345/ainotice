/**
 * AG-PHASE-3-048: Signal Manifest Integrity Guard
 *
 * Structural enforcement test that prevents signal ID drift:
 *   A. Every pack pattern ID has a corresponding signalManifest constant
 *   B. Every validation gate pattern ID exists in at least one pack
 *   C. No production code imports from deprecated registry.ts
 *   D. Signal manifest SIG_* values match pack + legacy inventory
 *
 * Run: npx tsx scripts/test-signal-manifest-integrity.ts
 */

import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Pack imports
import { GlobalPack } from '../src/detection/packs/global';
import { EnglishPack } from '../src/detection/packs/english';
import { NordicPack } from '../src/detection/packs/nordic';
import { RomancePack } from '../src/detection/packs/romance';

// Validation gate imports
import { PAYMENT_CARD_PATTERN_IDS } from '../src/detection/paymentCardValidation';
import { SWIFT_BIC_PATTERN_IDS } from '../src/detection/swiftBicValidation';
import { NATIONAL_ID_PATTERN_IDS } from '../src/detection/nationalIdValidation';
import { URL_CREDENTIAL_PATTERN_IDS } from '../src/detection/qualityGates';
import { CONFIDENTIAL_PATTERN_IDS } from '../src/detection/qualityGates';

// Signal manifest — import all SIG_* constants
import * as manifest from '../src/detection/signalManifest';

// ============================================================================
// TEST UTILITIES
// ============================================================================

let passed = 0;
let failed = 0;

function test(name: string, fn: () => void): void {
  try {
    fn();
    console.log(`  \u2713 ${name}`);
    passed++;
  } catch (e) {
    console.log(`  \u2717 ${name}`);
    console.log(`    Error: ${e}`);
    failed++;
  }
}

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

// ============================================================================
// COLLECT ALL PACK PATTERN IDs
// ============================================================================

const ALL_PACKS = [
  { name: 'global', pack: GlobalPack },
  { name: 'english', pack: EnglishPack },
  { name: 'nordic', pack: NordicPack },
  { name: 'romance', pack: RomancePack },
];

const allPackPatternIds = new Set<string>();
for (const { pack } of ALL_PACKS) {
  for (const pattern of pack.patterns) {
    allPackPatternIds.add(pattern.id);
  }
}

// ============================================================================
// COLLECT ALL MANIFEST SIG_* VALUES
// ============================================================================

const manifestValues = new Set<string>();
const manifestConstantNames = new Map<string, string>(); // value → constant name
for (const [key, value] of Object.entries(manifest)) {
  if (key.startsWith('SIG_') && typeof value === 'string') {
    manifestValues.add(value);
    manifestConstantNames.set(value, key);
  }
}

// ============================================================================
// SECTION A: Pack → Manifest Coverage
// ============================================================================

console.log('\n=== SECTION A: Every pack pattern ID has a manifest constant ===\n');

// National ID patterns emit a unified signal (global-national-id) instead of their
// own pattern ID. The pattern IDs (global-dk-cpr, global-se-personnummer, global-no-fnr)
// ARE in the manifest as individual constants for reference, but the emitted signal
// is the unified one.
for (const { name, pack } of ALL_PACKS) {
  test(`${name} pack: all pattern IDs in manifest`, () => {
    const missing: string[] = [];
    for (const pattern of pack.patterns) {
      if (!manifestValues.has(pattern.id)) {
        missing.push(pattern.id);
      }
    }
    assert(
      missing.length === 0,
      `Pack "${name}" has ${missing.length} pattern IDs not in signalManifest: ${missing.join(', ')}`
    );
  });
}

test('Every pack pattern ID has at least one SIG_* constant', () => {
  const missing: string[] = [];
  for (const id of allPackPatternIds) {
    if (!manifestValues.has(id)) {
      missing.push(id);
    }
  }
  assert(
    missing.length === 0,
    `${missing.length} pack pattern IDs missing from manifest: ${missing.join(', ')}`
  );
});

// ============================================================================
// SECTION B: Gate → Pack Coverage
// ============================================================================

console.log('\n=== SECTION B: Validation gate pattern IDs exist in packs ===\n');

const gatePatternSets: Array<{ name: string; ids: Set<string> | Map<string, unknown> }> = [
  { name: 'PAYMENT_CARD_PATTERN_IDS', ids: PAYMENT_CARD_PATTERN_IDS },
  { name: 'SWIFT_BIC_PATTERN_IDS', ids: SWIFT_BIC_PATTERN_IDS },
  { name: 'NATIONAL_ID_PATTERN_IDS', ids: NATIONAL_ID_PATTERN_IDS },
  { name: 'URL_CREDENTIAL_PATTERN_IDS', ids: URL_CREDENTIAL_PATTERN_IDS },
  { name: 'CONFIDENTIAL_PATTERN_IDS', ids: CONFIDENTIAL_PATTERN_IDS },
];

// Gate sets may contain legacy aliases (e.g., registry-credit-card) or reserved
// IDs (e.g., global-db-connection-string) that are intentionally in gates for
// backward/forward compatibility but do not have active pack patterns.
const KNOWN_GATE_ONLY_IDS = new Set([
  'registry-credit-card',          // Legacy alias in payment card gate
  'global-db-connection-string',   // Reserved in URL credential gate (manifest-only)
  'registry-fi-hetu',              // Legacy alias for global-fi-hetu (SIG_LEGACY_FI_HETU, backward-compat)
]);

for (const { name, ids } of gatePatternSets) {
  test(`${name}: all IDs exist in pack patterns or are known gate-only`, () => {
    const keys = ids instanceof Map ? [...ids.keys()] : [...ids];
    const orphaned: string[] = [];
    for (const id of keys) {
      if (!allPackPatternIds.has(id) && !KNOWN_GATE_ONLY_IDS.has(id)) {
        // Allow forward-compat IDs that use non-pack prefixes
        // (payment card gate has IDs like financial.payment_card)
        if (id.startsWith('global-') || id.startsWith('english-') ||
            id.startsWith('nordic-') || id.startsWith('romance-') ||
            id.startsWith('registry-')) {
          orphaned.push(id);
        }
      }
    }
    assert(
      orphaned.length === 0,
      `${name} has ${orphaned.length} IDs not found in any pack and not in KNOWN_GATE_ONLY_IDS: ${orphaned.join(', ')}`
    );
  });
}

// ============================================================================
// SECTION C: No production imports from registry.ts
// ============================================================================

console.log('\n=== SECTION C: No production code imports from registry.ts ===\n');

test('src/ has zero imports from registry.ts (excluding registry.ts itself)', () => {
  const srcDir = path.resolve(__dirname, '..', 'src');
  const violations: string[] = [];
  scanDirForRegistryImports(srcDir, violations, 'registry.ts');
  assert(
    violations.length === 0,
    `Found ${violations.length} production file(s) importing from registry.ts:\n    ${violations.join('\n    ')}`
  );
});

function scanDirForRegistryImports(dir: string, violations: string[], skipFile: string): void {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      scanDirForRegistryImports(fullPath, violations, skipFile);
    } else if (entry.isFile() && (entry.name.endsWith('.ts') || entry.name.endsWith('.js'))) {
      if (entry.name === skipFile) continue;
      const content = fs.readFileSync(fullPath, 'utf-8');
      // Match: from './registry', from '../detection/registry', etc.
      if (/from\s+['"][^'"]*\/registry['"]/.test(content) ||
          /from\s+['"]\.\/registry['"]/.test(content)) {
        const relPath = path.relative(path.resolve(__dirname, '..'), fullPath);
        violations.push(relPath);
      }
    }
  }
}

// ============================================================================
// SECTION D: Manifest completeness
// ============================================================================

console.log('\n=== SECTION D: Manifest completeness ===\n');

test('Manifest has at least one constant per naming prefix', () => {
  const prefixes = ['global-', 'english-', 'nordic-', 'romance-', 'registry-'];
  for (const prefix of prefixes) {
    const count = [...manifestValues].filter(v => v.startsWith(prefix)).length;
    assert(count > 0, `No manifest constants with prefix "${prefix}"`);
  }
});

test('Manifest semantic groups use only manifest constants (not raw strings)', () => {
  // Check that group arrays only contain values from manifest SIG_* constants
  const groups: Array<{ name: string; values: readonly string[] }> = [
    { name: 'NATIONAL_ID_SIGNALS', values: manifest.NATIONAL_ID_SIGNALS },
    { name: 'PAYMENT_CARD_SIGNALS', values: manifest.PAYMENT_CARD_SIGNALS },
    { name: 'MEDICAL_SIGNALS', values: manifest.MEDICAL_SIGNALS },
    { name: 'SECRET_SIGNALS', values: manifest.SECRET_SIGNALS },
    { name: 'PII_SIGNAL_IDS', values: manifest.PII_SIGNAL_IDS },
    { name: 'STRONG_REGULATED_SIGNAL_IDS', values: manifest.STRONG_REGULATED_SIGNAL_IDS },
  ];
  for (const { name, values } of groups) {
    const unknowns: string[] = [];
    for (const v of values) {
      if (!manifestValues.has(v)) {
        unknowns.push(v);
      }
    }
    assert(
      unknowns.length === 0,
      `${name} contains ${unknowns.length} values not matching any SIG_* constant: ${unknowns.join(', ')}`
    );
  }
});

test('No duplicate values in manifest SIG_* constants', () => {
  const seen = new Map<string, string>();
  const duplicates: string[] = [];
  for (const [key, value] of Object.entries(manifest)) {
    if (!key.startsWith('SIG_') || typeof value !== 'string') continue;
    if (seen.has(value)) {
      duplicates.push(`${key} and ${seen.get(value)} both equal "${value}"`);
    } else {
      seen.set(value, key);
    }
  }
  // Note: DB_CONNECTION_STRING is in manifest but not in packs — that's OK (reserved)
  // Legacy aliases intentionally duplicate pack IDs (different constant names)
  // We allow duplicates where one is SIG_LEGACY_*
  const realDuplicates = duplicates.filter(d => !d.includes('LEGACY'));
  assert(
    realDuplicates.length === 0,
    `Found ${realDuplicates.length} non-legacy duplicate manifest values:\n    ${realDuplicates.join('\n    ')}`
  );
});

// ============================================================================
// SECTION E: Pack pattern ID naming conventions
// ============================================================================

console.log('\n=== SECTION E: Pattern ID naming conventions ===\n');

const PACK_PREFIX_MAP: Record<string, string[]> = {
  global: ['global-', 'registry-'],  // global pack includes migrated registry patterns
  english: ['english-'],
  nordic: ['nordic-'],
  romance: ['romance-'],
};

for (const { name, pack } of ALL_PACKS) {
  test(`${name} pack: pattern IDs use correct prefix`, () => {
    const allowedPrefixes = PACK_PREFIX_MAP[name];
    if (!allowedPrefixes) return; // unknown pack, skip
    const violations: string[] = [];
    for (const pattern of pack.patterns) {
      if (!allowedPrefixes.some(p => pattern.id.startsWith(p))) {
        violations.push(pattern.id);
      }
    }
    assert(
      violations.length === 0,
      `Pack "${name}" has ${violations.length} pattern IDs with wrong prefix: ${violations.join(', ')}. Expected: ${allowedPrefixes.join(' or ')}`
    );
  });
}

// ============================================================================
// SECTION F: AG-PHASE-5E-060 RomancePack Disabled by Default
// ============================================================================

console.log('\n=== SECTION F: RomancePack disabled by default (AG-PHASE-5E-060) ===\n');

import { DEFAULT_PACK_CONFIG, resolveActivePacks } from '../src/detection/packRegistry';

test('RomancePack.metadata.enabledByDefault is false', () => {
  assert(
    RomancePack.metadata.enabledByDefault === false,
    `RomancePack.metadata.enabledByDefault should be false, got ${RomancePack.metadata.enabledByDefault}`
  );
});

test('DEFAULT_PACK_CONFIG.languagePacks.romance is false', () => {
  assert(
    DEFAULT_PACK_CONFIG.languagePacks?.romance === false,
    `DEFAULT_PACK_CONFIG.languagePacks.romance should be false, got ${DEFAULT_PACK_CONFIG.languagePacks?.romance}`
  );
});

test('RomancePack not in active packs under default config (medium confidence)', () => {
  const activePacks = resolveActivePacks(DEFAULT_PACK_CONFIG, 'medium');
  const romanceActive = activePacks.some(p => p.metadata.id === 'romance');
  assert(
    !romanceActive,
    'RomancePack should NOT be active under default config even with medium confidence'
  );
});

test('RomancePack not in active packs under default config (high confidence)', () => {
  const activePacks = resolveActivePacks(DEFAULT_PACK_CONFIG, 'high');
  const romanceActive = activePacks.some(p => p.metadata.id === 'romance');
  assert(
    !romanceActive,
    'RomancePack should NOT be active under default config even with high confidence'
  );
});

test('RomancePack CAN be enabled via explicit config override', () => {
  const explicitConfig = {
    ...DEFAULT_PACK_CONFIG,
    languagePacks: {
      ...DEFAULT_PACK_CONFIG.languagePacks,
      romance: true, // Explicit enablement
    },
  };
  const activePacks = resolveActivePacks(explicitConfig, 'medium');
  const romanceActive = activePacks.some(p => p.metadata.id === 'romance');
  assert(
    romanceActive,
    'RomancePack SHOULD be active when explicitly enabled via config'
  );
});

test('RomancePack IDs still present in manifest (forward compat)', () => {
  // RomancePack patterns should still have manifest entries even when disabled
  for (const pattern of RomancePack.patterns) {
    assert(
      manifestValues.has(pattern.id),
      `RomancePack pattern "${pattern.id}" should have a manifest constant even when pack is disabled`
    );
  }
});

// ============================================================================
// SUMMARY
// ============================================================================

console.log('\n' + '='.repeat(50));
console.log(`RESULTS: ${passed} passed, ${failed} failed`);
console.log(`Pack pattern IDs: ${allPackPatternIds.size}`);
console.log(`Manifest SIG_* constants: ${manifestValues.size}`);
console.log('='.repeat(50));

if (failed > 0) {
  process.exit(1);
}
