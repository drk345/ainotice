/**
 * Regulated-Signal Predicates — Single Source of Truth (AG-PROMPT-227)
 *
 * Centralizes the regulated-prefix / regulated-type lists and the
 * `isRegulatedSignalId` / `isRegulatedSignal` predicates that were previously
 * duplicated (and divergent) across:
 *   - src/policy/regulatedVisibilityGuardrail.ts  (rescue + visibility floor)
 *   - src/policy/interpretationCalibration.ts     (suppression rescue)
 *
 * AG-226 diagnosis proved the two copies disagreed on the plural `secrets.`
 * prefix: calibration recognized `secrets.*`; the guardrail did not. Real,
 * live signal IDs exist in BOTH forms (e.g. `secret.api_key` and
 * `secrets.api_key` — see src/policy/defaultPolicy.ts and contract.ts), so a
 * signal like `secrets.password` could be treated as regulated in one stage and
 * not regulated in another. Both forms are therefore regulated here.
 *
 * `none`/severity ordering is intentionally NOT part of this module — it owns
 * category membership only, not severity rank.
 *
 * @see docs/reports/AG-PROMPT-227-regulated-signal-predicate-source.md
 */

import type { RiskSignal } from '../types/riskSignal';

/**
 * Prefixes that indicate regulated content.
 *
 * Order matters: `regulatedVisibilityGuardrail.getPrefixPriority` uses the array
 * index as a rescue tie-breaker (earlier prefix = higher priority). The order
 * preserves the guardrail's historical priority — `secret.` first (secrets are
 * always critical) — and places the plural `secrets.` immediately after it, so
 * existing `secret.*`/`pii.*`/… signals keep their prior relative priority.
 */
export const REGULATED_PREFIXES = [
  'secret.',      // Highest priority - secrets are always critical
  'secrets.',     // Plural-form secret IDs (defaultPolicy.ts / contract.ts use secrets.*)
  'pii.',         // Personal identifiable information
  'financial.',   // Financial data
  'confidential', // Confidential markers (no dot, prefix match)
  'registry-',    // National ID registries (CPR, BSN, etc.)
  'coa-',         // Clinical ontology anchors
  'icd',          // ICD codes (no separator, prefix match)
  'hr-',          // HR-related signals
  'legal.',       // Legal document markers
] as const;

/**
 * Regulated signal types for fallback matching when signal.id is missing.
 * Legacy detection (analyzeTextContentLegacy) produces signals with a type
 * (e.g. 'pii') but no explicit id; these must still be recognized as regulated.
 */
export const REGULATED_TYPES = ['pii', 'secret', 'financial', 'confidential'] as const;

/**
 * Check if a signal ID indicates regulated content.
 *
 * Accepts `undefined` (returns false) so callers that may not have an id can
 * delegate here directly.
 */
export function isRegulatedSignalId(signalId: string | undefined): boolean {
  if (!signalId) return false;
  const lowerId = signalId.toLowerCase();
  return REGULATED_PREFIXES.some(prefix => lowerId.startsWith(prefix));
}

/**
 * Check if a signal indicates regulated content.
 *
 * Checks signal.id first (preferred, more specific), then falls back to
 * signal.type for legacy signals without an explicit id. Also accepts a raw
 * id string for backward compatibility.
 */
export function isRegulatedSignal(signal: RiskSignal | string): boolean {
  // Handle string ID (backward compatibility)
  if (typeof signal === 'string') {
    return isRegulatedSignalId(signal);
  }

  // Check by ID first (preferred - more specific)
  if (signal.id && isRegulatedSignalId(signal.id)) {
    return true;
  }

  // Fallback: check by type for legacy signals without explicit ID
  return REGULATED_TYPES.includes(signal.type as typeof REGULATED_TYPES[number]);
}
