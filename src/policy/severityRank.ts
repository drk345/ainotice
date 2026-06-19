/**
 * Canonical severity rank helpers (AG-PROMPT-231).
 *
 * Two intentionally separate scales exist in this codebase:
 *
 *   1. No-'none' (4-level): signal severity — low → medium → high → critical.
 *      Used wherever the subject is a RiskSignal.
 *
 *   2. With-'none' (5-level): overall risk / decision outcome — none → low →
 *      medium → high → critical. 'none' means no risk detected.
 *      Used in final decision objects and guardrails that compare against the
 *      whole-document risk level.
 *
 * IMPORTANT — what is NOT here:
 *   - Display/UI descending order (critical → high → medium → low) lives in
 *     the UI layer (modalRenderHelpers, uiComponents) and must NOT be merged
 *     with ranking order.
 *   - The hard-locked severityAggregation literal (low:0 medium:1 high:2
 *     critical:3) remains authoritative in severityAggregation.ts and is NOT
 *     replaced by this module — it is protected by test-ag-prompt-01-hardening.
 *
 * @see src/policy/severityAggregation.ts — locked aggregation scale
 * @see AG-PROMPT-226 — diagnosis that found the duplication
 * @see AG-PROMPT-231 — consolidation
 */

import type { Severity } from '../types/riskSignal';

// ============================================================================
// SCALE CONSTANTS
// ============================================================================

/**
 * Signal severity in ascending rank order.
 * 'none' is intentionally excluded — it is not a valid signal severity.
 */
export const SEVERITY_ORDER_NO_NONE: readonly Severity[] =
  ['low', 'medium', 'high', 'critical'];

/**
 * Overall-risk / decision-outcome scale in ascending rank order.
 * Includes 'none' (= no risk detected) as the floor value.
 */
export const SEVERITY_ORDER_WITH_NONE: readonly (Severity | 'none')[] =
  ['none', 'low', 'medium', 'high', 'critical'];

// ============================================================================
// RANK HELPERS
// ============================================================================

/**
 * Return the numeric rank of a signal severity (0 = low, 3 = critical).
 * Only valid for signal-level Severity values; 'none' is not a signal severity.
 */
export function rankSeverity(severity: Severity): number {
  return SEVERITY_ORDER_NO_NONE.indexOf(severity);
}

/**
 * Return the numeric rank of a severity string on the 5-level scale
 * (0 = none, 4 = critical). Accepts any string; returns 0 for unknowns.
 * Use for comparisons that involve the 'none' decision outcome.
 */
export function rankSeverityOrNone(severity: string): number {
  const idx = (SEVERITY_ORDER_WITH_NONE as readonly string[]).indexOf(severity);
  return idx >= 0 ? idx : 0;
}

/**
 * Compare two signal severities.
 * Returns a positive number if a > b, negative if a < b, 0 if equal.
 * Uses the 4-level no-'none' scale.
 */
export function compareSeverity(a: Severity, b: Severity): number {
  return rankSeverity(a) - rankSeverity(b);
}
