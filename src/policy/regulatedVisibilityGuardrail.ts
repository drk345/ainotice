/**
 * AgentGuard Regulated Visibility Guardrail (AG-PROMPT-071)
 *
 * Ensures that regulated evidence NEVER results in "No risk detected" UI.
 * This is the final safety net after calibration, dedup, and other processing.
 *
 * Invariant: If ANY regulated signal was detected at any stage,
 * the user MUST see at least one visible signal and severity >= LOW.
 *
 * Regulated evidence prefixes (centralized in ./regulatedSignals — AG-PROMPT-227):
 * - pii.*
 * - secret.*  (and plural secrets.*)
 * - financial.*
 * - confidential*
 * - registry-*
 * - coa-*
 * - icd*
 * - hr-*
 * - legal.*
 *
 * @see AG-PROMPT-071: Visibility Guardrail
 */

import type { RiskSignal } from '../types/riskSignal';
import type { UiEscalation } from './policyMapper';
// AG-PROMPT-227: regulated-signal predicates centralized in a single source of truth.
import {
  REGULATED_PREFIXES,
  isRegulatedSignalId,
  isRegulatedSignal,
} from './regulatedSignals';

// ============================================================================
// TYPES
// ============================================================================

/**
 * Rule IDs for audit trail.
 */
export const VISIBILITY_GUARDRAIL_RULE_IDS = {
  /** Signal rescued from suppression */
  SIGNAL_RESCUED: 'VGR-001-signal-rescued',
  /** Severity elevated to floor */
  SEVERITY_FLOOR: 'VGR-002-severity-floor',
  /** UI escalation elevated to inline */
  ESCALATION_FLOOR: 'VGR-003-escalation-floor',
  /** No regulated evidence found - no action */
  NO_REGULATED: 'VGR-010-no-regulated',
  /** Signals already visible - no action */
  ALREADY_VISIBLE: 'VGR-011-already-visible',
} as const;

/**
 * Severity ranking for comparison.
 */
const SEVERITY_ORDER = ['none', 'low', 'medium', 'high', 'critical'] as const;
type SeverityLevel = typeof SEVERITY_ORDER[number];

/**
 * Input for visibility guardrail.
 */
export interface VisibilityGuardrailInput {
  /** All signals detected (before any suppression) */
  allSignals: RiskSignal[];

  /** Signals that survived calibration/dedup */
  visibleSignals: RiskSignal[];

  /** Current severity from decision */
  severity: SeverityLevel;

  /** Current UI escalation level */
  uiEscalation: UiEscalation;
}

/**
 * Result of visibility guardrail enforcement.
 */
export interface VisibilityGuardrailResult {
  /** Enforced visible signals */
  visibleSignals: RiskSignal[];

  /** Enforced severity */
  severity: SeverityLevel;

  /** Enforced UI escalation */
  uiEscalation: UiEscalation;

  /** Whether any enforcement was applied */
  enforced: boolean;

  /** Whether a signal was rescued */
  signalRescued: boolean;

  /** The rescued signal (if any) */
  rescuedSignal: RiskSignal | null;

  /** Whether severity was elevated */
  severityElevated: boolean;

  /** Whether UI escalation was elevated */
  escalationElevated: boolean;

  /** Rule ID for audit trail */
  ruleId: string;

  /** Human-readable reason */
  reason: string;
}

// ============================================================================
// HELPERS
// ============================================================================

// AG-PROMPT-227: isRegulatedSignalId / isRegulatedSignal now live in
// ./regulatedSignals (single source of truth). Re-exported here to preserve
// the existing `from './regulatedVisibilityGuardrail'` import path.
export { isRegulatedSignalId, isRegulatedSignal };

/**
 * Get severity index for comparison.
 */
function severityIndex(severity: string): number {
  const index = SEVERITY_ORDER.indexOf(severity as SeverityLevel);
  return index >= 0 ? index : 0;
}

/**
 * Compare two severity levels.
 * Returns positive if a > b, negative if a < b, 0 if equal.
 */
function compareSeverity(a: string, b: string): number {
  return severityIndex(a) - severityIndex(b);
}

/**
 * Get the maximum severity from a list of signals.
 */
function getMaxSeverity(signals: RiskSignal[]): SeverityLevel {
  if (signals.length === 0) return 'none';

  let max: SeverityLevel = 'none';
  for (const signal of signals) {
    if (compareSeverity(signal.severity, max) > 0) {
      max = signal.severity as SeverityLevel;
    }
  }
  return max;
}

/**
 * Get the prefix priority for a signal (for sorting rescued signals).
 * AG-PROMPT-074: Handle signals without ID by returning max priority (lowest rank).
 */
function getPrefixPriority(signal: RiskSignal): number {
  if (!signal.id) {
    // Signals without ID matched by type - lower priority than specific IDs
    return REGULATED_PREFIXES.length;
  }
  const lowerId = signal.id.toLowerCase();
  const index = REGULATED_PREFIXES.findIndex(p => lowerId.startsWith(p));
  return index >= 0 ? index : REGULATED_PREFIXES.length;
}

/**
 * Generate a stable ID for a signal that doesn't have one.
 * AG-PROMPT-079: Ensures rescued signals always have displayable IDs.
 *
 * @param signal - Signal without ID
 * @returns Generated stable ID (e.g., 'legacy.pii', 'legacy.financial')
 */
function generateStableSignalId(signal: RiskSignal): string {
  // Generate based on type and severity for uniqueness
  return `legacy.${signal.type}`;
}

/**
 * Ensure a signal has a stable ID for display and logging.
 * AG-PROMPT-079: Creates a copy with generated ID if missing.
 *
 * @param signal - Original signal (may be missing ID)
 * @returns Signal with guaranteed ID (may be copy or original)
 */
export function ensureStableSignalId(signal: RiskSignal): RiskSignal {
  if (signal.id) {
    return signal; // Already has ID
  }

  // Create a copy with generated ID
  return {
    ...signal,
    id: generateStableSignalId(signal),
  };
}

/**
 * Find the highest-priority regulated signal to rescue.
 * Priority: highest severity, then earliest prefix match.
 */
function findBestSignalToRescue(signals: RiskSignal[]): RiskSignal | null {
  // AG-PROMPT-074: Pass full signal object, not just ID
  const regulatedSignals = signals.filter(s => isRegulatedSignal(s));

  if (regulatedSignals.length === 0) return null;

  // Sort by severity (descending), then by prefix priority (ascending)
  const sorted = [...regulatedSignals].sort((a, b) => {
    // First: higher severity wins
    const severityDiff = compareSeverity(b.severity, a.severity);
    if (severityDiff !== 0) return severityDiff;

    // Second: earlier prefix in REGULATED_PREFIXES wins
    // AG-PROMPT-074: Use helper that handles missing IDs
    const aPriority = getPrefixPriority(a);
    const bPriority = getPrefixPriority(b);
    return aPriority - bPriority;
  });

  return sorted[0];
}

// ============================================================================
// MAIN ENFORCEMENT FUNCTION
// ============================================================================

/**
 * Enforce regulated visibility guardrail.
 *
 * This function ensures that if ANY regulated signal was detected,
 * the user will see at least one visible signal and appropriate UI.
 *
 * Call this AFTER calibration/dedup but BEFORE building final DecisionExplanation.
 *
 * @param input - Visibility guardrail input
 * @returns VisibilityGuardrailResult with enforced values
 */
export function enforceRegulatedVisibility(
  input: VisibilityGuardrailInput
): VisibilityGuardrailResult {
  const { allSignals, visibleSignals, severity, uiEscalation } = input;

  // Find all regulated signals (from the full set, not just visible)
  // AG-PROMPT-074: Pass full signal object to handle signals without ID
  const regulatedSignals = allSignals.filter(s => isRegulatedSignal(s));

  // No regulated evidence - no enforcement needed
  if (regulatedSignals.length === 0) {
    return {
      visibleSignals,
      severity,
      uiEscalation,
      enforced: false,
      signalRescued: false,
      rescuedSignal: null,
      severityElevated: false,
      escalationElevated: false,
      ruleId: VISIBILITY_GUARDRAIL_RULE_IDS.NO_REGULATED,
      reason: 'No regulated evidence detected',
    };
  }

  // Check if any regulated signals are already visible
  // AG-PROMPT-074: Pass full signal object to handle signals without ID
  const visibleRegulated = visibleSignals.filter(s => isRegulatedSignal(s));

  if (visibleRegulated.length > 0 && severityIndex(severity) >= severityIndex('low')) {
    // Already have visible regulated signals with appropriate severity
    // Just ensure uiEscalation is at least 'inline'
    if (uiEscalation === 'none') {
      return {
        visibleSignals,
        severity,
        uiEscalation: 'inline',
        enforced: true,
        signalRescued: false,
        rescuedSignal: null,
        severityElevated: false,
        escalationElevated: true,
        ruleId: VISIBILITY_GUARDRAIL_RULE_IDS.ESCALATION_FLOOR,
        reason: 'Regulated evidence visible; UI escalation elevated to inline',
      };
    }

    return {
      visibleSignals,
      severity,
      uiEscalation,
      enforced: false,
      signalRescued: false,
      rescuedSignal: null,
      severityElevated: false,
      escalationElevated: false,
      ruleId: VISIBILITY_GUARDRAIL_RULE_IDS.ALREADY_VISIBLE,
      reason: 'Regulated evidence already visible with appropriate severity',
    };
  }

  // ENFORCEMENT NEEDED: Regulated evidence exists but would be invisible
  let enforcedVisibleSignals = [...visibleSignals];
  let enforcedSeverity = severity;
  let enforcedEscalation = uiEscalation;
  let signalRescued = false;
  let rescuedSignal: RiskSignal | null = null;
  let severityElevated = false;
  let escalationElevated = false;
  const reasons: string[] = [];

  // Rule 1: Rescue exactly 1 highest-severity regulated signal
  // AG-PROMPT-079: Ensure rescued signal has stable ID for logging/display
  if (visibleRegulated.length === 0) {
    const bestSignal = findBestSignalToRescue(regulatedSignals);
    if (bestSignal) {
      // Ensure the rescued signal has a stable ID (generate if missing)
      rescuedSignal = ensureStableSignalId(bestSignal);
      enforcedVisibleSignals = [...visibleSignals, rescuedSignal];
      signalRescued = true;
      reasons.push(`rescued signal ${rescuedSignal.id}`); // Now guaranteed to have ID
    }
  }

  // Rule 2: Severity floor at LOW (or rescued signal's severity if higher)
  const minSeverity = rescuedSignal
    ? (compareSeverity(rescuedSignal.severity, 'low') > 0 ? rescuedSignal.severity : 'low')
    : 'low';

  if (compareSeverity(enforcedSeverity, minSeverity) < 0) {
    enforcedSeverity = minSeverity as SeverityLevel;
    severityElevated = true;
    reasons.push(`severity elevated to ${minSeverity}`);
  }

  // Rule 3: UI escalation floor at 'inline'
  if (enforcedEscalation === 'none') {
    enforcedEscalation = 'inline';
    escalationElevated = true;
    reasons.push('UI escalation elevated to inline');
  }

  const enforced = signalRescued || severityElevated || escalationElevated;

  return {
    visibleSignals: enforcedVisibleSignals,
    severity: enforcedSeverity,
    uiEscalation: enforcedEscalation,
    enforced,
    signalRescued,
    rescuedSignal,
    severityElevated,
    escalationElevated,
    ruleId: VISIBILITY_GUARDRAIL_RULE_IDS.SIGNAL_RESCUED,
    reason: enforced
      ? `Regulated evidence guardrail: ${reasons.join(', ')}`
      : 'No enforcement needed',
  };
}

// ============================================================================
// VALIDATION HELPERS
// ============================================================================

/**
 * Check if a decision explanation would show "No risk detected".
 * This should NEVER happen when regulated evidence exists.
 */
export function wouldShowNoRisk(
  visibleSignalCount: number,
  severity: string
): boolean {
  return visibleSignalCount === 0 || severity === 'none';
}

/**
 * Validate that regulated evidence is visible.
 * Use this for testing and compliance checks.
 */
export function validateRegulatedVisibility(
  allSignals: RiskSignal[],
  visibleSignals: RiskSignal[],
  severity: string,
  uiEscalation: UiEscalation
): { compliant: boolean; violations: string[] } {
  const violations: string[] = [];
  // AG-PROMPT-074: Pass full signal object to handle signals without ID
  const regulatedSignals = allSignals.filter(s => isRegulatedSignal(s));

  // No regulated evidence - always compliant
  if (regulatedSignals.length === 0) {
    return { compliant: true, violations: [] };
  }

  // Check visibility
  // AG-PROMPT-074: Pass full signal object to handle signals without ID
  const visibleRegulated = visibleSignals.filter(s => isRegulatedSignal(s));
  if (visibleRegulated.length === 0) {
    violations.push(
      `Regulated evidence exists (${regulatedSignals.length} signals) but none are visible`
    );
  }

  // Check severity
  if (severityIndex(severity) < severityIndex('low')) {
    violations.push(
      `Severity ${severity} is below LOW despite regulated evidence`
    );
  }

  // Check UI escalation
  if (uiEscalation === 'none') {
    violations.push(
      'UI escalation is "none" despite regulated evidence - user would see no warning'
    );
  }

  return {
    compliant: violations.length === 0,
    violations,
  };
}

/**
 * Quick check if any signals are regulated.
 */
export function hasRegulatedEvidence(signals: RiskSignal[]): boolean {
  // AG-PROMPT-074: Pass full signal object to handle signals without ID
  return signals.some(s => isRegulatedSignal(s));
}
