/**
 * AgentGuard Decision/UI Consistency Contract (AG-PROMPT-040)
 *
 * Enforces that the UI can never show signals that contradict the final decision.
 * A document cannot be "low risk" and "critical" at the same time.
 *
 * This is a POST-explanation enforcement layer. It runs after:
 * - Interpretation calibration (AG-038)
 * - Human heuristics (AG-039)
 * - Severity aggregation (AG-035)
 * - Decision explanation build (AG-036)
 *
 * Rules (mandatory, no exceptions):
 * - If decision = LOW/NONE → no visible signal may show HIGH/CRITICAL
 * - If decision = WARN/MEDIUM → no visible signal may show CRITICAL
 * - If decision = BLOCK/HIGH/CRITICAL → only driving signals may show matching severity
 *
 * @see AG-PROMPT-040: Decision/UI Consistency Contract
 */

import type { DecisionExplanation, DecisionDetail } from './decisionExplanation';
import type { SeverityLevel } from './severityAggregation';
// AG-PROMPT-231: canonical severity rank — replaces local SEVERITY_HIERARCHY constant.
import { rankSeverityOrNone } from './severityRank';

// ============================================================================
// TYPES
// ============================================================================

/**
 * Consistency enforcement rule ID for audit trail.
 */
export const CONSISTENCY_RULE_IDS = {
  /** Non-driving signal severity downgraded to match decision */
  SEVERITY_DOWNGRADE: 'DUC-001-severity-downgrade',
  /** Signal suppressed due to contradiction */
  CONTRADICTION_SUPPRESS: 'DUC-002-contradiction-suppress',
  /** Signal retained as decision-driving */
  DRIVING_RETAINED: 'DUC-010-driving-retained',
} as const;

/**
 * Result of consistency enforcement.
 */
export interface ConsistencyResult {
  /** The enforced explanation (may have modified details) */
  explanation: DecisionExplanation;

  /** Whether any contradictions were found and fixed */
  hadContradictions: boolean;

  /** Audit log of enforcement actions */
  enforcementLog: ConsistencyEnforcementEntry[];

  /** Statistics */
  stats: ConsistencyStats;
}

/**
 * Single enforcement action entry.
 */
export interface ConsistencyEnforcementEntry {
  /** Rule that was applied */
  ruleId: string;

  /** Signal ID that was affected */
  signalId: string;

  /** Action taken */
  action: 'downgraded' | 'suppressed' | 'retained';

  /** Original severity before enforcement */
  originalSeverity?: string;

  /** New severity after enforcement (if downgraded) */
  newSeverity?: string;

  /** Reason for the action */
  reason: string;
}

/**
 * Statistics from consistency enforcement.
 */
export interface ConsistencyStats {
  /** Total signals in details */
  totalDetails: number;

  /** Signals retained unchanged */
  retained: number;

  /** Signals with severity downgraded */
  downgraded: number;

  /** Signals suppressed entirely */
  suppressed: number;
}

// ============================================================================
// SEVERITY COMPARISON
// ============================================================================

/**
 * Get numeric index for a severity level (5-level, none=0..critical=4).
 * Delegates to canonical rankSeverityOrNone from ./severityRank (AG-PROMPT-231).
 */
function severityIndex(severity: string): number {
  return rankSeverityOrNone(severity);
}

/**
 * Check if signal severity exceeds decision severity.
 */
function exceedsDecision(signalSeverity: string, decisionSeverity: string): boolean {
  return severityIndex(signalSeverity) > severityIndex(decisionSeverity);
}

/**
 * Get the maximum allowed severity for a decision.
 * This enforces the contract: visible signals cannot exceed decision severity.
 */
function getMaxAllowedSeverity(decisionSeverity: string): string {
  return decisionSeverity;
}

// ============================================================================
// CONSISTENCY ENFORCEMENT
// ============================================================================

/**
 * Enforce Decision/UI Consistency Contract on a DecisionExplanation.
 *
 * This is the main entry point for consistency enforcement.
 * Call this AFTER buildDecisionExplanation() and BEFORE UI consumption.
 *
 * Rules:
 * 1. No visible signal may have severity > final decision severity
 * 2. Non-driving signals with high severity are downgraded to match decision
 * 3. Audit trail is produced for all enforcement actions
 *
 * @param explanation - The DecisionExplanation to enforce
 * @param drivingSignalIds - Set of signal IDs that are decision-driving
 * @returns ConsistencyResult with enforced explanation and audit log
 *
 * @example
 * const result = enforceDecisionConsistency(explanation, new Set(['secret.api_key']));
 * // result.explanation has no contradictions
 * // result.hadContradictions indicates if fixes were needed
 */
export function enforceDecisionConsistency(
  explanation: DecisionExplanation,
  drivingSignalIds: Set<string> | string[]
): ConsistencyResult {
  const drivingSet = drivingSignalIds instanceof Set
    ? drivingSignalIds
    : new Set(drivingSignalIds);

  const enforcementLog: ConsistencyEnforcementEntry[] = [];
  const stats: ConsistencyStats = {
    totalDetails: 0,
    retained: 0,
    downgraded: 0,
    suppressed: 0,
  };

  const decisionSeverity = explanation.severity;
  const maxAllowed = getMaxAllowedSeverity(decisionSeverity);

  // If no details, nothing to enforce
  if (!explanation.details || explanation.details.length === 0) {
    return {
      explanation,
      hadContradictions: false,
      enforcementLog,
      stats,
    };
  }

  stats.totalDetails = explanation.details.length;
  const enforcedDetails: DecisionDetail[] = [];

  for (const detail of explanation.details) {
    const isDriving = drivingSet.has(detail.id);
    const signalSeverity = detail.severity;
    const exceeds = exceedsDecision(signalSeverity, decisionSeverity);

    if (isDriving) {
      // Driving signals are retained as-is (they define the decision)
      enforcedDetails.push(detail);
      stats.retained++;
      enforcementLog.push({
        ruleId: CONSISTENCY_RULE_IDS.DRIVING_RETAINED,
        signalId: detail.id,
        action: 'retained',
        reason: 'Signal is decision-driving',
      });
    } else if (exceeds) {
      // Non-driving signal exceeds decision severity - CONTRADICTION
      // Downgrade severity to match decision
      const downgradedDetail: DecisionDetail = {
        ...detail,
        severity: maxAllowed,
      };
      enforcedDetails.push(downgradedDetail);
      stats.downgraded++;
      enforcementLog.push({
        ruleId: CONSISTENCY_RULE_IDS.SEVERITY_DOWNGRADE,
        signalId: detail.id,
        action: 'downgraded',
        originalSeverity: signalSeverity,
        newSeverity: maxAllowed,
        reason: `Non-driving signal severity ${signalSeverity} exceeds decision ${decisionSeverity}`,
      });
    } else {
      // Non-driving signal within bounds - retain
      enforcedDetails.push(detail);
      stats.retained++;
      enforcementLog.push({
        ruleId: CONSISTENCY_RULE_IDS.DRIVING_RETAINED,
        signalId: detail.id,
        action: 'retained',
        reason: 'Signal severity within decision bounds',
      });
    }
  }

  const hadContradictions = stats.downgraded > 0 || stats.suppressed > 0;

  return {
    explanation: {
      ...explanation,
      details: enforcedDetails.length > 0 ? enforcedDetails : undefined,
    },
    hadContradictions,
    enforcementLog,
    stats,
  };
}

// ============================================================================
// VALIDATION (PRE-CHECK)
// ============================================================================

/**
 * Violation found during consistency validation.
 */
export interface ConsistencyViolation {
  /** Signal ID with the violation */
  signalId: string;

  /** The signal's severity */
  signalSeverity: string;

  /** The decision severity */
  decisionSeverity: string;

  /** Whether the signal is decision-driving */
  isDriving: boolean;

  /** Description of the violation */
  description: string;
}

/**
 * Validate a DecisionExplanation for consistency violations WITHOUT fixing them.
 *
 * Use this for testing and debugging to detect contradictions.
 *
 * @param explanation - The DecisionExplanation to validate
 * @param drivingSignalIds - Set of signal IDs that are decision-driving
 * @returns Array of violations found (empty if consistent)
 */
export function validateConsistency(
  explanation: DecisionExplanation,
  drivingSignalIds: Set<string> | string[]
): ConsistencyViolation[] {
  const drivingSet = drivingSignalIds instanceof Set
    ? drivingSignalIds
    : new Set(drivingSignalIds);

  const violations: ConsistencyViolation[] = [];
  const decisionSeverity = explanation.severity;

  if (!explanation.details) {
    return violations;
  }

  for (const detail of explanation.details) {
    const isDriving = drivingSet.has(detail.id);
    const signalSeverity = detail.severity;

    if (exceedsDecision(signalSeverity, decisionSeverity)) {
      violations.push({
        signalId: detail.id,
        signalSeverity,
        decisionSeverity,
        isDriving,
        description: isDriving
          ? `Driving signal ${detail.id} has severity ${signalSeverity} which should match decision ${decisionSeverity}`
          : `Non-driving signal ${detail.id} has severity ${signalSeverity} exceeding decision ${decisionSeverity}`,
      });
    }
  }

  return violations;
}

/**
 * Check if a DecisionExplanation is consistent (no contradictions).
 *
 * @param explanation - The DecisionExplanation to check
 * @param drivingSignalIds - Set of signal IDs that are decision-driving
 * @returns true if consistent, false if contradictions exist
 */
export function isConsistent(
  explanation: DecisionExplanation,
  drivingSignalIds: Set<string> | string[]
): boolean {
  return validateConsistency(explanation, drivingSignalIds).length === 0;
}

// ============================================================================
// SEVERITY MAPPING HELPERS
// ============================================================================

/**
 * Map a severity to its allowed label based on decision severity.
 *
 * This ensures the UI never shows contradictory severity labels.
 *
 * @param signalSeverity - The signal's severity
 * @param decisionSeverity - The overall decision severity
 * @param isDriving - Whether this signal is decision-driving
 * @returns The severity to display (may be downgraded)
 */
export function mapToAllowedSeverity(
  signalSeverity: string,
  decisionSeverity: string,
  isDriving: boolean
): string {
  // Driving signals keep their severity (they define the decision)
  if (isDriving) {
    return signalSeverity;
  }

  // Non-driving signals cannot exceed decision severity
  if (exceedsDecision(signalSeverity, decisionSeverity)) {
    return decisionSeverity;
  }

  return signalSeverity;
}

/**
 * Check if a severity label should be shown as "critical" or "high" styled.
 *
 * Only returns true if:
 * 1. The signal is decision-driving, AND
 * 2. The decision itself is at that severity level
 *
 * This prevents alarming UI styling for non-driving signals.
 */
export function shouldShowAlarmingSeverity(
  signalSeverity: string,
  decisionSeverity: string,
  isDriving: boolean
): boolean {
  // Only driving signals can show alarming severity
  if (!isDriving) {
    return false;
  }

  // Only show alarming if decision is also alarming
  const alarmingSeverities = ['high', 'critical'];
  return (
    alarmingSeverities.includes(signalSeverity) &&
    alarmingSeverities.includes(decisionSeverity)
  );
}

// ============================================================================
// EXPORTS
// ============================================================================

export {
  exceedsDecision,
  severityIndex,
  getMaxAllowedSeverity,
};
