/**
 * AgentGuard Decision Authority (AG-PROMPT-042)
 *
 * This module establishes the SINGLE SOURCE OF TRUTH for final decision severity.
 * No downstream process may alter or reinterpret this decision.
 *
 * Core Rule (MANDATORY):
 * FinalDecisionSeverity = MAX(DocumentBaselineSeverity, AggregatedSignalSeverity)
 *
 * Under NO circumstances may a later pipeline stage downgrade below the document baseline.
 *
 * Design principles:
 * - Single authoritative decision object
 * - Baseline floors are non-overridable
 * - All UI/explanation layers derive from this decision
 * - Deterministic, auditor-obvious logic
 *
 * @see ADR-021: Decision Authority & Baseline Severity Floors
 * @see AG-PROMPT-042
 */

import type { Severity } from '../types/riskSignal';
// AG-PROMPT-231: canonical severity rank — replaces local SEVERITY_HIERARCHY constant.
import { rankSeverityOrNone } from './severityRank';
import type { DocumentClass } from './documentClassAnchors';
import { DOCUMENT_CLASS_BASELINES } from './documentClassAnchors';
import type { IdentityConfidence } from './documentClassAnchors';
import type { AggregatedSeverityResult, SeverityLevel } from './severityAggregation';

// ============================================================================
// TYPES
// ============================================================================

/**
 * The authoritative decision object.
 * This is the SINGLE SOURCE OF TRUTH for final decision severity.
 * All UI, explanation, and disclosure layers MUST derive from this.
 */
export interface AuthoritativeDecision {
  /** Final decision severity - this is authoritative and non-overridable */
  severity: SeverityLevel;

  /** Whether baseline floor was applied */
  baselineApplied: boolean;

  /** Document class that triggered baseline (if any) */
  documentClass: DocumentClass | null;

  /** Original aggregated severity before baseline */
  aggregatedSeverity: SeverityLevel;

  /** Baseline severity that was enforced (if any) */
  baselineSeverity: Severity | null;

  /** Driving signal IDs from aggregation */
  drivingSignalIds: string[];

  /** Driving sources from aggregation */
  drivingSources: string[];

  /** Total signal count */
  signalCount: number;

  /** Human-readable reason for the decision */
  reason: string;

  /** Rule ID for audit trail */
  ruleId: string;
}

/**
 * Rule IDs for decision authority audit trail.
 */
export const DECISION_AUTHORITY_RULE_IDS = {
  /** Baseline floor elevated the decision */
  BASELINE_ELEVATED: 'DA-001-baseline-elevated',
  /** Aggregated severity was authoritative */
  AGGREGATED_AUTHORITATIVE: 'DA-002-aggregated-authoritative',
  /** Medical document safety rule applied */
  MEDICAL_SAFETY: 'DA-003-medical-safety',
} as const;

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
 * Compare two severity levels.
 * Returns positive if a > b, negative if a < b, 0 if equal.
 */
export function compareSeverity(a: SeverityLevel, b: SeverityLevel): number {
  return severityIndex(a) - severityIndex(b);
}

/**
 * Get the maximum of two severity levels.
 */
export function maxSeverity(a: SeverityLevel, b: SeverityLevel | null): SeverityLevel {
  if (b === null) return a;
  return severityIndex(a) >= severityIndex(b) ? a : b;
}

// ============================================================================
// AUTHORITATIVE DECISION BUILDER
// ============================================================================

/**
 * Input for building an authoritative decision.
 */
export interface BuildDecisionInput {
  /** Aggregated severity result from AG-PROMPT-035 */
  aggregatedResult: AggregatedSeverityResult;

  /** Document class from AG-PROMPT-041 (null if not classified) */
  documentClass: DocumentClass | null;

  /** AG-PROMPT-SIGNAL-BYPASS-FIX-028: Identity confidence for baseline gating */
  identityConfidence?: IdentityConfidence;
}

/**
 * Build the authoritative decision.
 *
 * This is the ONLY function that should be used to determine final severity.
 * It enforces the core rule: FinalSeverity = MAX(Baseline, Aggregated)
 *
 * @param input - Aggregated result and document class
 * @returns AuthoritativeDecision - the single source of truth
 */
export function buildAuthoritativeDecision(input: BuildDecisionInput): AuthoritativeDecision {
  const { aggregatedResult, documentClass, identityConfidence } = input;
  const aggregatedSeverity = aggregatedResult.severity;

  // Get baseline severity for document class (if any)
  // AG-PROMPT-SIGNAL-BYPASS-FIX-028: When identityConfidence is weak,
  // do NOT apply CRITICAL baseline. Cap baseline at HIGH instead.
  let baselineSeverity = documentClass ? DOCUMENT_CLASS_BASELINES[documentClass] : null;
  if (baselineSeverity === 'critical' && identityConfidence && identityConfidence !== 'strong') {
    baselineSeverity = 'high';
  }

  // CORE RULE: FinalSeverity = MAX(Baseline, Aggregated)
  const finalSeverity = maxSeverity(aggregatedSeverity, baselineSeverity);
  const baselineApplied = baselineSeverity !== null &&
    severityIndex(finalSeverity) > severityIndex(aggregatedSeverity);

  // Determine rule ID and reason
  let ruleId: string;
  let reason: string;

  if (documentClass === 'doc.medical_record' && identityConfidence === 'strong') {
    // Explicit medical safety rule (only when identity is corroborated)
    ruleId = DECISION_AUTHORITY_RULE_IDS.MEDICAL_SAFETY;
    reason = `Medical document classified with corroborated identity - minimum CRITICAL severity enforced`;
  } else if (documentClass === 'doc.medical_record' && identityConfidence !== 'strong') {
    ruleId = DECISION_AUTHORITY_RULE_IDS.BASELINE_ELEVATED;
    reason = `Medical terminology detected but identity not corroborated - baseline capped at HIGH`;
  } else if (baselineApplied) {
    ruleId = DECISION_AUTHORITY_RULE_IDS.BASELINE_ELEVATED;
    reason = `Baseline floor ${baselineSeverity} elevated decision from ${aggregatedSeverity} to ${finalSeverity}`;
  } else {
    ruleId = DECISION_AUTHORITY_RULE_IDS.AGGREGATED_AUTHORITATIVE;
    reason = `Aggregated severity ${aggregatedSeverity} is authoritative`;
  }

  return {
    severity: finalSeverity,
    baselineApplied,
    documentClass,
    aggregatedSeverity,
    baselineSeverity,
    drivingSignalIds: aggregatedResult.drivingSignalIds,
    drivingSources: aggregatedResult.drivingSources,
    signalCount: aggregatedResult.signalCount,
    reason,
    ruleId,
  };
}

// ============================================================================
// VALIDATION
// ============================================================================

/**
 * Validate that a severity respects the document class baseline.
 * Returns true if valid (severity >= baseline), false if violated.
 */
export function validateBaselineRespected(
  severity: SeverityLevel,
  documentClass: DocumentClass | null
): { valid: boolean; violation?: string } {
  if (!documentClass) {
    return { valid: true };
  }

  const baseline = DOCUMENT_CLASS_BASELINES[documentClass];
  if (severityIndex(severity) < severityIndex(baseline)) {
    return {
      valid: false,
      violation: `Severity ${severity} is below ${documentClass} baseline ${baseline}`,
    };
  }

  return { valid: true };
}

/**
 * Assert that a severity respects the document class baseline.
 * Throws if violated - use for testing and debug assertions.
 */
export function assertBaselineRespected(
  severity: SeverityLevel,
  documentClass: DocumentClass | null
): void {
  const result = validateBaselineRespected(severity, documentClass);
  if (!result.valid) {
    throw new Error(`Baseline violation: ${result.violation}`);
  }
}

// ============================================================================
// CONVENIENCE FUNCTIONS
// ============================================================================

/**
 * Check if a document class requires at least HIGH severity.
 */
export function requiresHighSeverity(documentClass: DocumentClass | null): boolean {
  if (!documentClass) return false;
  const baseline = DOCUMENT_CLASS_BASELINES[documentClass];
  return severityIndex(baseline) >= severityIndex('high');
}

/**
 * Check if a document class requires CRITICAL severity (medical only).
 */
export function requiresCriticalSeverity(documentClass: DocumentClass | null): boolean {
  if (!documentClass) return false;
  const baseline = DOCUMENT_CLASS_BASELINES[documentClass];
  return baseline === 'critical';
}

/**
 * Get the minimum allowed severity for a document class.
 */
export function getMinimumSeverity(documentClass: DocumentClass | null): SeverityLevel {
  if (!documentClass) return 'none';
  return DOCUMENT_CLASS_BASELINES[documentClass];
}

/**
 * Convert AuthoritativeDecision to a format compatible with AggregatedSeverityResult.
 * Use this when passing to downstream functions that expect AggregatedSeverityResult.
 */
export function toAggregatedResult(decision: AuthoritativeDecision): AggregatedSeverityResult {
  return {
    severity: decision.severity,
    drivingSignalIds: decision.drivingSignalIds,
    drivingSources: decision.drivingSources as Array<'content' | 'metadata' | 'filename'>,
    signalCount: decision.signalCount,
  };
}

// ============================================================================
// EXPORTS
// ============================================================================

export {
  severityIndex,
};
