/**
 * AgentGuard Severity Floor Enforcement (AG-PROMPT-080)
 *
 * Ensures that regulated evidence NEVER resolves to severity=low.
 * This is the final safety net that enforces minimum severity floors
 * based on the presence of regulated signal categories.
 *
 * Invariant: If regulated evidence is present, severity MUST be at least
 * the floor defined for that evidence category.
 *
 * Floors by category:
 * - secret.*              → severity >= HIGH
 * - pii.* / registry-*    → severity >= MEDIUM (HIGH if count >= PII_HIGH_THRESHOLD)
 * - hr-* / doc.hr_record  → severity >= MEDIUM
 * - legal.* / doc.legal   → severity >= MEDIUM
 * - financial.*           → severity >= MEDIUM (HIGH if critical patterns)
 *
 * Note: Medical escalation (doc.medical_record + patient context → HIGH)
 * is handled separately in medicalRecordEscalation.ts.
 *
 * @see AG-PROMPT-080: Severity Floor Alignment
 */

import type { RiskSignal, Severity } from '../types/riskSignal';
import type { DocumentClass } from './documentClassAnchors';
import type { SeverityLevel } from './severityAggregation';

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * Severity floor rule IDs for audit trail.
 */
export const SEVERITY_FLOOR_RULE_IDS = {
  /** Secret detected - floor at HIGH */
  SECRET_FLOOR: 'SFL-001-secret-floor',
  /** PII batch detected - floor at HIGH */
  PII_BATCH_FLOOR: 'SFL-002-pii-batch-floor',
  /** PII detected - floor at MEDIUM */
  PII_FLOOR: 'SFL-003-pii-floor',
  /** HR data detected - floor at MEDIUM */
  HR_FLOOR: 'SFL-004-hr-floor',
  /** Legal data detected - floor at MEDIUM */
  LEGAL_FLOOR: 'SFL-005-legal-floor',
  /** Financial data detected - floor at MEDIUM */
  FINANCIAL_FLOOR: 'SFL-006-financial-floor',
  /** No regulated evidence - no floor applied */
  NO_REGULATED: 'SFL-010-no-regulated',
  /** Already at or above floor - no change */
  ALREADY_COMPLIANT: 'SFL-011-already-compliant',
} as const;

/**
 * Threshold for escalating PII from MEDIUM to HIGH.
 * If >= this many distinct PII signals are present, escalate to HIGH.
 */
export const PII_HIGH_THRESHOLD = 3;

// ============================================================================
// TYPES
// ============================================================================

/**
 * Input for severity floor enforcement.
 */
export interface SeverityFloorInput {
  /** All detected signals */
  signals: RiskSignal[];

  /** Current severity from aggregation */
  severity: SeverityLevel;

  /** Document class (if classified) */
  documentClass: DocumentClass | null;

  /** Whether patient context was detected (for medical - handled separately) */
  hasPatientContext?: boolean;
}

/**
 * Result of severity floor enforcement.
 */
export interface SeverityFloorResult {
  /** Enforced severity (may be elevated) */
  severity: SeverityLevel;

  /** Whether severity was elevated */
  elevated: boolean;

  /** Original severity before enforcement */
  originalSeverity: SeverityLevel;

  /** Which floor was applied */
  appliedFloor: SeverityLevel | null;

  /** Rule ID for audit trail */
  ruleId: string;

  /** Human-readable reason */
  reason: string;

  /** Categories that triggered the floor */
  triggeringCategories: string[];
}

// ============================================================================
// SEVERITY COMPARISON
// ============================================================================

const SEVERITY_ORDER: readonly string[] = ['none', 'low', 'medium', 'high', 'critical'];

function severityIndex(severity: string): number {
  const index = SEVERITY_ORDER.indexOf(severity);
  return index >= 0 ? index : 0;
}

function isBelowSeverity(current: string, threshold: string): boolean {
  return severityIndex(current) < severityIndex(threshold);
}

function maxSeverity(a: string, b: string): SeverityLevel {
  return severityIndex(a) >= severityIndex(b) ? a as SeverityLevel : b as SeverityLevel;
}

// ============================================================================
// SIGNAL CATEGORY DETECTION
// ============================================================================

/**
 * Check if a signal is a secret (API keys, passwords, tokens).
 */
function isSecretSignal(signal: RiskSignal): boolean {
  const id = signal.id?.toLowerCase() ?? '';
  return (
    id.startsWith('secret.') ||
    id.startsWith('secret-') ||
    id.includes('api_key') ||
    id.includes('api-key') ||
    id.includes('password') ||
    id.includes('private_key') ||
    id.includes('private-key') ||
    id.includes('bearer_token') ||
    id.includes('bearer-token')
  );
}

/**
 * Check if a signal is PII (personal identifiable information).
 */
function isPIISignal(signal: RiskSignal): boolean {
  const id = signal.id?.toLowerCase() ?? '';
  const type = signal.type?.toLowerCase() ?? '';

  return (
    id.startsWith('pii.') ||
    id.startsWith('pii-') ||
    id.startsWith('registry-') ||
    type === 'pii'
  );
}

/**
 * Check if a signal is HR/employee data.
 */
function isHRSignal(signal: RiskSignal): boolean {
  const id = signal.id?.toLowerCase() ?? '';
  return (
    id.startsWith('hr-') ||
    id.startsWith('hr.') ||
    id.includes('employee') ||
    id.includes('compensation') ||
    id.includes('salary') ||
    id.includes('payroll')
  );
}

/**
 * Check if a signal is legal/contract data.
 */
function isLegalSignal(signal: RiskSignal): boolean {
  const id = signal.id?.toLowerCase() ?? '';
  return (
    id.startsWith('legal.') ||
    id.startsWith('legal-') ||
    id.includes('contract') ||
    id.includes('nda') ||
    id.includes('privileged')
  );
}

/**
 * Check if a signal is financial data.
 */
function isFinancialSignal(signal: RiskSignal): boolean {
  const id = signal.id?.toLowerCase() ?? '';
  const type = signal.type?.toLowerCase() ?? '';

  return (
    id.startsWith('financial.') ||
    id.startsWith('financial-') ||
    id.includes('credit_card') ||
    id.includes('credit-card') ||
    id.includes('iban') ||
    id.includes('banking') ||
    type === 'financial'
  );
}

/**
 * Check if a signal is a critical financial pattern (credit card, etc.).
 */
function isCriticalFinancialSignal(signal: RiskSignal): boolean {
  const id = signal.id?.toLowerCase() ?? '';
  return (
    id.includes('credit_card') ||
    id.includes('credit-card') ||
    signal.severity === 'critical'
  );
}

// ============================================================================
// MAIN ENFORCEMENT FUNCTION
// ============================================================================

/**
 * Enforce severity floors based on regulated evidence categories.
 *
 * This function ensures that if regulated evidence is present,
 * the severity cannot be below the defined floor for that category.
 *
 * Call this AFTER severity aggregation, AFTER medical escalation.
 *
 * @param input - Severity floor enforcement input
 * @returns SeverityFloorResult with enforced severity
 */
export function enforceSeverityFloor(input: SeverityFloorInput): SeverityFloorResult {
  const { signals, severity, documentClass } = input;

  // Categorize signals
  const secretSignals = signals.filter(isSecretSignal);
  const piiSignals = signals.filter(isPIISignal);
  const hrSignals = signals.filter(isHRSignal);
  const legalSignals = signals.filter(isLegalSignal);
  const financialSignals = signals.filter(isFinancialSignal);

  // Track which categories triggered floors
  const triggeringCategories: string[] = [];
  let requiredFloor: SeverityLevel = 'none';
  let ruleId: string = SEVERITY_FLOOR_RULE_IDS.NO_REGULATED;

  // Rule 1: Secrets → HIGH floor (highest priority)
  if (secretSignals.length > 0) {
    triggeringCategories.push('secret');
    requiredFloor = maxSeverity(requiredFloor, 'high');
    ruleId = SEVERITY_FLOOR_RULE_IDS.SECRET_FLOOR;
  }

  // Rule 2: PII → MEDIUM floor (or HIGH if batch)
  if (piiSignals.length > 0) {
    triggeringCategories.push('pii');
    if (piiSignals.length >= PII_HIGH_THRESHOLD) {
      // Batch PII (multiple distinct signals) → HIGH
      requiredFloor = maxSeverity(requiredFloor, 'high');
      if (ruleId === SEVERITY_FLOOR_RULE_IDS.NO_REGULATED) {
        ruleId = SEVERITY_FLOOR_RULE_IDS.PII_BATCH_FLOOR;
      }
    } else {
      // Single/few PII → MEDIUM
      requiredFloor = maxSeverity(requiredFloor, 'medium');
      if (ruleId === SEVERITY_FLOOR_RULE_IDS.NO_REGULATED) {
        ruleId = SEVERITY_FLOOR_RULE_IDS.PII_FLOOR;
      }
    }
  }

  // Rule 3: HR data → MEDIUM floor
  if (hrSignals.length > 0 || documentClass === 'doc.hr_record' || documentClass === 'doc.payroll') {
    triggeringCategories.push('hr');
    requiredFloor = maxSeverity(requiredFloor, 'medium');
    if (ruleId === SEVERITY_FLOOR_RULE_IDS.NO_REGULATED) {
      ruleId = SEVERITY_FLOOR_RULE_IDS.HR_FLOOR;
    }
  }

  // Rule 4: Legal data → MEDIUM floor
  if (legalSignals.length > 0) {
    triggeringCategories.push('legal');
    requiredFloor = maxSeverity(requiredFloor, 'medium');
    if (ruleId === SEVERITY_FLOOR_RULE_IDS.NO_REGULATED) {
      ruleId = SEVERITY_FLOOR_RULE_IDS.LEGAL_FLOOR;
    }
  }

  // Rule 5: Financial data → MEDIUM floor (or keep original if higher)
  // Critical financial patterns (credit cards) already have high severity
  if (financialSignals.length > 0) {
    triggeringCategories.push('financial');
    const hasCriticalFinancial = financialSignals.some(isCriticalFinancialSignal);
    if (hasCriticalFinancial) {
      // Critical financial patterns should stay critical
      // Don't lower to medium floor
      requiredFloor = maxSeverity(requiredFloor, 'high');
    } else {
      requiredFloor = maxSeverity(requiredFloor, 'medium');
    }
    if (ruleId === SEVERITY_FLOOR_RULE_IDS.NO_REGULATED) {
      ruleId = SEVERITY_FLOOR_RULE_IDS.FINANCIAL_FLOOR;
    }
  }

  // No regulated evidence found
  if (triggeringCategories.length === 0) {
    return {
      severity,
      elevated: false,
      originalSeverity: severity,
      appliedFloor: null,
      ruleId: SEVERITY_FLOOR_RULE_IDS.NO_REGULATED,
      reason: 'No regulated evidence categories detected',
      triggeringCategories: [],
    };
  }

  // Check if current severity is already at or above floor
  if (!isBelowSeverity(severity, requiredFloor)) {
    return {
      severity,
      elevated: false,
      originalSeverity: severity,
      appliedFloor: requiredFloor,
      ruleId: SEVERITY_FLOOR_RULE_IDS.ALREADY_COMPLIANT,
      reason: `Severity ${severity} already meets floor ${requiredFloor} for categories: ${triggeringCategories.join(', ')}`,
      triggeringCategories,
    };
  }

  // Enforce the floor
  return {
    severity: requiredFloor,
    elevated: true,
    originalSeverity: severity,
    appliedFloor: requiredFloor,
    ruleId,
    reason: `Severity elevated from ${severity} to ${requiredFloor} for categories: ${triggeringCategories.join(', ')}`,
    triggeringCategories,
  };
}

// ============================================================================
// VALIDATION HELPER
// ============================================================================

/**
 * Validate that severity meets floor requirements.
 *
 * Use this for testing and compliance checks.
 *
 * @param signals - Detected signals
 * @param severity - Current severity
 * @param documentClass - Document class (if any)
 * @returns Validation result with any violations
 */
export function validateSeverityFloor(
  signals: RiskSignal[],
  severity: string,
  documentClass: DocumentClass | null
): { compliant: boolean; violations: string[] } {
  const result = enforceSeverityFloor({
    signals,
    severity: severity as SeverityLevel,
    documentClass,
  });

  if (result.elevated) {
    return {
      compliant: false,
      violations: [
        `Severity ${severity} is below required floor ${result.appliedFloor} for categories: ${result.triggeringCategories.join(', ')}`,
      ],
    };
  }

  return { compliant: true, violations: [] };
}

/**
 * Quick check if any signals would trigger a severity floor.
 */
export function hasRegulatedCategories(signals: RiskSignal[]): boolean {
  return signals.some(s =>
    isSecretSignal(s) ||
    isPIISignal(s) ||
    isHRSignal(s) ||
    isLegalSignal(s) ||
    isFinancialSignal(s)
  );
}
