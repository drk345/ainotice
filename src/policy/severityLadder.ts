import {
  SIG_LEGACY_CREDIT_CARD, SIG_CREDIT_CARD_SPACED, SIG_CREDIT_CARD,
} from '../detection/signalManifest';

/**
 * AG-PROMPT-SIGNAL-SEVERITY-LADDER-025: Severity Ladder with Confidence Caps
 *
 * Defines the severity ladder and enforces caps based on surfaceConfidence.
 * This prevents over-assertion of severity when evidence quality is low.
 *
 * Severity Ladder (descending):
 * - CRITICAL: Absolute red-line (secrets, confirmed SSN with high confidence)
 * - HIGH: Strong signals with confirmed evidence
 * - MEDIUM: Moderate signals or high signals with inferred confidence
 * - LOW: Weak signals or moderate signals with fallback confidence
 * - NONE: No actionable signals
 *
 * Confidence Caps (non-negotiable):
 * - fallback → max MEDIUM (no confirmed document class, no strong signals)
 * - inferred → max HIGH (some evidence but not definitive)
 * - confirmed → CRITICAL allowed (strong structural evidence)
 *
 * Payment Card CRITICAL Guard:
 * - Payment card can only reach CRITICAL if:
 *   1. Luhn checksum passes
 *   2. Valid issuer prefix (Visa, MC, AmEx, etc.)
 *   3. Context proximity (card keywords nearby)
 *   4. surfaceConfidence !== 'fallback'
 *
 * @see AG-PROMPT-SIGNAL-VALIDATION-GATES-024
 * @see docs/PRODUCT_DOCTRINE.md
 */

import type { Severity } from '../types/riskSignal';
import type { SurfaceConfidence } from './awarenessFraming';
import type { DocumentClass } from './documentClassAnchors';
import { validatePaymentCard, isPaymentCardPattern } from '../detection/paymentCardValidation';

// ============================================================================
// TYPES
// ============================================================================

/**
 * Input signal for severity capping.
 * Includes the essential fields needed for cap decisions.
 */
export interface SignalForCapping {
  id?: string;
  severity: Severity;
  /** Matched string for payment card validation */
  match?: string;
  /** Position in text for context validation */
  offset?: number;
}

/**
 * Input for applySeverityCaps function.
 */
export interface SeverityCapsInput {
  surfaceConfidence: SurfaceConfidence;
  documentClass: DocumentClass | null;
  signals: SignalForCapping[];
  /** Full text content for context validation (payment card proximity check) */
  textContent?: string;
}

/**
 * Result of severity capping.
 */
export interface SeverityCapsResult {
  /** Signals with capped severity */
  signals: SignalForCapping[];
  /** Whether any severity was capped */
  anyCapped: boolean;
  /** Rule IDs applied */
  rulesApplied: string[];
  /** Audit log of caps applied */
  capsApplied: CapAuditEntry[];
}

/**
 * Audit entry for severity cap application.
 */
export interface CapAuditEntry {
  signalId: string;
  originalSeverity: Severity;
  cappedSeverity: Severity;
  reason: string;
  ruleId: string;
}

// ============================================================================
// RULE IDS (stable for audit trail)
// ============================================================================

export const SEVERITY_LADDER_RULE_IDS = {
  /** Fallback confidence caps severity at MEDIUM */
  FALLBACK_CAP_MEDIUM: 'SL-001-fallback-cap-medium',
  /** Inferred confidence caps severity at HIGH */
  INFERRED_CAP_HIGH: 'SL-002-inferred-cap-high',
  /** Payment card requires validation gates for CRITICAL */
  PAYMENT_CARD_CRITICAL_GUARD: 'SL-003-payment-card-critical-guard',
  /** Payment card in fallback context caps at MEDIUM */
  PAYMENT_CARD_FALLBACK_CAP: 'SL-004-payment-card-fallback-cap',
  /** Confirmed confidence allows full severity */
  CONFIRMED_NO_CAP: 'SL-005-confirmed-no-cap',
} as const;

// ============================================================================
// SEVERITY ORDERING
// ============================================================================

const SEVERITY_ORDER: Record<Severity | 'none', number> = {
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/**
 * Compare severity levels.
 * Returns positive if a > b, negative if a < b, zero if equal.
 */
function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_ORDER[a] - SEVERITY_ORDER[b];
}

/**
 * Cap severity to a maximum level.
 * Returns the lower of the two severities.
 */
function capSeverity(severity: Severity, maxSeverity: Severity): Severity {
  if (compareSeverity(severity, maxSeverity) > 0) {
    return maxSeverity;
  }
  return severity;
}

// ============================================================================
// CONFIDENCE-BASED SEVERITY CAPS
// ============================================================================

/**
 * Maximum severity allowed for each confidence level.
 *
 * - fallback: MEDIUM (low evidence quality → capped assertions)
 * - inferred: HIGH (some evidence → moderate assertions)
 * - confirmed: CRITICAL (strong evidence → full assertions)
 */
const CONFIDENCE_SEVERITY_CAPS: Record<SurfaceConfidence, Severity> = {
  fallback: 'medium',
  inferred: 'high',
  confirmed: 'critical',
};

/**
 * Get the maximum severity allowed for a confidence level.
 */
export function getMaxSeverityForConfidence(confidence: SurfaceConfidence): Severity {
  return CONFIDENCE_SEVERITY_CAPS[confidence];
}

// ============================================================================
// PAYMENT CARD SEVERITY GUARD
// ============================================================================

/**
 * Payment card signal IDs that require validation gates for CRITICAL.
 */
const PAYMENT_CARD_SIGNAL_IDS = new Set([
  'pii.credit_card',
  'financial.credit_card',
  'financial.payment_card',
  SIG_LEGACY_CREDIT_CARD,
  SIG_CREDIT_CARD_SPACED,
  SIG_CREDIT_CARD,
]);

/**
 * Check if a signal ID is a payment card signal.
 */
export function isPaymentCardSignal(signalId: string | undefined): boolean {
  if (!signalId) return false;
  return PAYMENT_CARD_SIGNAL_IDS.has(signalId) || isPaymentCardPattern(signalId);
}

/**
 * Validate payment card signal for CRITICAL severity.
 *
 * A payment card signal can only reach CRITICAL if:
 * 1. Luhn checksum passes
 * 2. Valid issuer prefix (Visa, MC, AmEx, etc.)
 * 3. Context proximity (card keywords within 100 chars)
 * 4. surfaceConfidence !== 'fallback'
 *
 * @param signal - The payment card signal
 * @param confidence - Surface confidence level
 * @param textContent - Full text for context validation
 * @returns Maximum allowed severity for this payment card
 */
export function validatePaymentCardForCritical(
  signal: SignalForCapping,
  confidence: SurfaceConfidence,
  textContent?: string
): { maxSeverity: Severity; reason: string; ruleId: string } {
  // Rule 1: Fallback confidence → max MEDIUM
  if (confidence === 'fallback') {
    return {
      maxSeverity: 'medium',
      reason: 'Payment card in fallback context capped at MEDIUM',
      ruleId: SEVERITY_LADDER_RULE_IDS.PAYMENT_CARD_FALLBACK_CAP,
    };
  }

  // Rule 2: Validate through all gates if match data available
  if (signal.match && textContent && signal.offset !== undefined) {
    const validationResult = validatePaymentCard(signal.match, textContent, signal.offset);

    // If validation fails → cap at MEDIUM
    if (!validationResult.isValidCard) {
      return {
        maxSeverity: 'medium',
        reason: `Payment card validation failed: ${validationResult.rejectionReason}`,
        ruleId: SEVERITY_LADDER_RULE_IDS.PAYMENT_CARD_CRITICAL_GUARD,
      };
    }

    // If validation passes and context proximity confirmed → allow severity based on confidence
    if (validationResult.gatesPassed.contextProximity) {
      // With confirmed confidence → allow CRITICAL
      if (confidence === 'confirmed') {
        return {
          maxSeverity: 'critical',
          reason: 'Payment card validated with context (Luhn + issuer + proximity)',
          ruleId: SEVERITY_LADDER_RULE_IDS.CONFIRMED_NO_CAP,
        };
      }
      // With inferred confidence → max HIGH
      return {
        maxSeverity: 'high',
        reason: 'Payment card validated but confidence is inferred',
        ruleId: SEVERITY_LADDER_RULE_IDS.INFERRED_CAP_HIGH,
      };
    }

    // Validation passed but no context proximity → max HIGH
    return {
      maxSeverity: 'high',
      reason: 'Payment card passes Luhn + issuer but lacks context proximity',
      ruleId: SEVERITY_LADDER_RULE_IDS.PAYMENT_CARD_CRITICAL_GUARD,
    };
  }

  // No match data available → apply standard confidence caps
  return {
    maxSeverity: getMaxSeverityForConfidence(confidence),
    reason: 'No match data for payment card validation',
    ruleId: confidence === 'inferred'
      ? SEVERITY_LADDER_RULE_IDS.INFERRED_CAP_HIGH
      : SEVERITY_LADDER_RULE_IDS.CONFIRMED_NO_CAP,
  };
}

// ============================================================================
// MAIN SEVERITY CAPPING FUNCTION
// ============================================================================

/**
 * Apply severity caps based on surfaceConfidence.
 *
 * This function enforces the severity ladder invariants:
 * - fallback → max MEDIUM
 * - inferred → max HIGH
 * - confirmed → CRITICAL allowed (subject to per-signal rules)
 *
 * Payment card signals receive additional validation:
 * - Must pass Luhn + issuer prefix for HIGH
 * - Must also have context proximity for CRITICAL
 *
 * @param input - Capping input with confidence, document class, and signals
 * @returns Capping result with modified signals and audit log
 */
export function applySeverityCaps(input: SeverityCapsInput): SeverityCapsResult {
  const { surfaceConfidence, signals, textContent } = input;
  const capsApplied: CapAuditEntry[] = [];
  const rulesApplied = new Set<string>();

  // Get the base cap for this confidence level
  const baseCap = getMaxSeverityForConfidence(surfaceConfidence);

  // Process each signal
  const cappedSignals: SignalForCapping[] = signals.map(signal => {
    const originalSeverity = signal.severity;
    let cappedSeverity = originalSeverity;
    let reason = '';
    let ruleId = '';

    // Special handling for payment card signals
    if (isPaymentCardSignal(signal.id)) {
      const cardValidation = validatePaymentCardForCritical(
        signal,
        surfaceConfidence,
        textContent
      );
      cappedSeverity = capSeverity(originalSeverity, cardValidation.maxSeverity);
      reason = cardValidation.reason;
      ruleId = cardValidation.ruleId;
    } else {
      // Standard confidence-based capping
      cappedSeverity = capSeverity(originalSeverity, baseCap);

      if (surfaceConfidence === 'fallback') {
        reason = 'Fallback confidence caps at MEDIUM';
        ruleId = SEVERITY_LADDER_RULE_IDS.FALLBACK_CAP_MEDIUM;
      } else if (surfaceConfidence === 'inferred') {
        reason = 'Inferred confidence caps at HIGH';
        ruleId = SEVERITY_LADDER_RULE_IDS.INFERRED_CAP_HIGH;
      } else {
        reason = 'Confirmed confidence allows full severity';
        ruleId = SEVERITY_LADDER_RULE_IDS.CONFIRMED_NO_CAP;
      }
    }

    // Record if cap was applied
    if (cappedSeverity !== originalSeverity) {
      capsApplied.push({
        signalId: signal.id ?? 'unknown',
        originalSeverity,
        cappedSeverity,
        reason,
        ruleId,
      });
      rulesApplied.add(ruleId);
    }

    return {
      ...signal,
      severity: cappedSeverity,
    };
  });

  return {
    signals: cappedSignals,
    anyCapped: capsApplied.length > 0,
    rulesApplied: Array.from(rulesApplied),
    capsApplied,
  };
}

// ============================================================================
// SEVERITY LADDER INVARIANTS (for testing)
// ============================================================================

/**
 * Check if a severity is allowed for a given confidence level.
 * Used for test assertions.
 */
export function isSeverityAllowedForConfidence(
  severity: Severity,
  confidence: SurfaceConfidence
): boolean {
  const maxAllowed = getMaxSeverityForConfidence(confidence);
  return compareSeverity(severity, maxAllowed) <= 0;
}

/**
 * Severity ladder invariant checks (for assertions/testing).
 */
export const SEVERITY_LADDER_INVARIANTS = {
  /** Fallback can never produce CRITICAL */
  fallbackNeverCritical: (severity: Severity, confidence: SurfaceConfidence): boolean => {
    if (confidence === 'fallback' && severity === 'critical') {
      return false; // Invariant violated
    }
    return true;
  },

  /** Fallback can never produce HIGH */
  fallbackNeverHigh: (severity: Severity, confidence: SurfaceConfidence): boolean => {
    if (confidence === 'fallback' && severity === 'high') {
      return false; // Invariant violated
    }
    return true;
  },

  /** Inferred can never produce CRITICAL */
  inferredNeverCritical: (severity: Severity, confidence: SurfaceConfidence): boolean => {
    if (confidence === 'inferred' && severity === 'critical') {
      return false; // Invariant violated
    }
    return true;
  },
} as const;

// ============================================================================
// EXPORTS
// ============================================================================

export {
  SEVERITY_ORDER,
  compareSeverity,
  capSeverity,
};
