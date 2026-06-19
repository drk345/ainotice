/**
 * AG-PROMPT-MEDICAL-PII-DETECTION-REGRESSION-034: Danish CPR Validation Gates
 * AG-XLSX-HARDENING-PLAN-001: Added Mod-11 scoring + Gate & Boost confidence
 *
 * Three-gate validation to prevent false positives from digit sequences
 * that match the DDMMYY-?XXXX pattern but aren't real CPR numbers.
 *
 * Gate 1: Date plausibility (HARD) — DD 01-31, MM 01-12
 * Gate 2: Digit boundary (HARD) — not embedded in a longer digit sequence
 * Gate 3: CPR context proximity (SOFT — informational only)
 * Gate 4: Mod-11 checksum (SOFT — confidence scoring only, NOT rejection)
 *
 * Decision: isValidCpr = datePlausible AND digitBoundaryClean
 * Confidence (Gate & Boost):
 *   mod11 pass + anchor  → 0.99
 *   mod11 pass, no anchor → 0.60
 *   mod11 fail + anchor  → 0.40   (downgrade; post-2007 CPRs skip mod11)
 *   mod11 fail, no anchor → 0.20
 *
 * Privacy: No raw content is ever logged or returned in results.
 * Note: Mod-11 is NOT a hard rejection gate — Danish CPR authority stopped
 *       issuing mod-11-valid numbers after 2007 (ran out of valid numbers).
 */

import { mod11Dk } from './checksums';
import { scoreProximity, DK_CPR_ANCHORS } from './proximityScorer';

// ============================================================================
// TYPES
// ============================================================================

/**
 * Result of CPR validation.
 * Privacy-safe: contains only metrics, never raw content.
 */
export interface CprValidationResult {
  /** Whether this is a valid CPR match */
  isValidCpr: boolean;
  /** Gates that passed */
  gatesPassed: {
    datePlausible: boolean;
    digitBoundaryClean: boolean;
    contextProximity: boolean;
    /** AG-XLSX-HARDENING-PLAN-001: Mod-11 result (soft gate — not used for rejection) */
    mod11Valid: boolean;
  };
  /** Reason for rejection (privacy-safe) */
  rejectionReason: string | null;
  /** Metrics for audit (privacy-safe) */
  metrics: {
    matchLength: number;
    day: number;
    month: number;
    hasHyphen: boolean;
    hasCprContext: boolean;
    /** AG-XLSX-HARDENING-PLAN-001: Mod-11 checksum result */
    mod11Valid: boolean;
  };
  /**
   * AG-XLSX-HARDENING-PLAN-001: Gate & Boost confidence score (0.20 – 0.99).
   * Only present when isValidCpr is true.
   */
  confidence?: number;
}

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * CPR/patient context keywords for proximity check.
 * Danish + English + common Nordic variants.
 */
const CPR_CONTEXT_KEYWORDS = [
  'cpr', 'personnummer', 'patient', 'borger', 'identifikation',
  'fødselsdato', 'personnr', 'cpr-nr', 'cprnr', 'cpr-nummer',
  'person', 'id-nummer', 'national id',
];

/** Context window for CPR keyword proximity check */
const CPR_CONTEXT_WINDOW_CHARS = 80;

// ============================================================================
// GATE 1: DATE PLAUSIBILITY
// ============================================================================

/**
 * Validate the date portion of a CPR match.
 * Format: DDMMYY (first 6 digits). DD must be 01-31, MM must be 01-12.
 */
function validateDatePlausibility(matchString: string): { valid: boolean; day: number; month: number } {
  // Extract digits only (remove optional hyphen)
  const digits = matchString.replace(/-/g, '');
  if (digits.length < 6) {
    return { valid: false, day: 0, month: 0 };
  }

  const day = parseInt(digits.substring(0, 2), 10);
  const month = parseInt(digits.substring(2, 4), 10);

  const valid = day >= 1 && day <= 31 && month >= 1 && month <= 12;
  return { valid, day, month };
}

// ============================================================================
// GATE 2: DIGIT BOUNDARY
// ============================================================================

/**
 * Check that the match is not embedded in a longer digit sequence.
 * Prevents matching inside phone numbers, account numbers, etc.
 */
export function checkDigitBoundary(
  fullText: string,
  matchIndex: number,
  matchLength: number
): boolean {
  // Check character before match
  if (matchIndex > 0) {
    const charBefore = fullText.charCodeAt(matchIndex - 1);
    if (charBefore >= 0x30 && charBefore <= 0x39) {
      return false; // Digit before match → embedded
    }
  }

  // Check character after match
  const afterIndex = matchIndex + matchLength;
  if (afterIndex < fullText.length) {
    const charAfter = fullText.charCodeAt(afterIndex);
    if (charAfter >= 0x30 && charAfter <= 0x39) {
      return false; // Digit after match → embedded
    }
  }

  return true;
}

// ============================================================================
// GATE 3: CPR CONTEXT PROXIMITY (SOFT)
// ============================================================================

/**
 * Check if CPR-related keywords exist near the match.
 * This is a soft gate — informational only, not used for rejection.
 */
function checkCprContext(
  fullText: string,
  matchIndex: number,
  matchLength: number
): boolean {
  const windowStart = Math.max(0, matchIndex - CPR_CONTEXT_WINDOW_CHARS);
  const windowEnd = Math.min(fullText.length, matchIndex + matchLength + CPR_CONTEXT_WINDOW_CHARS);
  const contextWindow = fullText.slice(windowStart, windowEnd).toLowerCase();

  for (const keyword of CPR_CONTEXT_KEYWORDS) {
    if (contextWindow.includes(keyword)) {
      return true;
    }
  }
  return false;
}

// ============================================================================
// MAIN VALIDATION FUNCTION
// ============================================================================

/**
 * Validate a potential Danish CPR match through all three gates.
 *
 * @param matchString - The matched string (DDMMYY-XXXX or DDMMYYXXXX)
 * @param fullText - The full text content (for context checks)
 * @param matchIndex - Start index of match in fullText
 * @returns Validation result (privacy-safe, no raw content)
 */
export function validateCpr(
  matchString: string,
  fullText: string,
  matchIndex: number
): CprValidationResult {
  // Gate 1: Date plausibility (HARD)
  const dateCheck = validateDatePlausibility(matchString);

  // Gate 2: Digit boundary (HARD)
  const digitBoundaryClean = checkDigitBoundary(fullText, matchIndex, matchString.length);

  // Gate 3: CPR context proximity (SOFT)
  const hasCprContext = checkCprContext(fullText, matchIndex, matchString.length);

  // Gate 4 (AG-XLSX-HARDENING-PLAN-001): Mod-11 checksum (SOFT — scoring only)
  const digits = matchString.replace(/-/g, '');
  const mod11Valid = digits.length === 10 ? mod11Dk(digits) : false;

  // Decision: both HARD gates must pass (mod-11 does NOT affect isValidCpr)
  const isValidCpr = dateCheck.valid && digitBoundaryClean;

  // Determine rejection reason
  let rejectionReason: string | null = null;
  if (!dateCheck.valid) {
    rejectionReason = `Implausible date: day=${dateCheck.day}, month=${dateCheck.month}`;
  } else if (!digitBoundaryClean) {
    rejectionReason = 'Match is embedded in a longer digit sequence';
  }

  // AG-XLSX-HARDENING-PLAN-001: Gate & Boost confidence
  let confidence: number | undefined;
  if (isValidCpr) {
    const score = scoreProximity(fullText, matchIndex, matchString.length, DK_CPR_ANCHORS, mod11Valid);
    confidence = score.confidence;
  }

  return {
    isValidCpr,
    gatesPassed: {
      datePlausible: dateCheck.valid,
      digitBoundaryClean,
      contextProximity: hasCprContext,
      mod11Valid,
    },
    rejectionReason,
    metrics: {
      matchLength: matchString.length,
      day: dateCheck.day,
      month: dateCheck.month,
      hasHyphen: matchString.includes('-'),
      hasCprContext,
      mod11Valid,
    },
    confidence,
  };
}

// ============================================================================
// PATTERN IDS FOR INTEGRATION
// ============================================================================

/**
 * CPR pattern IDs that should use validation gates.
 */
export const CPR_PATTERN_IDS = new Set([
  'global-dk-cpr',
]);
