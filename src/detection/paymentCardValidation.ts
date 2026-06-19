/**
 * AG-PROMPT-SIGNAL-VALIDATION-GATES-024: Payment Card Validation Gates
 *
 * Three-gate validation to prevent false positives from numeric sequences
 * that look like payment cards but aren't (policy numbers, IDs, etc.).
 *
 * Gate 1: Luhn checksum validation
 * Gate 2: Issuer prefix validation (Visa, MC, AmEx, Discover, etc.)
 * Gate 3: Context proximity - require card-related keywords nearby
 *
 * Also contains card match quality heuristics (AG-PROMPT-098) for
 * filtering noise matches (PDF artifacts, clause numbers, etc.).
 *
 * Privacy: No raw card numbers are ever logged or returned in results.
 *
 * AG-PHASE-3-048: luhnValidate, checkIssuerPrefix, assessCardMatchQuality
 * moved here from registry.ts during Phase 3 decomposition.
 */

// ============================================================================
// LUHN + ISSUER PREFIX (moved from registry.ts)
// ============================================================================

/**
 * Luhn algorithm validation for card numbers.
 * Returns true if the number passes Luhn check.
 */
export function luhnValidate(digits: string): boolean {
  const nums = digits.replace(/\D/g, '').split('').map(Number);
  if (nums.length < 13 || nums.length > 19) return false;

  let sum = 0;
  let alternate = false;
  for (let i = nums.length - 1; i >= 0; i--) {
    let n = nums[i];
    if (alternate) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

/**
 * AG-PROMPT-SIGNAL-VALIDATION-GATES-024: Check if digits match a known card issuer prefix.
 *
 * Issuer Identification Numbers (IIN):
 * - Visa: starts with 4 (length 13, 16, or 19)
 * - Mastercard: starts with 51-55 or 2221-2720 (length 16)
 * - AmEx: starts with 34 or 37 (length 15)
 * - Discover: starts with 6011, 644-649, or 65 (length 16 or 19)
 * - Diners: starts with 300-305, 36, or 38-39 (length 14 or 16)
 * - JCB: starts with 3528-3589 (length 16-19)
 *
 * @param digits - Digits only (no separators)
 * @returns true if matches a known issuer prefix
 */
export function checkIssuerPrefix(digits: string): boolean {
  const len = digits.length;

  // Visa: 4xxx (length 13, 16, or 19)
  if (digits.startsWith('4') && (len === 13 || len === 16 || len === 19)) {
    return true;
  }

  // Mastercard: 51-55 or 2221-2720 (length 16)
  if (len === 16) {
    const prefix2 = parseInt(digits.slice(0, 2), 10);
    const prefix4 = parseInt(digits.slice(0, 4), 10);
    if ((prefix2 >= 51 && prefix2 <= 55) || (prefix4 >= 2221 && prefix4 <= 2720)) {
      return true;
    }
  }

  // AmEx: 34 or 37 (length 15)
  if (len === 15) {
    const prefix2 = digits.slice(0, 2);
    if (prefix2 === '34' || prefix2 === '37') {
      return true;
    }
  }

  // Discover: 6011, 644-649, 65 (length 16 or 19)
  if (len === 16 || len === 19) {
    const prefix4 = digits.slice(0, 4);
    const prefix3 = parseInt(digits.slice(0, 3), 10);
    const prefix2 = digits.slice(0, 2);
    if (prefix4 === '6011' || (prefix3 >= 644 && prefix3 <= 649) || prefix2 === '65') {
      return true;
    }
  }

  // Diners: 300-305, 36, 38-39 (length 14 or 16)
  if (len === 14 || len === 16) {
    const prefix3 = parseInt(digits.slice(0, 3), 10);
    const prefix2 = digits.slice(0, 2);
    if ((prefix3 >= 300 && prefix3 <= 305) || prefix2 === '36' || prefix2 === '38' || prefix2 === '39') {
      return true;
    }
  }

  // JCB: 3528-3589 (length 16-19)
  if (len >= 16 && len <= 19) {
    const prefix4 = parseInt(digits.slice(0, 4), 10);
    if (prefix4 >= 3528 && prefix4 <= 3589) {
      return true;
    }
  }

  return false;
}

// ============================================================================
// CARD MATCH QUALITY HEURISTICS (AG-PROMPT-098, moved from registry.ts)
// ============================================================================

/**
 * AG-PROMPT-098: Card match quality category.
 * Used for filtering/down-ranking low-quality matches.
 */
export type CardMatchQuality = 'plausible' | 'low_quality' | 'noise';

/**
 * AG-PROMPT-098: Card match quality assessment result.
 * Privacy-safe: contains only metrics, never raw content.
 */
export interface CardMatchQualityResult {
  quality: CardMatchQuality;
  /** Reason for classification (for debugging) */
  reason: string;
  /** Whether to reject this match entirely */
  shouldReject: boolean;
  /** Metrics used for assessment (privacy-safe) */
  metrics: {
    digitCount: number;
    separatorDensity: number;
    spansLineBreaks: boolean;
    clauseNumberingDensity: boolean;
  };
}

/**
 * Analyze neighborhood characters around a match (privacy-safe).
 * AG-PROMPT-097B: Returns counts only, never raw text.
 */
function analyzeNeighborhood(text: string, matchStart: number, matchEnd: number, radius = 40): {
  letterCount: number;
  digitCount: number;
  punctuationCount: number;
  whitespaceCount: number;
} {
  const before = text.slice(Math.max(0, matchStart - radius), matchStart);
  const after = text.slice(matchEnd, Math.min(text.length, matchEnd + radius));
  const neighborhood = before + after;

  let letterCount = 0;
  let digitCount = 0;
  let punctuationCount = 0;
  let whitespaceCount = 0;

  for (const char of neighborhood) {
    if (/[a-zA-Z]/.test(char)) letterCount++;
    else if (/\d/.test(char)) digitCount++;
    else if (/\s/.test(char)) whitespaceCount++;
    else punctuationCount++;
  }

  return { letterCount, digitCount, punctuationCount, whitespaceCount };
}

/**
 * AG-PROMPT-098 + AG-PROMPT-SIGNAL-VALIDATION-GATES-024: Assess card match quality.
 *
 * This function determines if a card-like pattern match is:
 * - plausible: Looks like a real card number
 * - low_quality: Suspicious but not definitively noise
 * - noise: Clearly an artifact (PDF coordinates, clause numbers, policy IDs, etc.)
 *
 * VALIDATION GATES (AG-PROMPT-024):
 * 1. Luhn checksum validation (called separately via pattern.validate)
 * 2. Issuer prefix validation (Visa, MC, AmEx, etc.)
 * 3. Quality heuristics (line breaks, separator density, etc.)
 *
 * @param text - Full text content (for neighborhood analysis)
 * @param matchString - The matched card-like string
 * @param matchIndex - Position of match in text
 * @returns Quality assessment result
 */
export function assessCardMatchQuality(
  text: string,
  matchString: string,
  matchIndex: number
): CardMatchQualityResult {
  const digitsOnly = matchString.replace(/\D/g, '');
  const digitCount = digitsOnly.length;

  // Calculate separator density (non-digit chars / total chars)
  const separatorCount = matchString.length - digitCount;
  const separatorDensity = matchString.length > 0
    ? separatorCount / matchString.length
    : 0;

  // Check if match spans line breaks
  const spansLineBreaks = /[\r\n]/.test(matchString);

  // Analyze neighborhood for clause-numbering density
  const neighborhood = analyzeNeighborhood(text, matchIndex, matchIndex + matchString.length, 40);
  const clauseNumberingDensity = neighborhood.digitCount > neighborhood.letterCount * 2;

  const metrics = {
    digitCount,
    separatorDensity,
    spansLineBreaks,
    clauseNumberingDensity,
  };

  // Heuristic 1: Matches spanning line breaks are PDF artifacts
  if (spansLineBreaks) {
    return {
      quality: 'noise',
      reason: 'spans_line_breaks',
      shouldReject: true,
      metrics,
    };
  }

  // Heuristic 2: Extreme separator density indicates fragmented ID/coordinates
  if (separatorDensity > 0.4) {
    return {
      quality: 'noise',
      reason: 'extreme_separator_density',
      shouldReject: true,
      metrics,
    };
  }

  // AG-PROMPT-SIGNAL-VALIDATION-GATES-024: Issuer prefix validation
  if (digitCount >= 13 && digitCount <= 19) {
    const hasValidIssuer = checkIssuerPrefix(digitsOnly);
    if (!hasValidIssuer) {
      return {
        quality: 'noise',
        reason: 'no_valid_issuer_prefix',
        shouldReject: true,
        metrics,
      };
    }
  }

  // Heuristic 3: High separator density in clause-heavy context
  if (separatorDensity > 0.2 && clauseNumberingDensity) {
    return {
      quality: 'low_quality',
      reason: 'clause_context_with_separators',
      shouldReject: false,
      metrics,
    };
  }

  // Default: Plausible card pattern
  return {
    quality: 'plausible',
    reason: 'passes_quality_checks',
    shouldReject: false,
    metrics,
  };
}

// ============================================================================
// TYPES
// ============================================================================

/**
 * Result of payment card validation.
 * Privacy-safe: contains only metrics, never raw card numbers.
 */
export interface PaymentCardValidationResult {
  /** Whether this is a valid payment card match */
  isValidCard: boolean;
  /** Gates that passed */
  gatesPassed: {
    luhn: boolean;
    issuerPrefix: boolean;
    contextProximity: boolean;
  };
  /** Detected card type (null if not valid) */
  cardType: string | null;
  /** Reason for rejection (privacy-safe) */
  rejectionReason: string | null;
  /** Metrics for audit (privacy-safe) */
  metrics: {
    digitCount: number;
    hasValidLength: boolean;
    passesIssuerPrefix: boolean;
  };
}

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * Card-related keywords for context proximity check.
 * English + common Danish/German variants.
 */
const CARD_CONTEXT_KEYWORDS = [
  // English
  'card', 'credit', 'debit', 'visa', 'mastercard', 'amex', 'american express',
  'discover', 'cvv', 'cvc', 'cvv2', 'cvc2', 'expiry', 'expiration', 'exp date',
  'valid thru', 'valid through', 'cardholder', 'card number', 'card no',
  'payment card', 'credit card', 'debit card',
  // Danish
  'kort', 'kreditkort', 'betalingskort', 'dankort',
  // German
  'karte', 'kreditkarte', 'bankkarte', 'gültig bis',
];

/**
 * Context proximity window (characters before and after match).
 */
const CONTEXT_WINDOW_CHARS = 100;

// ============================================================================
// CONTEXT PROXIMITY VALIDATION
// ============================================================================

/**
 * Check if card-related keywords exist near the match.
 *
 * @param fullText - The full text content
 * @param matchIndex - Start index of the matched number
 * @param matchLength - Length of the matched number
 * @returns true if card-related keywords are found nearby
 */
export function validateContextProximity(
  fullText: string,
  matchIndex: number,
  matchLength: number
): boolean {
  // Extract context window
  const windowStart = Math.max(0, matchIndex - CONTEXT_WINDOW_CHARS);
  const windowEnd = Math.min(fullText.length, matchIndex + matchLength + CONTEXT_WINDOW_CHARS);
  const contextWindow = fullText.slice(windowStart, windowEnd).toLowerCase();

  // Check for any card-related keyword
  for (const keyword of CARD_CONTEXT_KEYWORDS) {
    if (contextWindow.includes(keyword.toLowerCase())) {
      return true;
    }
  }

  return false;
}

// ============================================================================
// MAIN VALIDATION FUNCTION
// ============================================================================

/**
 * Validate a potential payment card match through all three gates.
 *
 * @param matchString - The matched string (may include separators)
 * @param fullText - The full text content (for context check)
 * @param matchIndex - Start index of match in fullText
 * @returns Validation result (privacy-safe, no raw numbers)
 */
export function validatePaymentCard(
  matchString: string,
  fullText: string,
  matchIndex: number
): PaymentCardValidationResult {
  const cleaned = matchString.replace(/\D/g, '');
  const hasValidLength = cleaned.length >= 13 && cleaned.length <= 19;

  // Gate 1: Luhn checksum
  const passesLuhn = hasValidLength && luhnValidate(cleaned);

  // Gate 2: Issuer prefix
  const passesIssuerPrefix = passesLuhn && checkIssuerPrefix(cleaned);

  // Gate 3: Context proximity
  const passesContext = validateContextProximity(fullText, matchIndex, matchString.length);

  // Determine validity - require Luhn + issuer prefix
  const isValidCard = passesLuhn && passesIssuerPrefix;

  // Determine rejection reason
  let rejectionReason: string | null = null;
  if (!hasValidLength) {
    rejectionReason = 'Invalid length (must be 13-19 digits)';
  } else if (!passesLuhn) {
    rejectionReason = 'Failed Luhn checksum';
  } else if (!passesIssuerPrefix) {
    rejectionReason = 'No known issuer prefix match';
  }

  // Determine card type based on prefix (simplified)
  let cardType: string | null = null;
  if (isValidCard) {
    if (cleaned.startsWith('4')) cardType = 'visa';
    else if (/^5[1-5]/.test(cleaned) || /^2[2-7]/.test(cleaned)) cardType = 'mastercard';
    else if (/^3[47]/.test(cleaned)) cardType = 'amex';
    else if (/^6/.test(cleaned)) cardType = 'discover';
    else cardType = 'other';
  }

  return {
    isValidCard,
    gatesPassed: {
      luhn: passesLuhn,
      issuerPrefix: passesIssuerPrefix,
      contextProximity: passesContext,
    },
    cardType,
    rejectionReason,
    metrics: {
      digitCount: cleaned.length,
      hasValidLength,
      passesIssuerPrefix,
    },
  };
}

// ============================================================================
// PATTERN IDS FOR INTEGRATION
// ============================================================================

/**
 * Payment card pattern IDs that should use validation gates.
 */
export const PAYMENT_CARD_PATTERN_IDS = new Set([
  'financial.payment_card',
  'financial.credit_card',
  'pii.credit_card',
  'global-credit-card',
  'registry-credit-card',
  'registry-credit-card-spaced',
]);

/**
 * Check if a pattern ID is a payment card pattern.
 */
export function isPaymentCardPattern(patternId: string): boolean {
  return PAYMENT_CARD_PATTERN_IDS.has(patternId);
}
