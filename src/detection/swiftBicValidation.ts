/**
 * AG-PROMPT-SIGNAL-SWIFT-FALSEPOS-FIX-032: SWIFT/BIC Validation Gates
 * AG-PROMPT-NATIONAL-ID-ARCHITECTURE-035: Gate 4 — Common word exclusion
 *
 * Four-gate validation to prevent false positives from random uppercase
 * sequences that match the SWIFT/BIC pattern but aren't real bank codes.
 *
 * Gate 1: ISO 3166-1 country code validation (HARD)
 * Gate 2: PDF substrate guard (HARD)
 * Gate 3: Financial context proximity (SOFT — informational only)
 * Gate 4: Common word exclusion (HARD)
 *
 * Decision: isValidBic = countryCode AND substrateClean AND commonWordClean
 *
 * Privacy: No raw content is ever logged or returned in results.
 */

// ============================================================================
// TYPES
// ============================================================================

/**
 * Result of SWIFT/BIC validation.
 * Privacy-safe: contains only metrics, never raw content.
 */
export interface SwiftBicValidationResult {
  /** Whether this is a valid SWIFT/BIC match */
  isValidBic: boolean;
  /** Gates that passed */
  gatesPassed: {
    countryCode: boolean;
    substrateClean: boolean;
    contextProximity: boolean;
    commonWordClean: boolean;
  };
  /** Reason for rejection (privacy-safe) */
  rejectionReason: string | null;
  /** Metrics for audit (privacy-safe) */
  metrics: {
    matchLength: number;
    countryCode: string;
    hasFinancialContext: boolean;
    hasPdfSubstrate: boolean;
    isCommonWord: boolean;
  };
}

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * ISO 3166-1 alpha-2 country codes.
 * BIC format: BBBBCCLL[LLL] — positions 5-6 (0-indexed: 4-5) are the country code.
 */
const ISO_3166_COUNTRY_CODES = new Set([
  'AD', 'AE', 'AF', 'AG', 'AI', 'AL', 'AM', 'AO', 'AQ', 'AR', 'AS', 'AT', 'AU', 'AW', 'AX', 'AZ',
  'BA', 'BB', 'BD', 'BE', 'BF', 'BG', 'BH', 'BI', 'BJ', 'BL', 'BM', 'BN', 'BO', 'BQ', 'BR', 'BS',
  'BT', 'BV', 'BW', 'BY', 'BZ',
  'CA', 'CC', 'CD', 'CF', 'CG', 'CH', 'CI', 'CK', 'CL', 'CM', 'CN', 'CO', 'CR', 'CU', 'CV', 'CW',
  'CX', 'CY', 'CZ',
  'DE', 'DJ', 'DK', 'DM', 'DO', 'DZ',
  'EC', 'EE', 'EG', 'EH', 'ER', 'ES', 'ET',
  'FI', 'FJ', 'FK', 'FM', 'FO', 'FR',
  'GA', 'GB', 'GD', 'GE', 'GF', 'GG', 'GH', 'GI', 'GL', 'GM', 'GN', 'GP', 'GQ', 'GR', 'GS', 'GT',
  'GU', 'GW', 'GY',
  'HK', 'HM', 'HN', 'HR', 'HT', 'HU',
  'ID', 'IE', 'IL', 'IM', 'IN', 'IO', 'IQ', 'IR', 'IS', 'IT',
  'JE', 'JM', 'JO', 'JP',
  'KE', 'KG', 'KH', 'KI', 'KM', 'KN', 'KP', 'KR', 'KW', 'KY', 'KZ',
  'LA', 'LB', 'LC', 'LI', 'LK', 'LR', 'LS', 'LT', 'LU', 'LV', 'LY',
  'MA', 'MC', 'MD', 'ME', 'MF', 'MG', 'MH', 'MK', 'ML', 'MM', 'MN', 'MO', 'MP', 'MQ', 'MR', 'MS',
  'MT', 'MU', 'MV', 'MW', 'MX', 'MY', 'MZ',
  'NA', 'NC', 'NE', 'NF', 'NG', 'NI', 'NL', 'NO', 'NP', 'NR', 'NU', 'NZ',
  'OM',
  'PA', 'PE', 'PF', 'PG', 'PH', 'PK', 'PL', 'PM', 'PN', 'PR', 'PS', 'PT', 'PW', 'PY',
  'QA',
  'RE', 'RO', 'RS', 'RU', 'RW',
  'SA', 'SB', 'SC', 'SD', 'SE', 'SG', 'SH', 'SI', 'SJ', 'SK', 'SL', 'SM', 'SN', 'SO', 'SR', 'SS',
  'ST', 'SV', 'SX', 'SY', 'SZ',
  'TC', 'TD', 'TF', 'TG', 'TH', 'TJ', 'TK', 'TL', 'TM', 'TN', 'TO', 'TR', 'TT', 'TV', 'TW', 'TZ',
  'UA', 'UG', 'UM', 'US', 'UY', 'UZ',
  'VA', 'VC', 'VE', 'VG', 'VI', 'VN', 'VU',
  'WF', 'WS',
  'XK',
  'YE', 'YT',
  'ZA', 'ZM', 'ZW',
]);

/**
 * PDF structural tokens that indicate the match is from raw PDF syntax,
 * not from extracted user-visible text.
 */
const PDF_SUBSTRATE_TOKENS = [
  '%PDF',
  'FlateDecode',
  '/Filter',
  'stream',
  'endstream',
  'endobj',
  '/Length',
  '/Type',
  '/Page',
  '/Font',
  '/Resources',
  '/Contents',
];

/**
 * Financial context keywords for proximity check.
 * English + common Nordic/German variants.
 */
const FINANCIAL_CONTEXT_KEYWORDS = [
  'swift', 'bic', 'iban', 'bank', 'routing', 'wire', 'transfer',
  'konto', 'bankforbindelse', 'bankverbindung', 'kontonummer',
  'overforsel', 'remittance', 'beneficiary',
];

/**
 * AG-PROMPT-035: Common words that happen to have valid ISO 3166-1
 * country codes at positions 4-5, causing false SWIFT/BIC matches.
 * Gate 4 (HARD): reject these unconditionally.
 *
 * Each entry: WORD (country code at positions 4-5)
 * English:
 * - DOCUMENT (ME=Montenegro), ARGUMENT (ME), JUDGMENT (ME), MOVEMENT (ME)
 * - FRAGMENT (ME), ORNAMENT (ME), MONUMENT (ME), BASEMENT (ME)
 * - ABSOLUTE (LU=Luxembourg), INTEREST (RE=Réunion)
 * - EVALUATE (UA=Ukraine), ESTIMATE (MA=Morocco)
 * - COMBINED (IN=India), REQUIRED (IR=Iran), ACQUIRED (IR=Iran)
 * - PLATFORM (FO=Faroe Islands)
 * Nordic (AG-PROMPT-039):
 * - UNDERSKRIFT (RS=Serbia) — Danish/Norwegian for "signature"
 */
const COMMON_WORD_EXCLUSIONS = new Set([
  'DOCUMENT', 'ARGUMENT', 'JUDGMENT', 'MOVEMENT',
  'FRAGMENT', 'ORNAMENT', 'MONUMENT', 'BASEMENT',
  'ABSOLUTE', 'INTEREST',
  'EVALUATE', 'ESTIMATE',
  'COMBINED', 'REQUIRED', 'ACQUIRED',
  'PLATFORM',
  // Nordic — AG-PROMPT-039
  'UNDERSKRIFT',
  // Dutch — AG-PROMPT-133: eliminates metamorphic hallucination on CB-LEG-NL-DEPTH-001
  'JURISDICTIE',
]);

/** Context window for PDF substrate check (chars before and after match) */
const SUBSTRATE_WINDOW_CHARS = 200;

/** Context window for financial keyword proximity check */
const FINANCIAL_CONTEXT_WINDOW_CHARS = 80;

// ============================================================================
// GATE 1: ISO 3166-1 COUNTRY CODE
// ============================================================================

/**
 * Extract and validate the country code from a BIC match.
 * BIC format: BBBBCCLL[LLL] — positions 4-5 (0-indexed) are the country code.
 */
function validateCountryCode(match: string): { valid: boolean; code: string } {
  if (match.length < 6) {
    return { valid: false, code: '' };
  }
  const code = match.substring(4, 6);
  return { valid: ISO_3166_COUNTRY_CODES.has(code), code };
}

// ============================================================================
// GATE 2: PDF SUBSTRATE GUARD
// ============================================================================

/**
 * Check if the match is surrounded by PDF structural tokens,
 * indicating it comes from raw PDF syntax rather than extracted text.
 */
function checkPdfSubstrate(
  fullText: string,
  matchIndex: number,
  matchLength: number
): boolean {
  const windowStart = Math.max(0, matchIndex - SUBSTRATE_WINDOW_CHARS);
  const windowEnd = Math.min(fullText.length, matchIndex + matchLength + SUBSTRATE_WINDOW_CHARS);
  const contextWindow = fullText.slice(windowStart, windowEnd);

  for (const token of PDF_SUBSTRATE_TOKENS) {
    if (contextWindow.includes(token)) {
      return true; // PDF substrate detected
    }
  }
  return false;
}

// ============================================================================
// GATE 3: FINANCIAL CONTEXT PROXIMITY (SOFT)
// ============================================================================

/**
 * Check if financial keywords exist near the match.
 * This is a soft gate — informational only, not used for rejection.
 */
function checkFinancialContext(
  fullText: string,
  matchIndex: number,
  matchLength: number
): boolean {
  const windowStart = Math.max(0, matchIndex - FINANCIAL_CONTEXT_WINDOW_CHARS);
  const windowEnd = Math.min(fullText.length, matchIndex + matchLength + FINANCIAL_CONTEXT_WINDOW_CHARS);
  const contextWindow = fullText.slice(windowStart, windowEnd).toLowerCase();

  for (const keyword of FINANCIAL_CONTEXT_KEYWORDS) {
    if (contextWindow.includes(keyword)) {
      return true;
    }
  }
  return false;
}

// ============================================================================
// GATE 4: COMMON WORD EXCLUSION (HARD)
// ============================================================================

/**
 * AG-PROMPT-035: Check if the match is a common English word that happens
 * to have a valid ISO 3166-1 country code at positions 4-5.
 * Returns true if the match IS a common word (should be excluded).
 */
function isCommonWordExclusion(matchString: string): boolean {
  return COMMON_WORD_EXCLUSIONS.has(matchString.toUpperCase());
}

// ============================================================================
// MAIN VALIDATION FUNCTION
// ============================================================================

/**
 * Validate a potential SWIFT/BIC match through all three gates.
 *
 * @param matchString - The matched string (8 or 11 uppercase chars)
 * @param fullText - The full text content (for context checks)
 * @param matchIndex - Start index of match in fullText
 * @returns Validation result (privacy-safe, no raw content)
 */
export function validateSwiftBic(
  matchString: string,
  fullText: string,
  matchIndex: number
): SwiftBicValidationResult {
  // Gate 1: Country code validation (HARD)
  const countryCheck = validateCountryCode(matchString);

  // Gate 2: PDF substrate guard (HARD)
  const hasPdfSubstrate = checkPdfSubstrate(fullText, matchIndex, matchString.length);
  const substrateClean = !hasPdfSubstrate;

  // Gate 3: Financial context proximity (SOFT)
  const hasFinancialContext = checkFinancialContext(fullText, matchIndex, matchString.length);

  // Gate 4: Common word exclusion (HARD)
  const isCommonWord = isCommonWordExclusion(matchString);
  const commonWordClean = !isCommonWord;

  // Decision: all hard gates must pass
  const isValidBic = countryCheck.valid && substrateClean && commonWordClean;

  // Determine rejection reason
  let rejectionReason: string | null = null;
  if (!countryCheck.valid) {
    rejectionReason = `Invalid country code: ${countryCheck.code}`;
  } else if (!substrateClean) {
    rejectionReason = 'Match found in PDF substrate context';
  } else if (!commonWordClean) {
    rejectionReason = `Common word exclusion: ${matchString}`;
  }

  return {
    isValidBic,
    gatesPassed: {
      countryCode: countryCheck.valid,
      substrateClean,
      contextProximity: hasFinancialContext,
      commonWordClean,
    },
    rejectionReason,
    metrics: {
      matchLength: matchString.length,
      countryCode: countryCheck.code,
      hasFinancialContext,
      hasPdfSubstrate,
      isCommonWord,
    },
  };
}

// ============================================================================
// PATTERN IDS FOR INTEGRATION
// ============================================================================

/**
 * SWIFT/BIC pattern IDs that should use validation gates.
 */
export const SWIFT_BIC_PATTERN_IDS = new Set([
  'global-swift',
]);
