/**
 * AgentGuard Text Normalization Contract
 *
 * Deterministic, bounded text normalization for detection reliability.
 * Addresses DATA2 false negatives caused by extraction artifacts.
 *
 * Pipeline stages (strict order, all O(n)):
 *   1. Unicode NFKC normalization
 *   2. Control + zero-width character stripping
 *   3. Hyphenation repair (word-\nbreak → wordbreak)
 *   4. Whitespace collapse (multiple spaces → single space)
 *   5. Spaced-character collapsing (P A S S P O R T → PASSPORT)
 *
 * Design constraints:
 *   - No OCR, ML, NER, or probabilistic heuristics
 *   - O(n) time complexity for all operations
 *   - Deterministic output for same input
 *   - No persistent storage of normalized text
 *   - Conservative defaults to avoid false positives
 *
 * @see ADR-025 Normalization and Unicode Hardening
 * @see docs/regex learning/chatgptlearning.md (authoritative constraints)
 */

// ============================================================================
// CONFIGURATION CONSTANTS (centralized, documented)
// ============================================================================

/**
 * Minimum run length for spaced-character collapsing.
 * A sequence like "P A S S P O R T" has 8 letters → collapses.
 * A sequence like "U S A" has 3 letters → does NOT collapse.
 *
 * Rationale: 6+ letters avoids collapsing common abbreviations (USA, FBI, CIA, etc.)
 * while catching extraction artifacts from COVID tests, passports, etc.
 */
export const SPACED_COLLAPSE_MIN_LENGTH = 6;

/**
 * AG-PHASE-5E-064: Minimum digits for gated spaced-digit collapsing.
 * Only collapse spaced digits when sequence contains >= this many digits.
 */
export const SPACED_DIGIT_MIN_LENGTH = 6;

/**
 * AG-PHASE-5E-064: Proximity window for anchor-gated digit collapsing.
 * Spaced digits must be within this many characters of an ID anchor.
 */
export const ID_ANCHOR_PROXIMITY = 120;

/**
 * AG-PROMPT-6 D1: Financial anchor tokens that gate numeric-shadow transformation.
 * When these tokens are within proximity, EU number formats (space thousands,
 * comma decimals) are transformed to canonical format for detection.
 */
export const FINANCIAL_ANCHOR_TOKENS: RegExp[] = [
  // Currency codes/symbols
  /\bDKK\b/i,
  /\bEUR\b/i,
  /\bSEK\b/i,
  /\bNOK\b/i,
  /\bUSD\b/i,
  /\bGBP\b/i,
  /\bCHF\b/i,
  /\bPLN\b/i,
  /\bkr\.?\b/i,
  /€/,
  /\$/,
  /£/,
  // Financial terms - English
  /\bamount\b/i,
  /\btotal\b/i,
  /\bsum\b/i,
  /\bvat\b/i,
  /\binvoice\b/i,
  /\bprice\b/i,
  /\bcost\b/i,
  /\bpayment\b/i,
  /\bbalance\b/i,
  /\bsalary\b/i,
  /\bnet\b/i,
  /\bgross\b/i,
  // Financial terms - Danish/Nordic
  /\bsaldo\b/i,
  /(?<!\p{L})beløb(?!\p{L})/iu,
  /\bmoms\b/i,       // Danish VAT
  /\bfaktura\b/i,    // Nordic invoice
  /\bpris\b/i,       // Nordic price
  /\bbetaling\b/i,   // Danish payment
  /(?<!\p{L})lön(?!\p{L})/iu,         // Swedish salary
  /(?<!\p{L})løn(?!\p{L})/iu,         // Danish salary
  /\bbrutto\b/i,
  /\bnetto\b/i,
  // Financial terms - German (AG-PROMPT-6 D1 extension)
  /\bbetrag\b/i,               // amount
  /\bgesamtbetrag\b/i,         // total amount
  /\bsumme\b/i,                // sum
  /\brechnungsbetrag\b/i,      // invoice amount
  /\bzahlbetrag\b/i,           // payment amount
  /\biban\b/i,                 // IBAN
  /\bbic\b/i,                  // BIC
  /\bkontoinhaber\b/i,         // account holder
  /\bbankverbindung\b/i,       // bank details
  /\bverwendungszweck\b/i,     // payment reference
  /\bmwst\b/i,                 // German VAT (Mehrwertsteuer)
  /\bust\b/i,                  // German VAT (Umsatzsteuer)
  // Payroll terms - German (AG-PROMPT-6 D1 extension)
  /\bgehalt\b/i,               // salary
  /\blohn\b/i,                 // wage
  /\babrechnung\b/i,           // statement/payslip
  /\bgehaltsabrechnung\b/i,    // salary statement
  /\blohnabrechnung\b/i,       // wage statement
  /\bbruttogehalt\b/i,         // gross salary
  /\bnettogehalt\b/i,          // net salary
];

/**
 * AG-PROMPT-6 D1: Proximity window for financial anchor gating.
 * Numeric shadow transformation only applies within this distance of anchors.
 */
export const FINANCIAL_ANCHOR_PROXIMITY = 120;

/**
 * AG-PHASE-5E-064: ID anchor tokens that gate spaced-digit collapsing.
 * Multilingual coverage: Danish, Swedish, Norwegian, Spanish.
 * Patterns are case-insensitive.
 */
export const ID_ANCHOR_TOKENS: RegExp[] = [
  // Danish
  /\bCPR\b/i,
  /\bCPR[-\s]*nr\.?\b/i,
  /(?<!\p{L})Fødselsdato(?!\p{L})/iu,
  /(?<!\p{L})cpr[-\s]*nummer(?!\p{L})/iu,
  // Swedish
  /\bPersonnummer\b/i,
  /\bPersonnr\.?\b/i,
  /\bsamordningsnummer\b/i,
  // Norwegian
  /(?<!\p{L})Fødselsnummer(?!\p{L})/iu,
  /(?<!\p{L})Fodselsnummer(?!\p{L})/iu,  // ASCII variant
  /\bfnr\.?\b/i,
  // Spanish/LatAm
  /\bDNI\b/i,
  /\bNIE\b/i,
  /\bNIF\b/i,
  /\bRUT\b/i,
  /\bCURP\b/i,
  /\bRFC\b/i,
  // Generic
  /\bNational\s*ID\b/i,
  /\bID[-\s]*nummer\b/i,
];

/**
 * Characters that indicate the end of a spaced sequence.
 * Collapsing does NOT occur across tabs, wide gaps, or punctuation.
 */
const SPACED_COLLAPSE_BOUNDARY = /[\t\n\r.,;:!?()[\]{}]/;

// ============================================================================
// ZERO-WIDTH AND CONTROL CHARACTER PATTERNS
// ============================================================================

/**
 * Control characters to strip (C0 except LF/TAB, C1 range).
 * These appear in broken PDF extractions and serve no detection purpose.
 *
 * Ranges:
 *   U+0000–U+0008: C0 controls (NUL through BS)
 *   U+000B–U+000C: VT, FF
 *   U+000E–U+001F: C0 controls (SO through US)
 *   U+007F–U+009F: DEL + C1 controls
 *
 * Preserves: U+0009 (TAB), U+000A (LF), U+000D (CR → normalized later)
 */
const CONTROL_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g;

/**
 * Zero-width and invisible formatting characters.
 * These enable evasion (e.g., "employ\u200Bment" bypassing "employment" regex)
 * and appear as extraction noise in PDFs.
 *
 * Characters stripped:
 *   U+200B: Zero-Width Space (ZWSP)
 *   U+200C: Zero-Width Non-Joiner (ZWNJ)
 *   U+200D: Zero-Width Joiner (ZWJ)
 *   U+200E: Left-to-Right Mark
 *   U+200F: Right-to-Left Mark
 *   U+2060: Word Joiner
 *   U+FEFF: Byte Order Mark (mid-stream)
 *   U+00AD: Soft Hyphen
 *   U+202A–U+202E: Bidi embedding/override controls
 *   U+2066–U+2069: Bidi isolate controls
 *
 * Reference: Trojan Source CVE-2021-42574 (bidi exploitation)
 */
const ZERO_WIDTH_CHARS = /[\u200B-\u200F\u2060\uFEFF\u00AD\u202A-\u202E\u2066-\u2069]/g;

// ============================================================================
// NORMALIZATION PIPELINE
// ============================================================================

export interface NormalizationOptions {
  /**
   * Enable artifact repair stages (hyphenation, spaced-char collapsing).
   * Default: true. Set false for contexts where layout preservation matters.
   */
  enableArtifactRepair?: boolean;

  /**
   * Skip spaced-character collapsing specifically.
   * Used when document appears to be a ticket/travel document (FP risk).
   */
  skipSpacedCollapse?: boolean;
}

/**
 * Normalize text for detection.
 *
 * This is the main entry point. Applies all normalization stages in order.
 *
 * @param text - Raw extracted text
 * @param options - Optional configuration
 * @returns Normalized text ready for pattern matching
 */
export function normalizeForDetection(
  text: string,
  options: NormalizationOptions = {}
): string {
  const { enableArtifactRepair = true, skipSpacedCollapse = false } = options;

  let result = text;

  // Stage 1: Unicode NFKC normalization
  // Handles compatibility characters (e.g., ﬁ → fi, ① → 1) and
  // composes combining sequences (e.g., e + ́ → é)
  result = result.normalize('NFKC');

  // Stage 1b: Normalize Unicode hyphens to ASCII hyphen-minus (U+002D)
  // After NFKC, U+2011 becomes U+2010. This stage converts remaining
  // Unicode hyphens (HYPHEN U+2010, FIGURE DASH U+2012, EN DASH U+2013)
  // to ASCII hyphen-minus for consistent pattern matching.
  // AG-PROMPT-132: Fixes SSN non-breaking hyphen fragility from AG-130.
  result = normalizeUnicodeHyphens(result);

  // Stage 2: Strip control + zero-width characters
  result = stripControlChars(result);
  result = stripZeroWidthChars(result);

  // Stage 3: Hyphenation repair (gated)
  if (enableArtifactRepair) {
    result = repairHyphenation(result);
  }

  // Stage 4: Whitespace collapse
  // Always applied (safe, improves pattern matching)
  result = collapseWhitespace(result);

  // Stage 5: Spaced-character collapsing (gated)
  if (enableArtifactRepair && !skipSpacedCollapse) {
    result = collapseSpacedCharacters(result);
  }

  // Stage 6: AG-PHASE-5E-064 - Gated spaced-digit collapsing
  // Only collapses spaced digit sequences when near an ID anchor token.
  // This recovers CPR/national IDs like "0 1 0 2 8 9 - 1 2 3 4" → "010289-1234"
  // without globally collapsing digits in tables/columns.
  if (enableArtifactRepair) {
    result = collapseSpacedDigitsNearAnchors(result);
  }

  return result;
}

// ============================================================================
// INDIVIDUAL NORMALIZATION STAGES
// ============================================================================

/**
 * Normalize Unicode hyphens to ASCII hyphen-minus (U+002D).
 *
 * Converts HYPHEN (U+2010), NON-BREAKING HYPHEN (U+2011, → U+2010 after NFKC),
 * FIGURE DASH (U+2012), and EN DASH (U+2013) to ASCII hyphen-minus.
 *
 * EM DASH (U+2014) and HORIZONTAL BAR (U+2015) are intentionally excluded
 * as they serve different typographic roles.
 *
 * AG-PROMPT-132: Fixes SSN non-breaking hyphen fragility.
 */
export function normalizeUnicodeHyphens(text: string): string {
  return text.replace(/[\u2010\u2011\u2012\u2013]/g, '-');
}

/**
 * Strip C0/C1 control characters.
 * Replaces with space to avoid gluing adjacent tokens.
 */
export function stripControlChars(text: string): string {
  return text.replace(CONTROL_CHARS, ' ');
}

/**
 * Strip zero-width and invisible formatting characters.
 * These are removed entirely (not replaced with space).
 */
export function stripZeroWidthChars(text: string): string {
  return text.replace(ZERO_WIDTH_CHARS, '');
}

/**
 * Repair hyphenation across line breaks.
 *
 * Pattern: lowercase letter + hyphen-like char + newline + lowercase letter
 * Result: joined word without hyphen or newline
 *
 * Example: "identi-\nfication" → "identification"
 *
 * AG-PROMPT-5 Item 8: Extended to handle:
 *   - Various hyphen-like characters (hyphen-minus, en-dash, em-dash, minus sign)
 *   - Soft hyphen (U+00AD) that may remain in extracted text
 *   - Optional whitespace before newline (PDF extraction artifact)
 *
 * Does NOT join when:
 *   - Next line starts uppercase (could be compound: "Schleswig-\nHolstein")
 *   - Digits involved (could be ID: "INV-\n2026")
 *   - Paragraph break (multiple newlines)
 *
 * Hyphen-like characters matched:
 *   U+002D: Hyphen-minus (standard ASCII hyphen)
 *   U+2010: Hyphen
 *   U+2011: Non-breaking hyphen
 *   U+2012: Figure dash
 *   U+2013: En-dash
 *   U+2014: Em-dash
 *   U+2212: Minus sign
 *   U+00AD: Soft hyphen
 */
export function repairHyphenation(text: string): string {
  // Match: letter + hyphen-like char + optional space + single newline + lowercase letter
  // Only join lowercase→lowercase to avoid breaking compound nouns
  // Do NOT match across paragraph breaks (multiple newlines)
  // AG-PROMPT-6 A3: Use \p{Ll} (lowercase letter) for Unicode-complete matching
  // including German ß and all EU accented letters
  return text.replace(
    /(\p{L})[\u002D\u2010-\u2014\u2212\u00AD] ?\r?\n(\p{Ll})/gu,
    (match, before, after) => {
      // Only join if 'before' is lowercase, OR if joining doesn't change meaning
      // Conservative: only lowercase-to-lowercase joins
      // Use Unicode lowercase check
      if (before === before.toLowerCase()) {
        return before + after;
      }
      return match; // Keep hyphenated compound
    }
  );
}

/**
 * Collapse multiple whitespace characters to single space.
 * Normalizes line endings and removes excessive spacing.
 */
export function collapseWhitespace(text: string): string {
  // First normalize line endings: CRLF → LF, CR → LF
  let result = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');

  // Collapse multiple spaces/tabs to single space (preserve newlines for now)
  result = result.replace(/[ \t]+/g, ' ');

  // Collapse multiple newlines to single newline
  result = result.replace(/\n+/g, '\n');

  // Trim leading/trailing whitespace from each line
  result = result
    .split('\n')
    .map(line => line.trim())
    .join('\n');

  return result.trim();
}

/**
 * Collapse spaced single-character sequences.
 *
 * Addresses extraction artifacts where PDF text comes out as:
 *   "D o k u m e n t I D" instead of "Dokument ID"
 *   "P A S S P O R T" instead of "PASSPORT"
 *
 * Algorithm:
 *   1. Find sequences of single letters separated by single spaces
 *   2. Only collapse if sequence has ≥ SPACED_COLLAPSE_MIN_LENGTH letters
 *   3. Do NOT collapse across tabs, multiple spaces, or punctuation
 *   4. Preserve case of original letters
 *
 * Safety:
 *   - Does NOT collapse "U S A" (3 letters < threshold)
 *   - Does NOT collapse "A\t B" (tab boundary)
 *   - Does NOT collapse mixed word-length tokens
 */
export function collapseSpacedCharacters(text: string): string {
  // Split on newlines to process line by line (don't collapse across lines)
  const lines = text.split('\n');
  const processedLines = lines.map(line => collapseSpacedInLine(line));
  return processedLines.join('\n');
}

/**
 * Collapse spaced characters within a single line.
 * Internal helper for collapseSpacedCharacters.
 */
function collapseSpacedInLine(line: string): string {
  // Pattern: sequence of single letters each followed by single space
  // We look for runs of "X " where X is a single letter, then a final letter
  //
  // Approach: scan through, identify candidate runs, collapse if long enough

  const result: string[] = [];
  let i = 0;

  while (i < line.length) {
    // Check if we're at the start of a potential spaced sequence
    if (isSpacedSequenceStart(line, i)) {
      const { collapsed, endIndex } = extractAndCollapseSequence(line, i);
      if (collapsed !== null) {
        result.push(collapsed);
        i = endIndex;
        continue;
      }
    }

    // Not a spaced sequence, copy character
    result.push(line[i]);
    i++;
  }

  return result.join('');
}

/**
 * Check if position is the start of a potential spaced sequence.
 * A spaced sequence starts with: single letter + space + single letter
 */
function isSpacedSequenceStart(text: string, pos: number): boolean {
  if (pos + 3 >= text.length) return false;

  const char1 = text[pos];
  const space = text[pos + 1];
  const char2 = text[pos + 2];

  return (
    isLetter(char1) &&
    space === ' ' &&
    isLetter(char2) &&
    // Ensure not preceded by a letter (would be mid-word)
    (pos === 0 || !isLetter(text[pos - 1]))
  );
}

/**
 * Extract and potentially collapse a spaced sequence starting at pos.
 * Returns { collapsed, endIndex } where:
 *   - collapsed is the collapsed string (or null if below threshold)
 *   - endIndex is the position after the sequence
 */
function extractAndCollapseSequence(
  text: string,
  startPos: number
): { collapsed: string | null; endIndex: number } {
  const letters: string[] = [];
  let i = startPos;

  // Collect letters from the spaced sequence
  while (i < text.length) {
    const char = text[i];

    if (isLetter(char)) {
      letters.push(char);
      i++;

      // Check what follows
      if (i >= text.length) {
        // End of text
        break;
      }

      const next = text[i];
      if (next === ' ') {
        // Check if followed by another single letter
        if (i + 1 < text.length && isLetter(text[i + 1])) {
          // Peek ahead: is it "X " pattern or "XX" (multi-letter word)?
          if (i + 2 < text.length && isLetter(text[i + 2])) {
            // It's a multi-letter word, stop here
            break;
          }
          // Continue collecting
          i++; // Skip the space
          continue;
        }
      }
      // Not followed by space+letter, end of sequence
      break;
    } else {
      // Not a letter, sequence ended before we expected
      break;
    }
  }

  // Check if we collected enough letters
  if (letters.length >= SPACED_COLLAPSE_MIN_LENGTH) {
    return {
      collapsed: letters.join(''),
      endIndex: i,
    };
  }

  // Below threshold, don't collapse
  return {
    collapsed: null,
    endIndex: startPos, // Didn't consume anything
  };
}

/**
 * Check if character is a letter (ASCII for now, handles most EU languages).
 * Note: After NFKC normalization, most accented characters are preserved.
 */
/**
 * AG-PROMPT-6 A3: Unicode-safe letter check.
 * Uses \p{L} property for complete Unicode letter coverage including:
 * - German: ä, ö, ü, ß
 * - Nordic: æ, ø, å
 * - Accented letters: é, ñ, etc.
 * - Future EU language growth
 */
function isLetter(char: string): boolean {
  return /^\p{L}$/u.test(char);
}

// ============================================================================
// AG-PHASE-5E-064: GATED SPACED-DIGIT COLLAPSING
// ============================================================================

/**
 * AG-PHASE-5E-064: Collapse spaced digit sequences ONLY when near ID anchor tokens.
 *
 * This stage addresses PDF extraction artifacts where national IDs appear as:
 *   "0 1 0 2 8 9 - 1 2 3 4" instead of "010289-1234"
 *
 * GATING RULES:
 * - Sequence must contain >= SPACED_DIGIT_MIN_LENGTH (6) digits
 * - Must be within ID_ANCHOR_PROXIMITY (120) chars of an anchor token
 * - Anchor tokens include: CPR, Personnummer, Fødselsnummer, DNI, NIE, NIF, RUT
 * - Allows optional hyphen separators between digit groups
 *
 * Does NOT apply global digit collapsing (would break tables/columns).
 *
 * @param text - Text after other normalization stages
 * @returns Text with spaced digits collapsed near ID anchors
 */
export function collapseSpacedDigitsNearAnchors(text: string): string {
  if (text.length < 10) return text; // Too short to contain spaced ID

  // Find all anchor positions
  const anchorPositions: number[] = [];
  for (const pattern of ID_ANCHOR_TOKENS) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    // Create a fresh regex for each search to avoid lastIndex issues
    const freshPattern = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');
    while ((match = freshPattern.exec(text)) !== null) {
      anchorPositions.push(match.index);
      anchorPositions.push(match.index + match[0].length); // End of anchor
    }
  }

  if (anchorPositions.length === 0) {
    return text; // No anchors found, no collapsing
  }

  // Pattern: spaced digits with optional hyphen separators
  // Matches: "0 1 0 2 8 9" or "0 1 0 2 8 9 - 1 2 3 4"
  // The pattern captures single digits separated by single spaces,
  // with optional hyphen (possibly spaced) as separator between groups
  const spacedDigitPattern = /(\d(?:\s+\d)+(?:\s*-\s*\d(?:\s+\d)+)?)/g;

  return text.replace(spacedDigitPattern, (match, group, offset) => {
    // Count actual digits in the match
    const digitCount = (match.match(/\d/g) || []).length;
    if (digitCount < SPACED_DIGIT_MIN_LENGTH) {
      return match; // Not enough digits
    }

    // Check if within proximity of any anchor
    const matchEnd = offset + match.length;
    const isNearAnchor = anchorPositions.some(anchorPos => {
      // Check if anchor is within proximity before or after the match
      const distanceBefore = offset - anchorPos;
      const distanceAfter = anchorPos - matchEnd;
      return (distanceBefore >= 0 && distanceBefore <= ID_ANCHOR_PROXIMITY) ||
             (distanceAfter >= 0 && distanceAfter <= ID_ANCHOR_PROXIMITY);
    });

    if (!isNearAnchor) {
      return match; // Not near an anchor, don't collapse
    }

    // Collapse: remove spaces between digits, preserve hyphen
    // "0 1 0 2 8 9 - 1 2 3 4" → "010289-1234"
    return match
      .replace(/(\d)\s+(?=\d)/g, '$1')  // Remove spaces between digits
      .replace(/\s*-\s*/g, '-');        // Normalize hyphen spacing
  });
}

// ============================================================================
// AG-PROMPT-6 D1: NUMERIC SHADOW FOR EU FORMATS
// ============================================================================

/**
 * AG-PROMPT-6 D1: Result of normalization with optional numeric shadow.
 * The shadow is a secondary representation used only for financial amount detection.
 */
export interface NormalizationResult {
  /** Primary normalized text (no numeric transformation) */
  primary: string;
  /** Shadow text with EU numeric formats converted (space→thousands, comma→decimal) */
  shadow: string | null;
}

/**
 * AG-PROMPT-6 D1: Normalize with optional numeric shadow for EU formats.
 *
 * This function returns both the primary normalized text AND a "shadow" string
 * where EU number formats (space thousands, comma decimals) are converted to
 * canonical format (no separators, dot decimals) ONLY near financial anchors.
 *
 * Example transformation: "90 500,00" → "90500.00"
 *
 * GATING RULES:
 * - Only applies within FINANCIAL_ANCHOR_PROXIMITY (120 chars) of anchors
 * - Anchors: DKK, EUR, SEK, kr, beløb, amount, total, invoice, faktura, etc.
 * - Does NOT transform table-like data without anchors
 *
 * @param text - Raw extracted text
 * @param options - Optional configuration
 * @returns { primary: normalized text, shadow: numeric-shadow text or null }
 */
export function normalizeWithNumericShadow(
  text: string,
  options: NormalizationOptions = {}
): NormalizationResult {
  // Get primary normalization
  const primary = normalizeForDetection(text, options);

  // Generate numeric shadow if financial anchors are present
  const shadow = generateNumericShadow(primary);

  return {
    primary,
    shadow,
  };
}

/**
 * AG-PROMPT-6 D1: Generate numeric shadow representation.
 *
 * Transforms EU number formats to canonical format ONLY near financial anchors.
 * EU format: "90 500,00" (space thousands, comma decimal)
 * Canonical: "90500.00" (no thousands, dot decimal)
 *
 * Returns null if no financial anchors are found (no shadow needed).
 */
export function generateNumericShadow(text: string): string | null {
  if (text.length < 10) return null;

  // Find all financial anchor positions
  const anchorPositions: number[] = [];
  for (const pattern of FINANCIAL_ANCHOR_TOKENS) {
    pattern.lastIndex = 0;
    const freshPattern = new RegExp(
      pattern.source,
      pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g'
    );
    let match: RegExpExecArray | null;
    while ((match = freshPattern.exec(text)) !== null) {
      anchorPositions.push(match.index);
      anchorPositions.push(match.index + match[0].length);
    }
  }

  if (anchorPositions.length === 0) {
    return null; // No anchors, no shadow needed
  }

  // Pattern for EU numeric formats:
  // - Optional leading digits + space OR period + 3 digits (thousands separator)
  // - Comma + 2 digits (decimal)
  // Examples: "90 500,00", "1 234 567,89", "500,00", "1.234,56" (German)
  // AG-PROMPT-6 D1 extension: Added period thousands separator for German format
  const euNumberPattern = /(\d{1,3}(?:[\s.]\d{3})*),(\d{2})\b/g;

  let result = text;
  let hadTransformation = false;

  // Find and replace EU numbers only near anchors
  result = text.replace(euNumberPattern, (match, integerPart, decimalPart, offset) => {
    const matchEnd = offset + match.length;

    // Check if within proximity of any anchor
    const isNearAnchor = anchorPositions.some(anchorPos => {
      const distanceBefore = offset - anchorPos;
      const distanceAfter = anchorPos - matchEnd;
      return (distanceBefore >= 0 && distanceBefore <= FINANCIAL_ANCHOR_PROXIMITY) ||
             (distanceAfter >= 0 && distanceAfter <= FINANCIAL_ANCHOR_PROXIMITY);
    });

    if (!isNearAnchor) {
      return match; // Not near anchor, keep original
    }

    hadTransformation = true;
    // Transform: remove spaces and periods from integer part, replace comma with dot
    // Handles both "90 500,00" (Nordic) and "1.234,56" (German) formats
    const canonicalInteger = integerPart.replace(/[\s.]/g, '');
    return `${canonicalInteger}.${decimalPart}`;
  });

  return hadTransformation ? result : null;
}

// ============================================================================
// EXPORTS FOR TESTING
// ============================================================================

export const _testExports = {
  CONTROL_CHARS,
  ZERO_WIDTH_CHARS,
  isLetter,
  isSpacedSequenceStart,
  extractAndCollapseSequence,
  collapseSpacedInLine,
  // AG-PHASE-5E-064: Spaced digit collapsing
  collapseSpacedDigitsNearAnchors,
  // AG-PROMPT-6 D1: Numeric shadow
  generateNumericShadow,
};
