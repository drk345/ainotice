/**
 * Normalization Module
 *
 * Deterministic text normalization for detection reliability.
 *
 * @see textNormalizer.ts for implementation details
 * @see ADR-025 Normalization and Unicode Hardening
 */

export {
  normalizeForDetection,
  stripControlChars,
  stripZeroWidthChars,
  repairHyphenation,
  collapseWhitespace,
  collapseSpacedCharacters,
  SPACED_COLLAPSE_MIN_LENGTH,
  // AG-PHASE-5E-064: Gated spaced-digit collapsing exports
  SPACED_DIGIT_MIN_LENGTH,
  ID_ANCHOR_PROXIMITY,
  ID_ANCHOR_TOKENS,
  // AG-PROMPT-6 D1: Numeric shadow exports
  normalizeWithNumericShadow,
  generateNumericShadow,
  FINANCIAL_ANCHOR_TOKENS,
  FINANCIAL_ANCHOR_PROXIMITY,
  // AG-PROMPT-132: Unicode hyphen normalization export
  normalizeUnicodeHyphens,
  _testExports,
  type NormalizationOptions,
  type NormalizationResult,
} from './textNormalizer';
