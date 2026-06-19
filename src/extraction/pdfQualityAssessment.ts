/**
 * AG-PHASE-1-UNIFIED-PDF-EXTRACTION-SPINE: PDF text quality assessment.
 * AG-050: Renamed blocked_by_ocr → blocked. Added readable word rescue heuristic.
 *
 * Classifies extracted text quality to drive downstream decisions:
 * - Detection pipeline: skip detection for blocked text
 * - UX: show appropriate awareness frames
 * - Reporting: categorize extraction outcomes
 *
 * Thresholds aligned with existing test-doc-pack.ts assessExtraction() logic.
 */

import type { QualityLevel } from './types';

// ============================================================================
// CONSTANTS
// ============================================================================

const MIN_TEXT_LENGTH = 50;
const PDF_TOKEN_RATIO_THRESHOLD = 0.3;
const NON_PRINTABLE_BLOCKED_THRESHOLD = 0.4;
const NON_PRINTABLE_DEGRADED_THRESHOLD = 0.2;
const NON_PRINTABLE_PARTIAL_THRESHOLD = 0.05;
const SAMPLE_SIZE = 2000;

// AG-050: Readable word rescue — prevents over-blocking when text contains
// substantial readable content despite non-printable char noise.
const READABLE_WORD_PATTERN = /^[a-zA-Z\u00C0-\u00FF\u0100-\u017F0-9.,;:!?()\-\/'\"@#$%&*+=]+$/;
const RESCUE_BLOCKED_TO_DEGRADED_THRESHOLD = 0.60;  // blocked → degraded if ≥60% readable words
const RESCUE_DEGRADED_TO_PARTIAL_THRESHOLD = 0.60;   // degraded → partial if ≥60% readable words
const RESCUE_BLOCKED_CASCADE_TO_PARTIAL_THRESHOLD = 0.80;  // AG-PHASE-5-053: blocked → partial if ≥80% readable words (cascade)

// ============================================================================
// QUALITY ASSESSMENT
// ============================================================================

export interface QualityAssessment {
  quality: QualityLevel;
  nonPrintableRatio: number;
  readableWordRatio: number;
  reason: string;
}

/**
 * Count the ratio of readable words (Latin chars, digits, common punctuation)
 * to total words in the text. Used as a rescue heuristic when non-printable
 * ratio would otherwise over-classify.
 */
function computeReadableWordRatio(text: string): number {
  const words = text.split(/\s+/).filter(w => w.length > 0);
  if (words.length === 0) return 0;
  const readable = words.filter(w => READABLE_WORD_PATTERN.test(w));
  return readable.length / words.length;
}

/**
 * Assess the quality of extracted PDF text.
 *
 * Classification (AG-050 updated):
 * - empty: less than 50 chars extracted
 * - blocked: text starts with %PDF- (raw bytes leaked) or >40% non-printable with low readable word ratio
 * - degraded: 20-40% non-printable with low readable word ratio, or high PDF token ratio
 * - partial: 5-20% non-printable, or rescued from degraded by high readable word ratio
 * - clean: otherwise
 */
export function assessExtractionQuality(text: string): QualityAssessment {
  // Raw PDF bytes leaked through ASCII run fallback (check before length gate —
  // %PDF- prefix is a strong signal regardless of text length)
  if (text.startsWith('%PDF-')) {
    return {
      quality: 'blocked',
      nonPrintableRatio: 1,
      readableWordRatio: 0,
      reason: 'Raw PDF bytes — BT/ET stream extraction failed (image-only PDF)',
    };
  }

  if (text.length < MIN_TEXT_LENGTH) {
    return { quality: 'empty', nonPrintableRatio: 0, readableWordRatio: 0, reason: `Only ${text.length} chars extracted` };
  }

  // Check PDF structural token ratio
  const pdfTokens = (text.match(/\b(endobj|endstream|\/Filter|\/FlateDecode|xref)\b/g) || []).length;
  const totalWords = text.split(/\s+/).length;
  const tokenRatio = pdfTokens / Math.max(totalWords, 1);
  if (tokenRatio >= PDF_TOKEN_RATIO_THRESHOLD) {
    return {
      quality: 'degraded',
      nonPrintableRatio: tokenRatio,
      readableWordRatio: 0,
      reason: `High PDF token ratio (${(tokenRatio * 100).toFixed(1)}%)`,
    };
  }

  // Check non-printable character ratio (sample first 2000 chars)
  const sample = text.slice(0, SAMPLE_SIZE);
  let nonPrintable = 0;
  for (let i = 0; i < sample.length; i++) {
    const code = sample.charCodeAt(i);
    if (
      code < 0x20 && code !== 0x09 && code !== 0x0a && code !== 0x0d || // control chars (except tab, LF, CR)
      code > 0x7e && code < 0xa0 || // C1 control chars
      code === 0xfffd // replacement character
    ) {
      nonPrintable++;
    }
  }
  const nonPrintableRatio = nonPrintable / Math.max(sample.length, 1);

  if (nonPrintableRatio >= NON_PRINTABLE_BLOCKED_THRESHOLD) {
    // AG-050: Rescue heuristic — if most words are readable despite binary noise,
    // downgrade from blocked to degraded.
    const readableWordRatio = computeReadableWordRatio(text);
    if (readableWordRatio >= RESCUE_BLOCKED_TO_DEGRADED_THRESHOLD) {
      // AG-PHASE-5-053: Cascade rescue — if readable word ratio is very high (≥80%),
      // the text is usable enough for detection despite binary noise. Rescue to partial.
      if (readableWordRatio >= RESCUE_BLOCKED_CASCADE_TO_PARTIAL_THRESHOLD) {
        return {
          quality: 'partial',
          nonPrintableRatio,
          readableWordRatio,
          reason: `${(nonPrintableRatio * 100).toFixed(0)}% non-printable but ${(readableWordRatio * 100).toFixed(0)}% readable words — cascade rescued to partial`,
        };
      }
      return {
        quality: 'degraded',
        nonPrintableRatio,
        readableWordRatio,
        reason: `${(nonPrintableRatio * 100).toFixed(0)}% non-printable but ${(readableWordRatio * 100).toFixed(0)}% readable words — rescued to degraded`,
      };
    }
    return {
      quality: 'blocked',
      nonPrintableRatio,
      readableWordRatio,
      reason: `Garbled text — ${(nonPrintableRatio * 100).toFixed(0)}% non-printable, ${(readableWordRatio * 100).toFixed(0)}% readable words`,
    };
  }

  if (nonPrintableRatio >= NON_PRINTABLE_DEGRADED_THRESHOLD) {
    // AG-050: Rescue heuristic — if most words are readable, downgrade to partial.
    const readableWordRatio = computeReadableWordRatio(text);
    if (readableWordRatio >= RESCUE_DEGRADED_TO_PARTIAL_THRESHOLD) {
      return {
        quality: 'partial',
        nonPrintableRatio,
        readableWordRatio,
        reason: `${(nonPrintableRatio * 100).toFixed(0)}% non-printable but ${(readableWordRatio * 100).toFixed(0)}% readable words — rescued to partial`,
      };
    }
    return {
      quality: 'degraded',
      nonPrintableRatio,
      readableWordRatio,
      reason: `Partially garbled text — ${(nonPrintableRatio * 100).toFixed(0)}% non-printable, ${(readableWordRatio * 100).toFixed(0)}% readable words`,
    };
  }

  if (nonPrintableRatio >= NON_PRINTABLE_PARTIAL_THRESHOLD) {
    return {
      quality: 'partial',
      nonPrintableRatio,
      readableWordRatio: -1, // not computed — not needed for clean/partial path
      reason: `Minor quality issues — ${(nonPrintableRatio * 100).toFixed(0)}% non-printable chars`,
    };
  }

  // AG-PROMPT-184/WS-02: Single-character dominance check.
  // Spaced-character PDFs (e.g. AcroForm metadata) produce text like "A s s e s s m e n t"
  // which is printable but semantically useless. If >50% of words in the sample are
  // single characters, the text is effectively junk despite low non-printable ratio.
  const sampleWords = sample.split(/\s+/).filter(w => w.length > 0);
  if (sampleWords.length >= 10) {
    const singleCharWords = sampleWords.filter(w => w.length === 1).length;
    const singleCharRatio = singleCharWords / sampleWords.length;
    if (singleCharRatio > 0.5) {
      return {
        quality: 'degraded',
        nonPrintableRatio,
        readableWordRatio: 0,
        reason: `Spaced-character text — ${(singleCharRatio * 100).toFixed(0)}% single-char words (AcroForm/layout artifact)`,
      };
    }
  }

  return { quality: 'clean', nonPrintableRatio, readableWordRatio: -1, reason: '' };
}
