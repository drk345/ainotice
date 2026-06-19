/**
 * AgentGuard PDF Fallback Text Extractor (AG-PROMPT-073)
 *
 * Provides a minimal, deterministic fallback for extracting text from PDFs
 * when the primary extractor (complex BT/ET + ToUnicode parsing) returns 0 chars.
 *
 * Design principles:
 * - SIMPLE: Basic ASCII/printable text extraction from raw bytes
 * - SAFE: No heavy PDF rendering, caps output length
 * - DETERMINISTIC: Same file -> same output
 * - LOCAL-ONLY: No external calls
 *
 * Use cases:
 * - Simple text PDFs where primary extractor fails (Firefox Xray issues)
 * - PDFs with embedded ASCII text outside font-encoded streams
 *
 * NOT suitable for:
 * - Scanned/image-only PDFs (will return empty)
 * - Encrypted PDFs (will return empty)
 * - Complex font-encoded PDFs (primary extractor is better)
 *
 * @see AG-PROMPT-073: PDF Extraction Fallback
 */

// ============================================================================
// CONSTANTS
// ============================================================================

/** Maximum output length to prevent memory issues */
const MAX_OUTPUT_CHARS = 50_000;

/** Minimum run length of printable ASCII to consider as text */
const MIN_TEXT_RUN_LENGTH = 4;

/** Reason codes for extraction diagnostics */
export const PDF_EXTRACTION_REASON_CODES = {
  /** Primary extractor succeeded */
  PRIMARY_SUCCESS: 'PDF_PRIMARY_SUCCESS',
  /** Fallback extractor succeeded */
  FALLBACK_SUCCESS: 'PDF_FALLBACK_SUCCESS',
  /** Primary returned empty, fallback also empty */
  EXTRACT_EMPTY: 'PDF_EXTRACT_EMPTY',
  /** Primary extraction error */
  PRIMARY_ERROR: 'PDF_PRIMARY_ERROR',
  /** Fallback extraction error */
  FALLBACK_ERROR: 'PDF_FALLBACK_ERROR',
  /** File too large to scan */
  FILE_TOO_LARGE: 'PDF_FILE_TOO_LARGE',
  /** Not a PDF file */
  NOT_PDF: 'PDF_NOT_PDF',
  /** Encrypted PDF was readable without password prompt */
  ENCRYPTED_READABLE_NO_PROMPT: 'PDF_ENCRYPTED_READABLE_NO_PROMPT',
  /** Encrypted PDF became readable only after blank-password retry */
  ENCRYPTED_READABLE_BLANK_PASSWORD: 'PDF_ENCRYPTED_READABLE_BLANK_PASSWORD',
  /** Encrypted PDF still required password after blank-password retry */
  ENCRYPTED_PASSWORD_REQUIRED: 'PDF_ENCRYPTED_PASSWORD_REQUIRED',
} as const;

export type PdfExtractionReasonCode = typeof PDF_EXTRACTION_REASON_CODES[keyof typeof PDF_EXTRACTION_REASON_CODES];

// ============================================================================
// TYPES
// ============================================================================

/**
 * Result of fallback extraction attempt.
 */
export interface FallbackExtractionResult {
  /** Extracted text (may be empty) */
  text: string;

  /** Length of extracted text */
  textLength: number;

  /** Whether extraction succeeded (text.length > 0) */
  success: boolean;

  /** Reason code for diagnostics */
  reasonCode: PdfExtractionReasonCode;

  /** Extraction method used */
  method: 'fallback-ascii' | 'fallback-btj' | 'none';

  /** Duration in milliseconds */
  durationMs: number;
}

// ============================================================================
// FALLBACK EXTRACTION STRATEGIES
// ============================================================================

/**
 * Strategy 1: Extract printable ASCII runs from raw bytes.
 * Finds continuous sequences of printable characters.
 */
function extractAsciiRuns(bytes: Uint8Array, maxChars: number): string {
  const chunks: string[] = [];
  let currentRun = '';
  let totalChars = 0;

  for (let i = 0; i < bytes.length && totalChars < maxChars; i++) {
    const byte = bytes[i];

    // Check if printable ASCII (space through tilde, plus common whitespace)
    const isPrintable = (byte >= 0x20 && byte <= 0x7E) || byte === 0x0A || byte === 0x0D || byte === 0x09;

    if (isPrintable) {
      currentRun += String.fromCharCode(byte);
    } else {
      // End of printable run
      if (currentRun.length >= MIN_TEXT_RUN_LENGTH) {
        // Filter out PDF operators and structural elements
        if (!isPdfOperatorOrStructure(currentRun)) {
          chunks.push(currentRun);
          totalChars += currentRun.length + 1; // +1 for space separator
        }
      }
      currentRun = '';
    }
  }

  // Don't forget the last run
  if (currentRun.length >= MIN_TEXT_RUN_LENGTH && !isPdfOperatorOrStructure(currentRun)) {
    chunks.push(currentRun);
  }

  return chunks.join(' ').slice(0, maxChars);
}

/**
 * Strategy 2: Extract text from Tj/TJ operators (simpler than full BT/ET parsing).
 * Looks for literal strings in parentheses after text operators.
 */
function extractTjOperatorText(bytes: Uint8Array, maxChars: number): string {
  const chunks: string[] = [];
  let totalChars = 0;

  // Convert to string for regex matching (limited range)
  const searchLimit = Math.min(bytes.length, 2 * 1024 * 1024); // 2MB limit
  let text = '';
  for (let i = 0; i < searchLimit; i++) {
    text += String.fromCharCode(bytes[i]);
  }

  // Match literal strings: (text) Tj or [(text)] TJ
  // Simple pattern: capture content in parentheses followed by Tj/TJ
  const tjPattern = /\(([^)\\]*(?:\\.[^)\\]*)*)\)\s*T[jJ]/g;
  let match;

  while ((match = tjPattern.exec(text)) !== null && totalChars < maxChars) {
    const content = unescapePdfString(match[1]);
    if (content.length >= 2) {
      chunks.push(content);
      totalChars += content.length + 1;
    }
  }

  return chunks.join(' ').slice(0, maxChars);
}

/**
 * Check if a string is likely a PDF operator or structural element.
 */
function isPdfOperatorOrStructure(str: string): boolean {
  const trimmed = str.trim();

  // Common PDF operators and keywords
  const pdfKeywords = [
    'stream', 'endstream', 'endobj', 'obj', 'xref', 'trailer',
    'startxref', 'pdf', 'eof', 'null', 'true', 'false',
    '/type', '/page', '/font', '/encoding', '/filter',
    'flatedecode', 'ascii85decode', 'asciihexdecode',
    'begincmap', 'endcmap', 'begincodespacerange', 'endcodespacerange',
    'beginbfchar', 'endbfchar', 'beginbfrange', 'endbfrange',
    'defincmap', 'cmapname', 'cmaptype',
  ];

  const lowerTrimmed = trimmed.toLowerCase();

  // Check exact matches with keywords
  if (pdfKeywords.includes(lowerTrimmed)) {
    return true;
  }

  // Check if it's mostly numeric (object references, coordinates)
  const numericRatio = (trimmed.match(/[\d.]/g)?.length ?? 0) / trimmed.length;
  if (numericRatio > 0.7 && trimmed.length > 3) {
    return true;
  }

  // Check if it starts with common PDF prefixes
  if (/^[\/\[\]<>{}]/.test(trimmed) || /^[\d]+\s+[\d]+\s+[Rr]/.test(trimmed)) {
    return true;
  }

  // Check if it's a hex string marker
  if (/^[0-9A-Fa-f]+$/.test(trimmed) && trimmed.length > 8) {
    return true;
  }

  return false;
}

/**
 * Unescape PDF literal string escape sequences.
 */
function unescapePdfString(str: string): string {
  return str
    .replace(/\\n/g, '\n')
    .replace(/\\r/g, '\r')
    .replace(/\\t/g, '\t')
    .replace(/\\b/g, '\b')
    .replace(/\\f/g, '\f')
    .replace(/\\\(/g, '(')
    .replace(/\\\)/g, ')')
    .replace(/\\\\/g, '\\')
    .replace(/\\([0-7]{1,3})/g, (_, octal) => String.fromCharCode(parseInt(octal, 8)));
}

/**
 * Normalize extracted text (collapse whitespace, trim).
 */
function normalizeText(text: string): string {
  return text
    .replace(/\s+/g, ' ')
    .replace(/[^\x20-\x7E\xA0-\xFF\u0100-\u017F]/g, ' ') // Keep ASCII + Latin Extended
    .replace(/\s+/g, ' ')
    .trim();
}

// ============================================================================
// MAIN FALLBACK FUNCTION
// ============================================================================

/**
 * Extract text from PDF using fallback strategies.
 *
 * This function runs ONLY when the primary extractor returns 0 chars.
 * It tries two strategies in order:
 * 1. Tj operator extraction (better for fonts)
 * 2. ASCII run extraction (catches raw text)
 *
 * Returns the best result (non-empty, or empty with reason code).
 *
 * @param file - The PDF file to extract text from
 * @returns FallbackExtractionResult with extracted text and diagnostics
 */
export async function extractPdfTextFallback(file: File): Promise<FallbackExtractionResult> {
  const startTime = performance.now();

  // Check file type
  if (!file.name.toLowerCase().endsWith('.pdf') && file.type !== 'application/pdf') {
    return {
      text: '',
      textLength: 0,
      success: false,
      reasonCode: PDF_EXTRACTION_REASON_CODES.NOT_PDF,
      method: 'none',
      durationMs: performance.now() - startTime,
    };
  }

  // Size limit: 10MB for fallback (conservative)
  const MAX_FALLBACK_SIZE = 10 * 1024 * 1024;
  if (file.size > MAX_FALLBACK_SIZE) {
    return {
      text: '',
      textLength: 0,
      success: false,
      reasonCode: PDF_EXTRACTION_REASON_CODES.FILE_TOO_LARGE,
      method: 'none',
      durationMs: performance.now() - startTime,
    };
  }

  try {
    // Read file bytes
    const buffer = await file.arrayBuffer();
    const bytes = new Uint8Array(buffer);

    // Strategy 1: Try Tj operator extraction first (better quality)
    const tjText = normalizeText(extractTjOperatorText(bytes, MAX_OUTPUT_CHARS));
    if (tjText.length >= MIN_TEXT_RUN_LENGTH * 2) {
      return {
        text: tjText,
        textLength: tjText.length,
        success: true,
        reasonCode: PDF_EXTRACTION_REASON_CODES.FALLBACK_SUCCESS,
        method: 'fallback-btj',
        durationMs: performance.now() - startTime,
      };
    }

    // Strategy 2: Fall back to ASCII run extraction
    const asciiText = normalizeText(extractAsciiRuns(bytes, MAX_OUTPUT_CHARS));
    if (asciiText.length >= MIN_TEXT_RUN_LENGTH * 2) {
      return {
        text: asciiText,
        textLength: asciiText.length,
        success: true,
        reasonCode: PDF_EXTRACTION_REASON_CODES.FALLBACK_SUCCESS,
        method: 'fallback-ascii',
        durationMs: performance.now() - startTime,
      };
    }

    // Both strategies failed - likely scanned/image-only PDF
    return {
      text: '',
      textLength: 0,
      success: false,
      reasonCode: PDF_EXTRACTION_REASON_CODES.EXTRACT_EMPTY,
      method: 'none',
      durationMs: performance.now() - startTime,
    };

  } catch (e) {
    return {
      text: '',
      textLength: 0,
      success: false,
      reasonCode: PDF_EXTRACTION_REASON_CODES.FALLBACK_ERROR,
      method: 'none',
      durationMs: performance.now() - startTime,
    };
  }
}

// ============================================================================
// COMBINED EXTRACTION RESULT TYPE
// ============================================================================

/**
 * Extended extraction result including extraction status.
 */
export interface PdfExtractionStatus {
  /** Primary extractor text length */
  primaryTextLength: number;

  /** Fallback extractor text length (if used) */
  fallbackTextLength: number;

  /** Whether fallback was attempted */
  fallbackAttempted: boolean;

  /** Final reason code */
  reasonCode: PdfExtractionReasonCode;

  /** Which method produced the final text */
  finalMethod: 'primary' | 'fallback-ascii' | 'fallback-btj' | 'none';

  /** Total extraction duration */
  totalDurationMs: number;
}
