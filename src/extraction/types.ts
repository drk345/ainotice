/**
 * AG-PHASE-1-UNIFIED-PDF-EXTRACTION-SPINE: Shared types for PDF text extraction.
 *
 * These types form the contract between the platform-agnostic core extractor
 * and the platform-specific inflate adapters (browser pure-JS, Node zlib).
 */

// ============================================================================
// INFLATE PROVIDER
// ============================================================================

/**
 * Inflate function signature.
 * Implementers provide platform-specific decompression (zlib, pure-JS, etc.).
 * Must handle both zlib-wrapped and raw DEFLATE data.
 * Returns null on failure.
 */
export type InflateFn = (data: Uint8Array) => Uint8Array | null;

// ============================================================================
// FONT TYPES
// ============================================================================

/** Font encoding types recognized during extraction */
export type FontEncoding =
  | 'WinAnsiEncoding'
  | 'MacRomanEncoding'
  | 'StandardEncoding'
  | 'Identity-H'
  | 'Identity-V'
  | 'Other';

/** Per-font entry in the font registry */
export interface FontEntry {
  /** ToUnicode CMap: glyph code (numeric) → unicode string */
  cmap: Map<number, string> | null;
  /** Bytes per glyph code (1 for simple fonts, 2 for CID fonts) */
  byteWidth: 1 | 2;
  /** Font encoding (for WinAnsi/MacRoman fallback) */
  encoding: FontEncoding | null;
  /** Font subtype (Type0, TrueType, Type1, etc.) */
  subtype: string | null;
}

/** Font registry: maps font alias (e.g. "F1") to its FontEntry */
export type FontRegistry = Map<string, FontEntry>;

// ============================================================================
// QUALITY ASSESSMENT
// ============================================================================

/** Quality classification for extracted text */
/**
 * AG-050: Renamed blocked_by_ocr → blocked (OCR is not implemented;
 * the label describes extraction outcome, not a remediation path).
 */
export type QualityLevel = 'clean' | 'partial' | 'degraded' | 'blocked' | 'empty';

// ============================================================================
// EXTRACTION RESULT
// ============================================================================

/** Extraction diagnostics for debugging and reporting */
export interface ExtractionDiagnostics {
  streamsProcessed: number;
  streamsInflated: number;
  streamsFailed: number;
  btEtChars: number;
  asciiChars: number;
  nonPrintableRatio: number;
  fontsFound: number;
  fontsWithCmap: number;
  fontsWithEncoding: number;
  extractionMethod: 'font-aware' | 'merged-cmap' | 'literal-fallback' | 'ascii-fallback' | 'none';
}

/** Result of PDF text extraction */
export interface PdfExtractionResult {
  /** Extracted text (normalized, capped at MAX_OUTPUT_CHARS) */
  text: string;
  /** Quality classification */
  quality: QualityLevel;
  /** Detailed extraction diagnostics */
  diagnostics: ExtractionDiagnostics;
}

// ============================================================================
// INFLATE ERROR CONTEXT (AG-ERROR-DIAGNOSTICS-INFLATERAW-NO-SILENT-FAIL)
// ============================================================================

/**
 * Error context captured when inflate fails.
 * Contains ONLY safe diagnostic fields — no user content.
 */
export interface InflateErrorContext {
  /** How the failure occurred */
  failureMode: 'exception' | 'graceful-return';
  /** Error constructor name (e.g., 'RangeError', 'TypeError') — only for exception mode */
  errorType?: string;
  /** Error code if present (e.g., 'ERR_INVALID_ARG_VALUE') */
  errorCode?: string;
  /** Brief reason for graceful-return failures */
  reason?: string;
  /** Input data length in bytes (safe: just a number) */
  inputLength: number;
  /** Which decompression mode was attempted */
  attemptedMode: 'zlib-wrapped' | 'raw-deflate';
  /** Timestamp for correlation */
  timestamp: number;
}
