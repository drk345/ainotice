/**
 * AG-MONSTER-HARDENING-TIERA-ENGINE-001 Phase 1: Magic Byte Tier-0 Gate
 *
 * Detects actual file format from first bytes, independent of extension/MIME.
 * Catches misnamed/legacy formats (e.g. OLE2 .xlsx, non-ZIP .docx) before
 * extractor paths run, preventing silent failures.
 *
 * Supported signatures:
 *  - ZIP  (PK\x03\x04)   → OOXML container (.docx/.xlsx/.pptx)
 *  - OLE2 (D0 CF 11 E0)  → Legacy Office (.xls/.doc/.ppt) or XLSB
 *  - PDF  (%PDF)          → PDF documents
 *
 * No dependencies. Pure byte inspection.
 */

// ============================================================================
// TYPES
// ============================================================================

export type DetectedFormat = 'zip' | 'ole2' | 'pdf' | 'unknown';

export interface MagicByteResult {
  /** Detected binary format from magic bytes */
  detected_type: DetectedFormat;
  /** Confidence of the detection */
  confidence: 'high' | 'medium' | 'low';
  /** True if extension implies a different format than magic bytes reveal */
  extension_mismatch: boolean;
}

// ============================================================================
// MAGIC BYTE SIGNATURES
// ============================================================================

/** ZIP local file header: PK\x03\x04 */
const ZIP_MAGIC = [0x50, 0x4B, 0x03, 0x04];

/** OLE2 Compound Binary File: D0 CF 11 E0 A1 B1 1A E1 */
const OLE2_MAGIC = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/** PDF header: %PDF (25 50 44 46) */
const PDF_MAGIC = [0x25, 0x50, 0x44, 0x46];

// ============================================================================
// EXTENSION → EXPECTED FORMAT MAPPING
// ============================================================================

/** Extensions that imply ZIP (OOXML) container */
const ZIP_EXTENSIONS = new Set(['.docx', '.xlsx', '.pptx', '.odt', '.ods', '.odp']);

/** Extensions that imply OLE2 container */
const OLE2_EXTENSIONS = new Set(['.xls', '.doc', '.ppt', '.xlsb']);

/** Extensions that imply PDF */
const PDF_EXTENSIONS = new Set(['.pdf']);

function expectedFormat(ext: string): DetectedFormat | null {
  const lower = ext.toLowerCase();
  if (ZIP_EXTENSIONS.has(lower)) return 'zip';
  if (OLE2_EXTENSIONS.has(lower)) return 'ole2';
  if (PDF_EXTENSIONS.has(lower)) return 'pdf';
  return null;
}

// ============================================================================
// SNIFF
// ============================================================================

/**
 * Check if bytes start with given magic sequence.
 */
function matchesMagic(bytes: Uint8Array | Buffer, magic: number[]): boolean {
  if (bytes.length < magic.length) return false;
  for (let i = 0; i < magic.length; i++) {
    if (bytes[i] !== magic[i]) return false;
  }
  return true;
}

/**
 * Sniff the first bytes of a file to determine its actual binary format.
 *
 * @param bytes  Raw file bytes (only first 8+ bytes needed)
 * @param extension  File extension including dot (e.g. '.xlsx')
 * @returns Detection result with format, confidence, and mismatch flag
 */
export function sniffMagicBytes(
  bytes: Uint8Array | Buffer,
  extension: string,
): MagicByteResult {
  if (bytes.length < 4) {
    return { detected_type: 'unknown', confidence: 'low', extension_mismatch: false };
  }

  let detected_type: DetectedFormat = 'unknown';
  let confidence: 'high' | 'medium' | 'low' = 'low';

  // Check signatures in order of specificity
  if (matchesMagic(bytes, OLE2_MAGIC)) {
    detected_type = 'ole2';
    confidence = 'high'; // 8-byte signature is very specific
  } else if (matchesMagic(bytes, ZIP_MAGIC)) {
    detected_type = 'zip';
    confidence = 'high'; // 4-byte signature, standard PK header
  } else if (matchesMagic(bytes, PDF_MAGIC)) {
    detected_type = 'pdf';
    confidence = 'high'; // %PDF is unambiguous
  }

  // Determine extension mismatch
  const expected = expectedFormat(extension);
  const extension_mismatch = expected !== null && detected_type !== 'unknown' && detected_type !== expected;

  return { detected_type, confidence, extension_mismatch };
}
