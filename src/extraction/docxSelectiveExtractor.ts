/**
 * AG-DOCX-ENGINEERING-CORPUS-ONLY-001: Selective DOCX Extractor
 *
 * Extracts text from DOCX files using selective ZIP entry reading with
 * hard budgets to prevent hangs on media-heavy or adversarial documents.
 *
 * Strategy:
 *   1. Load ZIP via JSZip (reads central directory, lazy decompression)
 *   2. Enumerate entries — skip media/embeddings by prefix and extension
 *   3. Read only the XML entries we need (document.xml, headers, footers, etc.)
 *   4. Enforce hard budgets: time, XML bytes, entry count
 *   5. Return structured metrics alongside extracted text
 *
 * This module is used by metadataExtractor.ts for DOCX files.
 * No extracted text is logged — only byte counts and booleans.
 */

import JSZip from 'jszip';

// ============================================================================
// CONFIGURATION — BUDGETS
// ============================================================================

/** Hard timeout for the entire DOCX extraction (ZIP load + entry reads + parse) */
export const DOCX_HARD_TIMEOUT_MS = 5000;

/** Max uncompressed XML bytes to read across all entries */
export const DOCX_MAX_XML_BYTES = 8_000_000; // 8 MB

/** Max ZIP entries to scan (prevents zip-bomb-like structures) */
export const DOCX_MAX_ENTRIES_SCANNED = 2000;

/** Max body text output length */
const DOCX_MAX_TEXT_LENGTH = 500_000; // 500K chars

// ============================================================================
// ENTRY CLASSIFICATION
// ============================================================================

/** Prefixes that must never be decompressed */
const SKIP_PREFIXES = [
  'word/media/',
  'word/embeddings/',
  'customXml/',
];

/** Extensions that must never be decompressed (case-insensitive) */
const SKIP_EXTENSIONS = new Set([
  '.bin', '.png', '.jpg', '.jpeg', '.gif',
  '.tif', '.tiff', '.bmp', '.webp', '.emf', '.wmf',
]);

/** Entries we definitely want to read for text extraction */
const TEXT_ENTRY_PATTERNS: Array<{ pattern: RegExp; priority: number; type?: string }> = [
  { pattern: /^word\/document\.xml$/, priority: 0 },
  { pattern: /^word\/header\d*\.xml$/, priority: 1 },
  { pattern: /^word\/footer\d*\.xml$/, priority: 1 },
  { pattern: /^word\/comments\.xml$/, priority: 2 },
  { pattern: /^word\/footnotes\.xml$/, priority: 2 },
  { pattern: /^word\/endnotes\.xml$/, priority: 2 },
  // AG-MONSTER-ENGINE-VETTED-SPEC-AND-BACKLOG-001: DCG-01 — textbox/drawing text extraction
  { pattern: /^word\/drawings\/drawing\d+\.xml$/, priority: 3, type: 'textbox' },
  { pattern: /^word\/charts\/chart\d+\.xml$/, priority: 3, type: 'textbox' },
];

/** Entries we read for metadata */
const METADATA_ENTRIES = [
  'docProps/core.xml',
  'docProps/app.xml',
];

// ============================================================================
// TYPES
// ============================================================================

/** Reason codes for controlled extraction failures */
export type DocxFailureReason =
  | 'DOCX_TIMEOUT'
  | 'DOCX_XML_TOO_LARGE'
  | 'DOCX_TOO_MANY_ENTRIES'
  | 'DOCX_ZIP_INVALID'
  | 'DOCX_NO_DOCUMENT_XML'
  | 'DOCX_UNKNOWN_ERROR';

/** Per-file DOCX extraction metrics */
export interface DocxExtractionMetrics {
  entries_total: number;
  entries_skipped_media: number;
  entries_read_xml: number;
  document_xml_bytes: number;
  total_xml_bytes_read: number;
  has_media: boolean;
  timings: {
    open_zip_ms: number;
    read_entries_ms: number;
    parse_xml_ms: number;
    total_docx_ms: number;
  };
  failure_reason?: DocxFailureReason;
  /** AG-GOLD-TELEMETRY-HARNESS-001: Per-part coverage telemetry */
  coverage?: DocxCoverageTelemetry;
}

/** AG-GOLD-TELEMETRY-HARNESS-001: Which document parts were scanned */
export interface DocxCoverageTelemetry {
  scanned_document: boolean;
  scanned_headers: boolean;
  scanned_footers: boolean;
  scanned_footnotes: boolean;
  scanned_endnotes: boolean;
  scanned_comments: boolean;
  scanned_textboxes: boolean;
}

export interface DocxSelectiveResult {
  /** Extracted body text (concatenation of all text entries) */
  bodyText: string;
  /** Metadata XML strings: core.xml and app.xml content (truncated) */
  coreXml?: string;
  appXml?: string;
  /** Structured extraction metrics */
  metrics: DocxExtractionMetrics;
  /** Whether extraction succeeded (got at least some text) */
  success: boolean;
  /** Error message if failed */
  error?: string;
  /**
   * AG-PROMPT-304: true when a budget/entry/output cap truncated content — only part of the
   * document was inspected. Non-content fact (derived from existing metrics + caps); drives the
   * AG-303 partial-inspection / reduced-confidence surfacing. Never carries document content.
   */
  partialInspection: boolean;
}

// ============================================================================
// HELPERS
// ============================================================================

function shouldSkipEntry(entryName: string): boolean {
  // Skip directories
  if (entryName.endsWith('/')) return true;

  // Skip by prefix
  for (const prefix of SKIP_PREFIXES) {
    if (entryName.startsWith(prefix)) return true;
  }

  // Skip by extension
  const lastDot = entryName.lastIndexOf('.');
  if (lastDot >= 0) {
    const ext = entryName.substring(lastDot).toLowerCase();
    if (SKIP_EXTENSIONS.has(ext)) return true;
  }

  return false;
}

function isTextEntry(entryName: string): { match: boolean; priority: number; type?: string } {
  for (const { pattern, priority, type } of TEXT_ENTRY_PATTERNS) {
    if (pattern.test(entryName)) return { match: true, priority, type };
  }
  return { match: false, priority: 999 };
}

/**
 * Extract text content from OOXML by pulling <w:t> text nodes.
 * Lightweight regex approach — no DOM build.
 */
function extractWtText(xml: string): string {
  const parts: string[] = [];
  // Match <w:t ...>text</w:t> — handles xml:space="preserve" attribute
  const pattern = /<w:t[^>]*>([^<]*)<\/w:t>/gi;
  let match;
  while ((match = pattern.exec(xml)) !== null) {
    const text = match[1];
    if (text) parts.push(text);
  }

  if (parts.length === 0) {
    // Fallback: generic text node extraction (for comments, footnotes that use <a:t>)
    const genericPattern = /<(?:a:)?t[^>]*>([^<]+)<\/(?:a:)?t>/gi;
    while ((match = genericPattern.exec(xml)) !== null) {
      const text = match[1].trim();
      if (text) parts.push(text);
    }
  }

  return parts.join(' ')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#(\d+);/g, (_, code) => String.fromCharCode(parseInt(code, 10)))
    .replace(/\s+/g, ' ')
    .trim();
}

// ============================================================================
// MAIN EXTRACTION FUNCTION
// ============================================================================

/**
 * Extract text from a DOCX file using selective ZIP entry reading.
 *
 * @param data - Raw DOCX bytes (Uint8Array or ArrayBuffer)
 * @returns Extraction result with body text, metadata XML, and metrics
 *
 * Budget enforcement:
 *   - Hard timeout: DOCX_HARD_TIMEOUT_MS (5s) around entire operation
 *   - Max XML bytes: DOCX_MAX_XML_BYTES (8MB) total across all entries
 *   - Max entries: DOCX_MAX_ENTRIES_SCANNED (2000) scanned
 *   - On budget hit: returns controlled failure with reason code
 */
export async function extractDocxSelective(
  data: Uint8Array | ArrayBuffer,
): Promise<DocxSelectiveResult> {
  const totalStart = performance.now();

  const coverage: DocxCoverageTelemetry = {
    scanned_document: false,
    scanned_headers: false,
    scanned_footers: false,
    scanned_footnotes: false,
    scanned_endnotes: false,
    scanned_comments: false,
    scanned_textboxes: false,
  };

  const metrics: DocxExtractionMetrics = {
    entries_total: 0,
    entries_skipped_media: 0,
    entries_read_xml: 0,
    document_xml_bytes: 0,
    total_xml_bytes_read: 0,
    has_media: false,
    timings: {
      open_zip_ms: 0,
      read_entries_ms: 0,
      parse_xml_ms: 0,
      total_docx_ms: 0,
    },
    coverage,
  };

  const makeResult = (partial: Partial<DocxSelectiveResult>): DocxSelectiveResult => {
    metrics.timings.total_docx_ms = performance.now() - totalStart;
    const resolvedBodyText = partial.bodyText ?? '';
    // AG-PROMPT-307 (R2): use the effective metrics the caller is returning (some paths pass a
    // modified copy via partial.metrics, e.g. too-many-entries / timeout) rather than only the
    // closure snapshot, so a budget fact set on the returned copy is not under-reported.
    const m = partial.metrics ?? metrics;
    // AG-PROMPT-304: partial inspection if any existing budget/entry/output cap truncated content.
    // Reuses existing metrics + caps (no new thresholds, no extraction-text change).
    const partialInspection =
      m.failure_reason !== undefined ||
      m.total_xml_bytes_read >= DOCX_MAX_XML_BYTES ||
      m.entries_total > DOCX_MAX_ENTRIES_SCANNED ||
      resolvedBodyText.length >= DOCX_MAX_TEXT_LENGTH;
    return {
      bodyText: '',
      metrics,
      success: false,
      ...partial,
      partialInspection,
    };
  };

  // Helper: check if we've exceeded the time budget
  const isTimedOut = (): boolean =>
    (performance.now() - totalStart) >= DOCX_HARD_TIMEOUT_MS;

  // ------------------------------------------------------------------
  // Step 1: Load ZIP central directory
  // ------------------------------------------------------------------
  let zip: JSZip;
  const zipStart = performance.now();
  try {
    const input = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
    zip = await JSZip.loadAsync(input);
  } catch (e) {
    metrics.timings.open_zip_ms = performance.now() - zipStart;
    return makeResult({
      error: `ZIP load failed: ${e instanceof Error ? e.message : String(e)}`,
      metrics: { ...metrics, failure_reason: 'DOCX_ZIP_INVALID' },
    });
  }
  metrics.timings.open_zip_ms = performance.now() - zipStart;

  if (isTimedOut()) {
    return makeResult({
      error: 'Timeout after ZIP load',
      metrics: { ...metrics, failure_reason: 'DOCX_TIMEOUT' },
    });
  }

  // ------------------------------------------------------------------
  // Step 2: Enumerate and classify entries
  // ------------------------------------------------------------------
  const allEntryNames = Object.keys(zip.files);
  metrics.entries_total = allEntryNames.length;

  if (metrics.entries_total > DOCX_MAX_ENTRIES_SCANNED) {
    return makeResult({
      error: `Too many ZIP entries: ${metrics.entries_total} > ${DOCX_MAX_ENTRIES_SCANNED}`,
      metrics: { ...metrics, failure_reason: 'DOCX_TOO_MANY_ENTRIES' },
    });
  }

  // Classify entries
  const textEntries: Array<{ name: string; priority: number; type?: string }> = [];
  const metadataEntries: string[] = [];

  for (const name of allEntryNames) {
    if (shouldSkipEntry(name)) {
      metrics.entries_skipped_media++;
      // Check if any media prefix matched (for has_media flag)
      if (name.startsWith('word/media/')) {
        metrics.has_media = true;
      }
      continue;
    }

    const { match, priority, type } = isTextEntry(name);
    if (match) {
      textEntries.push({ name, priority, type });
    }

    if (METADATA_ENTRIES.includes(name)) {
      metadataEntries.push(name);
    }
  }

  // Sort text entries by priority (document.xml first)
  textEntries.sort((a, b) => a.priority - b.priority);

  // ------------------------------------------------------------------
  // Step 3: Read metadata entries
  // ------------------------------------------------------------------
  let coreXml: string | undefined;
  let appXml: string | undefined;

  const readStart = performance.now();

  for (const name of metadataEntries) {
    if (isTimedOut()) break;

    const entry = zip.file(name);
    if (!entry) continue;

    // AG-PROMPT-307: declared-size pre-check before decompressing metadata entries (same guard as
    // the text-entry loop; reuses DOCX_MAX_XML_BYTES as the per-entry bound, no new threshold).
    const declaredSize = (entry as { _data?: { uncompressedSize?: number } })._data?.uncompressedSize ?? 0;
    if (declaredSize > DOCX_MAX_XML_BYTES) {
      metrics.failure_reason = 'DOCX_XML_TOO_LARGE';
      continue;
    }

    try {
      const content = await entry.async('text');
      metrics.entries_read_xml++;
      const contentBytes = new TextEncoder().encode(content).length;
      metrics.total_xml_bytes_read += contentBytes;

      if (name === 'docProps/core.xml') {
        coreXml = content.substring(0, 2000);
      } else if (name === 'docProps/app.xml') {
        appXml = content.substring(0, 2000);
      }
    } catch {
      // Metadata read failure is non-fatal
    }
  }

  if (isTimedOut()) {
    return makeResult({
      coreXml,
      appXml,
      error: 'Timeout during metadata read',
      metrics: { ...metrics, failure_reason: 'DOCX_TIMEOUT' },
    });
  }

  // ------------------------------------------------------------------
  // Step 4: Read text entries with budget enforcement
  // ------------------------------------------------------------------
  const textParts: string[] = [];
  let foundDocumentXml = false;

  for (const { name, type } of textEntries) {
    if (isTimedOut()) {
      metrics.failure_reason = 'DOCX_TIMEOUT';
      break;
    }

    if (metrics.total_xml_bytes_read >= DOCX_MAX_XML_BYTES) {
      metrics.failure_reason = 'DOCX_XML_TOO_LARGE';
      break;
    }

    const entry = zip.file(name);
    if (!entry) continue;

    // AG-PROMPT-307: declared-uncompressed-size pre-check BEFORE decompressing the entry, to avoid
    // inflating an oversized entry into memory before the post-read budget catches it. Reuses the
    // existing DOCX_MAX_XML_BYTES budget as the per-entry bound (no new threshold). Defeatable by a
    // zip that understates the declared size (best-effort defense-in-depth; bounded inflate deferred).
    const declaredSize = (entry as { _data?: { uncompressedSize?: number } })._data?.uncompressedSize ?? 0;
    if (declaredSize > DOCX_MAX_XML_BYTES) {
      metrics.failure_reason = 'DOCX_XML_TOO_LARGE';
      continue; // skip oversized entry pre-inflate; partial inspection surfaced via failure_reason
    }

    try {
      const content = await entry.async('text');
      const contentBytes = new TextEncoder().encode(content).length;
      metrics.entries_read_xml++;
      metrics.total_xml_bytes_read += contentBytes;

      if (name === 'word/document.xml') {
        metrics.document_xml_bytes = contentBytes;
        foundDocumentXml = true;
        coverage.scanned_document = true;
      } else if (/^word\/header\d*\.xml$/.test(name)) {
        coverage.scanned_headers = true;
      } else if (/^word\/footer\d*\.xml$/.test(name)) {
        coverage.scanned_footers = true;
      } else if (name === 'word/footnotes.xml') {
        coverage.scanned_footnotes = true;
      } else if (name === 'word/endnotes.xml') {
        coverage.scanned_endnotes = true;
      } else if (name === 'word/comments.xml') {
        coverage.scanned_comments = true;
      } else if (type === 'textbox') {
        // AG-MONSTER-ENGINE-VETTED-SPEC-AND-BACKLOG-001: DCG-01 — textbox coverage
        coverage.scanned_textboxes = true;
      }

      // Budget check after read
      if (metrics.total_xml_bytes_read > DOCX_MAX_XML_BYTES) {
        metrics.failure_reason = 'DOCX_XML_TOO_LARGE';
        // Still extract what we read so far
      }

      const parseStart = performance.now();
      const text = extractWtText(content);
      metrics.timings.parse_xml_ms += performance.now() - parseStart;

      if (text) textParts.push(text);
    } catch {
      // Individual entry read failure is non-fatal — continue to next
    }
  }

  metrics.timings.read_entries_ms = performance.now() - readStart - metrics.timings.parse_xml_ms;

  // ------------------------------------------------------------------
  // Step 5: Assemble result
  // ------------------------------------------------------------------
  const bodyText = textParts.join(' ').substring(0, DOCX_MAX_TEXT_LENGTH);

  if (!foundDocumentXml && bodyText.length === 0) {
    return makeResult({
      coreXml,
      appXml,
      bodyText: '',
      error: 'No word/document.xml found in DOCX',
      metrics: { ...metrics, failure_reason: metrics.failure_reason ?? 'DOCX_NO_DOCUMENT_XML' },
    });
  }

  // If we hit a budget but still got text, mark as success (partial extraction)
  const success = bodyText.length > 0;

  return makeResult({
    bodyText,
    coreXml,
    appXml,
    success,
    error: metrics.failure_reason
      ? `Budget hit: ${metrics.failure_reason} (partial text: ${bodyText.length} chars)`
      : undefined,
  });
}

/**
 * Run extractDocxSelective with a hard timeout wrapper.
 * Returns a controlled failure on timeout — never hangs.
 */
export async function extractDocxSelectiveWithTimeout(
  data: Uint8Array | ArrayBuffer,
  timeoutMs: number = DOCX_HARD_TIMEOUT_MS,
): Promise<DocxSelectiveResult> {
  let timeoutId: ReturnType<typeof setTimeout>;

  const timeoutResult: DocxSelectiveResult = {
    bodyText: '',
    metrics: {
      entries_total: 0,
      entries_skipped_media: 0,
      entries_read_xml: 0,
      document_xml_bytes: 0,
      total_xml_bytes_read: 0,
      has_media: false,
      timings: { open_zip_ms: 0, read_entries_ms: 0, parse_xml_ms: 0, total_docx_ms: timeoutMs },
      failure_reason: 'DOCX_TIMEOUT',
    },
    success: false,
    error: `Hard timeout: ${timeoutMs}ms exceeded`,
    partialInspection: true,  // AG-PROMPT-304: hard timeout = incomplete inspection
  };

  const timeoutPromise = new Promise<DocxSelectiveResult>((resolve) => {
    timeoutId = setTimeout(() => resolve(timeoutResult), timeoutMs);
  });

  try {
    const result = await Promise.race([
      extractDocxSelective(data),
      timeoutPromise,
    ]);
    clearTimeout(timeoutId!);
    return result;
  } catch (e) {
    clearTimeout(timeoutId!);
    return {
      ...timeoutResult,
      error: `Extraction error: ${e instanceof Error ? e.message : String(e)}`,
      metrics: {
        ...timeoutResult.metrics,
        failure_reason: 'DOCX_UNKNOWN_ERROR',
      },
    };
  }
}
