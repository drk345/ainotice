/**
 * AG-XLSX-HARDENING-PLAN-001: XLSX Selective Extractor with Budgets
 *
 * Mirrors the DOCX selective extractor pattern (docxSelectiveExtractor.ts).
 * Used by the corpus harness for metriced XLSX extraction.
 *
 * Coverage priority (from plan):
 *  1. xl/sharedStrings.xml       — primary source of human-entered text
 *  2. xl/worksheets/sheet[n].xml — inlineStr + non-numeric <v> values
 *  3. xl/comments.xml            — user notes (may contain sensitive PII)
 *  4. xl/drawings/drawing[n].xml — text inside shapes / text boxes
 *  5. docProps/core.xml          — metadata (creator, title, etc.)
 *
 * Budgets (from plan):
 *  hard_timeout_ms:          5000
 *  max_entry_bytes:          20 MB (per ZIP entry, uncompressed)
 *  max_sharedStrings_bytes:  10 MB
 *  max_sheets:               10
 *  max_text_nodes:           200,000
 *  max_total_chars:          10,000,000 (output cap)
 *
 * Privacy: No extracted text is stored or returned to callers beyond
 * the in-memory bodyText string used for detection.
 */

import JSZip from 'jszip';

// ============================================================================
// BUDGET CONSTANTS
// ============================================================================

export const XLSX_HARD_TIMEOUT_MS = 5000;
export const XLSX_MAX_ENTRY_BYTES = 20 * 1024 * 1024;        // 20 MB per entry
export const XLSX_MAX_SHARED_STRINGS_BYTES = 10 * 1024 * 1024; // 10 MB
export const XLSX_MAX_SHEETS = 10;
export const XLSX_MAX_TEXT_NODES = 200_000;
export const XLSX_MAX_TOTAL_CHARS = 10_000_000;
const XLSX_OUTPUT_CAP = 500_000;                             // output cap for bodyText

// ============================================================================
// TYPES
// ============================================================================

export type XlsxFailureReason =
  | 'XLSX_TIMEOUT'
  | 'XLSX_ZIP_INVALID'
  | 'XLSX_NO_CONTENT'
  | 'XLSX_UNKNOWN_ERROR';

export interface XlsxExtractionMetrics {
  /** Total ZIP entries found */
  entries_total: number;
  /** Sheets processed (capped at XLSX_MAX_SHEETS) */
  sheets_processed: number;
  /** Total sheets in workbook */
  sheets_total: number;
  /** Whether sharedStrings.xml was present */
  has_shared_strings: boolean;
  /** Whether comments.xml was present */
  has_comments: boolean;
  /** Whether drawings were present */
  has_drawings: boolean;
  /** Uncompressed bytes read from sharedStrings.xml */
  shared_strings_bytes: number;
  /** Total uncompressed bytes read across all XML entries */
  total_xml_bytes_read: number;
  /** Total text nodes extracted */
  text_nodes_extracted: number;
  /** AG-XLSX-HARDENING-PLAN-001: true if any budget limit was hit */
  budget_exceeded: boolean;
  /** AG-XLSX-HARDENING-PLAN-001: true if output was sampled (truncated) */
  sampling_applied: boolean;
  /** AG-MONSTER-HARDENING-TIERA-ENGINE-001: inlineStr text nodes extracted from worksheets */
  inlineStr_hits: number;
  /** AG-MONSTER-HARDENING-TIERA-ENGINE-001: non-numeric cached <v> values extracted from worksheets */
  cachedValue_hits: number;
  timings: {
    open_zip_ms: number;
    read_entries_ms: number;
    parse_xml_ms: number;
    total_xlsx_ms: number;
  };
  failure_reason?: XlsxFailureReason;
  /** AG-GOLD-TELEMETRY-HARNESS-001: Per-part coverage telemetry */
  coverage?: XlsxCoverageTelemetry;
}

/** AG-GOLD-TELEMETRY-HARNESS-001: Which document parts were scanned */
export interface XlsxCoverageTelemetry {
  scanned_sharedStrings: boolean;
  scanned_worksheets: boolean;
  saw_inlineStr: boolean;
  scanned_comments: boolean;
  scanned_drawings: boolean;
  scanned_docProps: boolean;
}

export interface XlsxExtractionResult {
  success: boolean;
  bodyText: string;
  metrics: XlsxExtractionMetrics;
}

// ============================================================================
// XML TEXT EXTRACTION HELPERS
// ============================================================================

/**
 * Extract text from <t>...</t> tags (sharedStrings, comments, drawings).
 * Decodes basic XML entities.
 */
function extractTagT(xml: string, textParts: string[], nodeCount: { n: number }): void {
  const pattern = /<t[^>]*>([^<]*)<\/t>/gi;
  let match;
  while ((match = pattern.exec(xml)) !== null) {
    if (nodeCount.n >= XLSX_MAX_TEXT_NODES) break;
    const text = decodeXmlEntities(match[1].trim());
    if (text) {
      textParts.push(text);
      nodeCount.n++;
    }
  }
}

/**
 * Extract text from <is><t>...</t></is> inline string cells.
 */
function extractInlineStrings(xml: string, textParts: string[], nodeCount: { n: number }): void {
  const pattern = /<is[^>]*>[\s\S]*?<\/is>/gi;
  let isMatch;
  while ((isMatch = pattern.exec(xml)) !== null) {
    if (nodeCount.n >= XLSX_MAX_TEXT_NODES) break;
    const tPat = /<t[^>]*>([^<]*)<\/t>/gi;
    let tMatch;
    while ((tMatch = tPat.exec(isMatch[0])) !== null) {
      const text = decodeXmlEntities(tMatch[1].trim());
      if (text) {
        textParts.push(text);
        nodeCount.n++;
      }
    }
  }
}

/**
 * Extract non-numeric values from <v>...</v> cells.
 */
function extractCellValues(xml: string, textParts: string[], nodeCount: { n: number }): void {
  const pattern = /<v>([^<]*)<\/v>/gi;
  let match;
  while ((match = pattern.exec(xml)) !== null) {
    if (nodeCount.n >= XLSX_MAX_TEXT_NODES) break;
    const text = match[1].trim();
    if (text && isNaN(Number(text))) {
      textParts.push(decodeXmlEntities(text));
      nodeCount.n++;
    }
  }
}

/**
 * Decode common XML entities in extracted text.
 */
function decodeXmlEntities(s: string): string {
  return s
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#(\d+);/g, (_, code) => String.fromCharCode(parseInt(code, 10)));
}

// ============================================================================
// MAIN EXTRACTOR
// ============================================================================

/**
 * Extract text from an XLSX buffer with deterministic budget enforcement.
 *
 * @param buffer Raw XLSX file bytes
 * @returns Extraction result with bodyText and metrics
 */
export async function extractXlsxWithBudgets(buffer: Buffer): Promise<XlsxExtractionResult> {
  const totalStart = performance.now();

  const coverage: XlsxCoverageTelemetry = {
    scanned_sharedStrings: false,
    scanned_worksheets: false,
    saw_inlineStr: false,
    scanned_comments: false,
    scanned_drawings: false,
    scanned_docProps: false,
  };

  const metrics: XlsxExtractionMetrics = {
    entries_total: 0,
    sheets_processed: 0,
    sheets_total: 0,
    has_shared_strings: false,
    has_comments: false,
    has_drawings: false,
    shared_strings_bytes: 0,
    total_xml_bytes_read: 0,
    text_nodes_extracted: 0,
    budget_exceeded: false,
    sampling_applied: false,
    inlineStr_hits: 0,
    cachedValue_hits: 0,
    timings: { open_zip_ms: 0, read_entries_ms: 0, parse_xml_ms: 0, total_xlsx_ms: 0 },
    coverage,
  };

  const textParts: string[] = [];
  const nodeCount = { n: 0 };

  // ── Open ZIP ──────────────────────────────────────────────────────────────
  const zipStart = performance.now();
  let zip: JSZip;
  try {
    zip = await JSZip.loadAsync(buffer);
  } catch {
    metrics.timings.total_xlsx_ms = performance.now() - totalStart;
    metrics.failure_reason = 'XLSX_ZIP_INVALID';
    return { success: false, bodyText: '', metrics };
  }
  metrics.timings.open_zip_ms = performance.now() - zipStart;

  const allEntries = Object.keys(zip.files);
  metrics.entries_total = allEntries.length;

  // ── Collect relevant entry names ──────────────────────────────────────────
  const sheetFiles = allEntries
    .filter(n => /^xl\/worksheets\/sheet\d+\.xml$/i.test(n))
    .sort((a, b) => {
      const na = parseInt(a.match(/\d+/)![0]);
      const nb = parseInt(b.match(/\d+/)![0]);
      return na - nb;
    });

  const commentFiles = allEntries.filter(n => /^xl\/comments\d*\.xml$/i.test(n));
  const drawingFiles = allEntries.filter(n => /^xl\/drawings\/drawing\d+\.xml$/i.test(n));

  metrics.sheets_total = sheetFiles.length;
  metrics.has_comments = commentFiles.length > 0;
  metrics.has_drawings = drawingFiles.length > 0;

  const readStart = performance.now();

  // Abort helper for hard timeout
  const hardDeadline = totalStart + XLSX_HARD_TIMEOUT_MS;
  function checkTimeout(): boolean {
    return performance.now() >= hardDeadline;
  }

  // ── 1. sharedStrings.xml ─────────────────────────────────────────────────
  const ssEntry = zip.file('xl/sharedStrings.xml');
  if (ssEntry) {
    metrics.has_shared_strings = true;
    coverage.scanned_sharedStrings = true;
    const ssBytes = ssEntry.name in zip.files
      ? (zip.files[ssEntry.name] as { _data?: { uncompressedSize?: number } })._data?.uncompressedSize ?? 0
      : 0;
    metrics.shared_strings_bytes = ssBytes;

    if (ssBytes <= XLSX_MAX_SHARED_STRINGS_BYTES) {
      const content = await ssEntry.async('text');
      metrics.total_xml_bytes_read += content.length;
      extractTagT(content, textParts, nodeCount);
    } else {
      // Budget exceeded on shared strings — read first chunk only
      metrics.budget_exceeded = true;
      metrics.sampling_applied = true;
      const content = await ssEntry.async('text');
      const chunk = content.substring(0, XLSX_MAX_SHARED_STRINGS_BYTES);
      metrics.total_xml_bytes_read += chunk.length;
      extractTagT(chunk, textParts, nodeCount);
    }
    if (checkTimeout()) {
      metrics.budget_exceeded = true;
      metrics.timings.total_xlsx_ms = performance.now() - totalStart;
      metrics.failure_reason = 'XLSX_TIMEOUT';
      return { success: false, bodyText: '', metrics };
    }
  }

  // ── 2. Sheet XML (up to XLSX_MAX_SHEETS) ─────────────────────────────────
  const sheetsToProcess = sheetFiles.slice(0, XLSX_MAX_SHEETS);
  if (sheetFiles.length > XLSX_MAX_SHEETS) {
    metrics.budget_exceeded = true;
  }

  for (const sheetName of sheetsToProcess) {
    if (checkTimeout()) {
      metrics.budget_exceeded = true;
      metrics.timings.total_xlsx_ms = performance.now() - totalStart;
      metrics.failure_reason = 'XLSX_TIMEOUT';
      return { success: false, bodyText: '', metrics };
    }
    if (nodeCount.n >= XLSX_MAX_TEXT_NODES) {
      metrics.budget_exceeded = true;
      break;
    }

    const sheetEntry = zip.file(sheetName);
    if (!sheetEntry) continue;

    const rawSize: number = (sheetEntry as { _data?: { uncompressedSize?: number } })._data?.uncompressedSize ?? 0;
    if (rawSize > XLSX_MAX_ENTRY_BYTES) {
      metrics.budget_exceeded = true;
      metrics.sampling_applied = true;
      continue; // Skip oversized sheet entry
    }

    const content = await sheetEntry.async('text');
    metrics.total_xml_bytes_read += content.length;
    metrics.sheets_processed++;
    coverage.scanned_worksheets = true;

    const preCell = nodeCount.n;
    extractCellValues(content, textParts, nodeCount);
    metrics.cachedValue_hits += nodeCount.n - preCell;

    const preInline = nodeCount.n;
    extractInlineStrings(content, textParts, nodeCount);
    const inlineAdded = nodeCount.n - preInline;
    metrics.inlineStr_hits += inlineAdded;
    if (inlineAdded > 0) coverage.saw_inlineStr = true;

    extractTagT(content, textParts, nodeCount);
  }

  // ── 3. comments.xml ──────────────────────────────────────────────────────
  for (const commentFile of commentFiles) {
    if (checkTimeout()) { metrics.budget_exceeded = true; break; }
    if (nodeCount.n >= XLSX_MAX_TEXT_NODES) { metrics.budget_exceeded = true; break; }

    const entry = zip.file(commentFile);
    if (!entry) continue;
    const content = await entry.async('text');
    metrics.total_xml_bytes_read += content.length;
    coverage.scanned_comments = true;
    extractTagT(content, textParts, nodeCount);
  }

  // ── 4. Drawings (text boxes, shapes) ─────────────────────────────────────
  for (const drawingFile of drawingFiles) {
    if (checkTimeout()) { metrics.budget_exceeded = true; break; }
    if (nodeCount.n >= XLSX_MAX_TEXT_NODES) { metrics.budget_exceeded = true; break; }

    const entry = zip.file(drawingFile);
    if (!entry) continue;
    const content = await entry.async('text');
    metrics.total_xml_bytes_read += content.length;
    coverage.scanned_drawings = true;
    // Drawings use DrawingML <a:t> tags for text in shapes
    const drawPat = /<a:t[^>]*>([^<]*)<\/a:t>/gi;
    let dm;
    while ((dm = drawPat.exec(content)) !== null) {
      if (nodeCount.n >= XLSX_MAX_TEXT_NODES) { metrics.budget_exceeded = true; break; }
      const text = decodeXmlEntities(dm[1].trim());
      if (text) { textParts.push(text); nodeCount.n++; }
    }
  }

  // ── 5. docProps/core.xml (metadata) ──────────────────────────────────────
  const coreEntry = zip.file('docProps/core.xml');
  if (coreEntry && !checkTimeout()) {
    coverage.scanned_docProps = true;
    const content = await coreEntry.async('text');
    // Extract title, subject, creator, description — common Dublin Core fields
    const metaPat = /<dc:(?:title|subject|description|creator)>([^<]+)<\/dc:/gi;
    let mm;
    while ((mm = metaPat.exec(content)) !== null) {
      const text = decodeXmlEntities(mm[1].trim());
      if (text) textParts.push(text);
    }
  }

  metrics.timings.read_entries_ms = performance.now() - readStart;
  metrics.text_nodes_extracted = nodeCount.n;

  // ── Assemble output ───────────────────────────────────────────────────────
  const parseStart = performance.now();
  const combined = textParts.join(' ');
  let bodyText: string;
  if (combined.length > XLSX_OUTPUT_CAP) {
    bodyText = combined.substring(0, XLSX_OUTPUT_CAP);
    metrics.sampling_applied = true;
  } else {
    bodyText = combined;
  }
  metrics.timings.parse_xml_ms = performance.now() - parseStart;
  metrics.timings.total_xlsx_ms = performance.now() - totalStart;

  const success = bodyText.length > 0 || metrics.has_shared_strings;
  if (!success && !metrics.failure_reason) {
    metrics.failure_reason = 'XLSX_NO_CONTENT';
  }

  return { success, bodyText, metrics };
}
