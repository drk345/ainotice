/**
 * AG-MONSTER-HARDENING-TIERA-ENGINE-001-CONSOLIDATE-AND-GAPS: PPTX Selective Extractor
 *
 * Extracts text from PPTX files using selective ZIP entry reading with
 * hard budgets to prevent hangs on media-heavy or adversarial presentations.
 *
 * Strategy:
 *   1. Load ZIP via JSZip (reads central directory, lazy decompression)
 *   2. Enumerate entries — skip media/embeddings by prefix and extension
 *   3. Read only XML entries we need (slides, notes, comments)
 *   4. Enforce hard budgets: time, XML bytes, entry count
 *   5. Return structured metrics alongside extracted text
 *
 * Coverage priority:
 *   1. ppt/slides/slide[n].xml       — primary slide text (<a:t> tags)
 *   2. ppt/notesSlides/notesSlide[n].xml — presenter notes
 *   3. ppt/comments/*.xml            — review comments
 *
 * No extracted text is logged — only byte counts and booleans.
 */

import JSZip from 'jszip';

// ============================================================================
// CONFIGURATION — BUDGETS
// ============================================================================

/** Hard timeout for the entire PPTX extraction (ZIP load + entry reads + parse) */
export const PPTX_HARD_TIMEOUT_MS = 5000;

/** Max uncompressed XML bytes to read across all entries */
export const PPTX_MAX_XML_BYTES = 8_000_000; // 8 MB

/** Max ZIP entries to scan (prevents zip-bomb-like structures) */
export const PPTX_MAX_ENTRIES_SCANNED = 2000;

/** Max per-entry uncompressed size */
export const PPTX_MAX_PER_ENTRY_BYTES = 2_000_000; // 2 MB

/** Max body text output length */
const PPTX_MAX_TEXT_LENGTH = 500_000; // 500K chars

// ============================================================================
// ENTRY CLASSIFICATION
// ============================================================================

/** Prefixes that must never be decompressed */
const SKIP_PREFIXES = [
  'ppt/media/',
  'ppt/embeddings/',
  'ppt/fonts/',
  'ppt/theme/',
  'ppt/slideLayouts/',
  'ppt/slideMasters/',
  'ppt/handoutMasters/',
  'ppt/notesMasters/',
  '_rels/',
  'docProps/',
];

/** Extensions that must never be decompressed (case-insensitive) */
const SKIP_EXTENSIONS = new Set([
  '.bin', '.png', '.jpg', '.jpeg', '.gif',
  '.tif', '.tiff', '.bmp', '.webp', '.emf', '.wmf',
  '.mp3', '.mp4', '.wav', '.avi', '.mov',
]);

/** Entries we want to read for text extraction, ordered by priority */
const TEXT_ENTRY_PATTERNS: Array<{ pattern: RegExp; priority: number; type: 'slide' | 'note' | 'comment' }> = [
  { pattern: /^ppt\/slides\/slide\d+\.xml$/, priority: 0, type: 'slide' },
  { pattern: /^ppt\/notesSlides\/notesSlide\d+\.xml$/, priority: 1, type: 'note' },
  { pattern: /^ppt\/comments\/comment\d*\.xml$/, priority: 2, type: 'comment' },
  // Modern PPTX comments (Office 365)
  { pattern: /^ppt\/comments\/modernComment\d*\.xml$/, priority: 2, type: 'comment' },
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
export type PptxFailureReason =
  | 'PPTX_TIMEOUT'
  | 'PPTX_XML_TOO_LARGE'
  | 'PPTX_BUDGET_EXCEEDED'
  | 'PPTX_ZIP_INVALID'
  | 'PPTX_UNSUPPORTED_STRUCTURE'
  | 'PPTX_UNKNOWN_ERROR';

/** Per-file PPTX extraction metrics */
export interface PptxExtractionMetrics {
  entries_total: number;
  entries_skipped_media: number;
  entries_read_xml: number;
  total_xml_bytes_read: number;
  has_media: boolean;
  scanned_slides: number;
  scanned_notes: number;
  scanned_comments: number;
  a_t_nodes_seen: number;
  budget_exceeded: boolean;
  timings: {
    open_zip_ms: number;
    read_entries_ms: number;
    parse_xml_ms: number;
    total_pptx_ms: number;
  };
  failure_reason?: PptxFailureReason;
  coverage?: PptxCoverageTelemetry;
}

/** Which document parts were scanned */
export interface PptxCoverageTelemetry {
  scanned_slides: boolean;
  scanned_notes: boolean;
  scanned_comments: boolean;
}

export interface PptxSelectiveResult {
  /** Extracted body text (concatenation of all text entries) */
  bodyText: string;
  /** Metadata XML strings: core.xml and app.xml content (truncated) */
  coreXml?: string;
  appXml?: string;
  /** Structured extraction metrics */
  metrics: PptxExtractionMetrics;
  /** Whether extraction succeeded (got at least some text) */
  success: boolean;
  /** Error message if failed */
  error?: string;
}

// ============================================================================
// HELPERS
// ============================================================================

function shouldSkipEntry(entryName: string): boolean {
  if (entryName.endsWith('/')) return true;

  for (const prefix of SKIP_PREFIXES) {
    if (entryName.startsWith(prefix)) return true;
  }

  const lastDot = entryName.lastIndexOf('.');
  if (lastDot >= 0) {
    const ext = entryName.substring(lastDot).toLowerCase();
    if (SKIP_EXTENSIONS.has(ext)) return true;
  }

  return false;
}

function classifyEntry(entryName: string): { match: boolean; priority: number; type: 'slide' | 'note' | 'comment' } | null {
  for (const { pattern, priority, type } of TEXT_ENTRY_PATTERNS) {
    if (pattern.test(entryName)) return { match: true, priority, type };
  }
  return null;
}

/**
 * Extract text content from PPTX XML by pulling <a:t> and <p:text> text nodes.
 * AG-MONSTER-ENGINE-VETTED-SPEC-AND-BACKLOG-001: GAP-4 — also extract <p:text>
 * for modern Office 365 comment bodies that use PresentationML tags instead of DrawingML.
 * Lightweight regex approach — no DOM build.
 */
function extractAtText(xml: string): string {
  const parts: string[] = [];
  // Primary: DrawingML <a:t> tags (slides, notes, legacy comments)
  const atPattern = /<a:t>([^<]*)<\/a:t>/gi;
  let match;
  while ((match = atPattern.exec(xml)) !== null) {
    const text = match[1].trim();
    if (text) parts.push(text);
  }
  // GAP-4: PresentationML <p:text> tags (modern Office 365 comments)
  const ptextPattern = /<p:text>([^<]*)<\/p:text>/gi;
  while ((match = ptextPattern.exec(xml)) !== null) {
    const text = match[1].trim();
    if (text) parts.push(text);
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
 * Extract text from a PPTX file using selective ZIP entry reading.
 *
 * Budget enforcement:
 *   - Hard timeout: PPTX_HARD_TIMEOUT_MS (5s) around entire operation
 *   - Max XML bytes: PPTX_MAX_XML_BYTES (8MB) total across all entries
 *   - Max per-entry: PPTX_MAX_PER_ENTRY_BYTES (2MB) per entry
 *   - Max entries: PPTX_MAX_ENTRIES_SCANNED (2000) scanned
 *   - On budget hit: returns controlled failure with reason code
 */
export async function extractPptxSelective(
  data: Uint8Array | ArrayBuffer,
): Promise<PptxSelectiveResult> {
  const totalStart = performance.now();

  const coverage: PptxCoverageTelemetry = {
    scanned_slides: false,
    scanned_notes: false,
    scanned_comments: false,
  };

  const metrics: PptxExtractionMetrics = {
    entries_total: 0,
    entries_skipped_media: 0,
    entries_read_xml: 0,
    total_xml_bytes_read: 0,
    has_media: false,
    scanned_slides: 0,
    scanned_notes: 0,
    scanned_comments: 0,
    a_t_nodes_seen: 0,
    budget_exceeded: false,
    timings: {
      open_zip_ms: 0,
      read_entries_ms: 0,
      parse_xml_ms: 0,
      total_pptx_ms: 0,
    },
    coverage,
  };

  const makeResult = (partial: Partial<PptxSelectiveResult>): PptxSelectiveResult => {
    metrics.timings.total_pptx_ms = performance.now() - totalStart;
    return {
      bodyText: '',
      metrics,
      success: false,
      ...partial,
    };
  };

  const isTimedOut = (): boolean =>
    (performance.now() - totalStart) >= PPTX_HARD_TIMEOUT_MS;

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
      metrics: { ...metrics, failure_reason: 'PPTX_ZIP_INVALID' },
    });
  }
  metrics.timings.open_zip_ms = performance.now() - zipStart;

  if (isTimedOut()) {
    return makeResult({
      error: 'Timeout after ZIP load',
      metrics: { ...metrics, failure_reason: 'PPTX_TIMEOUT' },
    });
  }

  // ------------------------------------------------------------------
  // Step 2: Enumerate and classify entries
  // ------------------------------------------------------------------
  const allEntryNames = Object.keys(zip.files);
  metrics.entries_total = allEntryNames.length;

  if (metrics.entries_total > PPTX_MAX_ENTRIES_SCANNED) {
    return makeResult({
      error: `Too many ZIP entries: ${metrics.entries_total} > ${PPTX_MAX_ENTRIES_SCANNED}`,
      metrics: { ...metrics, failure_reason: 'PPTX_BUDGET_EXCEEDED', budget_exceeded: true },
    });
  }

  const textEntries: Array<{ name: string; priority: number; type: 'slide' | 'note' | 'comment' }> = [];
  const metadataEntryNames: string[] = [];

  for (const name of allEntryNames) {
    // Check metadata entries first (docProps/ is in SKIP_PREFIXES but we want these)
    if (METADATA_ENTRIES.includes(name)) {
      metadataEntryNames.push(name);
    }

    if (shouldSkipEntry(name)) {
      metrics.entries_skipped_media++;
      if (name.startsWith('ppt/media/')) {
        metrics.has_media = true;
      }
      continue;
    }

    const classification = classifyEntry(name);
    if (classification) {
      textEntries.push({ name, priority: classification.priority, type: classification.type });
    }
  }

  // Sort text entries by priority (slides first, then notes, then comments)
  textEntries.sort((a, b) => a.priority - b.priority || a.name.localeCompare(b.name));

  // ------------------------------------------------------------------
  // Step 3: Read metadata entries
  // ------------------------------------------------------------------
  let coreXml: string | undefined;
  let appXml: string | undefined;

  const readStart = performance.now();

  for (const name of metadataEntryNames) {
    if (isTimedOut()) break;

    const entry = zip.file(name);
    if (!entry) continue;

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
      metrics: { ...metrics, failure_reason: 'PPTX_TIMEOUT' },
    });
  }

  metrics.timings.read_entries_ms = performance.now() - readStart;

  // ------------------------------------------------------------------
  // Step 4: Read text entries (slides, notes, comments)
  // ------------------------------------------------------------------
  const textParts: string[] = [];
  const parseStart = performance.now();

  for (const { name, type } of textEntries) {
    if (isTimedOut()) {
      metrics.budget_exceeded = true;
      break;
    }

    if (metrics.total_xml_bytes_read >= PPTX_MAX_XML_BYTES) {
      metrics.budget_exceeded = true;
      break;
    }

    const entry = zip.file(name);
    if (!entry) continue;

    try {
      const content = await entry.async('text');
      const contentBytes = new TextEncoder().encode(content).length;

      // Per-entry size guard
      if (contentBytes > PPTX_MAX_PER_ENTRY_BYTES) {
        continue; // Skip oversized entry
      }

      metrics.entries_read_xml++;
      metrics.total_xml_bytes_read += contentBytes;

      // Extract <a:t> text nodes
      const text = extractAtText(content);
      if (text) {
        textParts.push(text);
        // Count <a:t> nodes for telemetry
        const nodeCount = (content.match(/<a:t>/gi) || []).length;
        metrics.a_t_nodes_seen += nodeCount;
      }

      // Update per-type counters and coverage
      switch (type) {
        case 'slide':
          metrics.scanned_slides++;
          coverage.scanned_slides = true;
          break;
        case 'note':
          metrics.scanned_notes++;
          coverage.scanned_notes = true;
          break;
        case 'comment':
          metrics.scanned_comments++;
          coverage.scanned_comments = true;
          break;
      }
    } catch {
      // Individual entry read failure is non-fatal
    }
  }

  metrics.timings.parse_xml_ms = performance.now() - parseStart;

  // ------------------------------------------------------------------
  // Step 5: Build result
  // ------------------------------------------------------------------
  const bodyText = textParts.join(' ').substring(0, PPTX_MAX_TEXT_LENGTH);

  return makeResult({
    bodyText,
    coreXml,
    appXml,
    success: bodyText.length > 0 || coreXml !== undefined,
  });
}

// ============================================================================
// TIMEOUT WRAPPER
// ============================================================================

/**
 * Run extractPptxSelective with a hard timeout wrapper.
 * Returns a controlled failure on timeout — never hangs.
 */
export async function extractPptxSelectiveWithTimeout(
  data: Uint8Array | ArrayBuffer,
  timeoutMs: number = PPTX_HARD_TIMEOUT_MS,
): Promise<PptxSelectiveResult> {
  let timeoutId: ReturnType<typeof setTimeout>;

  const timeoutResult: PptxSelectiveResult = {
    bodyText: '',
    metrics: {
      entries_total: 0,
      entries_skipped_media: 0,
      entries_read_xml: 0,
      total_xml_bytes_read: 0,
      has_media: false,
      scanned_slides: 0,
      scanned_notes: 0,
      scanned_comments: 0,
      a_t_nodes_seen: 0,
      budget_exceeded: false,
      timings: { open_zip_ms: 0, read_entries_ms: 0, parse_xml_ms: 0, total_pptx_ms: timeoutMs },
      failure_reason: 'PPTX_TIMEOUT',
    },
    success: false,
    error: `Hard timeout: ${timeoutMs}ms exceeded`,
  };

  const timeoutPromise = new Promise<PptxSelectiveResult>((resolve) => {
    timeoutId = setTimeout(() => resolve(timeoutResult), timeoutMs);
  });

  try {
    const result = await Promise.race([
      extractPptxSelective(data),
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
        failure_reason: 'PPTX_UNKNOWN_ERROR',
      },
    };
  }
}
