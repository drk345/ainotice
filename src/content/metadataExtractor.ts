/**
 * AgentGuard Metadata & Content Extractor
 * Extracts metadata and body text from PDF and Office documents (DOCX, XLSX, PPTX).
 *
 * Architecture (post AG-216/218/219):
 * - PDF body text extraction delegates to the unified PDF spine
 *   (src/extraction/pdfTextExtractorCore.ts) via the browser pure-JS inflate
 *   adapter (src/extraction/pdfInflateBrowser.ts).
 * - OOXML (DOCX/XLSX/PPTX) extraction delegates to the selective extraction
 *   modules under src/extraction/*.
 * - This file owns extraction dispatch, metadata normalization, and orchestration.
 *
 * Limitations:
 * - Scanned/image-only PDFs won't yield text
 * - Encrypted PDFs may still be unreadable if they require non-blank passwords
 * - Not DLP-grade; best-effort risk awareness
 */

import JSZip from 'jszip';
import {
  isDebugMode,
  logExtractionDiagnostics,
  type ExtractionDiagnostics,
} from '../debug/diagnostics';
import {
  extractPdfTextFallback,
  PDF_EXTRACTION_REASON_CODES,
  type FallbackExtractionResult,
  type PdfExtractionReasonCode,
} from './pdfFallbackExtractor';
import { probeEncryptedPdfWithBlankPassword } from './pdfEncryptionReadability';
import { isEncryptedReadableState, type PdfEncryptionReadability } from '../types/pdfEncryption';
// AG-PHASE-5B-055: Unified extraction spine — browser uses same core as tests
import { extractPdfTextFromBytes } from '../extraction/pdfTextExtractorCore';
import { inflateBrowser } from '../extraction/pdfInflateBrowser';
// AG-DOCX-ENGINEERING-CORPUS-ONLY-001: Selective DOCX extraction with budgets
import { extractDocxSelectiveWithTimeout, DOCX_HARD_TIMEOUT_MS } from '../extraction/docxSelectiveExtractor';
// AG-MONSTER-HARDENING-TIERA-ENGINE-001-CONSOLIDATE-AND-GAPS: Selective PPTX extraction with budgets
import { extractPptxSelectiveWithTimeout, PPTX_HARD_TIMEOUT_MS } from '../extraction/pptxSelectiveExtractor';
// AG-MONSTER-ENGINE-VETTED-SPEC-AND-BACKLOG-001: Unified XLSX selective extraction (SG-02)
import { extractXlsxWithBudgets } from '../extraction/xlsxExtractor';
// AG-MONSTER-HARDENING-TIERA-ENGINE-001-CONSOLIDATE-AND-GAPS: Magic byte runtime gate
import { sniffMagicBytes } from '../extraction/magicByteSniffer';

// ============================================================================
// CONFIGURATION
// ============================================================================

const BODY_SCAN_MAX_SIZE = 10 * 1024 * 1024; // 10 MB - files larger than this skip body scan
const BODY_SCAN_TIMEOUT_MS = 800;             // Primary scan timeout
const PDF_BODY_SCAN_READ_BYTES = 2 * 1024 * 1024;      // 2 MB - initial read
const PDF_BODY_SCAN_EXTENDED_BYTES = 6 * 1024 * 1024;  // 6 MB - extended read for large PDFs
const MAX_BODY_TEXT_LENGTH = 500000;          // 500K chars output cap
const MIN_USEFUL_TEXT_LENGTH = 100;           // Minimum chars to consider scan successful

// ============================================================================
// TYPES
// ============================================================================

export interface DocumentMetadata {
  title?: string;
  author?: string;
  subject?: string;
  keywords?: string[];
  creator?: string;
  created?: Date;
  modified?: Date;
  company?: string;
  manager?: string;
  lastModifiedBy?: string;
  revision?: string;
  category?: string;
  description?: string;
  producer?: string;
  raw?: Record<string, string>;
}

export interface ExtractionResult {
  success: boolean;
  metadata: DocumentMetadata;
  bodyText?: string;
  fileType: 'pdf' | 'docx' | 'xlsx' | 'pptx' | 'unknown';
  error?: string;
  /** AG-PROMPT-073: PDF extraction status for awareness frame selection */
  pdfExtractionStatus?: PdfExtractionStatusInfo;
  /**
   * AG-PROMPT-304: true when a DOCX/XLSX budget/entry/sample/output cap truncated content, so
   * only part of the document was inspected. Non-content fact threaded into the AG-303
   * partial-inspection / reduced-confidence path. (PDF uses pdfExtractionStatus.truncated.)
   */
  partialInspection?: boolean;
}

/** AG-PROMPT-073: PDF extraction status for UI awareness */
export interface PdfExtractionStatusInfo {
  /** Whether text extraction failed (0 chars from both primary and fallback) */
  extractionFailed: boolean;
  /** Reason code for diagnostics */
  reasonCode: string;
  /** Primary extractor text length */
  primaryTextLength: number;
  /** Fallback extractor text length (if attempted) */
  fallbackTextLength: number;
  /** Whether fallback was attempted */
  fallbackAttempted: boolean;
  /** Which method produced the final text */
  finalMethod: 'primary' | 'fallback-ascii' | 'fallback-btj' | 'pdfjs' | 'none';
  /** AG-PHASE-5E-058: Extraction quality level for fallback classification */
  quality?: 'clean' | 'partial' | 'degraded' | 'blocked' | 'empty';
  /**
   * AG-PROMPT-303: true when only part of the file was inspected (byte-window read and/or
   * output-cap truncation). Non-content fact used to surface partial inspection; never persisted.
   */
  truncated?: boolean;
  /** Encryption readability classification for owner-password / blank-password edge cases */
  encryptionReadability: PdfEncryptionReadability;
}

// ============================================================================
// UTILITY: TIMEOUT WRAPPER
// ============================================================================

async function withTimeout<T>(promise: Promise<T>, ms: number, fallback: T): Promise<T> {
  let timeoutId: ReturnType<typeof setTimeout>;
  const timeoutPromise = new Promise<T>((resolve) => {
    timeoutId = setTimeout(() => resolve(fallback), ms);
  });
  
  try {
    const result = await Promise.race([promise, timeoutPromise]);
    clearTimeout(timeoutId!);
    return result;
  } catch (e) {
    clearTimeout(timeoutId!);
    throw e;
  }
}

// ============================================================================
// PDF BODY TEXT EXTRACTION
// ============================================================================

/**
 * Extract and process PDF streams to get body text.
 *
 * AG-PHASE-5B-055: Uses the UNIFIED extraction core (pdfTextExtractorCore.ts)
 * with the browser-compatible pure-JS inflate adapter. This ensures the browser
 * and test scripts use the same extraction logic, eliminating false positives
 * caused by extraction divergence.
 *
 * Implements progressive scanning: starts with 2MB, extends to 6MB if text
 * yield is too low. No collapsed/no-space text is appended — detection patterns
 * must match on properly extracted text only.
 */
/** AG-PHASE-5E-058: Return type for PDF body extraction with quality */
interface PdfBodyExtractionResult {
  text: string;
  quality: 'clean' | 'partial' | 'degraded' | 'blocked' | 'empty';
  /**
   * AG-PROMPT-303: true when only part of the file was inspected — either fewer bytes than the
   * full file were read (byte-window) or the extracted text was truncated at the output cap.
   * Non-content fact used to surface partial inspection (reduced confidence), never persisted.
   */
  truncated?: boolean;
}

async function extractPdfBodyText(file: File): Promise<PdfBodyExtractionResult> {
  // Check size limit
  if (file.size > BODY_SCAN_MAX_SIZE) {
    console.log(`[Ai Notice] PDF body scan skipped: file too large (${(file.size / 1024 / 1024).toFixed(1)}MB)`);
    return { text: '', quality: 'empty' };
  }

  try {
    // Phase 1: Initial scan (2MB)
    const initialReadBytes = Math.min(file.size, PDF_BODY_SCAN_READ_BYTES);
    console.log(`[Ai Notice] PDF scan phase 1: reading ${(initialReadBytes / 1024 / 1024).toFixed(2)}MB of ${(file.size / 1024 / 1024).toFixed(2)}MB`);

    const initialSlice = file.slice(0, initialReadBytes);
    const initialBuffer = await initialSlice.arrayBuffer();
    const initialView = new Uint8Array(initialBuffer);

    // CRITICAL: Deep-copy into content-script realm to avoid Firefox Xray wrapper issues
    const initialBytes = new Uint8Array(initialView.length);
    initialBytes.set(initialView);

    // AG-PHASE-5B-055: Use unified extraction core with browser inflate adapter
    const initialResult = extractPdfTextFromBytes(initialBytes, inflateBrowser);

    console.log(`[Ai Notice] PDF scan phase 1: ${initialResult.text.length} chars, quality=${initialResult.quality}`);

    // Decide if we need extended scan
    const needsExtendedScan = (
      file.size > PDF_BODY_SCAN_READ_BYTES &&  // File is larger than initial read
      initialResult.text.length < MIN_USEFUL_TEXT_LENGTH  // Too little text extracted
    );

    if (needsExtendedScan) {
      // Phase 2: Extended scan (up to 6MB)
      const extendedReadBytes = Math.min(file.size, PDF_BODY_SCAN_EXTENDED_BYTES);
      console.log(`[Ai Notice] PDF scan phase 2: extending to ${(extendedReadBytes / 1024 / 1024).toFixed(2)}MB`);

      const extendedSlice = file.slice(0, extendedReadBytes);
      const extendedBuffer = await extendedSlice.arrayBuffer();
      const extendedView = new Uint8Array(extendedBuffer);

      const extendedBytes = new Uint8Array(extendedView.length);
      extendedBytes.set(extendedView);

      // Run extended extraction with same core
      const extendedResult = extractPdfTextFromBytes(extendedBytes, inflateBrowser);

      // Use extended result if it's better
      if (extendedResult.text.length > initialResult.text.length) {
        console.log(`[Ai Notice] PDF scan complete: ${extendedResult.text.length} chars, quality=${extendedResult.quality} (extended)`);
        // AG-PROMPT-303: partial inspection if not all bytes were read, or output was capped.
        const truncated = file.size > extendedReadBytes || extendedResult.text.length > MAX_BODY_TEXT_LENGTH;
        return {
          text: extendedResult.text.substring(0, MAX_BODY_TEXT_LENGTH),
          quality: extendedResult.quality,
          truncated,
        };
      }
    }

    // Return initial result
    console.log(`[Ai Notice] PDF scan complete: ${initialResult.text.length} chars, quality=${initialResult.quality}`);
    // AG-PROMPT-303: partial inspection if not all bytes were read, or output was capped.
    const truncated = file.size > initialReadBytes || initialResult.text.length > MAX_BODY_TEXT_LENGTH;
    return {
      text: initialResult.text.substring(0, MAX_BODY_TEXT_LENGTH),
      quality: initialResult.quality,
      truncated,
    };

  } catch (e) {
    console.warn('[Ai Notice] PDF body extraction error:', e);
    return { text: '', quality: 'blocked' };
  }
}

// ============================================================================
// PDF METADATA EXTRACTION
// ============================================================================

function decodeUtf16BE(str: string): string {
  if (str.startsWith('\xFE\xFF') || str.startsWith('þÿ')) {
    str = str.substring(2);
  }
  
  if (str.includes('\x00') || str.includes('\u0000')) {
    let result = '';
    for (let i = 0; i < str.length; i += 2) {
      const charCode = (str.charCodeAt(i) << 8) + (str.charCodeAt(i + 1) || 0);
      if (charCode > 0) {
        result += String.fromCharCode(charCode);
      }
    }
    return result.trim();
  }
  
  return str.trim();
}

function cleanValue(value: string | undefined): string | undefined {
  if (!value) return undefined;
  value = decodeUtf16BE(value);
  value = value.replace(/[\x00-\x1F]/g, '').trim();
  if (!value || value === '��' || value.length < 2) return undefined;
  return value;
}

async function detectPdfEncryptionMarker(file: File): Promise<boolean> {
  const inspectChunkSize = 256 * 1024; // Inspect first/last 256KB deterministically
  const firstSlice = file.slice(0, Math.min(file.size, inspectChunkSize));
  const firstText = new TextDecoder('latin1').decode(await firstSlice.arrayBuffer());
  if (firstText.includes('/Encrypt')) {
    return true;
  }

  if (file.size <= inspectChunkSize) {
    return false;
  }

  const tailStart = Math.max(0, file.size - inspectChunkSize);
  const tailSlice = file.slice(tailStart, file.size);
  const tailText = new TextDecoder('latin1').decode(await tailSlice.arrayBuffer());
  return tailText.includes('/Encrypt');
}

async function extractPdfMetadata(file: File): Promise<ExtractionResult> {
  try {
    // --- Metadata extraction (first 100KB) ---
    const metadataSlice = file.slice(0, 102400);
    const metadataBuffer = await metadataSlice.arrayBuffer();
    const metadataBytes = new Uint8Array(metadataBuffer);
    
    let text = '';
    for (let i = 0; i < metadataBytes.length; i++) {
      text += String.fromCharCode(metadataBytes[i]);
    }
    
    const metadata: DocumentMetadata = { raw: {} };
    
    const extractPdfField = (fieldName: string): string | undefined => {
      const parenPattern = new RegExp(`/${fieldName}\\s*\\(([^)]*(?:\\)[^)]*)*?)\\)`, 'i');
      const parenMatch = text.match(parenPattern);
      if (parenMatch && parenMatch[1]) {
        return cleanValue(parenMatch[1]);
      }
      
      const hexPattern = new RegExp(`/${fieldName}\\s*<([0-9A-Fa-f]+)>`, 'i');
      const hexMatch = text.match(hexPattern);
      if (hexMatch && hexMatch[1]) {
        const hex = hexMatch[1];
        let str = '';
        for (let i = 0; i < hex.length; i += 2) {
          const code = parseInt(hex.substr(i, 2), 16);
          str += String.fromCharCode(code);
        }
        return cleanValue(str);
      }
      
      return undefined;
    };
    
    const author = extractPdfField('Author');
    const title = extractPdfField('Title');
    const subject = extractPdfField('Subject');
    const keywords = extractPdfField('Keywords');
    const creator = extractPdfField('Creator');
    const producer = extractPdfField('Producer');
    const company = extractPdfField('Company');
    
    if (author) { metadata.author = author; metadata.raw!['Author'] = author; }
    if (title) { metadata.title = title; metadata.raw!['Title'] = title; }
    if (subject) { metadata.subject = subject; metadata.raw!['Subject'] = subject; }
    if (keywords) { 
      metadata.keywords = keywords.split(/[,;]\s*/);
      metadata.raw!['Keywords'] = keywords;
    }
    if (creator) { metadata.creator = creator; metadata.raw!['Creator'] = creator; }
    if (producer) { metadata.producer = producer; metadata.raw!['Producer'] = producer; }
    if (company) { metadata.company = company; metadata.raw!['Company'] = company; }
    
    // XMP metadata
    const xmpMatch = text.match(/<x:xmpmeta[^>]*>([\s\S]*?)<\/x:xmpmeta>/i);
    if (xmpMatch) {
      const xmp = xmpMatch[1];
      
      const dcCreator = xmp.match(/<dc:creator[^>]*>[\s\S]*?<rdf:li[^>]*>([^<]+)<\/rdf:li>/i);
      if (dcCreator && !metadata.author) {
        const val = cleanValue(dcCreator[1]);
        if (val) metadata.author = val;
      }
      
      const dcTitle = xmp.match(/<dc:title[^>]*>[\s\S]*?<rdf:li[^>]*>([^<]+)<\/rdf:li>/i);
      if (dcTitle && !metadata.title) {
        const val = cleanValue(dcTitle[1]);
        if (val) metadata.title = val;
      }
      
      const pdfProducer = xmp.match(/<pdf:Producer>([^<]+)<\/pdf:Producer>/i);
      if (pdfProducer && !metadata.producer) {
        const val = cleanValue(pdfProducer[1]);
        if (val) metadata.producer = val;
      }
      
      const creatorTool = xmp.match(/<xmp:CreatorTool>([^<]+)<\/xmp:CreatorTool>/i);
      if (creatorTool && !metadata.creator) {
        const val = cleanValue(creatorTool[1]);
        if (val) metadata.creator = val;
      }
    }
    
    // AG-PROMPT-294: removed console.log of the PDF metadata object (title/author/creator =
    // derived identity). Never log document metadata.

    // --- Body text extraction with fallback (AG-PROMPT-073) ---
    let bodyText: string | undefined;
    let pdfExtractionStatus: PdfExtractionStatusInfo | undefined;
    const hasEncryptMarker = await detectPdfEncryptionMarker(file);

    if (file.size <= BODY_SCAN_MAX_SIZE) {
      const extractionStart = performance.now();
      let primaryTextLength = 0;
      let fallbackTextLength = 0;
      let fallbackAttempted = false;
      let finalMethod: 'primary' | 'fallback-ascii' | 'fallback-btj' | 'pdfjs' | 'none' = 'none';
      let reasonCode: PdfExtractionReasonCode = PDF_EXTRACTION_REASON_CODES.PRIMARY_SUCCESS;
      // AG-PHASE-5E-058: Track extraction quality for fallback classification
      let extractionQuality: PdfExtractionStatusInfo['quality'] = 'empty';
      let bodyTruncated = false;  // AG-PROMPT-303: partial inspection (byte-window/output-cap)
      let encryptionReadability: PdfEncryptionReadability = hasEncryptMarker
        ? 'ENCRYPTED_PASSWORD_REQUIRED'
        : 'NOT_ENCRYPTED';

      try {
        // Step 1: Try primary extractor
        const primaryResult = await withTimeout(
          extractPdfBodyText(file),
          BODY_SCAN_TIMEOUT_MS,
          { text: '', quality: 'blocked' as const }
        );
        bodyText = primaryResult.text;
        extractionQuality = primaryResult.quality;
        primaryTextLength = bodyText?.length ?? 0;
        bodyTruncated = primaryResult.truncated ?? false;  // AG-PROMPT-303

        // Step 2: If primary returns empty, try fallback (AG-PROMPT-073)
        if (!bodyText || bodyText.length === 0) {
          console.log('[Ai Notice] PDF primary extraction empty, trying fallback...');
          fallbackAttempted = true;

          const fallbackResult = await extractPdfTextFallback(file);
          fallbackTextLength = fallbackResult.textLength;

          if (fallbackResult.success && fallbackResult.text.length > 0) {
            bodyText = fallbackResult.text;
            finalMethod = fallbackResult.method;
            reasonCode = PDF_EXTRACTION_REASON_CODES.FALLBACK_SUCCESS;
            console.log(`[Ai Notice] PDF fallback succeeded: ${fallbackResult.textLength} chars via ${fallbackResult.method}`);
          } else {
            // Both extractors failed
            reasonCode = PDF_EXTRACTION_REASON_CODES.EXTRACT_EMPTY;
            console.log(`[Ai Notice] PDF extraction failed: both primary and fallback returned empty (${fallbackResult.reasonCode})`);
          }
        } else {
          finalMethod = 'primary';
          reasonCode = PDF_EXTRACTION_REASON_CODES.PRIMARY_SUCCESS;
        }
      } catch (e) {
        console.warn('[Ai Notice] PDF body extraction error:', e);
        reasonCode = PDF_EXTRACTION_REASON_CODES.PRIMARY_ERROR;
        bodyText = '';

        // Try fallback even on primary error
        try {
          fallbackAttempted = true;
          const fallbackResult = await extractPdfTextFallback(file);
          fallbackTextLength = fallbackResult.textLength;

          if (fallbackResult.success) {
            bodyText = fallbackResult.text;
            finalMethod = fallbackResult.method;
            reasonCode = PDF_EXTRACTION_REASON_CODES.FALLBACK_SUCCESS;
          }
        } catch {
          reasonCode = PDF_EXTRACTION_REASON_CODES.FALLBACK_ERROR;
        }
      }

      if (hasEncryptMarker) {
        if (bodyText && bodyText.length > 0) {
          encryptionReadability = 'ENCRYPTED_READABLE_NO_PROMPT';
          reasonCode = PDF_EXTRACTION_REASON_CODES.ENCRYPTED_READABLE_NO_PROMPT;
        } else {
          const probe = await probeEncryptedPdfWithBlankPassword(file);
          encryptionReadability = probe.state;

          if (probe.reason === 'load_no_prompt') {
            reasonCode = PDF_EXTRACTION_REASON_CODES.ENCRYPTED_READABLE_NO_PROMPT;
          } else if (probe.reason === 'load_blank_password') {
            reasonCode = PDF_EXTRACTION_REASON_CODES.ENCRYPTED_READABLE_BLANK_PASSWORD;
          } else {
            reasonCode = PDF_EXTRACTION_REASON_CODES.ENCRYPTED_PASSWORD_REQUIRED;
          }

          if (probe.text.length > 0) {
            bodyText = probe.text;
            primaryTextLength = probe.text.length;
            fallbackTextLength = 0;
            fallbackAttempted = false;
            finalMethod = 'pdfjs';
            extractionQuality = 'partial';
          } else if (encryptionReadability === 'ENCRYPTED_PASSWORD_REQUIRED') {
            extractionQuality = 'blocked';
          }
        }
      }

      const totalDurationMs = performance.now() - extractionStart;
      const extractionFailed = isEncryptedReadableState(encryptionReadability)
        ? false
        : (!bodyText || bodyText.length === 0);

      // Build extraction status for awareness frame selection
      pdfExtractionStatus = {
        extractionFailed,
        reasonCode,
        primaryTextLength,
        fallbackTextLength,
        fallbackAttempted,
        finalMethod,
        quality: extractionQuality,  // AG-PHASE-5E-058
        truncated: bodyTruncated,  // AG-PROMPT-303
        encryptionReadability,
      };

      // Debug logging (counts only, no content - ADR-002)
      if (isDebugMode()) {
        console.log(`[Ai Notice] PDF extraction status: primary=${primaryTextLength} chars, fallback=${fallbackAttempted ? fallbackTextLength + ' chars' : 'not attempted'}, final=${finalMethod}, quality=${extractionQuality}, reason=${reasonCode}, duration=${totalDurationMs.toFixed(0)}ms`);
      }
    } else {
      console.log(`[Ai Notice] PDF body scan skipped: file too large`);
      pdfExtractionStatus = {
        extractionFailed: true,
        reasonCode: PDF_EXTRACTION_REASON_CODES.FILE_TOO_LARGE,
        primaryTextLength: 0,
        fallbackTextLength: 0,
        fallbackAttempted: false,
        finalMethod: 'none',
        quality: 'blocked',  // AG-PHASE-5E-058: File too large is effectively blocked
        encryptionReadability: hasEncryptMarker ? 'ENCRYPTED_PASSWORD_REQUIRED' : 'NOT_ENCRYPTED',
      };
    }

    return {
      success: true,
      metadata,
      bodyText: bodyText || undefined,
      fileType: 'pdf',
      pdfExtractionStatus,
    };
  } catch (e) {
    console.warn('[Ai Notice] PDF metadata extraction failed:', e);
    return { success: false, metadata: {}, fileType: 'pdf', error: e instanceof Error ? e.message : 'Unknown error' };
  }
}

// ============================================================================
// OFFICE METADATA EXTRACTION
// ============================================================================

function parseXmlValue(xml: string, tagName: string): string | undefined {
  const patterns = [
    new RegExp(`<(?:\\w+:)?${tagName}[^>]*>([^<]*)</(?:\\w+:)?${tagName}>`, 'i'),
    new RegExp(`<${tagName}[^>]*>([^<]*)</${tagName}>`, 'i'),
  ];
  
  for (const pattern of patterns) {
    const match = xml.match(pattern);
    if (match && match[1]) {
      return match[1].trim();
    }
  }
  return undefined;
}

function parseXmlDate(xml: string, tagName: string): Date | undefined {
  const value = parseXmlValue(xml, tagName);
  if (value) {
    const date = new Date(value);
    if (!isNaN(date.getTime())) return date;
  }
  return undefined;
}

/**
 * AG-DOCX-ENGINEERING-CORPUS-ONLY-001: Selective DOCX extraction.
 * Uses selective ZIP entry reading with hard budgets — never hangs.
 * Replaces the previous JSZip full-load path for DOCX files.
 */
/**
 * AG-PROMPT-370/371: Deep-copy an ArrayBuffer-backed view into a fresh, same-realm
 * Uint8Array before handing bytes to a ZIP parser (JSZip). Firefox can hand back a
 * foreign-realm (Xray-wrapped) ArrayBuffer/Uint8Array from Blob.arrayBuffer() on a
 * File that crossed the content-script/page boundary; JSZip's internal
 * `instanceof Uint8Array` / `instanceof ArrayBuffer` checks (utils.getTypeOf) then
 * fail across realms, throwing "Can't read the data of..." — silently converted by
 * the caller's fail-open try/catch into success:false (no signals, no warning),
 * while the identical bytes parse fine on Chrome (no Xray wrappers). A fresh,
 * same-realm copy sidesteps this regardless of the buffer's origin. Mirrors the
 * pattern already used for PDF extraction (see extractPdfBodyText above). Shared
 * by all ZIP-based Office extractors (DOCX/XLSX/PPTX) so the defense lives in one
 * place instead of being re-derived per format.
 */
function toRealmSafeBytes(view: Uint8Array): Uint8Array {
  const copy = new Uint8Array(view.length);
  copy.set(view);
  return copy;
}

async function extractDocxMetadataSelective(file: File): Promise<ExtractionResult> {
  try {
    const arrayBuffer = await file.arrayBuffer();
    const uint8Array = toRealmSafeBytes(new Uint8Array(arrayBuffer));

    const docxResult = await extractDocxSelectiveWithTimeout(uint8Array, DOCX_HARD_TIMEOUT_MS);

    // Parse metadata from coreXml / appXml
    const metadata: DocumentMetadata = { raw: {} };

    if (docxResult.coreXml) {
      metadata.raw!['core.xml'] = docxResult.coreXml.substring(0, 500);

      const title = parseXmlValue(docxResult.coreXml, 'title');
      const creator = parseXmlValue(docxResult.coreXml, 'creator');
      const subject = parseXmlValue(docxResult.coreXml, 'subject');
      const description = parseXmlValue(docxResult.coreXml, 'description');
      const keywords = parseXmlValue(docxResult.coreXml, 'keywords');
      const lastModifiedBy = parseXmlValue(docxResult.coreXml, 'lastModifiedBy');
      const revision = parseXmlValue(docxResult.coreXml, 'revision');
      const category = parseXmlValue(docxResult.coreXml, 'category');
      const created = parseXmlDate(docxResult.coreXml, 'created');
      const modified = parseXmlDate(docxResult.coreXml, 'modified');

      if (title) metadata.title = title;
      if (creator) metadata.author = creator;
      if (subject) metadata.subject = subject;
      if (description) metadata.description = description;
      if (keywords) metadata.keywords = keywords.split(/[,;]\s*/);
      if (lastModifiedBy) metadata.lastModifiedBy = lastModifiedBy;
      if (revision) metadata.revision = revision;
      if (category) metadata.category = category;
      if (created) metadata.created = created;
      if (modified) metadata.modified = modified;
    }

    if (docxResult.appXml) {
      metadata.raw!['app.xml'] = docxResult.appXml.substring(0, 500);

      const company = parseXmlValue(docxResult.appXml, 'Company');
      const manager = parseXmlValue(docxResult.appXml, 'Manager');
      const application = parseXmlValue(docxResult.appXml, 'Application');

      if (company) metadata.company = company;
      if (manager) metadata.manager = manager;
      if (application) metadata.creator = application;
    }

    // AG-PROMPT-294: removed console.log of the Office metadata object (title/author/
    // company/manager/creator = derived identity). Never log document metadata.
    const bodyText = docxResult.bodyText || undefined;
    if (bodyText) {
      console.log(`[Ai Notice] Extracted ${bodyText.length} chars of body text`);
    }

    // Success if we got metadata or body text
    const success = docxResult.success || Object.keys(metadata).length > 1;

    return {
      success,
      metadata,
      bodyText,
      fileType: 'docx',
      error: !success ? (docxResult.error ?? 'DOCX extraction failed') : undefined,
      partialInspection: docxResult.partialInspection,  // AG-PROMPT-304
    };
  } catch (e) {
    console.warn('[Ai Notice] DOCX extraction failed:', e);
    return { success: false, metadata: {}, fileType: 'docx', error: e instanceof Error ? e.message : 'Unknown error' };
  }
}

/**
 * AG-MONSTER-ENGINE-VETTED-SPEC-AND-BACKLOG-001: Unified XLSX selective extraction (SG-02).
 * Routes runtime XLSX through the same xlsxExtractor.ts used by corpus harness.
 * Replaces the previous inline extractXlsxBodyText() path.
 */
async function extractXlsxMetadataSelective(file: File): Promise<ExtractionResult> {
  try {
    const arrayBuffer = await file.arrayBuffer();
    // AG-PROMPT-371: same-realm copy before ANY use — this buffer is passed to
    // JSZip.loadAsync() twice below (once inside extractXlsxWithBudgets, once
    // directly for metadata). See toRealmSafeBytes doc comment above.
    const buffer = toRealmSafeBytes(new Uint8Array(arrayBuffer));

    const xlsxResult = await extractXlsxWithBudgets(buffer);

    // Parse metadata from docProps if available — re-parse core.xml for structured metadata
    const metadata: DocumentMetadata = { raw: {} };
    // xlsxExtractor already extracts docProps text into bodyText; we need structured metadata
    // Re-open ZIP briefly for metadata (coreXml/appXml) — kept lightweight
    try {
      const zip = await JSZip.loadAsync(buffer);
      const coreFile = zip.file('docProps/core.xml');
      if (coreFile) {
        const coreXml = await coreFile.async('text');
        metadata.raw!['core.xml'] = coreXml.substring(0, 500);
        const title = parseXmlValue(coreXml, 'title');
        const creator = parseXmlValue(coreXml, 'creator');
        const subject = parseXmlValue(coreXml, 'subject');
        const description = parseXmlValue(coreXml, 'description');
        const keywords = parseXmlValue(coreXml, 'keywords');
        const lastModifiedBy = parseXmlValue(coreXml, 'lastModifiedBy');
        const created = parseXmlDate(coreXml, 'created');
        const modified = parseXmlDate(coreXml, 'modified');
        if (title) metadata.title = title;
        if (creator) metadata.author = creator;
        if (subject) metadata.subject = subject;
        if (description) metadata.description = description;
        if (keywords) metadata.keywords = keywords.split(/[,;]\s*/);
        if (lastModifiedBy) metadata.lastModifiedBy = lastModifiedBy;
        if (created) metadata.created = created;
        if (modified) metadata.modified = modified;
      }
      const appFile = zip.file('docProps/app.xml');
      if (appFile) {
        const appXml = await appFile.async('text');
        metadata.raw!['app.xml'] = appXml.substring(0, 500);
        const company = parseXmlValue(appXml, 'Company');
        const manager = parseXmlValue(appXml, 'Manager');
        const application = parseXmlValue(appXml, 'Application');
        if (company) metadata.company = company;
        if (manager) metadata.manager = manager;
        if (application) metadata.creator = application;
      }
    } catch {
      // Metadata parse failure is non-fatal — bodyText extraction is the priority
    }

    // AG-PROMPT-374: mirror extractDocxMetadataSelective's/extractPptxMetadataSelective's
    // success determination — fall back to "did we find real structured metadata
    // fields" when body text is genuinely empty, instead of xlsxExtractor.ts's old
    // (now-removed) mere sharedStrings-entry-exists fallback. Object.keys(metadata)
    // .length > 1 because `metadata` always has the `raw` key.
    const success = xlsxResult.success || Object.keys(metadata).length > 1;
    return {
      success,
      metadata,
      bodyText: xlsxResult.bodyText || undefined,
      fileType: 'xlsx',
      error: !success ? (xlsxResult.metrics.failure_reason ?? 'XLSX extraction failed') : undefined,
      // AG-PROMPT-304: thread existing XLSX budget/sample facts into partial-inspection.
      partialInspection: xlsxResult.metrics.budget_exceeded || xlsxResult.metrics.sampling_applied,
    };
  } catch (e) {
    console.warn('[Ai Notice] XLSX selective extraction failed:', e);
    return { success: false, metadata: {}, fileType: 'xlsx', error: e instanceof Error ? e.message : 'Unknown error' };
  }
}

/**
 * AG-MONSTER-HARDENING-TIERA-ENGINE-001-CONSOLIDATE-AND-GAPS: Selective PPTX extraction.
 * Uses selective ZIP entry reading with hard budgets — never hangs.
 * Replaces the previous JSZip full-load path for PPTX files.
 */
async function extractPptxMetadataSelective(file: File): Promise<ExtractionResult> {
  try {
    const arrayBuffer = await file.arrayBuffer();
    // AG-PROMPT-371: same-realm copy before handing bytes to JSZip.loadAsync()
    // inside extractPptxSelective. See toRealmSafeBytes doc comment above.
    const uint8Array = toRealmSafeBytes(new Uint8Array(arrayBuffer));

    const pptxResult = await extractPptxSelectiveWithTimeout(uint8Array, PPTX_HARD_TIMEOUT_MS);

    // Parse metadata from coreXml / appXml
    const metadata: DocumentMetadata = { raw: {} };

    if (pptxResult.coreXml) {
      metadata.raw!['core.xml'] = pptxResult.coreXml.substring(0, 500);

      const title = parseXmlValue(pptxResult.coreXml, 'title');
      const creator = parseXmlValue(pptxResult.coreXml, 'creator');
      const subject = parseXmlValue(pptxResult.coreXml, 'subject');
      const description = parseXmlValue(pptxResult.coreXml, 'description');
      const keywords = parseXmlValue(pptxResult.coreXml, 'keywords');
      const lastModifiedBy = parseXmlValue(pptxResult.coreXml, 'lastModifiedBy');
      const revision = parseXmlValue(pptxResult.coreXml, 'revision');
      const category = parseXmlValue(pptxResult.coreXml, 'category');
      const created = parseXmlDate(pptxResult.coreXml, 'created');
      const modified = parseXmlDate(pptxResult.coreXml, 'modified');

      if (title) metadata.title = title;
      if (creator) metadata.author = creator;
      if (subject) metadata.subject = subject;
      if (description) metadata.description = description;
      if (keywords) metadata.keywords = keywords.split(/[,;]\s*/);
      if (lastModifiedBy) metadata.lastModifiedBy = lastModifiedBy;
      if (revision) metadata.revision = revision;
      if (category) metadata.category = category;
      if (created) metadata.created = created;
      if (modified) metadata.modified = modified;
    }

    if (pptxResult.appXml) {
      metadata.raw!['app.xml'] = pptxResult.appXml.substring(0, 500);

      const company = parseXmlValue(pptxResult.appXml, 'Company');
      const manager = parseXmlValue(pptxResult.appXml, 'Manager');
      const application = parseXmlValue(pptxResult.appXml, 'Application');

      if (company) metadata.company = company;
      if (manager) metadata.manager = manager;
      if (application) metadata.creator = application;
    }

    // AG-PROMPT-294: removed console.log of the Office metadata object (title/author/
    // company/manager/creator = derived identity). Never log document metadata.
    const bodyText = pptxResult.bodyText || undefined;
    if (bodyText) {
      console.log(`[Ai Notice] Extracted ${bodyText.length} chars of body text`);
    }

    const success = pptxResult.success || Object.keys(metadata).length > 1;

    return {
      success,
      metadata,
      bodyText,
      fileType: 'pptx',
      error: !success ? (pptxResult.error ?? 'PPTX extraction failed') : undefined,
      partialInspection: pptxResult.partialInspection,  // AG-PROMPT-305
    };
  } catch (e) {
    console.warn('[Ai Notice] PPTX extraction failed:', e);
    return { success: false, metadata: {}, fileType: 'pptx', error: e instanceof Error ? e.message : 'Unknown error' };
  }
}

// ============================================================================
// MAIN EXTRACTION FUNCTION
// ============================================================================

export async function extractMetadata(file: File): Promise<ExtractionResult> {
  const extractionStart = performance.now();
  const extension = file.name.split('.').pop()?.toLowerCase();
  const mimeType = file.type.toLowerCase();

  console.log('[Ai Notice] Extracting metadata —', 'type:', mimeType, 'ext:', extension);

  let fileType: ExtractionResult['fileType'] = 'unknown';

  if (extension === 'pdf' || mimeType === 'application/pdf') {
    fileType = 'pdf';
  } else if (extension === 'docx' || mimeType.includes('wordprocessingml')) {
    fileType = 'docx';
  } else if (extension === 'xlsx' || mimeType.includes('spreadsheetml')) {
    fileType = 'xlsx';
  } else if (extension === 'pptx' || mimeType.includes('presentationml')) {
    fileType = 'pptx';
  }

  if (fileType === 'unknown') {
    // AG-PROMPT-044: Log extraction diagnostics for unknown file types
    if (isDebugMode()) {
      const diag: ExtractionDiagnostics = {
        docId: file.name,
        method: 'unknown',
        textLength: 0,
        nearEmpty: true,
        durationMs: performance.now() - extractionStart,
        warnings: ['Unsupported file type'],
      };
      logExtractionDiagnostics(diag);
    }
    return { success: false, metadata: {}, fileType: 'unknown', error: 'Unsupported file type' };
  }

  // AG-MONSTER-HARDENING-TIERA-ENGINE-001-CONSOLIDATE-AND-GAPS: Magic byte runtime gate
  // Prevent JSZip from attempting unzip on OLE2 masquerading files.
  if (fileType === 'docx' || fileType === 'xlsx' || fileType === 'pptx') {
    try {
      const headerBytes = new Uint8Array(await file.slice(0, 16).arrayBuffer());
      const ext = '.' + (extension || '');
      const magicResult = sniffMagicBytes(headerBytes, ext);
      if (magicResult.extension_mismatch && magicResult.detected_type === 'ole2') {
        console.warn(`[Ai Notice] Magic byte mismatch: OLE2 signature but ${ext} extension — skipping OOXML extraction`);
        return {
          success: false,
          metadata: {},
          fileType,
          error: `Format mismatch: file has OLE2 binary signature but ${ext} extension (legacy or misnamed format)`,
        };
      }
    } catch {
      // Non-fatal: proceed with normal extraction if header read fails
    }
  }

  let result: ExtractionResult;
  if (fileType === 'pdf') {
    result = await extractPdfMetadata(file);
  } else if (fileType === 'docx') {
    // AG-DOCX-ENGINEERING-CORPUS-ONLY-001: Use selective extractor with budgets
    result = await extractDocxMetadataSelective(file);
  } else if (fileType === 'xlsx') {
    // AG-MONSTER-ENGINE-VETTED-SPEC-AND-BACKLOG-001: Unified XLSX selective extraction (SG-02)
    result = await extractXlsxMetadataSelective(file);
  } else if (fileType === 'pptx') {
    // AG-MONSTER-HARDENING-TIERA-ENGINE-001-CONSOLIDATE-AND-GAPS: Use selective extractor with budgets
    result = await extractPptxMetadataSelective(file);
  } else {
    // AG-PROMPT-219: unreachable. fileType is narrowed to 'pdf'|'docx'|'xlsx'|'pptx'
    // above ('unknown' returns early at the guard), and each is handled by an explicit
    // branch. The dead extractOfficeMetadata fallback that previously occupied this
    // branch was removed; this is a defensive compile-time exhaustiveness guard only.
    throw new Error(`Unsupported file type in extraction dispatch: ${fileType}`);
  }

  // AG-PROMPT-044: Log extraction diagnostics
  if (isDebugMode()) {
    const textLength = result.bodyText?.length ?? 0;
    const diag: ExtractionDiagnostics = {
      docId: file.name,
      method: fileType === 'pdf' ? 'pdf-text' : 'ooxml',
      textLength,
      nearEmpty: textLength < 50,
      durationMs: performance.now() - extractionStart,
      warnings: [],
    };
    if (!result.success) {
      diag.warnings.push(`Extraction failed: ${result.error ?? 'unknown'}`);
    }
    if (diag.nearEmpty && result.success) {
      diag.warnings.push('Near-empty extraction (<50 chars)');
    }
    logExtractionDiagnostics(diag);
  }

  return result;
}

// ============================================================================
// METADATA RISK ANALYSIS
// ============================================================================

/**
 * Re-export canonical RiskSignal and related types from src/types/riskSignal.ts
 * This file was the original "source of truth" but is now a re-export point
 * for backwards compatibility.
 *
 * @see src/types/riskSignal.ts for the canonical definition
 * @see AG-PROMPT-033B for centralization history
 */
export type { RiskSignal, SignalSource } from '../types/riskSignal';
