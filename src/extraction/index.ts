/**
 * AG-PHASE-1-UNIFIED-PDF-EXTRACTION-SPINE: Public API for PDF text extraction.
 */

export { extractPdfTextFromBytes, extractPdfText } from './pdfTextExtractorCore';
export { assessExtractionQuality } from './pdfQualityAssessment';
export { inflateBrowser } from './pdfInflateBrowser';
export type {
  InflateFn,
  PdfExtractionResult,
  ExtractionDiagnostics,
  QualityLevel,
  FontEntry,
  FontRegistry,
  FontEncoding,
} from './types';
