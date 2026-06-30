/**
 * Decision Quality Blocks (AG-PROMPT-134)
 *
 * Derives user-facing decision-quality content from existing repo primitives.
 * No new copy is invented — all text comes from existing explainability
 * copy or frame-based fallback tables.
 *
 * Data sources (priority order):
 * 1. Explainability copy (per-signal, specific to detected content type)
 * 2. Frame-based fallback (per-frame, general scenario guidance)
 * 3. Generic safe fallback
 *
 * Privacy-safe: no content snippets, no raw matched text.
 *
 * @see AG-PROMPT-134: Decision-quality UX uplift
 */

import type { DecisionExplanation } from '../policy/decisionExplanation';
import { getExplainabilityCopy } from '../policy/explainabilityCopy';

// ============================================================================
// DISPLAY CONFIDENCE
// ============================================================================

/**
 * User-facing confidence level for the decision assessment.
 * Derived from frameId and reasonCodes — no re-computation needed.
 *
 * Confidence contract (AG-PROMPT-134):
 * - confirmed: strong evidence, high-confidence frame
 * - inferred: pattern match, not definitive
 * - limited_analysis: extraction limited or PDF unreadable
 */
export type DisplayConfidence = 'confirmed' | 'inferred' | 'limited_analysis';

/** Frame IDs that indicate extraction was limited */
const EXTRACTION_LIMITED_FRAMES = new Set([
  'FRAME_PDF_UNREADABLE',
  'FRAME_DEGRADED_PAYROLL',
  'FRAME_DEGRADED_HR',
  'FRAME_DEGRADED_INSURANCE',
  // AG-PROMPT-325: scan skipped/timed out → reduced ("limited analysis") confidence, never "Confirmed"
  'FRAME_NOT_SCANNED',
]);

/** Frame IDs that reliably confirm a known scenario family */
const CONFIRMED_SCENARIO_FRAMES = new Set([
  'FRAME_MEDICAL',
  'FRAME_PAYROLL',
  'FRAME_REGULATED_SENSITIVE',
]);

/**
 * Derive user-facing confidence from the decision explanation.
 * Maps internal semantics to the three-state user-facing contract.
 */
export function deriveDisplayConfidence(
  decisionExplanation: DecisionExplanation,
  pdfExtractionFailed?: boolean,
  partialInspection?: boolean,
): DisplayConfidence {
  const frameId = decisionExplanation.frameId || '';
  const reasonCodes = decisionExplanation.reasonCodes || [];

  // Extraction failures OR cap-truncated partial inspection → limited analysis.
  // AG-PROMPT-303: when extraction caps truncated/sampled the content (only part of the file
  // was inspected), the result must not present as a full-confidence clean scan.
  if (
    pdfExtractionFailed ||
    partialInspection ||
    reasonCodes.includes('PDF_EXTRACTION_FAILED') ||
    reasonCodes.includes('PDF_ENCRYPTED_PASSWORD_REQUIRED') ||
    EXTRACTION_LIMITED_FRAMES.has(frameId)
  ) {
    return 'limited_analysis';
  }

  const severity = decisionExplanation.severity;

  // Confirmed scenario frame + high severity → confirmed
  if (
    (severity === 'critical' || severity === 'high') &&
    CONFIRMED_SCENARIO_FRAMES.has(frameId)
  ) {
    return 'confirmed';
  }

  // Strong signal evidence → confirmed
  if (
    (severity === 'critical' || severity === 'high') &&
    decisionExplanation.details &&
    decisionExplanation.details.length > 0 &&
    !reasonCodes.includes('FRAMES_DEFAULT_APPLIED')
  ) {
    return 'confirmed';
  }

  return 'inferred';
}

// ============================================================================
// CONFIDENCE DISPLAY
// ============================================================================

export interface ConfidenceDisplay {
  label: string;
  note: string;
}

const CONFIDENCE_DISPLAY: Record<DisplayConfidence, ConfidenceDisplay> = {
  confirmed: {
    label: 'Confirmed',
    note: 'Multiple strong indicators support this assessment.',
  },
  inferred: {
    label: 'Inferred',
    note: 'Some indicators suggest this, but the evidence is mixed.',
  },
  limited_analysis: {
    label: 'Reduced',
    note: 'This file could not be fully read. The AI tool you\u2019re uploading to may be able to read more than we could analyze.',
  },
};

export function getConfidenceDisplay(confidence: DisplayConfidence): ConfidenceDisplay {
  return CONFIDENCE_DISPLAY[confidence];
}

/**
 * AG-PROMPT-326: Resolve the SEVERITY shown in the modal header/dot/bar.
 *
 * Critical is reserved for confirmed high-impact findings. A generic, inferred-only finding must
 * not render as "Critical" — a red Critical paired with an amber "Inferred" confidence overstates
 * weak evidence and reads incoherently. When confidence is merely 'Inferred' and policy resolved
 * 'critical', cap the DISPLAYED severity to 'high'.
 *
 * This is DISPLAY-ONLY: it does not change policy severity, action, enforcement, or high/critical
 * friction (both 'high' and 'critical' are danger states that keep the friction checkbox).
 * Confirmed criticals (secrets, etc.) derive 'Confirmed' confidence and are never capped.
 */
export type DisplaySeverity = 'none' | 'low' | 'medium' | 'high' | 'critical';
export function resolveDisplaySeverity(
  overallRisk: DisplaySeverity,
  confidenceLabel?: string,
): DisplaySeverity {
  if (overallRisk === 'critical' && confidenceLabel === 'Inferred') {
    return 'high';
  }
  return overallRisk;
}

// ============================================================================
// FRAME-BASED FALLBACK COPY TABLES
// ============================================================================

/** Plain-language primary concern per frame (no technical terms) */
const FRAME_PRIMARY_CONCERN: Record<string, string> = {
  FRAME_MEDICAL: 'Medical or health-related information',
  FRAME_PAYROLL: 'Payroll or compensation information',
  FRAME_HR: 'HR or employee records',
  FRAME_LEGAL: 'Legal agreement content',
  FRAME_REGULATED_SENSITIVE: 'Government-issued identifier',
  FRAME_PERSONAL_DATA_AWARENESS: 'Personal contact information',
  FRAME_GENERAL_SENSITIVE: 'Sensitive document content',
  FRAME_PDF_UNREADABLE: 'Unknown content — document could not be fully read',
  FRAME_INSURANCE: 'Insurance-related information',
  FRAME_INVOICE: 'Invoice or receipt details (billing/payment)',  // AG-PROMPT-326
  FRAME_HEALTH_CERTIFICATE: 'Health certificate details',  // AG-PROMPT-326
  FRAME_COMPOSITE: 'Multiple sensitive content types',
  FRAME_DISTRIBUTION_RESTRICTION: 'Distribution-restricted document',
  FRAME_DEGRADED_PAYROLL: 'Possible payroll information',
  FRAME_DEGRADED_HR: 'Possible HR records',
  FRAME_DEGRADED_INSURANCE: 'Possible insurance information',
  FRAME_REVIEW_ADVISED: 'Content that may warrant review',
  FRAME_BUSINESS_SENSITIVE: 'Commercially sensitive information',  // AG-PROMPT-188
  FRAME_NOT_SCANNED: 'File not fully checked before sharing',  // AG-PROMPT-325
};

/** Consequence-oriented why-this-matters sentence per frame */
const FRAME_WHY_MATTERS: Record<string, string> = {
  FRAME_MEDICAL: 'Medical records contain protected health information that may be subject to privacy regulations.',
  FRAME_PAYROLL: 'Payroll files often contain salary details that are confidential between employees and HR.',
  FRAME_HR: 'HR records typically contain personal information that may be protected by employment policy.',
  FRAME_LEGAL: 'Legal documents may contain confidential terms or obligations affecting you or your organization.',
  FRAME_REGULATED_SENSITIVE: 'Government-issued identifiers can be used to verify identity and should be protected.',
  FRAME_PERSONAL_DATA_AWARENESS: 'Personal contact information may be subject to privacy laws in your region.',
  FRAME_GENERAL_SENSITIVE: 'Some of this content may not be intended for external sharing.',
  FRAME_PDF_UNREADABLE: 'Text extraction was limited, so the full content of this file could not be assessed.',
  FRAME_INSURANCE: 'Insurance documents may contain personal health or financial information.',
  FRAME_INVOICE: 'Invoices and receipts often contain billing, payment, or personal contact details.',  // AG-PROMPT-326
  FRAME_HEALTH_CERTIFICATE: 'Health certificates often contain personal identifiers alongside health information.',  // AG-PROMPT-326
  FRAME_COMPOSITE: 'This document contains multiple types of sensitive information that increase its overall sensitivity.',
  FRAME_DISTRIBUTION_RESTRICTION: 'This document contains language indicating it should not be redistributed.',
  FRAME_DEGRADED_PAYROLL: 'The document may contain salary or payment data that is typically confidential.',
  FRAME_DEGRADED_HR: 'The document may contain employee records that are typically confidential.',
  FRAME_DEGRADED_INSURANCE: 'The document may contain insurance policy information.',
  // AG-PROMPT-331: FRAME_REVIEW_ADVISED is the no-marker / "couldn't determine" fallback frame
  // (selected only when signalCount = 0). The prior copy ("Some patterns were found…") asserted a
  // finding the frame explicitly did not make, contradicting its own headline/summary. Replaced with
  // honest, non-claiming copy consistent with the frame's uncertainty semantics.
  FRAME_REVIEW_ADVISED: 'Ai Notice could not confidently classify this file. Review before sharing if unsure.',
  FRAME_BUSINESS_SENSITIVE: 'Business-sensitive content may include material non-public information that could affect transactions or negotiations.',  // AG-PROMPT-188
  FRAME_NOT_SCANNED: 'This file was not fully analyzed locally, so its contents could not be confirmed either way.',  // AG-PROMPT-325
};

/** Task-preserving safer option per frame */
const FRAME_SAFER_OPTION: Record<string, string> = {
  FRAME_MEDICAL: 'Ask your question without attaching the file, or share only the relevant excerpt.',
  FRAME_PAYROLL: 'Remove salary figures or share only the portion relevant to your question.',
  FRAME_HR: 'Remove or redact identifying employee details before uploading.',
  FRAME_LEGAL: 'If you need AI help with this document, share just the relevant clause rather than the full file.',
  FRAME_REGULATED_SENSITIVE: 'Remove or redact the identifier before uploading.',
  FRAME_PERSONAL_DATA_AWARENESS: 'Consider whether the contact details need to be included.',
  FRAME_GENERAL_SENSITIVE: 'Share only the relevant part, or ask without including the sensitive content.',
  FRAME_PDF_UNREADABLE: 'Try exporting a text-readable version of the PDF and scan it before sharing.',
  FRAME_INSURANCE: 'Share only the relevant policy section rather than the full document.',
  FRAME_INVOICE: 'Share only the line items you need, or remove names, addresses, and payment details first.',  // AG-PROMPT-326
  FRAME_HEALTH_CERTIFICATE: 'Share only the portion you need, or remove personal identifiers first.',  // AG-PROMPT-326
  FRAME_COMPOSITE: 'Split the document and share only the section relevant to your question.',
  FRAME_DISTRIBUTION_RESTRICTION: 'Ask without the attachment or describe the relevant parts instead.',
  FRAME_DEGRADED_PAYROLL: 'Try exporting a text-readable PDF so the content can be assessed before sharing.',
  FRAME_DEGRADED_HR: 'Try exporting a text-readable PDF so the content can be assessed before sharing.',
  FRAME_DEGRADED_INSURANCE: 'Try exporting a text-readable PDF so the content can be assessed before sharing.',
  FRAME_REVIEW_ADVISED: 'Upload only the relevant section, or ask your question without the full attachment.',
  FRAME_BUSINESS_SENSITIVE: 'Remove or redact sensitive business terms before uploading, or ask without the attachment.',  // AG-PROMPT-188
  FRAME_NOT_SCANNED: 'Review the file yourself before sharing, or upload a smaller or text-readable version so it can be checked.',  // AG-PROMPT-325
};

// ============================================================================
// MAIN OUTPUT TYPE
// ============================================================================

export interface DecisionQualityBlocks {
  /** One plain-language primary concern (e.g. "API key", "Social Security number") */
  primaryConcern: string;
  /** One consequence-oriented why-this-matters sentence */
  whyThisMatters: string;
  /** Confidence display (label + note) */
  confidence: ConfidenceDisplay;
  /** One concrete task-preserving safer option sentence */
  saferOption: string;
}

// ============================================================================
// DERIVATION
// ============================================================================

export interface DecisionQualityInput {
  decisionExplanation: DecisionExplanation;
  pdfExtractionFailed?: boolean;
  /**
   * AG-PROMPT-303: true when extraction caps truncated/sampled the content, so only part of
   * the file was inspected. Forces 'limited_analysis' (Reduced) confidence — a clean verdict on
   * a partially-inspected file must not be presented as full confidence.
   */
  partialInspection?: boolean;
}

/**
 * Derive all decision-quality blocks from existing repo primitives.
 *
 * Priority for each field:
 * 1. Signal-specific explainability copy (most specific)
 * 2. Frame-based fallback (general scenario)
 * 3. Generic safe fallback
 */
export function deriveDecisionQualityBlocks(
  input: DecisionQualityInput,
): DecisionQualityBlocks {
  const { decisionExplanation, pdfExtractionFailed, partialInspection } = input;
  const frameId = decisionExplanation.frameId || 'FRAME_GENERAL_SENSITIVE';

  // Top signal ID from decision details (driving signal)
  const topSignalId = decisionExplanation.details?.[0]?.id;
  const signalCopy = topSignalId ? getExplainabilityCopy(topSignalId) : null;

  // Primary concern: signal title > frame label > generic
  const primaryConcern =
    signalCopy?.title ||
    FRAME_PRIMARY_CONCERN[frameId] ||
    'Sensitive document content';

  // Why this matters: signal why > frame why > generic
  const whyThisMatters =
    signalCopy?.why ||
    FRAME_WHY_MATTERS[frameId] ||
    'Some of this content may not be intended for external sharing.';

  // Safer option: signal suggestedAction > frame safer option > generic
  const saferOption =
    signalCopy?.suggestedAction ||
    FRAME_SAFER_OPTION[frameId] ||
    'Share only the relevant part, or ask without including the sensitive content.';

  // Confidence derived from explanation semantics
  const confidence = getConfidenceDisplay(
    deriveDisplayConfidence(decisionExplanation, pdfExtractionFailed, partialInspection),
  );

  return { primaryConcern, whyThisMatters, confidence, saferOption };
}
