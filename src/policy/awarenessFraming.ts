/**
 * AgentGuard Awareness Framing - Thin Loader/Selector Engine
 *
 * Provides calm, human-facing explanations for risk decisions.
 * Frame templates and selection rules are loaded from JSON configuration.
 *
 * Design principles:
 * - Calm: Non-alarming language that helps users pause and consider
 * - Minimal: One headline + one summary sentence
 * - Consistent: Same frame = same explanation
 * - Deterministic: Frame selection based solely on document class + severity
 *
 * @see ADR-024: Awareness Framing Consistency
 * @see AG-PROMPT-044, AG-PROMPT-064
 */

import type { DocumentClass } from './documentClassAnchors';
import type { PdfEncryptionReadability } from '../types/pdfEncryption';
import {
  FRAME_MAP,
  FORBIDDEN_WORDS_LIST,
  REGULATED_PATTERNS,
  LEGAL_PATTERNS,
  DISTRIBUTION_PATTERNS,
  SECRETS_PATTERNS,
  SIGNAL_FAMILIES,
  type FrameData,
  type SignalFamily,
} from '../data/awareness-frames';

// ============================================================================
// TYPES
// ============================================================================

/** Awareness frame categories (closed set) */
export type AwarenessFrame =
  | 'FRAME_MEDICAL'
  | 'FRAME_PAYROLL'
  | 'FRAME_HR'
  | 'FRAME_LEGAL'
  | 'FRAME_REGULATED_SENSITIVE'
  | 'FRAME_PERSONAL_DATA_AWARENESS'
  | 'FRAME_GENERAL_SENSITIVE'
  | 'FRAME_PDF_UNREADABLE'
  | 'FRAME_INSURANCE'  // AG-PHASE-5C-056: Insurance policy documents
  | 'FRAME_COMPOSITE'  // AG-PROMPT-SURFACE-COMPOSITE-001: Multiple signal families
  | 'FRAME_DISTRIBUTION_RESTRICTION'  // AG-PROMPT-CONFIDENTIAL-QUALITY-008: Distribution-only signals
  | 'FRAME_DEGRADED_PAYROLL'  // AG-PHASE-5E-058: Degraded extraction with payroll indicators
  | 'FRAME_DEGRADED_HR'  // AG-PHASE-5E-058: Degraded extraction with HR indicators
  | 'FRAME_DEGRADED_INSURANCE'  // AG-PHASE-5E-058: Degraded extraction with insurance indicators
  | 'FRAME_INVOICE'  // AG-PROMPT-175: Invoice/receipt documents
  | 'FRAME_HEALTH_CERTIFICATE'  // AG-PROMPT-175: COVID/vaccination certificates
  | 'FRAME_BUSINESS_SENSITIVE'  // AG-PROMPT-188: M&A / commercially sensitive content
  | 'FRAME_REVIEW_ADVISED'  // AG-PROMPT-SURFACE-UNCERTAINTY-GRADIENT-013: Fallback for weak/no evidence
  | 'FRAME_NOT_SCANNED';  // AG-PROMPT-325: Scan skipped/timed out — honest "could not fully check"

/** Severity levels for frame selection */
export type FrameSeverity = 'low' | 'medium' | 'high' | 'critical' | 'none';

/**
 * AG-PROMPT-SURFACE-UNCERTAINTY-GRADIENT-013: Surface confidence state.
 *
 * Determines how assertive the UI copy should be:
 * - confirmed: Strong evidence (docClass or multiple strong signals)
 * - inferred: Some evidence but weak/ambiguous
 * - fallback: No signals or near-zero evidence
 */
export type SurfaceConfidence = 'confirmed' | 'inferred' | 'fallback';

/** Framed explanation output */
export interface FramedExplanation {
  headline: string;
  summary: string;
  guidance: string;  // AG-PROMPT-090: Actionable guidance from frame
  frame: AwarenessFrame;
  suppressDetails: boolean;
  ruleId: string;
  confidence: SurfaceConfidence;  // AG-PROMPT-SURFACE-UNCERTAINTY-GRADIENT-013
}

/** AG-PHASE-5E-058: Degraded document fallback classification result */
export interface DegradedFallbackInfo {
  /** Inferred domain from filename/metadata */
  domain: 'payroll' | 'hr_contract' | 'insurance';
  /** Matched tokens for audit */
  matchedTokens: string[];
  /** Source of classification */
  source: 'filename' | 'metadata' | 'both';
}

/** Input for frame selection */
export interface FrameSelectionInput {
  documentClass: DocumentClass | null;
  severity: FrameSeverity;
  ontologyDriven?: boolean;
  drivingSignalIds?: string[];
  singleStrongAwareness?: boolean;
  signalCount?: number;  // AG-PROMPT-SURFACE-UNCERTAINTY-GRADIENT-013
  filename?: string;  // AG-PROMPT-SURFACE-FALLBACK-GUIDANCE-REFINE-014
  identityConfidence?: 'none' | 'weak' | 'strong';  // AG-PROMPT-SIGNAL-BYPASS-FIX-028
  pdfExtractionFailed?: boolean;  // AG-PHASE-4-052: Route to FRAME_PDF_UNREADABLE
  pdfEncryptionReadability?: PdfEncryptionReadability;
  degradedFallback?: DegradedFallbackInfo;  // AG-PHASE-5E-058: Filename/metadata classification for degraded PDFs
  /**
   * AG-PROMPT-325: true when the local scan was skipped or timed out (detection timeout, or an
   * oversize file whose content was not inspected) — a non-content fact, distinct from parser
   * failure. Routes to FRAME_NOT_SCANNED so silence is not mistaken for a clean result. Never
   * carries content; only signals "we did not fully check this".
   */
  notScanned?: boolean;
}

// ============================================================================
// RULE IDS (stable for audit trail)
// ============================================================================

export const AWARENESS_FRAMING_RULE_IDS = {
  SELECT_MEDICAL: 'AWF-001-select-medical',
  SELECT_PAYROLL: 'AWF-002-select-payroll',
  SELECT_HR: 'AWF-003-select-hr',
  SELECT_LEGAL: 'AWF-004-select-legal',
  SELECT_REGULATED: 'AWF-005-select-regulated',
  SELECT_PERSONAL_DATA: 'AWF-007-select-personal-data',
  SELECT_GENERAL: 'AWF-006-select-general',
  SELECT_PDF_UNREADABLE: 'AWF-008-select-pdf-unreadable',
  SELECT_INSURANCE: 'AWF-014-select-insurance', // AG-PHASE-5C-056
  SELECT_INVOICE: 'AWF-018-select-invoice', // AG-PROMPT-175
  SELECT_HEALTH_CERTIFICATE: 'AWF-019-select-health-certificate', // AG-PROMPT-175
  SELECT_COMPOSITE: 'AWF-009-select-composite', // AG-PROMPT-SURFACE-COMPOSITE-001
  SELECT_DISTRIBUTION: 'AWF-012-select-distribution', // AG-PROMPT-CONFIDENTIAL-QUALITY-008
  SELECT_REVIEW_ADVISED: 'AWF-013-select-review-advised', // AG-PROMPT-SURFACE-UNCERTAINTY-GRADIENT-013
  SELECT_DEGRADED_PAYROLL: 'AWF-015-select-degraded-payroll', // AG-PHASE-5E-058
  SELECT_DEGRADED_HR: 'AWF-016-select-degraded-hr', // AG-PHASE-5E-058
  SELECT_DEGRADED_INSURANCE: 'AWF-017-select-degraded-insurance', // AG-PHASE-5E-058
  SELECT_BUSINESS_SENSITIVE: 'AWF-023-select-business-sensitive', // AG-PROMPT-188
  SELECT_NOT_SCANNED: 'AWF-024-select-not-scanned', // AG-PROMPT-325
  SUPPRESS_ONTOLOGY: 'AWF-010-suppress-ontology',
  SUPPRESS_DOC_CLASS: 'AWF-011-suppress-doc-class',
  // AG-PROMPT-SURFACE-UNCERTAINTY-GRADIENT-013: Confidence derivation rules
  CONFIDENCE_CONFIRMED: 'AWF-020-confidence-confirmed',
  CONFIDENCE_INFERRED: 'AWF-021-confidence-inferred',
  CONFIDENCE_FALLBACK: 'AWF-022-confidence-fallback',
} as const;

// ============================================================================
// FRAME TEMPLATES (loaded from JSON, exported for backward compatibility)
// ============================================================================

export const FRAME_TEMPLATES: Record<AwarenessFrame, { headline: string; inferredHeadline?: string; summary: string }> = {
  FRAME_MEDICAL: { headline: FRAME_MAP.FRAME_MEDICAL.headline, inferredHeadline: FRAME_MAP.FRAME_MEDICAL.inferredHeadline, summary: FRAME_MAP.FRAME_MEDICAL.summary },
  FRAME_PAYROLL: { headline: FRAME_MAP.FRAME_PAYROLL.headline, inferredHeadline: FRAME_MAP.FRAME_PAYROLL.inferredHeadline, summary: FRAME_MAP.FRAME_PAYROLL.summary },
  FRAME_HR: { headline: FRAME_MAP.FRAME_HR.headline, inferredHeadline: FRAME_MAP.FRAME_HR.inferredHeadline, summary: FRAME_MAP.FRAME_HR.summary },
  FRAME_LEGAL: { headline: FRAME_MAP.FRAME_LEGAL.headline, inferredHeadline: FRAME_MAP.FRAME_LEGAL.inferredHeadline, summary: FRAME_MAP.FRAME_LEGAL.summary },
  FRAME_REGULATED_SENSITIVE: { headline: FRAME_MAP.FRAME_REGULATED_SENSITIVE.headline, inferredHeadline: FRAME_MAP.FRAME_REGULATED_SENSITIVE.inferredHeadline, summary: FRAME_MAP.FRAME_REGULATED_SENSITIVE.summary },
  FRAME_PERSONAL_DATA_AWARENESS: { headline: FRAME_MAP.FRAME_PERSONAL_DATA_AWARENESS.headline, inferredHeadline: FRAME_MAP.FRAME_PERSONAL_DATA_AWARENESS.inferredHeadline, summary: FRAME_MAP.FRAME_PERSONAL_DATA_AWARENESS.summary },
  FRAME_GENERAL_SENSITIVE: { headline: FRAME_MAP.FRAME_GENERAL_SENSITIVE.headline, inferredHeadline: FRAME_MAP.FRAME_GENERAL_SENSITIVE.inferredHeadline, summary: FRAME_MAP.FRAME_GENERAL_SENSITIVE.summary },
  FRAME_PDF_UNREADABLE: { headline: FRAME_MAP.FRAME_PDF_UNREADABLE.headline, summary: FRAME_MAP.FRAME_PDF_UNREADABLE.summary },
  // AG-PHASE-5C-056: Insurance policy frame
  FRAME_INSURANCE: { headline: FRAME_MAP.FRAME_INSURANCE?.headline || 'This file contains insurance policy information', inferredHeadline: FRAME_MAP.FRAME_INSURANCE?.inferredHeadline, summary: FRAME_MAP.FRAME_INSURANCE?.summary || 'Some patterns are consistent with insurance policy details.' },
  // AG-PROMPT-SURFACE-COMPOSITE-001: Composite frame (template, replaced dynamically)
  FRAME_COMPOSITE: { headline: FRAME_MAP.FRAME_COMPOSITE?.headline || 'This file contains multiple types of sensitive information', inferredHeadline: FRAME_MAP.FRAME_COMPOSITE?.inferredHeadline, summary: FRAME_MAP.FRAME_COMPOSITE?.summary || 'It includes multiple types of sensitive data.' },
  // AG-PROMPT-CONFIDENTIAL-QUALITY-008: Distribution-only frame
  FRAME_DISTRIBUTION_RESTRICTION: { headline: FRAME_MAP.FRAME_DISTRIBUTION_RESTRICTION?.headline || 'This file has internal sharing restrictions', summary: FRAME_MAP.FRAME_DISTRIBUTION_RESTRICTION?.summary || 'It contains language commonly used to limit redistribution.' },
  // AG-PHASE-5E-058: Degraded extraction frames
  FRAME_DEGRADED_PAYROLL: { headline: FRAME_MAP.FRAME_DEGRADED_PAYROLL?.headline || 'This file may contain payroll information', summary: FRAME_MAP.FRAME_DEGRADED_PAYROLL?.summary || 'The filename or metadata suggests this may contain salary or payment information. Text extraction was limited.' },
  FRAME_DEGRADED_HR: { headline: FRAME_MAP.FRAME_DEGRADED_HR?.headline || 'This file may contain employment information', summary: FRAME_MAP.FRAME_DEGRADED_HR?.summary || 'The filename or metadata suggests this may contain HR or employment information. Text extraction was limited.' },
  FRAME_DEGRADED_INSURANCE: { headline: FRAME_MAP.FRAME_DEGRADED_INSURANCE?.headline || 'This file may contain insurance information', summary: FRAME_MAP.FRAME_DEGRADED_INSURANCE?.summary || 'The filename or metadata suggests this may contain insurance policy information. Text extraction was limited.' },
  // AG-PROMPT-SURFACE-UNCERTAINTY-GRADIENT-013: Fallback frame for weak/no evidence
  FRAME_REVIEW_ADVISED: { headline: FRAME_MAP.FRAME_REVIEW_ADVISED?.headline || 'We couldn\u2019t determine what this file contains', summary: FRAME_MAP.FRAME_REVIEW_ADVISED?.summary || 'This content could not be classified reliably. Treat it as sensitive if it contains personal or confidential details.' },
  // AG-PROMPT-175: Invoice and health certificate frames
  FRAME_INVOICE: { headline: FRAME_MAP.FRAME_INVOICE?.headline || 'This file appears to be an invoice or receipt', inferredHeadline: FRAME_MAP.FRAME_INVOICE?.inferredHeadline, summary: FRAME_MAP.FRAME_INVOICE?.summary || 'This document contains billing or payment information that may include personal or financial details.' },
  FRAME_HEALTH_CERTIFICATE: { headline: FRAME_MAP.FRAME_HEALTH_CERTIFICATE?.headline || 'This file appears to be a health certificate', inferredHeadline: FRAME_MAP.FRAME_HEALTH_CERTIFICATE?.inferredHeadline, summary: FRAME_MAP.FRAME_HEALTH_CERTIFICATE?.summary || 'This document contains health-related information that may include personal identifiers.' },
  // AG-PROMPT-188: Business-sensitive / M&A frame
  FRAME_BUSINESS_SENSITIVE: { headline: FRAME_MAP.FRAME_BUSINESS_SENSITIVE?.headline || 'This file may contain commercially sensitive information', inferredHeadline: FRAME_MAP.FRAME_BUSINESS_SENSITIVE?.inferredHeadline, summary: FRAME_MAP.FRAME_BUSINESS_SENSITIVE?.summary || 'Some patterns are consistent with business-sensitive or transaction-related content.' },
  // AG-PROMPT-325: Honest not-scanned frame (scan skipped/timed out — not a parser failure)
  FRAME_NOT_SCANNED: { headline: FRAME_MAP.FRAME_NOT_SCANNED?.headline || 'Ai Notice could not fully check this file', summary: FRAME_MAP.FRAME_NOT_SCANNED?.summary || 'This file was not fully analyzed locally, so its contents could not be confirmed before sharing.' },
};

export const LOW_SEVERITY_SUMMARIES: Record<AwarenessFrame, string> = {
  FRAME_MEDICAL: FRAME_MAP.FRAME_MEDICAL.lowSeveritySummary,
  FRAME_PAYROLL: FRAME_MAP.FRAME_PAYROLL.lowSeveritySummary,
  FRAME_HR: FRAME_MAP.FRAME_HR.lowSeveritySummary,
  FRAME_LEGAL: FRAME_MAP.FRAME_LEGAL.lowSeveritySummary,
  FRAME_REGULATED_SENSITIVE: FRAME_MAP.FRAME_REGULATED_SENSITIVE.lowSeveritySummary,
  FRAME_PERSONAL_DATA_AWARENESS: FRAME_MAP.FRAME_PERSONAL_DATA_AWARENESS.lowSeveritySummary,
  FRAME_GENERAL_SENSITIVE: FRAME_MAP.FRAME_GENERAL_SENSITIVE.lowSeveritySummary,
  FRAME_PDF_UNREADABLE: FRAME_MAP.FRAME_PDF_UNREADABLE.lowSeveritySummary,
  FRAME_INSURANCE: FRAME_MAP.FRAME_INSURANCE?.lowSeveritySummary || 'A few patterns may relate to insurance information.',
  FRAME_COMPOSITE: FRAME_MAP.FRAME_COMPOSITE?.lowSeveritySummary || 'This document may contain multiple types of sensitive data.',
  // AG-PROMPT-CONFIDENTIAL-QUALITY-008: Distribution-only frame
  FRAME_DISTRIBUTION_RESTRICTION: FRAME_MAP.FRAME_DISTRIBUTION_RESTRICTION?.lowSeveritySummary || 'This document includes markers that may indicate distribution limits.',
  // AG-PHASE-5E-058: Degraded extraction frames
  FRAME_DEGRADED_PAYROLL: FRAME_MAP.FRAME_DEGRADED_PAYROLL?.lowSeveritySummary || 'The filename or metadata suggests this may relate to payroll. Full content could not be verified.',
  FRAME_DEGRADED_HR: FRAME_MAP.FRAME_DEGRADED_HR?.lowSeveritySummary || 'The filename or metadata suggests this may relate to employment. Full content could not be verified.',
  FRAME_DEGRADED_INSURANCE: FRAME_MAP.FRAME_DEGRADED_INSURANCE?.lowSeveritySummary || 'The filename or metadata suggests this may relate to insurance. Full content could not be verified.',
  // AG-PROMPT-175: Invoice and health certificate frames
  FRAME_INVOICE: FRAME_MAP.FRAME_INVOICE?.lowSeveritySummary || 'A few patterns may relate to billing or invoice information.',
  FRAME_HEALTH_CERTIFICATE: FRAME_MAP.FRAME_HEALTH_CERTIFICATE?.lowSeveritySummary || 'A few patterns may relate to health documentation.',
  // AG-PROMPT-188: Business-sensitive / M&A frame
  FRAME_BUSINESS_SENSITIVE: FRAME_MAP.FRAME_BUSINESS_SENSITIVE?.lowSeveritySummary || 'A few patterns may relate to commercially sensitive information.',
  // AG-PROMPT-SURFACE-UNCERTAINTY-GRADIENT-013: Fallback frame
  FRAME_REVIEW_ADVISED: FRAME_MAP.FRAME_REVIEW_ADVISED?.lowSeveritySummary || 'We could not identify specific sensitive content. Review before sharing if it may contain personal details.',
  // AG-PROMPT-325: Not-scanned frame
  FRAME_NOT_SCANNED: FRAME_MAP.FRAME_NOT_SCANNED?.lowSeveritySummary || 'Some of this file may not have been analyzed locally before sharing.',
};

// AG-PROMPT-090: Export frame guidance for UI display
export const FRAME_GUIDANCE: Record<AwarenessFrame, string> = {
  FRAME_MEDICAL: FRAME_MAP.FRAME_MEDICAL.guidance,
  FRAME_PAYROLL: FRAME_MAP.FRAME_PAYROLL.guidance,
  FRAME_HR: FRAME_MAP.FRAME_HR.guidance,
  FRAME_LEGAL: FRAME_MAP.FRAME_LEGAL.guidance,
  FRAME_REGULATED_SENSITIVE: FRAME_MAP.FRAME_REGULATED_SENSITIVE.guidance,
  FRAME_PERSONAL_DATA_AWARENESS: FRAME_MAP.FRAME_PERSONAL_DATA_AWARENESS.guidance,
  FRAME_GENERAL_SENSITIVE: FRAME_MAP.FRAME_GENERAL_SENSITIVE.guidance,
  FRAME_PDF_UNREADABLE: FRAME_MAP.FRAME_PDF_UNREADABLE.guidance,
  FRAME_INSURANCE: FRAME_MAP.FRAME_INSURANCE?.guidance || 'Insurance documents often contain personal details. Review before sharing externally.',
  FRAME_COMPOSITE: FRAME_MAP.FRAME_COMPOSITE?.guidance || 'Review before sharing externally.',
  // AG-PROMPT-CONFIDENTIAL-QUALITY-008: Distribution-only frame
  FRAME_DISTRIBUTION_RESTRICTION: FRAME_MAP.FRAME_DISTRIBUTION_RESTRICTION?.guidance || 'Review before sharing externally.',
  // AG-PHASE-5E-058: Degraded extraction frames
  FRAME_DEGRADED_PAYROLL: FRAME_MAP.FRAME_DEGRADED_PAYROLL?.guidance || 'Consider this sensitive and review before sharing. This PDF could not be fully analyzed.',
  FRAME_DEGRADED_HR: FRAME_MAP.FRAME_DEGRADED_HR?.guidance || 'Consider this sensitive and review before sharing. This PDF could not be fully analyzed.',
  FRAME_DEGRADED_INSURANCE: FRAME_MAP.FRAME_DEGRADED_INSURANCE?.guidance || 'Consider this sensitive and review before sharing. This PDF could not be fully analyzed.',
  // AG-PROMPT-175: Invoice and health certificate frames
  FRAME_INVOICE: FRAME_MAP.FRAME_INVOICE?.guidance || 'Review before sharing externally.',
  FRAME_HEALTH_CERTIFICATE: FRAME_MAP.FRAME_HEALTH_CERTIFICATE?.guidance || 'Health documents typically contain sensitive personal data. Review before sharing.',
  // AG-PROMPT-188: Business-sensitive / M&A frame
  FRAME_BUSINESS_SENSITIVE: FRAME_MAP.FRAME_BUSINESS_SENSITIVE?.guidance || 'Business-sensitive documents may contain material non-public information. Review before sharing externally.',
  // AG-PROMPT-SURFACE-UNCERTAINTY-GRADIENT-013: Fallback frame
  FRAME_REVIEW_ADVISED: FRAME_MAP.FRAME_REVIEW_ADVISED?.guidance || 'Use your judgment based on what you know about this document.',
  // AG-PROMPT-325: Not-scanned frame
  FRAME_NOT_SCANNED: FRAME_MAP.FRAME_NOT_SCANNED?.guidance || 'Review it yourself before sharing if it may contain personal or confidential details.',
};

export const FORBIDDEN_WORDS = FORBIDDEN_WORDS_LIST;

// ============================================================================
// AG-PROMPT-SURFACE-HEADLINE-EPIS-POLICY-020: EPISTEMIC HEADLINE POLICY
// ============================================================================
// When documentClass is null, headlines must NOT imply document category.
// This is a final safety net enforced at headline render time.
// ============================================================================

/**
 * Forbidden headline patterns when documentClass is null.
 * These patterns imply document category rather than indicator detection.
 */
const CATEGORY_IMPLYING_PATTERNS: RegExp[] = [
  /\bmedical[- ]?related\b/i,
  /\blegal[- ]?related\b/i,
  /\bhr[- ]?related\b/i,
  /\bfinancial[- ]?related\b/i,
  /\bmedical record\b/i,
  /\blegal document\b/i,
  /\bhr document\b/i,
  /\bfinancial document\b/i,
];

/**
 * Safe fallback headline when category-implying language is detected
 * and documentClass is null.
 */
const SAFE_FALLBACK_HEADLINE = 'Indicators that may warrant review were found';

/**
 * AG-PROMPT-SURFACE-HEADLINE-EPIS-POLICY-020: Enforce epistemic headline policy.
 *
 * When documentClass is null, this function ensures the headline does not
 * imply document category. If a forbidden pattern is detected, it rewrites
 * to a safe indicator-centric headline.
 *
 * This is a SAFETY NET - the primary mechanism is noClassHeadline selection.
 * This function catches any code paths that might bypass that logic.
 *
 * @param headline - The headline to check
 * @param documentClass - The document classification (null if unclassified)
 * @returns The headline (possibly rewritten if policy violation detected)
 */
export function enforceEpistemicHeadlinePolicy(
  headline: string,
  documentClass: DocumentClass | null | undefined
): string {
  // If documentClass is set, category language is allowed
  if (documentClass !== null && documentClass !== undefined) {
    return headline;
  }

  // Check for forbidden patterns
  const hasForbiddenPattern = CATEGORY_IMPLYING_PATTERNS.some(pattern =>
    pattern.test(headline)
  );

  if (hasForbiddenPattern) {
    // Log the violation for debugging (non-blocking)
    console.warn(
      `[Ai Notice] epistemic violation caught: "${headline}" → "${SAFE_FALLBACK_HEADLINE}"`
    );
    return SAFE_FALLBACK_HEADLINE;
  }

  return headline;
}

/**
 * Check if a headline violates epistemic policy (for testing).
 */
export function checkEpistemicViolation(
  headline: string,
  documentClass: DocumentClass | null | undefined
): { violates: boolean; pattern?: string } {
  if (documentClass !== null && documentClass !== undefined) {
    return { violates: false };
  }

  for (const pattern of CATEGORY_IMPLYING_PATTERNS) {
    if (pattern.test(headline)) {
      return { violates: true, pattern: pattern.source };
    }
  }

  return { violates: false };
}

/**
 * AG-PROMPT-SURFACE-HEADLINE-POLICY-CONSOLIDATION-021: Single choke point for headline sanitization.
 *
 * This function MUST be called immediately before rendering ANY headline to the UI.
 * It consolidates all epistemic policy enforcement into a single location.
 *
 * Usage:
 * ```typescript
 * const safeHeadline = sanitizeHeadlineForRender(headline, documentClass);
 * element.textContent = safeHeadline;
 * ```
 *
 * @param headline - The headline text to render
 * @param documentClass - The document classification (null if unclassified)
 * @returns Sanitized headline safe for UI display
 */
export function sanitizeHeadlineForRender(
  headline: string,
  documentClass: DocumentClass | null | undefined
): string {
  // Delegate to the policy enforcement function
  // This ensures a single source of truth for the policy rules
  return enforceEpistemicHeadlinePolicy(headline, documentClass);
}

/**
 * AG-PROMPT-SURFACE-HEADLINE-POLICY-CONSOLIDATION-021: Get all forbidden headline patterns.
 * Exported for testing to verify no headlines match these patterns when documentClass is null.
 */
export function getForbiddenHeadlinePatterns(): RegExp[] {
  return [...CATEGORY_IMPLYING_PATTERNS];
}

// ============================================================================
// SIGNAL PATTERN MATCHING
// ============================================================================

/** Check if driving signals include regulated/clinical content */
function hasRegulatedSignals(signalIds?: string[]): boolean {
  if (!signalIds) return false;
  return signalIds.some(id => {
    const lowerId = id.toLowerCase();
    return REGULATED_PATTERNS.some(pattern => lowerId.includes(pattern));
  });
}

/** Check if driving signals include legal content */
function hasLegalSignals(signalIds: string[]): boolean {
  return signalIds.some(id => {
    const lowerId = id.toLowerCase();
    return LEGAL_PATTERNS.some(pattern => lowerId.includes(pattern));
  });
}

/**
 * AG-PROMPT-188: Check if driving signals include business-sensitive / M&A content.
 * M&A signals (global-ma-terms, global-ma-valuation-context) indicate material
 * non-public information that deserves its own calm frame rather than falling
 * through to generic FRAME_GENERAL_SENSITIVE.
 * AG-PROMPT-386: Added global-financial-report so corroborated financial-report
 * content (balance sheet, margins, EBITDA, P&L) surfaces as business-sensitive
 * instead of being hidden behind a co-occurring generic confidentiality marker,
 * or falling through to the less specific FRAME_GENERAL_SENSITIVE when no
 * confidentiality marker is present.
 */
const BUSINESS_SENSITIVE_PATTERNS = ['global-ma-terms', 'global-ma-valuation', 'global-financial-report'];
function hasBusinessSensitiveSignals(signalIds?: string[]): boolean {
  if (!signalIds) return false;
  return signalIds.some(id => {
    const lowerId = id.toLowerCase();
    return BUSINESS_SENSITIVE_PATTERNS.some(pattern => lowerId.includes(pattern));
  });
}

// ============================================================================
// AG-PROMPT-CONFIDENTIAL-QUALITY-008: DISTRIBUTION VS CONTENT SENSITIVITY
// ============================================================================
// Distribution sensitivity = HOW to share (confidentiality markers, internal-only)
// Content sensitivity = WHAT the document contains (secrets, PII, medical, legal)
//
// Key distinction:
// - Confidentiality markers ("CONFIDENTIAL", "internal only") = distribution only
// - Secrets/credentials (API keys, passwords) = content sensitivity
// - M&A terms = content sensitivity (material non-public info)
// ============================================================================

/**
 * Check if a signal ID matches distribution marker patterns.
 * AG-PROMPT-CONFIDENTIAL-QUALITY-008: Distribution markers indicate sharing
 * restrictions, not content sensitivity.
 */
function isDistributionMarker(signalId: string): boolean {
  const lowerId = signalId.toLowerCase();
  return DISTRIBUTION_PATTERNS.some(pattern => lowerId.includes(pattern.toLowerCase()));
}

/**
 * Check if a signal ID matches secrets/credentials patterns.
 * AG-PROMPT-CONFIDENTIAL-QUALITY-008: Secrets indicate actual content risk,
 * not just distribution restrictions.
 */
function isSecretOrCredential(signalId: string): boolean {
  const lowerId = signalId.toLowerCase();
  return SECRETS_PATTERNS.some(pattern => lowerId.includes(pattern.toLowerCase()));
}

/**
 * Check if ALL signals are distribution-only (no content sensitivity).
 * AG-PROMPT-CONFIDENTIAL-QUALITY-008: Returns true only when ALL driving signals
 * are distribution markers AND none are secrets/credentials/regulated content.
 */
export function hasOnlyDistributionSignals(signalIds?: string[]): boolean {
  if (!signalIds || signalIds.length === 0) return false;

  // Must have at least one distribution marker
  const hasDistribution = signalIds.some(id => isDistributionMarker(id));
  if (!hasDistribution) return false;

  // Must NOT have any secrets/credentials
  const hasSecrets = signalIds.some(id => isSecretOrCredential(id));
  if (hasSecrets) return false;

  // Must NOT have any regulated content patterns
  const hasRegulated = hasRegulatedSignals(signalIds);
  if (hasRegulated) return false;

  // Must NOT have any legal patterns
  const hasLegal = hasLegalSignals(signalIds);
  if (hasLegal) return false;

  // AG-PROMPT-386: Must NOT have any business-sensitive/financial content
  // patterns. Without this check, a confidential finance report (e.g.
  // global-confidential-en + global-financial-report) was incorrectly
  // treated as "distribution-only", hiding the financial content behind a
  // generic "internal sharing restrictions" headline instead of surfacing
  // it as business-sensitive.
  const hasBusinessSensitive = hasBusinessSensitiveSignals(signalIds);
  if (hasBusinessSensitive) return false;

  return true;
}

/**
 * Check if signals include BOTH distribution markers AND content signals.
 * AG-PROMPT-CONFIDENTIAL-QUALITY-008: When both present, content dominates
 * for headline, distribution modifies guidance.
 */
export function hasDistributionPlusContent(signalIds?: string[]): boolean {
  if (!signalIds || signalIds.length === 0) return false;

  const hasDistribution = signalIds.some(id => isDistributionMarker(id));
  const hasContent = signalIds.some(id =>
    isSecretOrCredential(id) ||
    hasRegulatedSignals([id]) ||
    hasLegalSignals([id])
  );

  return hasDistribution && hasContent;
}

// ============================================================================
// AG-PROMPT-SURFACE-COMPOSITE-001: COMPOSITE DOCUMENT DETECTION
// ============================================================================
// Surface language follows AG-PROMPT-SURFACE-COMPOSITE-001
// When multiple signal families are present, use "contains signals related to..."
// phrasing instead of asserting categorical identity.
// ============================================================================

/**
 * Detect which signal families are present in the driving signals.
 * Returns array of human-readable family labels.
 */
export function detectSignalFamilies(signalIds?: string[]): string[] {
  if (!signalIds || signalIds.length === 0 || SIGNAL_FAMILIES.length === 0) {
    return [];
  }

  const detectedFamilies: Set<string> = new Set();

  for (const signalId of signalIds) {
    const lowerId = signalId.toLowerCase();
    for (const family of SIGNAL_FAMILIES) {
      if (family.patterns.some(pattern => lowerId.includes(pattern))) {
        detectedFamilies.add(family.label);
        break; // One family match per signal is enough
      }
    }
  }

  return Array.from(detectedFamilies).sort();
}

/**
 * Check if document is composite (multiple signal families present).
 * AG-PROMPT-SURFACE-COMPOSITE-001: Composite documents require different surface language.
 */
export function isCompositeDocument(signalIds?: string[]): boolean {
  const families = detectSignalFamilies(signalIds);
  return families.length > 1;
}

/**
 * Format signal family labels into human-readable list.
 * E.g., ["legal", "financial"] => "legal and financial information"
 * E.g., ["legal", "financial", "personal"] => "legal, financial, and personal information"
 */
export function formatFamilyList(families: string[]): string {
  if (families.length === 0) {
    return 'sensitive information';
  }
  if (families.length === 1) {
    return `${families[0]} information`;
  }
  if (families.length === 2) {
    return `${families[0]} and ${families[1]} information`;
  }
  // Oxford comma for 3+
  const allButLast = families.slice(0, -1).join(', ');
  const last = families[families.length - 1];
  return `${allButLast}, and ${last} information`;
}

// ============================================================================
// AG-PROMPT-SURFACE-FALLBACK-GUIDANCE-REFINE-014: CONTEXTUAL HINTS FROM FILENAME
// ============================================================================

/**
 * Document context hints inferred from filename patterns.
 * These do NOT change frame selection - only guidance wording.
 */
export type DocumentContextHint =
  | 'contract_like'      // Contract, NDA, agreement patterns
  | 'hr_like'            // Resignation, employment, onboarding patterns
  | 'financial_like'     // Invoice, payroll, salary patterns
  | 'medical_like'       // Health, medical, patient patterns
  | 'insurance_like'     // Insurance, policy, claim patterns
  | 'public_like'        // Whitepaper, guide, manual, report patterns
  | 'unknown';           // No recognizable pattern

/**
 * Contextual guidance based on document hint.
 * Used only for fallback/inferred frames to add human-relevant context.
 */
interface ContextualGuidance {
  hint: DocumentContextHint;
  summaryAddition: string;
  guidanceAddition: string;
}

/**
 * Infer document context from filename.
 * AG-PROMPT-SURFACE-FALLBACK-GUIDANCE-REFINE-014: Provides contextual hints
 * for guidance wording without changing detection or frame selection.
 *
 * @param filename - Original filename (optional)
 * @returns Document context hint
 */
export function inferDocumentContextFromFilename(filename?: string): DocumentContextHint {
  if (!filename) return 'unknown';

  const lower = filename.toLowerCase();

  // Contract-like patterns
  if (
    lower.includes('contract') ||
    lower.includes('nda') ||
    lower.includes('agreement') ||
    lower.includes('docusign') ||
    lower.includes('signatur') ||
    lower.includes('terms')
  ) {
    return 'contract_like';
  }

  // HR-like patterns
  if (
    lower.includes('resign') ||
    lower.includes('employment') ||
    lower.includes('onboard') ||
    lower.includes('offer letter') ||
    lower.includes('termination') ||
    lower.includes('medarbejder') || // Danish: employee
    lower.includes('ansættel')       // Danish: employment
  ) {
    return 'hr_like';
  }

  // Financial-like patterns
  if (
    lower.includes('invoice') ||
    lower.includes('payroll') ||
    lower.includes('salary') ||
    lower.includes('løn') ||    // Danish: salary
    lower.includes('faktura')   // Danish/Nordic: invoice
  ) {
    return 'financial_like';
  }

  // Medical-like patterns
  if (
    lower.includes('medical') ||
    lower.includes('health') ||
    lower.includes('patient') ||
    lower.includes('diagnos') ||
    lower.includes('sundhed') ||  // Danish: health
    lower.includes('labsvar') ||  // Danish: lab results
    lower.includes('journal')     // Medical journal
  ) {
    return 'medical_like';
  }

  // Insurance-like patterns
  if (
    lower.includes('insurance') ||
    lower.includes('forsikring') ||  // Danish: insurance
    lower.includes('police') ||      // Insurance policy (Nordic)
    lower.includes('claim')
  ) {
    return 'insurance_like';
  }

  // Public/informational patterns
  if (
    lower.includes('whitepaper') ||
    lower.includes('guide') ||
    lower.includes('manual') ||
    lower.includes('handbook') ||
    lower.includes('operating model') ||
    lower.includes('operating-model') ||
    lower.includes('operating_model') ||
    lower.includes('readme') ||
    lower.includes('overview')
  ) {
    return 'public_like';
  }

  return 'unknown';
}

/**
 * Get contextual guidance additions based on document hint.
 * AG-PROMPT-SURFACE-FALLBACK-GUIDANCE-REFINE-014: Provides additional context
 * for fallback/inferred frames without changing the frame itself.
 */
export function getContextualGuidance(hint: DocumentContextHint): ContextualGuidance {
  switch (hint) {
    case 'contract_like':
      return {
        hint,
        summaryAddition: 'The filename suggests this may be a contract or agreement.',
        guidanceAddition: 'Contracts often contain terms that should be reviewed before external sharing, even without explicit markers.',
      };

    case 'hr_like':
      return {
        hint,
        summaryAddition: 'The filename suggests this may relate to HR or employment.',
        guidanceAddition: 'HR documents are often sensitive by nature, even without explicit personal data markers.',
      };

    case 'financial_like':
      return {
        hint,
        summaryAddition: 'The filename suggests this may relate to financial matters.',
        guidanceAddition: 'Financial documents often contain information that should be handled carefully.',
      };

    case 'medical_like':
      return {
        hint,
        summaryAddition: 'The filename suggests this may relate to health or medical information.',
        guidanceAddition: 'Medical documents typically require careful handling regardless of detected content.',
      };

    case 'insurance_like':
      return {
        hint,
        summaryAddition: 'The filename suggests this may be an insurance document.',
        guidanceAddition: 'Insurance documents often contain personal details that warrant review before sharing.',
      };

    case 'public_like':
      return {
        hint,
        summaryAddition: 'This appears to be informational or educational material.',
        guidanceAddition: 'Verify this is intended for external audiences before sharing.',
      };

    case 'unknown':
    default:
      return {
        hint: 'unknown',
        summaryAddition: '',
        guidanceAddition: '',
      };
  }
}

// ============================================================================
// AG-PROMPT-SURFACE-UNCERTAINTY-GRADIENT-013: SURFACE CONFIDENCE DERIVATION
// ============================================================================

/**
 * Derive surface confidence from existing structured signals.
 *
 * Rules (deterministic, priority-ordered):
 * - confirmed: documentClass is set OR high severity with multiple signals
 * - inferred: some signals exist but weak evidence
 * - fallback: no signals or signalCount = 0
 *
 * This function does NOT change detection logic or enforcement decisions.
 * It only affects how assertive the UI copy should be.
 */
export function deriveSurfaceConfidence(input: FrameSelectionInput): {
  confidence: SurfaceConfidence;
  ruleId: string;
} {
  const { documentClass, drivingSignalIds, severity, signalCount } = input;
  const effectiveSignalCount = signalCount ?? (drivingSignalIds?.length ?? 0);

  // Rule 1: If documentClass is set, we have confirmed evidence
  if (documentClass) {
    return {
      confidence: 'confirmed',
      ruleId: AWARENESS_FRAMING_RULE_IDS.CONFIDENCE_CONFIRMED,
    };
  }

  // Rule 2: If no signals at all, use fallback
  if (effectiveSignalCount === 0 || !drivingSignalIds || drivingSignalIds.length === 0) {
    return {
      confidence: 'fallback',
      ruleId: AWARENESS_FRAMING_RULE_IDS.CONFIDENCE_FALLBACK,
    };
  }

  // Rule 3: High/critical severity with multiple signals = confirmed
  const isHighSeverity = severity === 'high' || severity === 'critical';
  if (isHighSeverity && effectiveSignalCount >= 2) {
    return {
      confidence: 'confirmed',
      ruleId: AWARENESS_FRAMING_RULE_IDS.CONFIDENCE_CONFIRMED,
    };
  }

  // Rule 4: Multiple signal families = confirmed (composite)
  const families = detectSignalFamilies(drivingSignalIds);
  if (families.length >= 2) {
    return {
      confidence: 'confirmed',
      ruleId: AWARENESS_FRAMING_RULE_IDS.CONFIDENCE_CONFIRMED,
    };
  }

  // Rule 5: Single strong domain signal = confirmed
  // (medical, legal, financial identifiers are strong evidence)
  const hasStrongDomainSignal = drivingSignalIds.some(id => {
    const lower = id.toLowerCase();
    return (
      lower.includes('medical') ||
      lower.includes('clinical') ||
      lower.includes('icd') ||
      lower.includes('cpt') ||
      lower.includes('nda') ||
      lower.includes('contract') ||
      lower.includes('ssn') ||
      lower.includes('passport') ||
      lower.includes('card-') ||
      lower.includes('iban') ||
      lower.includes('api-key') ||
      lower.includes('password')
    );
  });

  if (hasStrongDomainSignal) {
    return {
      confidence: 'confirmed',
      ruleId: AWARENESS_FRAMING_RULE_IDS.CONFIDENCE_CONFIRMED,
    };
  }

  // Rule 6: Medium severity with at least 1 signal = inferred
  if (severity === 'medium' && effectiveSignalCount >= 1) {
    return {
      confidence: 'inferred',
      ruleId: AWARENESS_FRAMING_RULE_IDS.CONFIDENCE_INFERRED,
    };
  }

  // Rule 7: Low severity or single weak signal = inferred
  if (effectiveSignalCount >= 1) {
    return {
      confidence: 'inferred',
      ruleId: AWARENESS_FRAMING_RULE_IDS.CONFIDENCE_INFERRED,
    };
  }

  // Default: fallback
  return {
    confidence: 'fallback',
    ruleId: AWARENESS_FRAMING_RULE_IDS.CONFIDENCE_FALLBACK,
  };
}

// ============================================================================
// FRAME SELECTION (deterministic, priority-ordered)
// ============================================================================

/**
 * Select the appropriate awareness frame based on document context.
 * Rules are evaluated in priority order; first match wins.
 *
 * AG-PROMPT-SURFACE-COMPOSITE-001: When multiple signal families are present
 * and no specific document class applies, use FRAME_COMPOSITE for neutral
 * "contains X and Y information" phrasing.
 */
export function selectFrame(input: FrameSelectionInput): {
  frame: AwarenessFrame;
  ruleId: string;
  detectedFamilies?: string[];  // AG-PROMPT-SURFACE-COMPOSITE-001
} {
  const { documentClass, drivingSignalIds, severity, ontologyDriven, singleStrongAwareness, identityConfidence } = input;

  // AG-PROMPT-SIGNAL-BYPASS-FIX-028: Identity-gated frame selection.
  // Document class frames are only used when identity confidence is strong.
  // When weak, fall through to evidence-based (non-identity) frame selection.
  const identityIsStrong = identityConfidence === 'strong' || identityConfidence === undefined;

  // Priority 1: doc.medical_record (only with strong identity)
  if (documentClass === 'doc.medical_record' && identityIsStrong) {
    return { frame: 'FRAME_MEDICAL', ruleId: AWARENESS_FRAMING_RULE_IDS.SELECT_MEDICAL };
  }

  // Priority 2: doc.payroll (only with strong identity)
  if (documentClass === 'doc.payroll' && identityIsStrong) {
    return { frame: 'FRAME_PAYROLL', ruleId: AWARENESS_FRAMING_RULE_IDS.SELECT_PAYROLL };
  }

  // Priority 3: doc.hr_record (only with strong identity)
  if (documentClass === 'doc.hr_record' && identityIsStrong) {
    return { frame: 'FRAME_HR', ruleId: AWARENESS_FRAMING_RULE_IDS.SELECT_HR };
  }

  // Priority 3b: doc.insurance_policy (AG-PHASE-5C-056)
  if (documentClass === 'doc.insurance_policy') {
    return { frame: 'FRAME_INSURANCE', ruleId: AWARENESS_FRAMING_RULE_IDS.SELECT_INSURANCE };
  }

  // Priority 3c: doc.invoice (AG-PROMPT-175)
  if (documentClass === 'doc.invoice') {
    return { frame: 'FRAME_INVOICE', ruleId: AWARENESS_FRAMING_RULE_IDS.SELECT_INVOICE };
  }

  // Priority 3d: doc.health_certificate (AG-PROMPT-175)
  if (documentClass === 'doc.health_certificate') {
    return { frame: 'FRAME_HEALTH_CERTIFICATE', ruleId: AWARENESS_FRAMING_RULE_IDS.SELECT_HEALTH_CERTIFICATE };
  }

  // AG-PROMPT-CONFIDENTIAL-QUALITY-008: Distribution-only signals get calm framing
  // This MUST come BEFORE regulated/composite checks to ensure confidentiality markers
  // don't incorrectly trigger "sensitive" or "regulated" language.
  // Distribution sensitivity ≠ content sensitivity.
  if (!documentClass && hasOnlyDistributionSignals(drivingSignalIds)) {
    return { frame: 'FRAME_DISTRIBUTION_RESTRICTION', ruleId: AWARENESS_FRAMING_RULE_IDS.SELECT_DISTRIBUTION };
  }

  // AG-PROMPT-SURFACE-PLAIN-LANGUAGE-009: Single strong personal data signal awareness
  // This MUST come BEFORE composite/regulated checks to ensure personal data signals
  // get plain language framing ("identifies a person") instead of regulated/composite language.
  // Personal data deserves consequence-based framing at any severity.
  if (singleStrongAwareness && !documentClass) {
    return { frame: 'FRAME_PERSONAL_DATA_AWARENESS', ruleId: AWARENESS_FRAMING_RULE_IDS.SELECT_PERSONAL_DATA };
  }

  // AG-PROMPT-SURFACE-COMPOSITE-001: Check for composite documents
  // This must come BEFORE single-family checks when no document class is present
  const detectedFamilies = detectSignalFamilies(drivingSignalIds);
  if (detectedFamilies.length > 1 && !documentClass) {
    // Multiple signal families detected - use composite framing
    // DO NOT assert single categorical identity on surface
    return {
      frame: 'FRAME_COMPOSITE',
      ruleId: AWARENESS_FRAMING_RULE_IDS.SELECT_COMPOSITE,
      detectedFamilies,
    };
  }

  // Priority 4: Legal signals detected (single family)
  if (drivingSignalIds && hasLegalSignals(drivingSignalIds)) {
    return { frame: 'FRAME_LEGAL', ruleId: AWARENESS_FRAMING_RULE_IDS.SELECT_LEGAL };
  }

  // Priority 4b: AG-PROMPT-188: Business-sensitive / M&A signals (single family)
  // M&A terms indicate material non-public information. Without this check,
  // M&A content falls through to FRAME_GENERAL_SENSITIVE with no useful context.
  if (drivingSignalIds && !documentClass && hasBusinessSensitiveSignals(drivingSignalIds)) {
    return { frame: 'FRAME_BUSINESS_SENSITIVE', ruleId: AWARENESS_FRAMING_RULE_IDS.SELECT_BUSINESS_SENSITIVE };
  }

  // Priority 5: High severity + ontology/regulated signals, no document class
  const isHighSeverity = severity === 'high' || severity === 'critical';
  if (isHighSeverity && !documentClass) {
    if (ontologyDriven || hasRegulatedSignals(drivingSignalIds)) {
      return { frame: 'FRAME_REGULATED_SENSITIVE', ruleId: AWARENESS_FRAMING_RULE_IDS.SELECT_REGULATED };
    }
  }

  // Default: General sensitive
  return { frame: 'FRAME_GENERAL_SENSITIVE', ruleId: AWARENESS_FRAMING_RULE_IDS.SELECT_GENERAL };
}

// ============================================================================
// DETAIL SUPPRESSION
// ============================================================================

/**
 * Determine if signal details should be suppressed.
 */
export function shouldSuppressDetails(input: FrameSelectionInput): {
  suppress: boolean;
  ruleId: string | null;
} {
  if (input.ontologyDriven) {
    return { suppress: true, ruleId: AWARENESS_FRAMING_RULE_IDS.SUPPRESS_ONTOLOGY };
  }

  if (input.documentClass) {
    const docClassSignals = ['doc.payroll', 'doc.hr_record', 'doc.medical_record'];
    const isDrivenByDocClass = input.drivingSignalIds?.some(id =>
      docClassSignals.includes(id)
    );
    if (isDrivenByDocClass) {
      return { suppress: true, ruleId: AWARENESS_FRAMING_RULE_IDS.SUPPRESS_DOC_CLASS };
    }
  }

  return { suppress: false, ruleId: null };
}

// ============================================================================
// MAIN FRAMING FUNCTION
// ============================================================================

/**
 * Generate a framed explanation for a risk decision.
 * AG-PROMPT-090: Now includes guidance from frame data.
 * AG-PROMPT-SURFACE-COMPOSITE-001: Handles composite documents with dynamic family lists.
 * AG-PROMPT-CONFIDENTIAL-QUALITY-008: Adds distribution modifier when both content and distribution signals present.
 * AG-PROMPT-SURFACE-UNCERTAINTY-GRADIENT-013: Uses confidence-based copy gradients.
 */
export function generateFramedExplanation(input: FrameSelectionInput): FramedExplanation {
  // AG-PROMPT-SURFACE-UNCERTAINTY-GRADIENT-013: Derive confidence first
  const { confidence } = deriveSurfaceConfidence(input);

  // AG-PHASE-5E-058: Route to domain-specific degraded frame when fallback classification applies
  // This takes priority over generic FRAME_PDF_UNREADABLE because we have domain-specific indicators
  if (input.pdfExtractionFailed && input.degradedFallback) {
    const suppression = shouldSuppressDetails(input);
    let frame: AwarenessFrame;
    let ruleId: string;

    switch (input.degradedFallback.domain) {
      case 'payroll':
        frame = 'FRAME_DEGRADED_PAYROLL';
        ruleId = AWARENESS_FRAMING_RULE_IDS.SELECT_DEGRADED_PAYROLL;
        break;
      case 'hr_contract':
        frame = 'FRAME_DEGRADED_HR';
        ruleId = AWARENESS_FRAMING_RULE_IDS.SELECT_DEGRADED_HR;
        break;
      case 'insurance':
        frame = 'FRAME_DEGRADED_INSURANCE';
        ruleId = AWARENESS_FRAMING_RULE_IDS.SELECT_DEGRADED_INSURANCE;
        break;
    }

    const template = FRAME_TEMPLATES[frame];
    const guidance = FRAME_GUIDANCE[frame];

    return {
      headline: template.headline,
      summary: template.summary,
      guidance,
      frame,
      suppressDetails: suppression.suppress,
      ruleId,
      confidence: 'inferred', // Degraded fallback is inferred from filename/metadata
    };
  }

  // AG-PHASE-4-052: Route to FRAME_PDF_UNREADABLE when extraction failed
  // This takes priority over fallback confidence — user deserves honest "limited readability" framing
  if (input.pdfExtractionFailed && confidence === 'fallback') {
    const pdfTemplate = FRAME_TEMPLATES.FRAME_PDF_UNREADABLE;
    const pdfGuidance = FRAME_GUIDANCE.FRAME_PDF_UNREADABLE;
    const suppression = shouldSuppressDetails(input);

    // AG-PROMPT-SURFACE-FALLBACK-GUIDANCE-REFINE-014: Add contextual hints from filename
    const contextHint = inferDocumentContextFromFilename(input.filename);
    const contextualGuidance = getContextualGuidance(contextHint);

    let summary = pdfTemplate.summary;
    let guidance = pdfGuidance;

    if (input.pdfEncryptionReadability === 'ENCRYPTED_PASSWORD_REQUIRED') {
      summary = 'This PDF is encrypted and requires a password. Ai Notice cannot read its text without that password.';
      guidance = 'Open the PDF with the correct password, then re-upload an accessible version for analysis.';
    }

    if (contextHint !== 'unknown') {
      // Append context hint to the extraction-limited summary
      summary = `${pdfTemplate.summary} ${contextualGuidance.summaryAddition}`;
      guidance = contextualGuidance.guidanceAddition;
    }

    return {
      headline: pdfTemplate.headline,
      summary,
      guidance,
      frame: 'FRAME_PDF_UNREADABLE',
      suppressDetails: suppression.suppress,
      ruleId: AWARENESS_FRAMING_RULE_IDS.SELECT_PDF_UNREADABLE,
      confidence,
    };
  }

  // AG-PROMPT-325: Not-scanned (scan skipped / detection timed out, NOT a parser failure).
  // Honest "could not fully check" framing so silence/zero-signal is not read as a clean pass.
  // Guarded by confidence === 'fallback' so it only applies when no real signals were found
  // (if filename/metadata signals exist, the normal risk frame still wins). Placed AFTER
  // pdfExtractionFailed (parser failure is more specific) and BEFORE FRAME_REVIEW_ADVISED.
  if (input.notScanned && confidence === 'fallback') {
    const nsTemplate = FRAME_TEMPLATES.FRAME_NOT_SCANNED;
    const suppression = shouldSuppressDetails(input);
    return {
      headline: nsTemplate.headline,
      summary: nsTemplate.summary,
      guidance: FRAME_GUIDANCE.FRAME_NOT_SCANNED,
      frame: 'FRAME_NOT_SCANNED',
      suppressDetails: suppression.suppress,
      ruleId: AWARENESS_FRAMING_RULE_IDS.SELECT_NOT_SCANNED,
      confidence,
    };
  }

  // AG-PROMPT-SURFACE-UNCERTAINTY-GRADIENT-013: For fallback confidence, use FRAME_REVIEW_ADVISED
  // regardless of other frame selection logic
  // AG-PROMPT-SURFACE-FALLBACK-GUIDANCE-REFINE-014: Add contextual guidance based on filename
  if (confidence === 'fallback') {
    const fallbackTemplate = FRAME_TEMPLATES.FRAME_REVIEW_ADVISED;
    let fallbackGuidance = FRAME_GUIDANCE.FRAME_REVIEW_ADVISED;
    // AG-PROMPT-326: plainer consumer wording ("sensitive-data markers" not "regulated data") and
    // an explicit non-all-clear caveat so zero findings is not read as a safety guarantee.
    let fallbackSummary = 'No obvious sensitive-data markers were found — but that isn’t a guarantee. Review before sharing if unsure.';
    const suppression = shouldSuppressDetails(input);

    // AG-PROMPT-SURFACE-FALLBACK-GUIDANCE-REFINE-014: Add contextual hints from filename
    const contextHint = inferDocumentContextFromFilename(input.filename);
    const contextualGuidance = getContextualGuidance(contextHint);

    if (contextHint !== 'unknown') {
      // Add contextual information to summary and guidance
      fallbackSummary = contextualGuidance.summaryAddition;
      fallbackGuidance = contextualGuidance.guidanceAddition;
    }

    return {
      headline: fallbackTemplate.headline,
      summary: fallbackSummary,
      guidance: fallbackGuidance,
      frame: 'FRAME_REVIEW_ADVISED',
      suppressDetails: suppression.suppress,
      ruleId: AWARENESS_FRAMING_RULE_IDS.SELECT_REVIEW_ADVISED,
      confidence,
    };
  }

  const { frame, ruleId, detectedFamilies } = selectFrame(input);
  const template = FRAME_TEMPLATES[frame];

  // AG-PROMPT-SURFACE-EPISTEMIC-BOUNDARIES-018: Check if we have confirmed document classification
  // When documentClass is null, we only have signals - use indicator-centric headlines
  const hasDocumentClass = input.documentClass !== null && input.documentClass !== undefined;
  const frameData = FRAME_MAP[frame];

  const isLowSeverity = input.severity === 'low' || input.severity === 'none';
  let summary = isLowSeverity ? LOW_SEVERITY_SUMMARIES[frame] : template.summary;
  let headline = template.headline;
  let guidance = FRAME_GUIDANCE[frame];

  // AG-PROMPT-SURFACE-EPISTEMIC-BOUNDARIES-018: Use indicator-centric headline when no documentClass
  // This prevents category overreach (e.g., "Legal indicators" implying "legal document")
  if (!hasDocumentClass && frameData?.noClassHeadline) {
    headline = frameData.noClassHeadline;
  }

  // AG-PROMPT-SURFACE-AUTHORITY-CALIBRATION-016: Apply inferred confidence modifiers
  // For inferred confidence, use association-based language (not weakened verdicts)
  // Headlines must reflect epistemic authority, not semantic strength
  if (confidence === 'inferred') {
    // AG-PROMPT-SURFACE-EPISTEMIC-BOUNDARIES-018: Use noClassInferredHeadline when no documentClass
    if (!hasDocumentClass && frameData?.noClassInferredHeadline) {
      headline = frameData.noClassInferredHeadline;
    } else if (template.inferredHeadline) {
      // Use the dedicated inferredHeadline template if available
      // This uses association-based language ("includes information commonly associated with...")
      // instead of weakened verdicts ("may contain...")
      headline = template.inferredHeadline;
    }
    // For inferred, always use the low-severity (softer) summary
    summary = LOW_SEVERITY_SUMMARIES[frame];

    // AG-PROMPT-SURFACE-FALLBACK-GUIDANCE-REFINE-014: Add contextual hints for inferred too
    const contextHint = inferDocumentContextFromFilename(input.filename);
    if (contextHint !== 'unknown') {
      const contextualGuidance = getContextualGuidance(contextHint);
      guidance = `${guidance} ${contextualGuidance.guidanceAddition}`;
    }
  }

  // AG-PROMPT-SURFACE-COMPOSITE-001: Dynamic composite headline/summary
  // AG-PROMPT-SURFACE-PROBABILISTIC-LANGUAGE-017: Observational language
  // Surface language follows AG-PROMPT-SURFACE-PROBABILISTIC-LANGUAGE-017
  if (frame === 'FRAME_COMPOSITE' && detectedFamilies && detectedFamilies.length > 1) {
    const familyList = formatFamilyList(detectedFamilies);
    // Replace {familyList} placeholder or use dynamic format
    if (confidence === 'confirmed') {
      // AG-PROMPT-SURFACE-PROBABILISTIC-LANGUAGE-017: Observational, not verdict
      headline = `Indicators related to ${familyList} were detected`;
      summary = isLowSeverity
        ? `Some patterns may relate to ${familyList}.`
        : `Patterns consistent with ${familyList} were found.`;
    } else {
      // inferred confidence: explicitly probabilistic
      headline = `Patterns suggest possible ${familyList.replace(' information', '')} content`;
      summary = `Some indicators may relate to ${familyList}. Please verify before sharing.`;
    }
  }

  // AG-PROMPT-CONFIDENTIAL-QUALITY-008: When content frame is selected but distribution
  // markers are also present, modify guidance to note distribution restrictions.
  // Content dominates headline, distribution modifies guidance.
  if (frame !== 'FRAME_DISTRIBUTION_RESTRICTION' && hasDistributionPlusContent(input.drivingSignalIds)) {
    // Append distribution note to guidance (don't replace, just add)
    guidance = `${guidance} Distribution may also be restricted.`;
  }

  const suppression = shouldSuppressDetails(input);

  // AG-PROMPT-SURFACE-HEADLINE-EPIS-POLICY-020: Final safety net
  // Enforce epistemic headline policy - rewrite if category-implying and no documentClass
  const finalHeadline = enforceEpistemicHeadlinePolicy(headline, input.documentClass);

  return {
    headline: finalHeadline,
    summary,
    guidance,
    confidence,
    frame,
    suppressDetails: suppression.suppress,
    ruleId,
  };
}

// ============================================================================
// VALIDATION
// ============================================================================

/**
 * Check if text contains forbidden words.
 */
export function checkForbiddenWords(text: string): string[] {
  const lowerText = text.toLowerCase();
  return FORBIDDEN_WORDS.filter(word => lowerText.includes(word));
}

/**
 * Validate that a framed explanation contains no forbidden words.
 */
export function validateFramedExplanation(explanation: FramedExplanation): {
  valid: boolean;
  issues: string[];
} {
  const issues: string[] = [];

  const headlineForbidden = checkForbiddenWords(explanation.headline);
  if (headlineForbidden.length > 0) {
    issues.push(`Headline contains forbidden words: ${headlineForbidden.join(', ')}`);
  }

  const summaryForbidden = checkForbiddenWords(explanation.summary);
  if (summaryForbidden.length > 0) {
    issues.push(`Summary contains forbidden words: ${summaryForbidden.join(', ')}`);
  }

  if (explanation.headline.length > 80) {
    issues.push(`Headline exceeds 80 chars: ${explanation.headline.length}`);
  }

  if (explanation.summary.length > 140) {
    issues.push(`Summary exceeds 140 chars: ${explanation.summary.length}`);
  }

  return { valid: issues.length === 0, issues };
}

// ============================================================================
// INTEGRATION HELPER
// ============================================================================

/**
 * AG-PROMPT-087/090: Framed explanation result with frameId and guidance for contract enforcement.
 */
export interface FramedDecisionExplanation {
  headline: string;
  summary: string;
  guidance: string;  // AG-PROMPT-090: Actionable guidance from frame
  frameId: string;
  details?: unknown[];
}

/**
 * Apply awareness framing to an existing decision explanation.
 *
 * AG-PROMPT-087: ALWAYS applies a frame. If no specific context triggers a
 * specialized frame, defaults to FRAME_GENERAL_SENSITIVE. This ensures
 * awareness copy ONLY comes from frames, never from inline fallbacks.
 *
 * AG-PROMPT-090: Now includes guidance for display in modal.
 */
export function applyAwarenessFraming<T extends { headline: string; summary: string; details?: unknown[] }>(
  baseExplanation: T,
  input: FrameSelectionInput
): T & { frameId: string; guidance: string } {
  // AG-PROMPT-087: Always generate framed explanation (no early return)
  // This ensures UI copy ONLY comes from frames, never fallback strings
  const framed = generateFramedExplanation(input);

  return {
    ...baseExplanation,
    headline: framed.headline,
    summary: framed.summary,
    guidance: framed.guidance,
    frameId: framed.frame,
    details: framed.suppressDetails ? undefined : baseExplanation.details,
  };
}

/**
 * AG-PROMPT-087/091: Assert that a decision explanation has complete frame data.
 * Throws if frameId, headline, summary, or guidance are missing.
 *
 * This is the governance lock-in - UI code MUST call this before rendering
 * to ensure copy comes from frames, never fallbacks.
 */
export function assertFrameComplete(
  explanation: { frameId?: string; headline?: string; summary?: string; guidance?: string }
): asserts explanation is { frameId: string; headline: string; summary: string; guidance: string } {
  // AG-PROMPT-097: Check for both missing and whitespace-only strings
  if (!explanation.frameId || !explanation.frameId.trim()) {
    throw new Error('Frame contract violation: DecisionExplanation missing frameId');
  }
  if (!explanation.headline || !explanation.headline.trim()) {
    throw new Error('Frame contract violation: DecisionExplanation missing headline');
  }
  if (!explanation.summary || !explanation.summary.trim()) {
    throw new Error('Frame contract violation: DecisionExplanation missing summary');
  }
  if (!explanation.guidance || !explanation.guidance.trim()) {
    throw new Error('Frame contract violation: DecisionExplanation missing guidance');
  }
}
