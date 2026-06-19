/**
 * AgentGuard Decision Explanation Builder (AG-PROMPT-036)
 *
 * Produces a minimal, calm, UI-ready payload for risk decisions.
 * Data-only layer - no UI changes, no behavior changes.
 *
 * Design principles:
 * - Deterministic: Same inputs → same output
 * - Minimal: Short headline + one-sentence summary by default
 * - Privacy-safe: Never includes content snippets or raw matched text
 * - Calm tone: Non-alarmist, informative, professional
 * - Progressive disclosure ready: Optional details for future expanded UI
 * - Consistency: No signal severity can exceed decision severity (AG-040)
 *
 * @see ADR-019: Decision Explanation Payload
 * @see AG-PROMPT-036
 * @see AG-PROMPT-040: Decision/UI Consistency Contract
 */

import type { Severity } from '../types/riskSignal';
import type { PdfEncryptionReadability } from '../types/pdfEncryption';
import type { AggregatedSeverityResult, SeverityLevel } from './severityAggregation';
import type { DocumentClass } from './documentClassAnchors';
import {
  applyAwarenessFraming,
  assertFrameComplete,
  type FrameSelectionInput,
  type FrameSeverity,
} from './awarenessFraming';

// Re-export for external use
export { assertFrameComplete };
import {
  resolveSignalDominance,
  type SignalDominanceResult,
} from './signalDominance';
import { rankSeverityOrNone } from './severityRank';

// ============================================================================
// DISCLOSURE CAPS (AG-PROMPT-037)
// ============================================================================

/**
 * Hard limits on information density, enforced at build-time.
 * These ensure consistent, calm presentation across all decisions.
 *
 * @see AG-PROMPT-037: Progressive Disclosure Rules
 */
export const DECISION_CAPS = {
  /** Maximum headline length in characters */
  HEADLINE_MAX_CHARS: 80,

  /** Maximum summary length in characters */
  SUMMARY_MAX_CHARS: 140,

  /** Maximum number of signal details shown */
  MAX_SIGNAL_DETAILS: 3,

  /** Maximum label length per signal detail */
  SIGNAL_DETAIL_MAX_CHARS: 80,
} as const;

// Re-export caps under canonical name for progressive disclosure
export const DISCLOSURE_CAPS = DECISION_CAPS;

// ============================================================================
// DISCLOSURE LEVELS (AG-PROMPT-037)
// ============================================================================

/**
 * Disclosure levels control information density in the UI.
 *
 * NOT user-configurable - derived automatically from severity.
 *
 * - MINIMAL: Fastest decision path, headline + action only
 * - STANDARD: Normal flow, headline + summary + optional details
 * - EXPANDED: Reserved for future use (same as STANDARD for now)
 */
export type DisclosureLevel = 'minimal' | 'standard' | 'expanded';

/**
 * Disclosure level constants for use in comparisons.
 */
export const DisclosureLevels = {
  MINIMAL: 'minimal' as DisclosureLevel,
  STANDARD: 'standard' as DisclosureLevel,
  EXPANDED: 'expanded' as DisclosureLevel,
} as const;

// ============================================================================
// AWARENESS VISIBILITY (AG-PROMPT-076)
// ============================================================================

/**
 * Awareness visibility level for UI routing.
 * Controls HOW the awareness UI is presented, not WHAT it shows.
 *
 * Separate from uiEscalation to avoid conflating visibility with action.
 *
 * - 'silent': No visible UI (reserved for future trusted internal tools)
 * - 'notice': Centered popup, auto-dismiss (~2s), for zero-signal scans
 * - 'interrupt': Centered modal requiring user review
 *
 * @see AG-PROMPT-076: Awareness UX Calibration
 */
export type AwarenessVisibility = 'silent' | 'notice' | 'interrupt';

/**
 * Auto-dismiss duration for 'notice' visibility level (milliseconds).
 */
export const NOTICE_AUTO_DISMISS_MS = 2000;

/**
 * What fields are visible at each disclosure level.
 *
 * This defines the contract for UI rendering:
 * - MINIMAL: headline, action (no details)
 * - STANDARD: headline, summary, optional details
 * - EXPANDED: same as STANDARD (reserved for future)
 */
export interface DisclosureVisibility {
  /** Show headline */
  showHeadline: boolean;
  /** Show summary text */
  showSummary: boolean;
  /** Show action (block/warn/allow) */
  showAction: boolean;
  /** Allow showing signal details */
  allowDetails: boolean;
  /** Maximum number of details to show (if allowed) */
  maxDetails: number;
}

/**
 * Complete disclosure result combining level, visibility, and capped explanation.
 */
export interface DisclosureResult {
  /** The disclosure level */
  level: DisclosureLevel;
  /** Visibility rules for this level */
  visibility: DisclosureVisibility;
  /** The explanation with caps enforced */
  explanation: DecisionExplanation;
}

// ============================================================================
// REASON CODES (AG-PROMPT-095)
// ============================================================================

/**
 * Machine-readable reason codes for decision outcomes.
 * Used for support bundles, debugging, and audit trails.
 *
 * These codes reflect states/conditions that occurred during processing.
 * They do not change detection logic - only document what happened.
 *
 * @see AG-PROMPT-095: Internal Operability
 */
export type ReasonCode =
  | 'ACTIVATION_NON_TARGET_NOOP'      // Target activation gate: non-target host, no scanning
  | 'PDF_EXTRACTION_FAILED'           // PDF text extraction failed completely
  | 'PDF_ENCRYPTED_PASSWORD_REQUIRED' // Encrypted PDF could not be opened without password
  | 'PDF_FALLBACK_USED'               // PDF extraction used fallback method
  | 'MEDICAL_ESCALATION_ENFORCED'     // Medical record escalation rules applied
  | 'REGULATED_VISIBILITY_RESCUE'     // Regulated visibility guardrail rescued a signal
  | 'CALIBRATION_REGULATED_RESCUE'    // Calibration rescued regulated signal
  | 'SINGLE_STRONG_AWARENESS'         // Single strong signal awareness applied
  | 'SIGNAL_DOMINANCE_REORDERED'      // Signal dominance reordered driving signals
  | 'FRAMES_DEFAULT_APPLIED'          // FRAME_GENERAL_SENSITIVE was applied as default
  | 'UX_INVARIANT_ESCALATED_INTERRUPT'; // UX invariant forced interrupt visibility

/**
 * All reason codes as array for iteration/validation.
 */
export const ALL_REASON_CODES: ReasonCode[] = [
  'ACTIVATION_NON_TARGET_NOOP',
  'PDF_EXTRACTION_FAILED',
  'PDF_ENCRYPTED_PASSWORD_REQUIRED',
  'PDF_FALLBACK_USED',
  'MEDICAL_ESCALATION_ENFORCED',
  'REGULATED_VISIBILITY_RESCUE',
  'CALIBRATION_REGULATED_RESCUE',
  'SINGLE_STRONG_AWARENESS',
  'SIGNAL_DOMINANCE_REORDERED',
  'FRAMES_DEFAULT_APPLIED',
  'UX_INVARIANT_ESCALATED_INTERRUPT',
];

// ============================================================================
// TYPES
// ============================================================================

/**
 * Action to take based on severity and destination context.
 *
 * - 'allow': No blocking, minimal friction
 * - 'warn': Show warning, user can proceed
 * - 'block': Prevent upload (or strong friction in non-blocking mode)
 */
export type DecisionAction = 'allow' | 'warn' | 'block';

/**
 * Destination type for context-aware action decisions.
 * Re-exported from destination.ts for convenience.
 */
export type DestinationType = 'public_ai' | 'internal_ai' | 'unknown';

/**
 * Detail for a single driving signal.
 * Used for progressive disclosure (future expanded UI).
 *
 * Privacy: Never includes raw match text or content snippets.
 */
export interface DecisionDetail {
  /** Canonical signal ID (e.g., 'secret.api_key') */
  id: string;

  /** Short human-readable label (e.g., 'API key') */
  label: string;

  /** Severity level of this signal */
  severity: string;

  /** Source where detected: 'content', 'metadata', 'filename' */
  source?: string;
}

/**
 * Complete decision explanation payload.
 *
 * This is the minimal, UI-ready data structure for rendering
 * risk decisions. Designed for calm, professional presentation.
 */
export interface DecisionExplanation {
  /** Overall severity (max-wins from aggregation) */
  severity: string;

  /**
   * UI escalation hint from PolicyMapper.
   * - 'none': No special treatment needed
   * - 'inline': Can show inline notification
   * - 'modal': Should show modal dialog
   */
  uiEscalation?: string;

  /**
   * AG-PROMPT-076: Awareness visibility level.
   * Controls UI presentation style (centered notice vs modal).
   * - 'notice': Auto-dismiss popup for zero-signal scans
   * - 'interrupt': Modal for any detected signals
   */
  awarenessVisibility?: AwarenessVisibility;

  /** Destination context: 'public_ai', 'internal_ai', 'unknown' */
  destination?: string;

  /** Computed action based on severity + destination rules */
  action: DecisionAction;

  /** Short headline (4-8 words) */
  headline: string;

  /** One-sentence summary (<=140 chars) */
  summary: string;

  /**
   * AG-PROMPT-087: Frame ID that produced the headline/summary.
   * Enforces frames-only contract - copy must come from defined frames,
   * never from inline fallbacks.
   */
  frameId: string;

  /**
   * AG-PROMPT-090: Actionable guidance from the frame.
   * Displayed in modal for user reference.
   */
  guidance: string;

  /**
   * Optional details for progressive disclosure.
   * Only includes driving signals (not all signals).
   * Sorted by severity desc, then id asc for stability.
   */
  details?: DecisionDetail[];

  /**
   * AG-PROMPT-095: Machine-readable reason codes documenting what happened.
   * Used for support bundles, debugging, and audit trails.
   * Sorted lexicographically for determinism.
   */
  reasonCodes?: ReasonCode[];

  /** Timestamp when this explanation was created */
  createdAt: number;
}

// ============================================================================
// AWARENESS VISIBILITY DERIVATION (AG-PROMPT-076, AG-PROMPT-077)
// ============================================================================

/**
 * AG-PHASE-5E-UI-DECISION-DIGNITY: Frames that indicate extraction limitations.
 * UI visibility is derived from frame type rather than raw pdfExtractionFailed flag.
 */
export const EXTRACTION_LIMITED_FRAMES = new Set([
  'FRAME_PDF_UNREADABLE',
  'FRAME_DEGRADED_PAYROLL',
  'FRAME_DEGRADED_HR',
  'FRAME_DEGRADED_INSURANCE',
]);

/**
 * Check if a frame indicates extraction was limited.
 * AG-PHASE-5E-UI-DECISION-DIGNITY: Replaces raw pdfExtractionFailed checks.
 */
export function isExtractionLimitedFrame(frameId: string | undefined): boolean {
  return frameId !== undefined && EXTRACTION_LIMITED_FRAMES.has(frameId);
}

/**
 * Input for awareness visibility derivation.
 */
export interface AwarenessVisibilityInput {
  /** Overall severity level */
  severity: string;
  /** UI escalation hint from policy */
  uiEscalation: string;
  /** Whether any signals were detected */
  hasSignals: boolean;
  /**
   * @deprecated AG-PHASE-5E-UI-DECISION-DIGNITY: Use frameId instead.
   * Whether PDF extraction failed (user must be informed)
   */
  pdfExtractionFailed?: boolean;
  pdfEncryptionReadability?: PdfEncryptionReadability;
  /**
   * @deprecated AG-PHASE-5E-UI-DECISION-DIGNITY: Visibility now derived from severity/frame.
   * AG-PROMPT-079: Number of visible signals (if any visible, must interrupt)
   */
  visibleSignalCount?: number;
  /**
   * AG-PHASE-5E-UI-DECISION-DIGNITY: Frame ID for policy-derived visibility.
   * UI behavior is derived from frame rather than raw extraction flags.
   */
  frameId?: string;
}

/**
 * Derive awareness visibility from severity, uiEscalation, and context.
 *
 * AG-PHASE-5E-UI-DECISION-DIGNITY INVARIANTS (policy-output-driven):
 * - Invariant A: severity >= medium => ALWAYS 'interrupt'
 * - Invariant B: uiEscalation === 'modal' => ALWAYS 'interrupt'
 * - Invariant C: extraction-limited frame (FRAME_PDF_UNREADABLE, FRAME_DEGRADED_*) => 'interrupt'
 *
 * Notice is ONLY allowed when ALL of:
 * - severity in ['none', 'low']
 * - uiEscalation !== 'modal'
 * - frame does not indicate extraction limitations
 *
 * AG-PROMPT-077 Rules (subject to invariants above):
 * - severity='none' AND no signals → 'notice' (auto-dismiss)
 * - severity='low' AND uiEscalation='inline' → 'notice'
 *
 * @param input - Visibility derivation input
 * @returns AwarenessVisibility for UI routing
 *
 * @see AG-PROMPT-076: Awareness UX Calibration
 * @see AG-PROMPT-077: Low-Risk Non-Blocking Notice
 * @see AG-PHASE-5E-UI-DECISION-DIGNITY: Policy-output-driven visibility
 */
export function deriveAwarenessVisibility(
  input: AwarenessVisibilityInput
): AwarenessVisibility {
  const { severity, uiEscalation, hasSignals, pdfExtractionFailed, visibleSignalCount, frameId } = input;

  // ========================================================================
  // AG-PHASE-5E-UI-DECISION-DIGNITY: INVARIANTS (policy-output-driven)
  // ========================================================================

  // Invariant A: severity >= medium ALWAYS requires interrupt
  // This is the primary decision driver - HIGH/CRITICAL always interrupt
  if (severity === 'medium' || severity === 'high' || severity === 'critical') {
    return 'interrupt';
  }

  // Invariant B: explicit modal escalation ALWAYS requires interrupt
  if (uiEscalation === 'modal') {
    return 'interrupt';
  }

  // Invariant C: extraction-limited frames require user attention
  // AG-PHASE-5E-UI-DECISION-DIGNITY: Derived from frame, not raw pdfExtractionFailed
  if (isExtractionLimitedFrame(frameId)) {
    return 'interrupt';
  }

  // Legacy support: if frameId not provided, fall back to pdfExtractionFailed check
  // This maintains backward compatibility during migration
  if (frameId === undefined && pdfExtractionFailed) {
    return 'interrupt';
  }

  // Legacy support: if frameId not provided and visibleSignalCount is set, use it
  // AG-PHASE-5E-UI-DECISION-DIGNITY: When frameId is provided, visibility is frame-derived
  if (frameId === undefined && visibleSignalCount !== undefined && visibleSignalCount > 0) {
    return 'interrupt';
  }

  // ========================================================================
  // AG-PROMPT-077: Notice conditions (only after invariants pass)
  // ========================================================================

  // No signals and no risk = quick confirmation (auto-dismiss notice)
  if (!hasSignals && severity === 'none') {
    return 'notice';
  }

  // Low severity with inline escalation = non-blocking notice
  // AG-PROMPT-077: Low risk should be visible but not interrupt workflow
  // AG-PHASE-5E-UI-DECISION-DIGNITY: No visibleSignalCount check when frameId is provided
  if (severity === 'low' && uiEscalation === 'inline') {
    // Legacy: if frameId not provided, use visibleSignalCount for backward compat
    if (frameId === undefined && visibleSignalCount === undefined && hasSignals) {
      return 'interrupt';
    }
    return 'notice';
  }

  // Default: interrupt (safety fallback)
  return 'interrupt';
}

/**
 * AG-PHASE-5E-UI-DECISION-DIGNITY: Recompute awareness visibility from policy outputs.
 *
 * WHY POST-CALIBRATION ENFORCEMENT IS NEEDED:
 * The initial awarenessVisibility is computed before several guardrails run:
 * - Medical escalation (may add signals)
 * - Visibility guardrail (may remove signals from UI)
 * - Document class baseline floors (may increase severity)
 *
 * These guardrails can change severity and frame AFTER the initial
 * visibility was computed. This function ensures the final visibility
 * reflects the policy decision state.
 *
 * INVARIANTS ENFORCED (via policy outputs):
 * - severity >= medium → interrupt (user must review)
 * - extraction-limited frame → interrupt (user must be warned)
 * - no signals AND severity=none → notice (calm confirmation)
 *
 * AG-PHASE-5E-UI-DIGNITY-MIGRATION-COMPLETE-059:
 * When frameId is present in explanation, visibility is derived SOLELY from
 * policy outputs (severity + frameId). Legacy params are ignored completely.
 *
 * @param explanation - The decision explanation to update
 * @param visibleSignalCount - @deprecated Optional legacy param, ignored when frameId present
 * @param pdfExtractionFailed - @deprecated Optional legacy param, ignored when frameId present
 * @returns Updated decision explanation with correct awarenessVisibility
 */
export function enforceAwarenessVisibility(
  explanation: DecisionExplanation,
  visibleSignalCount?: number,
  pdfExtractionFailed?: boolean
): DecisionExplanation {
  // AG-PHASE-5E-UI-DIGNITY-MIGRATION-COMPLETE-059: Derive visibility from policy outputs
  // When frameId is present, visibility is SOLELY determined by severity + frameId.
  // Legacy params (visibleSignalCount, pdfExtractionFailed) are ignored entirely.
  const hasFrameId = explanation.frameId !== undefined;

  // Derive hasSignals from explanation.details when frameId is present (policy-driven)
  // Otherwise fall back to legacy visibleSignalCount if provided
  const hasSignals = hasFrameId
    ? (explanation.details?.length ?? 0) > 0
    : (visibleSignalCount ?? 0) > 0;

  const newVisibility = deriveAwarenessVisibility({
    severity: explanation.severity,
    uiEscalation: explanation.uiEscalation ?? 'modal',
    hasSignals,
    frameId: explanation.frameId,  // Policy-derived frame drives visibility
    // Legacy params ONLY when frameId not present (backward compat)
    pdfExtractionFailed: hasFrameId ? undefined : pdfExtractionFailed,
    visibleSignalCount: hasFrameId ? undefined : visibleSignalCount,
  });

  // AG-PROMPT-095: Track if UX invariant escalated to interrupt
  const escalatedToInterrupt =
    newVisibility === 'interrupt' &&
    explanation.awarenessVisibility !== 'interrupt';

  // If visibility changed, log for debugging
  if (newVisibility !== explanation.awarenessVisibility) {
    const detailCount = explanation.details?.length ?? 0;
    console.log(`[AgentGuard] AwarenessVisibility corrected: ${explanation.awarenessVisibility} => ${newVisibility} (details=${detailCount}, severity=${explanation.severity}, frameId=${explanation.frameId ?? 'none'})`);
  }

  // Build updated reason codes array if escalation occurred
  const updatedReasonCodes = escalatedToInterrupt
    ? [...(explanation.reasonCodes || []), 'UX_INVARIANT_ESCALATED_INTERRUPT' as ReasonCode].sort()
    : explanation.reasonCodes;

  return {
    ...explanation,
    awarenessVisibility: newVisibility,
    reasonCodes: updatedReasonCodes,
  };
}

// ============================================================================
// SIGNAL LABEL MAPPING
// ============================================================================

/**
 * Stable, short labels for canonical signal IDs.
 * Used for details array - minimal, professional language.
 *
 * This is intentionally a small, curated mapping table.
 * Unknown IDs get a generic fallback label.
 */
/**
 * AG-PROMPT-SIGNAL-SEMANTICS-HUMILITY-023: Evidence-log semantic labels.
 *
 * Pattern card labels describe WHAT WAS DETECTED (evidence), not WHAT THE DOCUMENT IS.
 * This prevents category overreach when documentClass is not confirmed.
 *
 * Good: "Payment card pattern" (we detected a pattern)
 * Bad:  "Payment card" (asserts the document IS a payment card)
 */
const SIGNAL_LABELS: Record<string, string> = {
  // Secrets (OK - these describe what was found)
  'secret.api_key': 'API key pattern',
  'secret.aws_key': 'AWS access key pattern',
  'secret.password': 'Password/secret pattern',
  'secret.private_key': 'Private key detected',
  'secret.bearer_token': 'Bearer token pattern',
  'secret.connection_string': 'Connection string pattern',

  // PII (evidence-log: describe patterns, not document types)
  'pii.ssn': 'National ID pattern',
  'pii.ssn_us': 'SSN pattern',
  'pii.phone': 'Phone number pattern',
  'pii.phone.density': 'Phone number patterns',
  'pii.email': 'Email address pattern',
  'pii.email.density': 'Email address patterns',
  'pii.email_batch': 'Contact information patterns',
  'pii.credit_card': 'Payment card pattern',
  'pii.national_id': 'National ID pattern',
  'pii.name': 'Personal name pattern',
  'pii.employee': 'Employee data patterns',
  'pii.compensation': 'Compensation data patterns',

  // Financial (evidence-log: patterns, not document types)
  'financial.iban': 'IBAN pattern',
  'financial.credit_card': 'Payment card pattern',
  'financial.banking': 'Banking terminology',
  'financial.data': 'Financial data patterns',

  // Legal (evidence-log: terminology/language, not document types)
  'legal.contract': 'Contract terminology',
  'legal.nda': 'NDA terminology',
  'legal.privileged': 'Legal terminology',
  'legal.agreement': 'Agreement terminology',

  // Confidential
  'confidential.marker': 'Confidentiality marker',
  'confidential.ma': 'M&A terminology',
  'confidential.ma_terms': 'M&A terminology',

  // IP
  'ip.content': 'IP-related patterns',

  // HR
  'hr.employee_data': 'HR/Employee patterns',

  // Dictionary matches
  'dictionary.finance': 'Finance terminology',
  'dictionary.hr': 'HR terminology',
  'dictionary.legal': 'Legal terminology',
  'dictionary.match': 'Policy-flagged term',
};

/**
 * Get human-readable label for a signal ID.
 * Returns a generic fallback for unknown IDs.
 */
function getSignalLabel(signalId: string): string {
  return SIGNAL_LABELS[signalId] || 'Sensitive information';
}

// ============================================================================
// SEVERITY ORDERING
// ============================================================================

/**
 * Compare two severity strings for sorting (descending).
 */
function compareSeverityDesc(a: string, b: string): number {
  return rankSeverityOrNone(b) - rankSeverityOrNone(a);
}

// ============================================================================
// ACTION RULES
// ============================================================================

/**
 * Determine action based on severity and destination.
 *
 * Rules (mandatory, no exceptions):
 * - CRITICAL → always 'block'
 * - HIGH → 'warn' if internal_ai, else 'block'
 * - MEDIUM → 'warn'
 * - LOW/NONE → 'allow'
 *
 * Rationale:
 * - CRITICAL signals (secrets, SSN) are never acceptable for external upload
 * - HIGH signals may be OK for internal AI (company-controlled)
 * - MEDIUM signals need user attention but aren't blocking
 * - LOW signals are informational only
 */
function determineAction(
  severity: string,
  destination?: DestinationType
): DecisionAction {
  switch (severity) {
    case 'critical':
      return 'block';

    case 'high':
      // Internal AI gets lenient treatment for HIGH
      return destination === 'internal_ai' ? 'warn' : 'block';

    case 'medium':
      return 'warn';

    case 'low':
    case 'none':
    default:
      return 'allow';
  }
}

// ============================================================================
// HEADLINE & SUMMARY
// ============================================================================

/**
 * Get short headline for severity level (4-8 words).
 */
function getHeadline(severity: string): string {
  switch (severity) {
    case 'critical':
      return 'Critical risk detected';
    case 'high':
      return 'High risk detected';
    case 'medium':
      return 'Potential risk detected';
    case 'low':
      return 'Low risk detected';
    case 'none':
    default:
      return 'No risk detected';
  }
}

/**
 * Get one-sentence summary for severity level (<=140 chars).
 * Tone: Calm, informative, non-alarmist.
 */
function getSummary(severity: string): string {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'Sensitive data appears present. Please remove it before sending.';

    case 'medium':
      return 'This may contain personal or internal information. Double-check before sending.';

    case 'low':
      return 'Minor risk indicators found. Consider reviewing before sending.';

    case 'none':
    default:
      return 'No risk indicators detected.';
  }
}

// ============================================================================
// BUILDER
// ============================================================================

/**
 * Input for the decision explanation builder.
 */
export interface BuildDecisionExplanationInput {
  /**
   * Aggregated severity result from AG-PROMPT-035.
   * Must include severity and drivingSignalIds.
   */
  aggregatedSeverity: {
    severity: string;
    drivingSignalIds: string[];
    drivingSources?: string[];
    signalCount: number;
  };

  /**
   * Optional signal explanations for enriching details.
   * Used to extract severity per signal if available.
   */
  explanations?: {
    signals?: Array<{
      id?: string;
      severity?: string;
      uiEscalation?: string;
      source?: string;
    }>;
    overall?: {
      uiEscalation?: string;
    };
  } | null;

  /** Destination context for action rules */
  destination?: DestinationType;

  /** UI escalation hint override (from PolicyMapper) */
  uiEscalation?: 'none' | 'inline' | 'modal';

  /**
   * AG-PROMPT-044: Document class for awareness framing.
   * If provided, calm framing will be applied based on document type.
   */
  documentClass?: DocumentClass | null;

  /**
   * AG-PROMPT-044: Whether classification was driven by ontology anchors.
   * If true, signal details will be suppressed (don't expose ICD codes, units, etc.)
   */
  ontologyDriven?: boolean;

  /**
   * AG-PROMPT-077: Whether PDF extraction failed.
   * If true, user must be informed (forces interrupt visibility).
   */
  pdfExtractionFailed?: boolean;

  /**
   * Encryption readability classification for encrypted-PDF edge cases.
   */
  pdfEncryptionReadability?: PdfEncryptionReadability;

  /**
   * AG-PROMPT-080: Text content for context inference in signal dominance.
   * Used when document classification fails but text clearly indicates HR/legal context.
   */
  textContent?: string;

  /**
   * AG-PROMPT-086: Single strong awareness flag from calibration.
   * When true, indicates a single regulated signal was detected with high confidence.
   * Used to select calm awareness framing even without document class.
   */
  singleStrongAwareness?: boolean;

  /**
   * AG-PROMPT-SIGNAL-BYPASS-FIX-028: Identity confidence for frame selection gating.
   * When weak, document class frames are bypassed and terminology framing is used instead.
   */
  identityConfidence?: 'none' | 'weak' | 'strong';

  /**
   * AG-PROMPT-095: Reason codes collected during processing.
   * These are passed through to the final DecisionExplanation.
   */
  reasonCodes?: ReasonCode[];

  /**
   * AG-PHASE-5E-058: Degraded document fallback classification.
   * When PDF extraction is degraded/blocked, this provides domain-specific
   * classification inferred from filename and metadata.
   */
  degradedFallback?: {
    domain: 'payroll' | 'hr_contract' | 'insurance';
    matchedTokens: string[];
    source: 'filename' | 'metadata' | 'both';
  };
}

/**
 * Build a decision explanation payload.
 *
 * This is the main entry point for creating UI-ready decision data.
 * The output is deterministic and privacy-safe.
 *
 * @param args - Input containing aggregated severity, explanations, and context
 * @returns DecisionExplanation ready for UI consumption
 *
 * @example
 * const explanation = buildDecisionExplanation({
 *   aggregatedSeverity: { severity: 'high', drivingSignalIds: ['secret.api_key'], signalCount: 3 },
 *   destination: 'public_ai',
 * });
 * // → { action: 'block', headline: 'High risk detected', ... }
 */
export function buildDecisionExplanation(
  args: BuildDecisionExplanationInput
): DecisionExplanation {
  const {
    aggregatedSeverity,
    explanations,
    destination,
    uiEscalation,
    documentClass,
    ontologyDriven,
    pdfExtractionFailed,
    pdfEncryptionReadability,
    textContent,
    singleStrongAwareness,
    identityConfidence,
    reasonCodes: inputReasonCodes,
    degradedFallback,
  } = args;
  const severity = aggregatedSeverity.severity;

  // AG-PROMPT-095: Collect reason codes during processing
  const reasonCodes: ReasonCode[] = inputReasonCodes ? [...inputReasonCodes] : [];

  // Determine action based on severity + destination
  const action = determineAction(severity, destination);

  // Get baseline headline and summary
  const headline = getHeadline(severity);
  const summary = getSummary(severity);

  // AG-PROMPT-078: Apply signal dominance resolution
  // Reorders driving signals so domain-appropriate signals appear first
  // (e.g., prefer HR/PII signals over payment card in HR documents)
  // AG-PROMPT-080: Now includes textContent for inferred context when docClass is null
  const dominanceResult = resolveSignalDominance({
    drivingSignalIds: aggregatedSeverity.drivingSignalIds,
    documentClass: documentClass ?? null,
    textContent,
  });

  // AG-PROMPT-095: Track signal dominance reordering
  if (dominanceResult.reordered) {
    reasonCodes.push('SIGNAL_DOMINANCE_REORDERED');
    console.log(`[AgentGuard] SignalDominance: ${dominanceResult.reason} (rule=${dominanceResult.ruleId})`);
  }

  // AG-PROMPT-095: Track single strong awareness
  if (singleStrongAwareness) {
    reasonCodes.push('SINGLE_STRONG_AWARENESS');
  }

  // Build details from prioritized (dominance-resolved) signal IDs
  const details = buildDetails(
    dominanceResult.prioritizedSignalIds,
    aggregatedSeverity.drivingSources,
    severity,
    explanations?.signals
  );

  // Resolve UI escalation (prefer explicit override, then from overall explanation)
  const resolvedUiEscalation =
    uiEscalation ?? explanations?.overall?.uiEscalation ?? 'modal';

  // AG-PROMPT-076/077: Derive awareness visibility for UI routing
  const hasSignals = aggregatedSeverity.signalCount > 0;
  const awarenessVisibility = deriveAwarenessVisibility({
    severity,
    uiEscalation: resolvedUiEscalation,
    hasSignals,
    pdfExtractionFailed,
  });

  // Build base explanation
  // AG-PROMPT-087/090: frameId and guidance are set to placeholders; applyAwarenessFraming will always override
  const baseExplanation: DecisionExplanation = {
    severity,
    uiEscalation: resolvedUiEscalation,
    awarenessVisibility,
    destination,
    action,
    headline,
    summary,
    frameId: '', // Will be set by applyAwarenessFraming
    guidance: '', // AG-PROMPT-090: Will be set by applyAwarenessFraming
    details: details.length > 0 ? details : undefined,
    createdAt: Date.now(),
  };

  // AG-PROMPT-044/086: Apply awareness framing for document-class or ontology-driven decisions
  // This overrides generic headline/summary with calm, human-facing text
  // AG-PROMPT-086: Now includes singleStrongAwareness for calm framing without doc class
  // AG-PROMPT-SIGNAL-BYPASS-FIX-028: Pass identityConfidence for frame selection gating
  const framingInput: FrameSelectionInput = {
    documentClass: documentClass ?? null,
    severity: severity as FrameSeverity,
    ontologyDriven,
    drivingSignalIds: aggregatedSeverity.drivingSignalIds,
    singleStrongAwareness,
    identityConfidence,
    pdfExtractionFailed,  // AG-PHASE-4-052: Route to FRAME_PDF_UNREADABLE
    pdfEncryptionReadability,
    degradedFallback,  // AG-PHASE-5E-058: Degraded document fallback classification
  };

  const framedExplanation = applyAwarenessFraming(baseExplanation, framingInput);

  // AG-PROMPT-095: Track if default frame was applied (no specific context)
  if (framedExplanation.frameId === 'FRAME_GENERAL_SENSITIVE' && !documentClass && !singleStrongAwareness) {
    reasonCodes.push('FRAMES_DEFAULT_APPLIED');
  }

  // AG-PROMPT-095: Sort reason codes lexicographically for determinism
  reasonCodes.sort();

  // Return explanation with reason codes
  return {
    ...framedExplanation,
    reasonCodes: reasonCodes.length > 0 ? reasonCodes : undefined,
  };
}

/**
 * Build details array from driving signal IDs.
 *
 * Privacy: Never includes raw match text.
 * Determinism: Sorted by severity desc, then id asc.
 * Consistency: Signal severity cannot exceed overall severity (AG-040).
 */
function buildDetails(
  drivingSignalIds: string[],
  drivingSources?: string[],
  overallSeverity?: string,
  signalExplanations?: Array<{
    id?: string;
    severity?: string;
    source?: string;
  }>
): DecisionDetail[] {
  if (!drivingSignalIds || drivingSignalIds.length === 0) {
    return [];
  }

  // Create lookup map from signal explanations if available
  const explanationMap = new Map<string, { severity?: string; source?: string }>();
  if (signalExplanations) {
    for (const exp of signalExplanations) {
      if (exp.id) {
        explanationMap.set(exp.id, { severity: exp.severity, source: exp.source });
      }
    }
  }

  // Default source if only one driving source
  const defaultSource = drivingSources?.length === 1 ? drivingSources[0] : undefined;

  // AG-040: Consistency Contract - create driving signal set
  const drivingSet = new Set(drivingSignalIds);

  // Build detail objects with consistency enforcement
  const details: DecisionDetail[] = drivingSignalIds.map((id) => {
    const explanation = explanationMap.get(id);
    let signalSeverity = explanation?.severity ?? overallSeverity ?? 'unknown';

    // AG-040: Enforce consistency - signal severity cannot exceed overall severity
    // Only driving signals can show severity equal to overall; non-driving must be lower
    if (overallSeverity && drivingSet.has(id)) {
      // Driving signal: can show its severity up to overall
      signalSeverity = capSeverity(signalSeverity, overallSeverity);
    } else if (overallSeverity) {
      // Non-driving: cap at overall severity
      signalSeverity = capSeverity(signalSeverity, overallSeverity);
    }

    return {
      id,
      label: getSignalLabel(id),
      severity: signalSeverity,
      source: explanation?.source ?? defaultSource,
    };
  });

  // Sort: severity desc, then id asc (deterministic)
  details.sort((a, b) => {
    const severityCmp = compareSeverityDesc(a.severity, b.severity);
    if (severityCmp !== 0) return severityCmp;
    return a.id.localeCompare(b.id);
  });

  // Enforce MAX_SIGNAL_DETAILS cap (AG-PROMPT-037)
  // Take only the top N most severe signals
  const cappedDetails = details.slice(0, DECISION_CAPS.MAX_SIGNAL_DETAILS);

  // Enforce label length cap (AG-PROMPT-037)
  return cappedDetails.map((detail) => ({
    ...detail,
    label: truncateLabel(detail.label, DECISION_CAPS.SIGNAL_DETAIL_MAX_CHARS),
  }));
}

/**
 * Cap a severity to not exceed a maximum (AG-040 consistency).
 */
function capSeverity(severity: string, maxSeverity: string): string {
  if (rankSeverityOrNone(severity) > rankSeverityOrNone(maxSeverity)) {
    return maxSeverity;
  }
  return severity;
}

/**
 * Truncate a label to max length, adding ellipsis if needed.
 * Used for enforcing disclosure caps at build time.
 */
function truncateLabel(text: string, maxLength: number): string {
  if (!text || text.length <= maxLength) {
    return text;
  }
  // Leave room for ellipsis
  const truncateAt = maxLength - 3;
  if (truncateAt <= 0) {
    return text.slice(0, maxLength);
  }
  return text.slice(0, truncateAt) + '...';
}

// ============================================================================
// DISCLOSURE RULES ENGINE (AG-PROMPT-037)
// ============================================================================

/**
 * Derive disclosure level from severity.
 *
 * Rules (mandatory, no exceptions):
 * - CRITICAL → MINIMAL (fastest decision path for highest risk)
 * - HIGH     → STANDARD
 * - MEDIUM   → STANDARD
 * - LOW      → MINIMAL (low risk = minimal friction)
 * - NONE     → MINIMAL
 *
 * Rationale:
 * Higher risk requires faster decisions, not more text.
 * CRITICAL situations need immediate action, not reading.
 *
 * @param severity - Overall severity from DecisionExplanation
 * @returns DisclosureLevel determining information density
 */
export function deriveDisclosureLevel(severity: string): DisclosureLevel {
  switch (severity) {
    case 'critical':
      // CRITICAL: User needs to act fast, minimize cognitive load
      return DisclosureLevels.MINIMAL;

    case 'high':
    case 'medium':
      // HIGH/MEDIUM: Standard disclosure with full context
      return DisclosureLevels.STANDARD;

    case 'low':
    case 'none':
    default:
      // LOW/NONE: Minimal friction, quick acknowledgment
      return DisclosureLevels.MINIMAL;
  }
}

/**
 * Derive disclosure level from a DecisionExplanation object.
 *
 * Convenience wrapper that extracts severity from the explanation.
 */
export function deriveDisclosureLevelFromExplanation(
  explanation: DecisionExplanation
): DisclosureLevel {
  return deriveDisclosureLevel(explanation.severity);
}

/**
 * Get visibility rules for a disclosure level.
 *
 * @param level - The disclosure level
 * @returns DisclosureVisibility defining what may be shown
 */
export function getDisclosureVisibility(level: DisclosureLevel): DisclosureVisibility {
  switch (level) {
    case 'minimal':
      return {
        showHeadline: true,
        showSummary: false,
        showAction: true,
        allowDetails: false,
        maxDetails: 0,
      };

    case 'standard':
    case 'expanded':
    default:
      return {
        showHeadline: true,
        showSummary: true,
        showAction: true,
        allowDetails: true,
        maxDetails: DISCLOSURE_CAPS.MAX_SIGNAL_DETAILS,
      };
  }
}

// ============================================================================
// CAP ENFORCEMENT
// ============================================================================

/**
 * Truncate a string to a maximum length, adding ellipsis if needed.
 *
 * @param text - The text to truncate
 * @param maxLength - Maximum length (including ellipsis)
 * @returns Truncated text, safe and deterministic
 */
export function truncateText(text: string, maxLength: number): string {
  if (!text || text.length <= maxLength) {
    return text;
  }
  // Leave room for ellipsis
  const truncateAt = maxLength - 3;
  if (truncateAt <= 0) {
    return text.slice(0, maxLength);
  }
  // Try to truncate at word boundary
  const truncated = text.slice(0, truncateAt);
  const lastSpace = truncated.lastIndexOf(' ');
  if (lastSpace > truncateAt * 0.5) {
    return truncated.slice(0, lastSpace) + '...';
  }
  return truncated + '...';
}

/**
 * Enforce headline cap.
 *
 * @param headline - The headline text
 * @returns Headline within cap, truncated if necessary
 */
export function enforceHeadlineCap(headline: string): string {
  return truncateText(headline, DISCLOSURE_CAPS.HEADLINE_MAX_CHARS);
}

/**
 * Enforce summary cap.
 *
 * @param summary - The summary text
 * @returns Summary within cap, truncated if necessary
 */
export function enforceSummaryCap(summary: string): string {
  return truncateText(summary, DISCLOSURE_CAPS.SUMMARY_MAX_CHARS);
}

/**
 * Enforce signal details cap.
 *
 * Limits number of details and truncates individual descriptions.
 *
 * @param details - Array of signal details
 * @returns Capped array of details, each with truncated label
 */
export function enforceDetailsCap(
  details: DecisionDetail[] | undefined
): DecisionDetail[] | undefined {
  if (!details || details.length === 0) {
    return details;
  }

  // Limit number of details
  const capped = details.slice(0, DISCLOSURE_CAPS.MAX_SIGNAL_DETAILS);

  // Truncate individual labels if needed
  return capped.map((detail) => ({
    ...detail,
    label: truncateText(detail.label, DISCLOSURE_CAPS.SIGNAL_DETAIL_MAX_CHARS),
  }));
}

/**
 * Enforce all disclosure caps on a DecisionExplanation.
 *
 * This is safe to call multiple times (idempotent).
 * Never throws, always returns valid data.
 *
 * @param explanation - The explanation to cap
 * @returns New explanation with all caps enforced
 */
export function enforceDisclosureCaps(
  explanation: DecisionExplanation
): DecisionExplanation {
  return {
    ...explanation,
    headline: enforceHeadlineCap(explanation.headline),
    summary: enforceSummaryCap(explanation.summary),
    details: enforceDetailsCap(explanation.details),
  };
}

/**
 * Apply progressive disclosure rules to a DecisionExplanation.
 *
 * This is the main entry point for the disclosure system.
 * Returns a complete DisclosureResult ready for UI consumption.
 *
 * @param explanation - The raw DecisionExplanation
 * @returns DisclosureResult with level, visibility, and capped explanation
 *
 * @example
 * const result = applyProgressiveDisclosure(decisionExplanation);
 * if (result.visibility.allowDetails) {
 *   // Render details
 * }
 */
export function applyProgressiveDisclosure(
  explanation: DecisionExplanation
): DisclosureResult {
  const level = deriveDisclosureLevel(explanation.severity);
  const visibility = getDisclosureVisibility(level);
  const cappedExplanation = enforceDisclosureCaps(explanation);

  // If details not allowed at this level, remove them
  const finalExplanation: DecisionExplanation = visibility.allowDetails
    ? cappedExplanation
    : { ...cappedExplanation, details: undefined };

  return {
    level,
    visibility,
    explanation: finalExplanation,
  };
}

// ============================================================================
// VALIDATION HELPERS
// ============================================================================

/**
 * Check if a headline is within cap.
 */
export function isHeadlineWithinCap(headline: string): boolean {
  return headline.length <= DISCLOSURE_CAPS.HEADLINE_MAX_CHARS;
}

/**
 * Check if a summary is within cap.
 */
export function isSummaryWithinCap(summary: string): boolean {
  return summary.length <= DISCLOSURE_CAPS.SUMMARY_MAX_CHARS;
}

/**
 * Check if details are within cap.
 */
export function areDetailsWithinCap(details: DecisionDetail[] | undefined): boolean {
  if (!details) return true;
  if (details.length > DISCLOSURE_CAPS.MAX_SIGNAL_DETAILS) return false;
  return details.every(
    (d) => d.label.length <= DISCLOSURE_CAPS.SIGNAL_DETAIL_MAX_CHARS
  );
}

/**
 * Validate that a DecisionExplanation meets all disclosure caps.
 */
export function validateDisclosureCaps(explanation: DecisionExplanation): {
  valid: boolean;
  violations: string[];
} {
  const violations: string[] = [];

  if (!isHeadlineWithinCap(explanation.headline)) {
    violations.push(
      `Headline exceeds ${DISCLOSURE_CAPS.HEADLINE_MAX_CHARS} chars (${explanation.headline.length})`
    );
  }

  if (!isSummaryWithinCap(explanation.summary)) {
    violations.push(
      `Summary exceeds ${DISCLOSURE_CAPS.SUMMARY_MAX_CHARS} chars (${explanation.summary.length})`
    );
  }

  if (!areDetailsWithinCap(explanation.details)) {
    if (explanation.details && explanation.details.length > DISCLOSURE_CAPS.MAX_SIGNAL_DETAILS) {
      violations.push(
        `Details exceed ${DISCLOSURE_CAPS.MAX_SIGNAL_DETAILS} items (${explanation.details.length})`
      );
    }
    explanation.details?.forEach((d, i) => {
      if (d.label.length > DISCLOSURE_CAPS.SIGNAL_DETAIL_MAX_CHARS) {
        violations.push(
          `Detail[${i}] label exceeds ${DISCLOSURE_CAPS.SIGNAL_DETAIL_MAX_CHARS} chars (${d.label.length})`
        );
      }
    });
  }

  return {
    valid: violations.length === 0,
    violations,
  };
}

// ============================================================================
// EXPORTS
// ============================================================================

export { getSignalLabel, determineAction, getHeadline, getSummary };
