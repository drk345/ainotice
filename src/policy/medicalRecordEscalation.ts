/**
 * AgentGuard Medical Record Awareness Escalation (AG-PROMPT-070)
 *
 * Ensures that patient-identifiable medical content NEVER resolves to:
 * - severity: none/low
 * - uiEscalation: 'inline'
 * - copy fallback: "No risk detected"
 *
 * Medical records with patient context require elevated awareness aligned
 * with regulatory reality (GDPR/HIPAA for health data).
 *
 * Rules (MANDATORY, NO EXCEPTIONS):
 * 1. doc.medical_record + hasPatientContext → severity >= HIGH
 * 2. doc.medical_record + hasPatientContext → uiEscalation = 'modal'
 * 3. At least one visible awareness signal must survive calibration
 *
 * This enforcement overrides:
 * - Calibration suppression
 * - Dedup side-effects
 * - Single-signal down-ranking
 *
 * @see AG-PROMPT-070: Medical Record Awareness Escalation
 */

import type { DocumentClass } from './documentClassAnchors';
import type { DecisionExplanation } from './decisionExplanation';
import type { RiskSignal } from '../types/riskSignal';
import { rankSeverityOrNone } from './severityRank';

// ============================================================================
// TYPES
// ============================================================================

/**
 * Rule IDs for medical record escalation audit trail.
 */
export const MEDICAL_ESCALATION_RULE_IDS = {
  /** Severity floor enforced for medical record with patient context */
  SEVERITY_FLOOR: 'MRE-001-severity-floor',
  /** UI escalation forced to modal for medical record with patient context */
  ESCALATION_MODAL: 'MRE-002-escalation-modal',
  /** Awareness signal rescued from suppression */
  AWARENESS_RESCUED: 'MRE-003-awareness-rescued',
  /** Medical record detected without patient context - no escalation */
  NO_PATIENT_CONTEXT: 'MRE-010-no-patient-context',
  /** Non-medical document - no escalation needed */
  NOT_MEDICAL: 'MRE-011-not-medical',
  /** AG-PROMPT-162-AREA1: Clinical reference bypass — medical terms without co-located PII */
  CLINICAL_REFERENCE_BYPASS: 'MRE-012-clinical-reference-bypass',
} as const;

/**
 * Input for medical record escalation enforcement.
 */
export interface MedicalEscalationInput {
  /** The decision explanation to enforce */
  explanation: DecisionExplanation;

  /** Document class from classification (null if not classified) */
  documentClass: DocumentClass | null;

  /** Whether patient-level context was detected */
  hasPatientContext: boolean;

  /** Visible signals (may need awareness rescue) */
  visibleSignals: RiskSignal[];

  /**
   * AG-PROMPT-162-AREA1: Clinical reference bypass.
   * When true, skip medical escalation because the document is a clinical
   * reference (drug guide, treatment protocol, ICD code table) without
   * patient-identifying PII co-located near medical terms.
   */
  clinicalReferenceBypass?: boolean;
}

/**
 * Result of medical record escalation enforcement.
 */
export interface MedicalEscalationResult {
  /** The enforced explanation */
  explanation: DecisionExplanation;

  /** Whether escalation was applied */
  escalated: boolean;

  /** Whether severity was elevated */
  severityElevated: boolean;

  /** Whether uiEscalation was changed to modal */
  escalationChanged: boolean;

  /** Whether a signal was rescued for awareness */
  awarenessRescued: boolean;

  /** The rescued signal (if any) */
  rescuedSignal: RiskSignal | null;

  /** Rule ID for audit trail */
  ruleId: string;

  /** Human-readable reason */
  reason: string;
}

// ============================================================================
// SEVERITY COMPARISON
// ============================================================================

function isBelowHigh(severity: string): boolean {
  return rankSeverityOrNone(severity) < rankSeverityOrNone('high');
}

// ============================================================================
// MAIN ENFORCEMENT FUNCTION
// ============================================================================

/**
 * Enforce medical record awareness escalation rules.
 *
 * This is a POST-calibration, POST-explanation enforcement layer.
 * Call this AFTER buildDecisionExplanation and enforceDecisionConsistency.
 *
 * Rules:
 * 1. If documentClass === 'doc.medical_record' AND hasPatientContext:
 *    - severity MUST be >= 'high' (enforce floor)
 *    - uiEscalation MUST be 'modal' (never inline for medical)
 *    - At least one signal MUST be visible (rescue if suppressed)
 *
 * @param input - Medical escalation input
 * @returns MedicalEscalationResult with enforced explanation
 */
export function enforceMedicalRecordEscalation(
  input: MedicalEscalationInput
): MedicalEscalationResult {
  const { explanation, documentClass, hasPatientContext, visibleSignals, clinicalReferenceBypass } = input;

  // Not a medical document - no escalation needed
  if (documentClass !== 'doc.medical_record') {
    return {
      explanation,
      escalated: false,
      severityElevated: false,
      escalationChanged: false,
      awarenessRescued: false,
      rescuedSignal: null,
      ruleId: MEDICAL_ESCALATION_RULE_IDS.NOT_MEDICAL,
      reason: 'Document is not classified as medical record',
    };
  }

  // AG-PROMPT-162-AREA1: Clinical reference bypass
  // Skip escalation for clinical reference material (drug guides, ICD tables)
  // when no real PII is co-located near medical terms
  if (clinicalReferenceBypass) {
    return {
      explanation,
      escalated: false,
      severityElevated: false,
      escalationChanged: false,
      awarenessRescued: false,
      rescuedSignal: null,
      ruleId: MEDICAL_ESCALATION_RULE_IDS.CLINICAL_REFERENCE_BYPASS,
      reason: 'Clinical reference material without co-located patient PII - standard handling',
    };
  }

  // Medical document but no patient context - no escalation
  // (Clinical reference data without patient identifiers)
  if (!hasPatientContext) {
    return {
      explanation,
      escalated: false,
      severityElevated: false,
      escalationChanged: false,
      awarenessRescued: false,
      rescuedSignal: null,
      ruleId: MEDICAL_ESCALATION_RULE_IDS.NO_PATIENT_CONTEXT,
      reason: 'Medical document without patient context - standard handling',
    };
  }

  // -------------------------------------------------------------------------
  // MEDICAL RECORD WITH PATIENT CONTEXT - ENFORCE ESCALATION
  // -------------------------------------------------------------------------

  let enforcedExplanation = { ...explanation };
  let severityElevated = false;
  let escalationChanged = false;
  let awarenessRescued = false;
  let rescuedSignal: RiskSignal | null = null;

  // Rule 1: Severity floor >= HIGH
  if (isBelowHigh(explanation.severity)) {
    enforcedExplanation = {
      ...enforcedExplanation,
      severity: 'high',
    };
    severityElevated = true;
  }

  // Rule 2: uiEscalation MUST be 'modal' (never inline for patient data)
  if (explanation.uiEscalation !== 'modal') {
    enforcedExplanation = {
      ...enforcedExplanation,
      uiEscalation: 'modal',
    };
    escalationChanged = true;
  }

  // Rule 3: At least one visible signal for awareness
  // If all signals were suppressed, rescue the document class signal
  if (visibleSignals.length === 0) {
    // Create a minimal awareness signal for the medical record
    rescuedSignal = {
      id: 'doc.medical_record',
      type: 'sensitive',
      description: 'Medical record with patient data',
      severity: 'high',
      detail: 'This document contains patient-identifiable medical information',
      source: 'content',
      detectedAt: Date.now(),
    };
    awarenessRescued = true;
  }

  const reasons: string[] = [];
  if (severityElevated) {
    reasons.push(`severity elevated from ${explanation.severity} to high`);
  }
  if (escalationChanged) {
    reasons.push(`uiEscalation changed from ${explanation.uiEscalation} to modal`);
  }
  if (awarenessRescued) {
    reasons.push('awareness signal rescued');
  }

  return {
    explanation: enforcedExplanation,
    escalated: severityElevated || escalationChanged || awarenessRescued,
    severityElevated,
    escalationChanged,
    awarenessRescued,
    rescuedSignal,
    ruleId: MEDICAL_ESCALATION_RULE_IDS.SEVERITY_FLOOR,
    reason: `Medical record with patient context: ${reasons.join(', ') || 'already compliant'}`,
  };
}

// ============================================================================
// VALIDATION HELPERS
// ============================================================================

/**
 * Check if a medical record decision is compliant with escalation rules.
 *
 * Use this for testing and validation.
 *
 * @param explanation - The decision explanation to check
 * @param documentClass - The document class
 * @param hasPatientContext - Whether patient context is present
 * @param visibleSignalCount - Number of visible signals
 * @returns Compliance result with any violations
 */
export function validateMedicalEscalation(
  explanation: DecisionExplanation,
  documentClass: DocumentClass | null,
  hasPatientContext: boolean,
  visibleSignalCount: number
): { compliant: boolean; violations: string[] } {
  const violations: string[] = [];

  // Only validate medical records with patient context
  if (documentClass !== 'doc.medical_record' || !hasPatientContext) {
    return { compliant: true, violations: [] };
  }

  // Check severity floor
  if (isBelowHigh(explanation.severity)) {
    violations.push(
      `Severity ${explanation.severity} is below required HIGH for medical record with patient context`
    );
  }

  // Check uiEscalation
  if (explanation.uiEscalation !== 'modal') {
    violations.push(
      `uiEscalation ${explanation.uiEscalation} should be 'modal' for medical record with patient context`
    );
  }

  // Check awareness signal presence
  if (visibleSignalCount === 0) {
    violations.push(
      'No visible signals for medical record with patient context - user would see "no risk"'
    );
  }

  return {
    compliant: violations.length === 0,
    violations,
  };
}

/**
 * Quick check if medical escalation should be applied.
 *
 * @param documentClass - The document class
 * @param hasPatientContext - Whether patient context is present
 * @returns true if escalation rules apply
 */
export function requiresMedicalEscalation(
  documentClass: DocumentClass | null,
  hasPatientContext: boolean
): boolean {
  return documentClass === 'doc.medical_record' && hasPatientContext;
}
