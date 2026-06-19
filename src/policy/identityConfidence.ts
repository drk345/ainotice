/**
 * AG-PROMPT-DOCUMENT-IDENTITY-THRESHOLDS-026: Identity Confidence Gating
 *
 * Separates domain evidence (terminology/patterns) from document identity claims.
 * Identity claims ("Medical record", "Legal document") require corroboration.
 *
 * Identity Confidence Levels:
 * - strong: documentClass confirmed OR 2+ corroborating identity signals across families
 * - weak: domain terminology signal(s) present without corroboration
 * - none: no domain evidence
 *
 * This prevents single-signal identity overreach, e.g.:
 * - Single "diagnosis" keyword → "Medical terminology" (NOT "Medical record")
 * - Single "contract" keyword → "Contract terminology" (NOT "Legal document")
 *
 * @see AG-PROMPT-SIGNAL-SEMANTICS-HUMILITY-023 (evidence-log semantic)
 * @see AG-PROMPT-SIGNAL-SEVERITY-LADDER-025 (severity caps)
 */

import type { DocumentClass } from './documentClassAnchors';
import {
  SIG_ICD10_CODE, SIG_MEDICAL_CONTENT, SIG_NATIONAL_ID, SIG_DK_CPR,
  SIG_LEGACY_DK_CPR, SIG_LEGACY_SE_PERSONNUMMER, SIG_LEGACY_NO_FNR,
  SIG_LEGACY_FI_HETU, SIG_HR_EMPLOYEE, SIG_NORDIC_PAYROLL,  // AG-PHASE-5D-057
} from '../detection/signalManifest';

// ============================================================================
// TYPES
// ============================================================================

/**
 * Identity confidence level.
 * - strong: Identity claim is corroborated (documentClass OR multiple signals)
 * - weak: Domain terminology present but not corroborated
 * - none: No domain evidence
 */
export type IdentityConfidence = 'none' | 'weak' | 'strong';

/**
 * Domain family for signal grouping.
 */
export type DomainFamily = 'medical' | 'legal' | 'hr' | 'financial' | 'other';

/**
 * Input for identity confidence derivation.
 */
export interface IdentityConfidenceInput {
  documentClass: DocumentClass | null;
  drivingSignalIds: string[];
  /** Optional: signals grouped by family for corroboration check */
  signalsByFamily?: Record<DomainFamily, string[]>;
}

/**
 * Result of identity confidence derivation.
 */
export interface IdentityConfidenceResult {
  confidence: IdentityConfidence;
  domain: DomainFamily | null;
  ruleId: string;
  reason: string;
  /** Signals that contributed to the confidence */
  corroboratingSignals: string[];
}

// ============================================================================
// RULE IDS (stable for audit trail)
// ============================================================================

export const IDENTITY_CONFIDENCE_RULE_IDS = {
  /** DocumentClass confirmed → strong */
  DOC_CLASS_CONFIRMED: 'IC-001-doc-class-confirmed',
  /** Multiple corroborating signals → strong */
  CORROBORATED: 'IC-002-corroborated',
  /** Single domain signal → weak */
  SINGLE_SIGNAL_WEAK: 'IC-003-single-signal-weak',
  /** No domain signals → none */
  NO_DOMAIN_SIGNALS: 'IC-004-no-domain-signals',
  /** Multiple families → strong (composite) */
  MULTI_FAMILY_STRONG: 'IC-005-multi-family-strong',
} as const;

// ============================================================================
// SIGNAL FAMILY CLASSIFICATION
// ============================================================================

/**
 * Medical domain signals and corroborating patterns.
 */
const MEDICAL_DOMAIN = {
  /** Primary signals that indicate medical domain */
  primary: new Set([
    'hr-medical',
    SIG_ICD10_CODE,
    SIG_MEDICAL_CONTENT,
    'COA-001-icd-standalone',
    'COA-002-unit-cluster',
    'COA-003-unit-range-proximity',
  ]),

  /** Corroborating signals that strengthen medical identity */
  corroborating: new Set([
    SIG_NATIONAL_ID,
    SIG_LEGACY_DK_CPR,
    SIG_DK_CPR,
    SIG_LEGACY_SE_PERSONNUMMER,
    SIG_LEGACY_NO_FNR,
    SIG_LEGACY_FI_HETU,
    'pii.ssn_us',
    'pii.national_id',
    'pii.name',
  ]),
};

/**
 * Legal domain signals and corroborating patterns.
 */
const LEGAL_DOMAIN = {
  /** Primary signals that indicate legal domain */
  primary: new Set([
    'legal.contract',
    'legal.nda',
    'legal.agreement',
    'legal.privileged',
    'dictionary.legal',
  ]),

  /** Corroborating signals that strengthen legal identity */
  corroborating: new Set([
    'structure.clause_numbering',
    'structure.signature_block',
    'structure.party_pattern',
    'structure.esignature',
    'pii.name',
  ]),
};

/**
 * HR domain signals and corroborating patterns.
 */
const HR_DOMAIN = {
  /** Primary signals that indicate HR domain */
  primary: new Set([
    'hr.employee_data',
    'hr-employee',
    SIG_HR_EMPLOYEE,
    'pii.employee',
    'dictionary.hr',
    SIG_NORDIC_PAYROLL,  // AG-PHASE-5D-057: Nordic payroll
  ]),

  /** Corroborating signals that strengthen HR identity */
  corroborating: new Set([
    SIG_NATIONAL_ID,
    'pii.compensation',
    'hr-compensation',
    'pii.ssn_us',
    'pii.national_id',
    'pii.name',
    'financial.banking',
  ]),
};

/**
 * Financial domain signals.
 */
const FINANCIAL_DOMAIN = {
  primary: new Set([
    'financial.iban',
    'financial.credit_card',
    'pii.credit_card',
    'financial.banking',
    'dictionary.finance',
  ]),
  corroborating: new Set([
    SIG_NATIONAL_ID,
    'pii.name',
    'pii.ssn_us',
  ]),
};

// ============================================================================
// DOMAIN FAMILY CLASSIFICATION
// ============================================================================

/**
 * Classify a signal into a domain family.
 */
export function classifySignalFamily(signalId: string): DomainFamily {
  const lower = signalId.toLowerCase();

  // Medical domain
  if (MEDICAL_DOMAIN.primary.has(signalId) ||
      lower.includes('medical') ||
      lower.includes('icd') ||
      lower.includes('coa-') ||
      lower.includes('clinical') ||
      lower.includes('health') ||
      lower.includes('patient')) {
    return 'medical';
  }

  // Legal domain
  if (LEGAL_DOMAIN.primary.has(signalId) ||
      lower.includes('legal') ||
      lower.includes('contract') ||
      lower.includes('nda') ||
      lower.includes('agreement')) {
    return 'legal';
  }

  // HR domain
  if (HR_DOMAIN.primary.has(signalId) ||
      lower.includes('hr-') ||
      lower.includes('employee') ||
      lower.includes('payroll') ||
      lower.includes('compensation')) {
    return 'hr';
  }

  // Financial domain
  if (FINANCIAL_DOMAIN.primary.has(signalId) ||
      lower.includes('financial') ||
      lower.includes('banking') ||
      lower.includes('iban') ||
      lower.includes('credit_card')) {
    return 'financial';
  }

  return 'other';
}

/**
 * Group signals by domain family.
 */
export function groupSignalsByFamily(signalIds: string[]): Record<DomainFamily, string[]> {
  const result: Record<DomainFamily, string[]> = {
    medical: [],
    legal: [],
    hr: [],
    financial: [],
    other: [],
  };

  for (const signalId of signalIds) {
    const family = classifySignalFamily(signalId);
    result[family].push(signalId);
  }

  return result;
}

// ============================================================================
// CORROBORATION LOGIC
// ============================================================================

/**
 * Check if medical domain signals are corroborated.
 * Requires: primary signal + corroborating signal (patient identifier)
 */
function isMedicalCorroborated(signalIds: string[]): { corroborated: boolean; signals: string[] } {
  const hasPrimary = signalIds.some(id => MEDICAL_DOMAIN.primary.has(id));
  const corroborating = signalIds.filter(id => MEDICAL_DOMAIN.corroborating.has(id));

  // Need primary + at least one corroborating signal
  if (hasPrimary && corroborating.length > 0) {
    return { corroborated: true, signals: corroborating };
  }

  // Alternative: 2+ primary signals (strong structural evidence)
  const primarySignals = signalIds.filter(id => MEDICAL_DOMAIN.primary.has(id));
  if (primarySignals.length >= 2) {
    return { corroborated: true, signals: primarySignals };
  }

  return { corroborated: false, signals: [] };
}

/**
 * Check if legal domain signals are corroborated.
 * Requires: primary signal + structural corroboration
 */
function isLegalCorroborated(signalIds: string[]): { corroborated: boolean; signals: string[] } {
  const hasPrimary = signalIds.some(id => LEGAL_DOMAIN.primary.has(id));
  const corroborating = signalIds.filter(id => LEGAL_DOMAIN.corroborating.has(id));

  if (hasPrimary && corroborating.length > 0) {
    return { corroborated: true, signals: corroborating };
  }

  // Alternative: 2+ primary legal signals
  const primarySignals = signalIds.filter(id => LEGAL_DOMAIN.primary.has(id));
  if (primarySignals.length >= 2) {
    return { corroborated: true, signals: primarySignals };
  }

  return { corroborated: false, signals: [] };
}

/**
 * Check if HR domain signals are corroborated.
 * Requires: primary signal + compensation/ID signals
 */
function isHrCorroborated(signalIds: string[]): { corroborated: boolean; signals: string[] } {
  const hasPrimary = signalIds.some(id => HR_DOMAIN.primary.has(id));
  const corroborating = signalIds.filter(id => HR_DOMAIN.corroborating.has(id));

  if (hasPrimary && corroborating.length > 0) {
    return { corroborated: true, signals: corroborating };
  }

  // Alternative: 2+ primary HR signals
  const primarySignals = signalIds.filter(id => HR_DOMAIN.primary.has(id));
  if (primarySignals.length >= 2) {
    return { corroborated: true, signals: primarySignals };
  }

  return { corroborated: false, signals: [] };
}

// ============================================================================
// MAIN DERIVATION FUNCTION
// ============================================================================

/**
 * Derive identity confidence from document class and signals.
 *
 * Rules (priority order):
 * 1. documentClass confirmed → strong (identity allowed)
 * 2. Multiple corroborating signals across families → strong
 * 3. Single domain signal without corroboration → weak (terminology only)
 * 4. No domain signals → none
 */
export function deriveIdentityConfidence(input: IdentityConfidenceInput): IdentityConfidenceResult {
  const { documentClass, drivingSignalIds } = input;

  // Rule 1: DocumentClass confirmed → strong
  if (documentClass !== null) {
    const domain = documentClassToDomain(documentClass);
    return {
      confidence: 'strong',
      domain,
      ruleId: IDENTITY_CONFIDENCE_RULE_IDS.DOC_CLASS_CONFIRMED,
      reason: `DocumentClass ${documentClass} confirmed`,
      corroboratingSignals: [],
    };
  }

  // Group signals by family
  const byFamily = input.signalsByFamily ?? groupSignalsByFamily(drivingSignalIds);

  // Rule 2: Check for corroborated domain signals
  // Medical corroboration
  if (byFamily.medical.length > 0) {
    const medCorr = isMedicalCorroborated(drivingSignalIds);
    if (medCorr.corroborated) {
      return {
        confidence: 'strong',
        domain: 'medical',
        ruleId: IDENTITY_CONFIDENCE_RULE_IDS.CORROBORATED,
        reason: 'Medical signals corroborated with patient identifiers',
        corroboratingSignals: medCorr.signals,
      };
    }
  }

  // Legal corroboration
  if (byFamily.legal.length > 0) {
    const legalCorr = isLegalCorroborated(drivingSignalIds);
    if (legalCorr.corroborated) {
      return {
        confidence: 'strong',
        domain: 'legal',
        ruleId: IDENTITY_CONFIDENCE_RULE_IDS.CORROBORATED,
        reason: 'Legal signals corroborated with structural patterns',
        corroboratingSignals: legalCorr.signals,
      };
    }
  }

  // HR corroboration
  if (byFamily.hr.length > 0) {
    const hrCorr = isHrCorroborated(drivingSignalIds);
    if (hrCorr.corroborated) {
      return {
        confidence: 'strong',
        domain: 'hr',
        ruleId: IDENTITY_CONFIDENCE_RULE_IDS.CORROBORATED,
        reason: 'HR signals corroborated with compensation/ID data',
        corroboratingSignals: hrCorr.signals,
      };
    }
  }

  // Rule 3: Multiple domain families present → strong (composite)
  const activeFamilies = Object.entries(byFamily)
    .filter(([family, signals]) => family !== 'other' && signals.length > 0)
    .map(([family]) => family);

  if (activeFamilies.length >= 2) {
    return {
      confidence: 'strong',
      domain: null, // Multiple domains
      ruleId: IDENTITY_CONFIDENCE_RULE_IDS.MULTI_FAMILY_STRONG,
      reason: `Multiple domain families present: ${activeFamilies.join(', ')}`,
      corroboratingSignals: [],
    };
  }

  // Rule 4: Single domain signal without corroboration → weak
  const hasDomainSignal = byFamily.medical.length > 0 ||
                          byFamily.legal.length > 0 ||
                          byFamily.hr.length > 0;

  if (hasDomainSignal) {
    const domain = byFamily.medical.length > 0 ? 'medical' :
                   byFamily.legal.length > 0 ? 'legal' :
                   byFamily.hr.length > 0 ? 'hr' : 'other';
    return {
      confidence: 'weak',
      domain,
      ruleId: IDENTITY_CONFIDENCE_RULE_IDS.SINGLE_SIGNAL_WEAK,
      reason: `${domain} terminology present without corroboration`,
      corroboratingSignals: [],
    };
  }

  // Rule 5: No domain signals → none
  return {
    confidence: 'none',
    domain: null,
    ruleId: IDENTITY_CONFIDENCE_RULE_IDS.NO_DOMAIN_SIGNALS,
    reason: 'No domain-specific signals detected',
    corroboratingSignals: [],
  };
}

/**
 * Map documentClass to domain family.
 */
function documentClassToDomain(documentClass: DocumentClass): DomainFamily {
  switch (documentClass) {
    case 'doc.medical_record':
      return 'medical';
    case 'doc.legal_contract':
      return 'legal';
    case 'doc.hr_record':
    case 'doc.payroll':
      return 'hr';
    case 'doc.insurance_policy':
      return 'financial';
    default:
      return 'other';
  }
}

// ============================================================================
// LABEL GATING
// ============================================================================

/**
 * Identity-assertive labels that require strong confidence.
 * Maps signal ID patterns → identity label → terminology fallback.
 */
const IDENTITY_LABELS: Record<string, { identity: string; terminology: string }> = {
  // Medical domain
  'hr-medical': { identity: 'Medical record', terminology: 'Medical terminology' },
  [SIG_MEDICAL_CONTENT]: { identity: 'Medical record', terminology: 'Medical terminology' },
  'COA-001-icd-standalone': { identity: 'Medical record', terminology: 'Clinical codes' },
  'COA-002-unit-cluster': { identity: 'Medical record', terminology: 'Clinical measurements' },
  'COA-003-unit-range-proximity': { identity: 'Medical record', terminology: 'Clinical data' },

  // Legal domain
  'legal.contract': { identity: 'Legal document', terminology: 'Contract terminology' },
  'legal.nda': { identity: 'Legal document', terminology: 'NDA terminology' },
  'legal.agreement': { identity: 'Legal document', terminology: 'Agreement terminology' },
  'legal.privileged': { identity: 'Legal document', terminology: 'Legal terminology' },

  // HR domain
  'hr.employee_data': { identity: 'HR record', terminology: 'HR/Employee patterns' },
  'hr-employee': { identity: 'HR record', terminology: 'HR terminology' },
  'pii.employee': { identity: 'HR record', terminology: 'Employee data patterns' },
};

/**
 * Check if a signal ID is identity-assertive.
 */
export function isIdentitySignal(signalId: string): boolean {
  return signalId in IDENTITY_LABELS;
}

/**
 * Get the appropriate label for a signal based on identity confidence.
 *
 * - strong: Identity label allowed ("Medical record")
 * - weak/none: Terminology label ("Medical terminology")
 *
 * @param signalId - The signal ID
 * @param identityConfidence - Current identity confidence level
 * @param documentClass - Current document classification
 * @returns Appropriate label for the signal
 */
export function getIdentityGatedLabel(
  signalId: string,
  identityConfidence: IdentityConfidence,
  documentClass: DocumentClass | null
): string | null {
  const labelConfig = IDENTITY_LABELS[signalId];
  if (!labelConfig) {
    return null; // Not an identity signal, use default label
  }

  // Strong confidence OR documentClass set → identity label allowed
  if (identityConfidence === 'strong' || documentClass !== null) {
    return labelConfig.identity;
  }

  // Weak or none → terminology label
  return labelConfig.terminology;
}

/**
 * Check if identity label is allowed for a domain.
 */
export function isIdentityAllowed(
  domain: DomainFamily,
  identityConfidence: IdentityConfidence,
  documentClass: DocumentClass | null
): boolean {
  // DocumentClass confirmed → always allowed
  if (documentClass !== null) {
    return true;
  }

  // Strong confidence → allowed
  if (identityConfidence === 'strong') {
    return true;
  }

  // Weak or none → not allowed
  return false;
}

// ============================================================================
// EXPORTS
// ============================================================================

export {
  MEDICAL_DOMAIN,
  LEGAL_DOMAIN,
  HR_DOMAIN,
  FINANCIAL_DOMAIN,
  IDENTITY_LABELS,
};
