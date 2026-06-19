import {
  SIG_HR_EMPLOYEE, SIG_BANKING_TERMS, SIG_ICD10_CODE, SIG_MEDICAL_CONTENT,
  SIG_NATIONAL_ID, SIG_LEGACY_DK_CPR, SIG_LEGACY_SE_PERSONNUMMER,
  SIG_LEGACY_NO_FNR, SIG_LEGACY_FI_HETU, SIG_CREDIT_CARD_SPACED,
  SIG_NORDIC_PAYROLL,  // AG-PHASE-5D-057: Nordic payroll
} from '../detection/signalManifest';

/**
 * AgentGuard Document Class Anchors (AG-PROMPT-041)
 *
 * Establishes baseline risk floors for inherently sensitive document classes.
 * Certain document types (payroll, HR, medical) are always sensitive regardless
 * of individual pattern matches.
 *
 * Design principles:
 * - Deterministic: Pattern-combination-based classification (no ML)
 * - Policy-layer only: Does NOT modify detection or scanning
 * - Auditor-obvious: Clear rules for document classification
 * - Composes with AG-038/039/040 (calibration, heuristics, consistency)
 *
 * Document Classes:
 * - doc.payroll: Payroll/salary documents → baseline HIGH
 * - doc.hr_record: HR/employment records → baseline HIGH
 * - doc.medical_record: Medical/health records → baseline CRITICAL
 *
 * @see AG-PROMPT-041: Document Class Anchors
 */

import type { RiskSignal, Severity, SignalSource } from '../types/riskSignal';
import { hasClinicalOntologyAnchors, CLINICAL_ONTOLOGY_RULE_IDS } from './clinicalOntologyAnchors';
import {
  detectDocumentArchetypes,
  getArchetypeEffects,
  isProtectedSignal,
  type ArchetypeMatch,
  type DocumentArchetypeId,
} from './documentArchetypes';

// ============================================================================
// TYPES
// ============================================================================

/**
 * Document class identifiers.
 * These are NOT new signals - they are inferred classifications.
 * AG-PROMPT-097C: Added doc.legal_contract for structural contract inference.
 */
export type DocumentClass = 'doc.payroll' | 'doc.hr_record' | 'doc.medical_record' | 'doc.legal_contract' | 'doc.insurance_policy' | 'doc.invoice' | 'doc.health_certificate';

/**
 * Rule ID for audit trail.
 */
export const DOCUMENT_CLASS_RULE_IDS = {
  // Classification rules
  CLASSIFY_PAYROLL: 'DCA-001-classify-payroll',
  CLASSIFY_HR_RECORD: 'DCA-002-classify-hr-record',
  CLASSIFY_MEDICAL: 'DCA-003-classify-medical',
  CLASSIFY_LEGAL_CONTRACT: 'DCA-004-classify-legal-contract',
  CLASSIFY_INSURANCE_POLICY: 'DCA-005-classify-insurance-policy',  // AG-PHASE-5C-056
  CLASSIFY_INVOICE: 'DCA-006-classify-invoice',  // AG-PROMPT-175
  CLASSIFY_HEALTH_CERTIFICATE: 'DCA-007-classify-health-certificate',  // AG-PROMPT-175

  // Baseline enforcement
  BASELINE_FLOOR: 'DCA-010-baseline-floor',
  BASELINE_ELEVATED: 'DCA-011-baseline-elevated',

  // Noise suppression
  SUPPRESS_CARD_NOISE: 'DCA-020-suppress-card-noise',
  SUPPRESS_URL_NOISE: 'DCA-021-suppress-url-noise',
  SUPPRESS_SWIFT_NOISE: 'DCA-022-suppress-swift-noise',
  SUPPRESS_TICKET_NOISE: 'DCA-023-suppress-ticket-noise',  // AG-PROMPT-5 Item 7
} as const;

/**
 * Classification result for a document.
 */
export interface DocumentClassification {
  /** Detected document class (if any) */
  documentClass: DocumentClass | null;

  /** Confidence indicators that led to classification */
  indicators: ClassificationIndicator[];

  /** Baseline severity floor for this class */
  baselineSeverity: Severity | null;

  /** Why this classification was made */
  reason: string;
}

/**
 * Single indicator contributing to classification.
 */
export interface ClassificationIndicator {
  /** Signal ID or pattern that contributed */
  signalId: string;

  /** Weight/importance of this indicator */
  weight: 'primary' | 'supporting';

  /** Category of indicator */
  category: 'keyword' | 'structure' | 'identifier' | 'context';
}

/**
 * Result of document class anchor processing.
 */
export interface DocumentClassResult {
  /** Classification result */
  classification: DocumentClassification;

  /** Signals after noise suppression */
  signals: RiskSignal[];

  /** Document class anchor signal (if classified) */
  anchorSignal: RiskSignal | null;

  /** Suppressed noisy signals */
  suppressedSignals: RiskSignal[];

  /** Audit trail */
  auditLog: DocumentClassAuditEntry[];

  /** Statistics */
  stats: DocumentClassStats;

  /**
   * AG-PROMPT-070: Whether patient-level context was detected.
   * True if the document contains patient identifiers (CPR, SSN, etc.)
   * or patient-specific keywords.
   * Used to enforce medical record awareness escalation.
   */
  hasPatientContext: boolean;

  /**
   * AG-PROMPT-SIGNAL-BYPASS-FIX-028: Identity confidence for this classification.
   * Determines whether identity-asserting labels ("Medical record") or
   * terminology labels ("Medical terminology") are used.
   * Also gates baseline severity in decisionAuthority and frame selection.
   */
  identityConfidence: IdentityConfidence;

  /**
   * AG-ARCHETYPE-073: Detected document archetypes.
   * Provides supplementary classification evidence for framing.
   * Archetypes are evidence only and do NOT suppress identity/PII signals.
   */
  archetypeMatches?: ArchetypeMatch[];
}

/**
 * Audit entry for document class processing.
 */
export interface DocumentClassAuditEntry {
  ruleId: string;
  action: 'classified' | 'floor_applied' | 'noise_suppressed' | 'elevated' | 'class_suppressed';
  details: string;
  affectedSignalIds?: string[];
}

/**
 * Statistics from document class processing.
 */
export interface DocumentClassStats {
  inputSignalCount: number;
  outputSignalCount: number;
  noiseSuppressed: number;
  classDetected: boolean;
  baselineApplied: boolean;
}

// ============================================================================
// CONFIGURATION
// ============================================================================

/**
 * Baseline severity floors for each document class.
 * Final decision severity can NEVER be lower than this.
 * AG-PROMPT-097C: Legal contracts baseline to medium (PII awareness, not blocking).
 */
export const DOCUMENT_CLASS_BASELINES: Record<DocumentClass, Severity> = {
  'doc.payroll': 'high',
  'doc.hr_record': 'high',
  'doc.medical_record': 'critical',
  'doc.legal_contract': 'medium',
  'doc.insurance_policy': 'high',  // AG-PHASE-5C-056: Insurance policies contain PII, financial terms
  'doc.invoice': 'low',  // AG-PROMPT-175: Invoices are low-risk unless PII/IBAN escalates
  'doc.health_certificate': 'high',  // AG-PROMPT-175: Health certificates contain patient identifiers
};

/**
 * Human-readable labels for document classes.
 */
export const DOCUMENT_CLASS_LABELS: Record<DocumentClass, string> = {
  'doc.payroll': 'Payroll document',
  'doc.hr_record': 'HR/Employment record',
  'doc.medical_record': 'Medical record',
  'doc.legal_contract': 'Legal/Contract document',
  'doc.insurance_policy': 'Insurance policy',  // AG-PHASE-5C-056
  'doc.invoice': 'Invoice/Receipt',  // AG-PROMPT-175
  'doc.health_certificate': 'Health certificate',  // AG-PROMPT-175
};

/**
 * Headlines for document class decisions.
 */
export const DOCUMENT_CLASS_HEADLINES: Record<DocumentClass, string> = {
  'doc.payroll': 'This appears to be a payroll document',
  'doc.hr_record': 'This appears to be an HR record',
  'doc.medical_record': 'This appears to be a medical record',
  'doc.legal_contract': 'This appears to be a legal document',
  'doc.insurance_policy': 'This appears to be an insurance policy',  // AG-PHASE-5C-056
  'doc.invoice': 'This appears to be an invoice',  // AG-PROMPT-175
  'doc.health_certificate': 'This appears to be a health certificate',  // AG-PROMPT-175
};

/**
 * AG-PROMPT-DOCUMENT-IDENTITY-THRESHOLDS-026: Terminology-only labels.
 * Used when identityConfidence is weak (single signal without corroboration).
 * These describe domain evidence without asserting document identity.
 */
export const DOCUMENT_CLASS_TERMINOLOGY_LABELS: Record<DocumentClass, string> = {
  'doc.payroll': 'Payroll/compensation terminology',
  'doc.hr_record': 'HR/employment terminology',
  'doc.medical_record': 'Medical/clinical terminology',
  'doc.legal_contract': 'Legal/contract terminology',
  'doc.insurance_policy': 'Insurance/policy terminology',  // AG-PHASE-5C-056
  'doc.invoice': 'Invoice/receipt terminology',  // AG-PROMPT-175
  'doc.health_certificate': 'Health/vaccination terminology',  // AG-PROMPT-175
};

/**
 * AG-PROMPT-DOCUMENT-IDENTITY-THRESHOLDS-026: Terminology-only headlines.
 * Used when identityConfidence is weak (no identity assertion).
 */
export const DOCUMENT_CLASS_TERMINOLOGY_HEADLINES: Record<DocumentClass, string> = {
  'doc.payroll': 'Payroll-related patterns were detected',
  'doc.hr_record': 'HR-related patterns were detected',
  'doc.medical_record': 'Medical-related patterns were detected',
  'doc.legal_contract': 'Legal/contract patterns were detected',
  'doc.insurance_policy': 'Insurance-related patterns were detected',  // AG-PHASE-5C-056
  'doc.invoice': 'Invoice-related patterns were detected',  // AG-PROMPT-175
  'doc.health_certificate': 'Health certificate patterns were detected',  // AG-PROMPT-175
};

// ============================================================================
// SIGNAL PATTERNS FOR CLASSIFICATION
// ============================================================================

/**
 * Signal IDs and keywords that indicate payroll documents.
 */
const PAYROLL_INDICATORS = {
  /** Primary indicators (strong signal) */
  primary: new Set([
    'pii.compensation',
    'hr-compensation',
    SIG_HR_EMPLOYEE,
    SIG_NORDIC_PAYROLL,  // AG-PHASE-5D-057: Nordic payroll terms
  ]),

  /** Keywords that strongly indicate payroll */
  keywords: [
    // English
    /\bpayslip\b/i,
    /\bpay\s*stub\b/i,
    /\bpayroll\b/i,
    /\bsalary\s*(statement|slip|details)\b/i,
    /\bnet\s*pay\b/i,
    /\bgross\s*pay\b/i,
    /\bdeductions?\b/i,
    /\btax\s*(withheld|deducted)\b/i,
    /\bearnings?\s*statement\b/i,
    /\bemployee\s*id\b/i,
    /\bpay\s*period\b/i,
    /\bbasic\s*salary\b/i,
    /\ballowances?\b/i,
    /\bovertime\s*pay\b/i,
    // AG-PHASE-5D-057: Nordic payroll keywords
    // AG-PHASE-5E-064: Unicode-safe boundaries for non-ASCII keywords
    // Swedish
    /(?<!\p{L})lönespecifikation(?!\p{L})/iu,
    /(?<!\p{L})lönspec(?!\p{L})/iu,
    /(?<!\p{L})månadslön(?!\p{L})/iu,
    /(?<!\p{L})månlön(?!\p{L})/iu,
    /(?<!\p{L})bruttolön(?!\p{L})/iu,
    /(?<!\p{L})nettolön(?!\p{L})/iu,
    /\bskatteavdrag\b/i,
    /\ba-skatt\b/i,
    // Norwegian
    /(?<!\p{L})lønnslipp(?!\p{L})/iu,
    /(?<!\p{L})månedslønn(?!\p{L})/iu,
    /(?<!\p{L})bruttolønn(?!\p{L})/iu,
    /(?<!\p{L})nettolønn(?!\p{L})/iu,
    /\bskattetrekk\b/i,
    // Danish
    /(?<!\p{L})lønseddel(?!\p{L})/iu,
    /(?<!\p{L})månedsløn(?!\p{L})/iu,
    /(?<!\p{L})bruttoløn(?!\p{L})/iu,
    /(?<!\p{L})nettoløn(?!\p{L})/iu,
    // AG-PHASE-5E-061: Spanish/LatAm payroll keywords
    // AG-PHASE-5E-064: Unicode-safe boundaries for accented characters
    /(?<!\p{L})n[oó]mina(?!\p{L})/iu,                    // nómina/nomina
    /(?<!\p{L})liquidaci[oó]n(?:\s+de\s+sueldo)?(?!\p{L})/iu,  // liquidación/liquidacion
    /\bsalario\b/i,
    /\bsueldo\b/i,
    /(?<!\p{L})remuneraci[oó]n(?!\p{L})/iu,              // remuneración/remuneracion
    /(?<!\p{L})recibo\s+de\s+n[oó]mina(?!\p{L})/iu,      // recibo de nómina
    /\bbruto\b/i,
    /\bneto\b/i,
    /\bsalario\s+(?:bruto|neto)\b/i,
    /\bsueldo\s+(?:bruto|neto)\b/i,
  ],

  /** Supporting indicators (context) */
  supporting: new Set([
    'pii.employee',
    'pii.ssn_us',
    'pii.national_id',
    'financial.banking',
    SIG_BANKING_TERMS,
  ]),
};

/**
 * Signal IDs and keywords that indicate HR records.
 */
const HR_RECORD_INDICATORS = {
  /** Primary indicators */
  primary: new Set([
    'hr-performance',
    'hr-compensation',
    SIG_HR_EMPLOYEE,
    'hr.employee_data',
  ]),

  /** Keywords that strongly indicate HR records */
  keywords: [
    /\bemployment\s*(contract|agreement)\b/i,
    /\bjob\s*offer\b/i,
    /\bperformance\s*review\b/i,
    /\btermination\b/i,
    /\bdisciplinary\b/i,
    /\bprobation(ary)?\s*period\b/i,
    /\bonnboarding\b/i,
    /\bexit\s*interview\b/i,
    /\bbenefits?\s*enrollment\b/i,
    /\bstock\s*options?\b/i,
    /\bbonus\s*(structure|payment)\b/i,
    /\bpay\s*grade\b/i,
    /\bsalary\s*band\b/i,
    /\bcompensation\s*package\b/i,
    // AG-PHASE-5E-061: Spanish/LatAm HR/employment contract keywords
    // AG-PHASE-5E-064: Unicode-safe boundaries for accented characters
    /\bcontrato\s+de\s+trabajo\b/i,
    /\bempleador\b/i,
    /\bempleado\b/i,
    /\btrabajador\b/i,
    /(?<!\p{L})relaci[oó]n\s+laboral(?!\p{L})/iu,        // relación laboral/relacion laboral
    /(?<!\p{L})cl[aá]usulas?(?!\p{L})/iu,                // cláusula(s)/clausula(s)
    /\bfecha\s+de\s+inicio\b/i,
    /(?<!\p{L})duraci[oó]n(?:\s+del\s+contrato)?(?!\p{L})/iu,  // duración/duracion
    /\bdespido\b/i,
    /\brenuncia\b/i,
    /\bpuesto\s+de\s+trabajo\b/i,
    /\bjornada\s+laboral\b/i,
  ],

  /** Supporting indicators */
  supporting: new Set([
    'pii.name',
    'pii.email',
    'pii.phone',
    'legal.agreement',
    'legal.contract',
  ]),
};

/**
 * AG-PHASE-5C-056: Signal IDs and keywords that indicate insurance policies.
 *
 * Insurance policies contain: policy numbers, coverage terms, premium amounts,
 * personal details (policyholder name, address, DOB).
 * Classified AFTER medical/payroll/HR to avoid over-capturing documents that
 * merely mention "health insurance" in an HR context.
 */
const INSURANCE_POLICY_INDICATORS = {
  /** Primary indicators (strong signal) */
  primary: new Set([
    'global-insurance-terms',
    'global-insurance-policy-number',
  ]),

  /** Keywords that indicate insurance policies */
  keywords: [
    // English insurance terms
    /\binsurance\s*polic(?:y|ies)\b/i,
    /\bpolicyholder\b/i,
    /\binsured\s*(?:person|party)\b/i,
    /\bunderwriter\b/i,
    /\bpremium\s*(?:amount|payment|schedule)\b/i,
    /\bcoverage\s*(?:period|amount|limit|type)\b/i,
    /\bdeductible\b/i,
    /\bclaim\s*(?:number|form|process)\b/i,
    /\bbenefit\s*(?:schedule|summary)\b/i,
    // Danish/Nordic insurance terms
    // AG-PHASE-5E-064: Unicode-safe boundaries for non-ASCII keywords
    /(?<!\p{L})forsikring(?:spolice|sbetingelser|sdækning)(?!\p{L})/iu,
    /\bselvrisiko\b/i,
    /(?<!\p{L})dæknings?oversigt(?!\p{L})/iu,
    /\bpolicenummer\b/i,
    /\bforsikringstager\b/i,
    /\bskadebehandling\b/i,
    // AG-PHASE-5E-061: Spanish/LatAm insurance keywords
    // AG-PHASE-5E-064: Unicode-safe boundaries for accented characters
    /(?<!\p{L})p[oó]liza(?:\s+de\s+seguro)?(?!\p{L})/iu,  // póliza/poliza
    /\basegurado\b/i,
    /\baseguradora\b/i,
    /\bcobertura\b/i,
    /\bprima(?:\s+de\s+seguro)?\b/i,
    /\bsiniestro\b/i,
    /\bcondiciones\s+generales\b/i,
    /\bseguro\s+(?:de\s+)?(?:vida|auto|hogar|salud|viaje)\b/i,
    /(?<!\p{L})n[uú]mero\s+de\s+p[oó]liza(?!\p{L})/iu,   // número de póliza
  ],

  /** Supporting indicators */
  supporting: new Set([
    'global-dob',
    SIG_NATIONAL_ID,
    'pii.name',
    'pii.address',
  ]),
};

/**
 * Signal IDs and keywords that indicate medical records.
 * AG-PROMPT-043: Added Nordic/Danish medical patterns and signal IDs.
 * AG-PROMPT-043: Added clinical ontology anchor signal IDs.
 * AG-PROMPT-056: Added patient context requirement for medical record classification.
 *
 * IMPORTANT: "Medical record" requires BOTH clinical anchors AND patient-level context.
 * Clinical anchors alone (ICD codes, units) without patient context do NOT qualify
 * as a medical record - they indicate regulated/sensitive data but not patient data.
 */
const MEDICAL_RECORD_INDICATORS = {
  /** Primary indicators - these strongly indicate medical documents */
  primary: new Set([
    'hr-medical',
    SIG_ICD10_CODE,             // AG-PROMPT-043: ICD-10 diagnosis codes
    SIG_MEDICAL_CONTENT,        // AG-PROMPT-043: Medical keywords
    SIG_LEGACY_DK_CPR,          // AG-PROMPT-043: Danish CPR in medical context
    // AG-PHASE-5C-056: Removed SIG_NATIONAL_ID from primary.
    // National ID corroborates medical classification (kept in supporting)
    // but should NOT be a primary indicator — it appears in employment
    // contracts, insurance policies, and other HR documents where the ID
    // belongs to an employee/policyholder, not a patient.
    // AG-PROMPT-043: Clinical ontology anchors (structural medical patterns)
    // Values must match CLINICAL_ONTOLOGY_RULE_IDS from clinicalOntologyAnchors.ts
    'COA-001-icd-standalone',   // ICD diagnostic codes
    'COA-002-unit-cluster',     // Multiple clinical units in proximity
    'COA-003-unit-range-proximity', // Clinical unit + reference range
  ]),

  /** Keywords that strongly indicate medical records */
  keywords: [
    // English medical terms
    /\bpatient\s*(id|name|record)\b/i,
    /\bdiagnosis\b/i,
    /\bmedical\s*(history|record|report)\b/i,
    /\btreatment\s*plan\b/i,
    /\bprescription\b/i,
    /\blab\s*results?\b/i,
    /\bblood\s*(test|type|pressure)\b/i,
    /\bhealth\s*(insurance|record|condition)\b/i,
    /\bhipaa\b/i,
    /\bprotected\s*health\s*information\b/i,
    /\bphi\b/i,
    /\bmedical\s*leave\b/i,
    /\bdisability\b/i,
    /\bworkers?\s*comp(ensation)?\b/i,
    /\bicd[-\s]?\d/i,
    /\bcpt\s*code\b/i,
    // AG-PROMPT-043: Danish/Nordic medical terms
    /\bpatientjournal\b/i,
    /\bsundhedsdata\b/i,
    /\bdiagnose\b/i,
    /\bbehandling\b/i,
    /\brecept\b/i,
    /\bepikrise\b/i,
    /\banamnese\b/i,
    /\bjournal\s*nr\b/i,
    /\bjournalnummer\b/i,
    /\bsygejournal\b/i,
    // AG-PHASE-5E-064: Unicode-safe boundaries for non-ASCII keywords
    /(?<!\p{L})lægejournal(?!\p{L})/iu,
    /\bhelbredsoplysninger\b/i,
    /\bsundhedsjournal\b/i,
    // Swedish medical terms
    // AG-PHASE-5E-064: Unicode-safe boundaries for non-ASCII keywords
    /\bpatientdata\b/i,
    /\bsjukjournal\b/i,
    /(?<!\p{L})vårdjournal(?!\p{L})/iu,
    /(?<!\p{L})läkarjournal(?!\p{L})/iu,
  ],

  /** Supporting indicators */
  supporting: new Set([
    SIG_NATIONAL_ID,            // AG-PROMPT-035: Unified national ID signal
    'pii.ssn_us',
    'pii.national_id',
    'pii.name',
    SIG_LEGACY_SE_PERSONNUMMER, // AG-PROMPT-043: Swedish personnummer (backward compat)
  ]),
};

/**
 * AG-PROMPT-056: Patient-level context indicators.
 *
 * These patterns indicate the document is about a SPECIFIC PATIENT,
 * not just clinical/medical content in general.
 *
 * Medical record classification requires: clinical anchors + patient context.
 * Without patient context, clinical anchors alone = "sensitive regulated data".
 */
const PATIENT_CONTEXT_INDICATORS = {
  /** Signal IDs that indicate patient-level data */
  signals: new Set([
    SIG_NATIONAL_ID,            // AG-PROMPT-035: Unified national ID signal
    SIG_LEGACY_DK_CPR,          // Danish CPR number (patient identifier)
    SIG_LEGACY_SE_PERSONNUMMER, // Swedish personnummer (patient identifier)
    SIG_LEGACY_NO_FNR,          // Norwegian fødselsnummer
    SIG_LEGACY_FI_HETU,         // Finnish henkilötunnus
    'pii.ssn_us',               // US Social Security Number
    'pii.national_id',          // National ID
    'pii.name',                 // Personal name
    'hr-medical',               // HR medical context
  ]),

  /** Keywords that indicate patient-specific context */
  keywords: [
    // Patient identity references
    /\bpatient\s*(id|name|number|nr)\b/i,
    /\bpatient\s*:\s*\w/i,
    /\bpatient\b.*\b(male|female|man|woman|child)\b/i,
    // Nordic patient references
    // AG-PROMPT-SIGNAL-PARITY-029: Removed forsikringstager (Danish: policyholder).
    // It falsely triggered patient context on insurance policy documents.
    /\bpatient\s*journal\b/i,
    /\bcpr[-\s]*nummer\b/i,       // Danish CPR reference
    /\bpersonnummer\b/i,          // Nordic personal ID reference
    // Medical record context
    /\bmedical\s*record\b/i,
    /\bhealth\s*record\b/i,
    /\bclinical\s*notes?\b/i,
    /\bdischarge\s*summary\b/i,
    /\badmission\s*(date|record)\b/i,
    // Treatment context (implies patient)
    /\btreatment\s*plan\b/i,
    /\bprescription\b/i,
    /\bmedication\s*list\b/i,
    /\bdiagnosis\s*:\s*\w/i,
    // Danish/Nordic patient context
    // AG-PHASE-5E-064: Unicode-safe boundaries for non-ASCII keywords
    /\bbehandlingsplan\b/i,       // Treatment plan
    /\bsygehistorie\b/i,          // Medical history
    /\bjournal\s*nr\b/i,          // Journal number
    /(?<!\p{L})ansvarlig\s*læge(?!\p{L})/iu,      // Responsible doctor
    /(?<!\p{L})kontrol\s*besøg(?!\p{L})/iu,       // Follow-up visit
  ],
};

/**
 * Noisy signal patterns to suppress within sensitive documents.
 */
const NOISY_PATTERNS = {
  /** Payment card patterns that may be noise (dates, IDs looking like cards) */
  cardNoise: new Set([
    SIG_CREDIT_CARD_SPACED,
    'financial.credit_card',
    'pii.credit_card',
  ]),

  /** URL/credential patterns that are noisy in HR/payroll docs */
  urlNoise: new Set([
    'secret.url_with_credentials',
    'secret.embedded_credentials',
  ]),

  /** SWIFT/BIC patterns without personal context */
  swiftNoise: new Set([
    'financial.swift',
    SIG_BANKING_TERMS,
  ]),

  /**
   * AG-PROMPT-5 Item 7: Ticket/travel document noise suppression.
   * These signals are suppressed when ticket context is detected and
   * no sensitive document class has been classified.
   */
  ticketNoise: new Set([
    'financial.banking',
    'financial.iban',
    'global-iban', // AG-DATA2-066: Include global pack IBAN signal
    SIG_BANKING_TERMS,
    'financial.swift',
    'global-swift',
  ]),
};

/**
 * AG-PROMPT-5 Item 7: Ticket/travel document context markers.
 * When these keywords are present and no sensitive document class is detected,
 * suppress banking/amount signals that are likely noise (booking refs, prices).
 *
 * Covers: Ferry tickets, airline boarding passes, event tickets, train tickets.
 */
const TICKET_CONTEXT_MARKERS = [
  // English
  // AG-DATA2-069: Updated patterns to handle "Label: Value" format common in tickets
  /\bboarding\s*pass\b/i,
  /\b(?:concert|event|train|ferry|bus)\s+ticket\b/i, // "Concert Ticket", "Event Ticket", etc.
  /\bflight\s*(?:number|no\.?|#)\b/i,
  /\bflight\s*[:#]?\s*[A-Z]{2}\d+\b/i, // "Flight: SK1234" or "Flight SK1234"
  /\bcheck-?in\b/i,
  /\be-?ticket\b/i,
  /\bconfirmation\s*(?:number|code|#)\b/i,
  /\bbooking\s*(?:ref|reference|number|no\.?|#|code)\b/i,
  /\breservation\b/i,
  /\bgate\s*[:#]?\s*(?:number|no\.?|#)?\s*[A-Z]?\d+\b/i, // "Gate: A15" or "Gate A15"
  /\bseat\s*[:#]?\s*(?:number|no\.?)?\s*\d+[A-Z]?\b/i, // "Seat: 22C" or "Seat 22C"
  /\bdeparture\s*[:#]?\s*(?:time|gate|terminal)\b/i, // "Departure: Terminal 2"
  /\barrival\s*[:#]?\s*(?:time|terminal)\b/i,
  /\bpassenger\s*name\b/i,
  /\bpassenger\s*[:#]/i, // "Passenger: John Doe"
  // Danish
  /\bbillet\b/i,
  /\bbookingnr\.?\b/i,
  /\brejsebetingelser\b/i,
  /\bafrejse\b/i,
  /\bankomst\b/i,
  /\bsejlads\b/i,
  // AG-PHASE-5E-064: Unicode-safe boundaries for non-ASCII keywords
  /(?<!\p{L})færge(?!\p{L})/iu,
  /\bafgang\b/i,
  /\btogbillet\b/i,
  // Norwegian
  /\bbillett\b/i,
  /\bbestillingsnr\.?\b/i,
  /\bavgang\b/i,
  /\bankomst\b/i,
  /\bferge\b/i,
  // Swedish
  // AG-PHASE-5E-064: Unicode-safe boundaries for non-ASCII keywords
  /\bbiljett\b/i,
  /\bbokningsnr\.?\b/i,
  /(?<!\p{L})avgång(?!\p{L})/iu,
  /\bankomst\b/i,
  /(?<!\p{L})färja(?!\p{L})/iu,
  // German
  /\bfahrkarte\b/i,
  /\bflugschein\b/i,
  /\bbuchungsnummer\b/i,
  /\babflug\b/i,
  /\bankunft\b/i,
  // Spanish
  // AG-PHASE-5E-064: Unicode-safe boundaries for accented characters
  /\btarjeta\s+de\s+embarque\b/i,
  /(?<!\p{L})n[uú]mero\s+de\s+(?:vuelo|reserva|confirmaci[oó]n)(?!\p{L})/iu,
  /\bsalida\b/i,
  /\bllegada\b/i,
  /\bpasajero\b/i,
  // Event tickets
  /\badmission\b/i,
  /\bevent\s*ticket\b/i,
  /\bentry\s*(?:ticket|pass)\b/i,
  /\bconcert\s*ticket\b/i,
];

/**
 * Minimum number of ticket markers required to trigger suppression.
 * Higher threshold = more conservative (fewer false positives from suppression).
 */
const TICKET_MARKER_THRESHOLD = 2;

/**
 * AG-PROMPT-6 C1: Bank transfer context markers that override ticket suppression.
 * When these markers are present WITH an IBAN, ticket suppression is bypassed
 * to protect against scam tickets that ask for bank transfers.
 */
const BANK_TRANSFER_CONTEXT_MARKERS = [
  // English transfer intent
  /\b(?:wire|bank)\s*transfer\b/i,
  /\btransfer\s*(?:to|funds?\s+to)\b/i,
  /\bpay\s*(?:to|into)\s*(?:account|iban)\b/i,
  /\bsend\s*(?:to|funds?\s+to)\b/i,
  /\bremit(?:tance)?\b/i,
  /\bbeneficiary\b/i,
  /\bpayment\s*details?\b/i,
  /\bbank\s*details?\b/i,
  // Danish transfer intent
  /(?<!\p{L})overførsel(?!\p{L})/iu,
  /(?<!\p{L})bankoverførsel(?!\p{L})/iu,
  /\bbetal\s*til\b/i,
  /\bkonto\s*(?:nummer|nr\.?)\b/i,
  // Norwegian transfer intent
  /(?<!\p{L})overføring(?!\p{L})/iu,
  /\bbetal\s*til\b/i,
  // Swedish transfer intent
  /(?<!\p{L})överföring(?!\p{L})/iu,
  /\bbetala\s*till\b/i,
  // German transfer intent
  /(?<!\p{L})überweisung(?!\p{L})/iu,
  /\bzahlen\s*(?:an|auf)\b/i,
  // Spanish transfer intent
  /\btransferencia(?:\s+bancaria)?\b/i,
  /\bpagar\s*a\b/i,
  /\benviar\s*a\b/i,
];

/**
 * AG-PROMPT-6 C1: Check for bank transfer context.
 * Returns true if the text contains markers indicating bank transfer intent.
 */
function hasBankTransferContext(textContent: string): boolean {
  if (!textContent || textContent.length < 20) return false;
  for (const marker of BANK_TRANSFER_CONTEXT_MARKERS) {
    marker.lastIndex = 0;
    if (marker.test(textContent)) {
      return true;
    }
  }
  return false;
}

// ============================================================================
// AG-DATA2-066: RESUME CONTEXT DETECTION (M&A Signal Veto)
// ============================================================================

/**
 * AG-DATA2-066: Resume/CV context markers.
 * When these are present, M&A signals (e.g., "acquisition" in "talent acquisition")
 * should be vetoed to prevent false positives on job resumes.
 */
const RESUME_CONTEXT_MARKERS = [
  // Section headers
  /\b(?:work\s+)?experience\b/i,
  /\beducation\b/i,
  /\bskills?\b/i,
  /\bcertifications?\b/i,
  /\bqualifications?\b/i,
  /\bprofessional\s+(?:summary|profile|experience)\b/i,
  /\bcareer\s+(?:summary|objective|highlights?)\b/i,
  /\bemployment\s+history\b/i,
  /\bwork\s+history\b/i,
  // Resume/CV identifiers
  /\bresume\b/i,
  /\bcurriculum\s*vitae\b/i,
  /\b(?:cv|c\.v\.)\b/i,
  // Common resume phrases
  /\b(?:responsible\s+for|managed|led|developed|implemented)\b/i,
  /\byears?\s+(?:of\s+)?experience\b/i,
  /\bproficient\s+in\b/i,
  // Non-English resume markers
  /\blebenslauf\b/i,          // German CV
  /\bberufserfahrung\b/i,     // German work experience
  /\bausbildung\b/i,          // German education
  /\bmeritförteckning\b/i,    // Swedish CV
  /\barbejdserfaring\b/i,     // Danish work experience
  /\buddannelse\b/i,          // Danish education
];

/**
 * Minimum number of resume markers required to trigger M&A veto.
 * Higher threshold = fewer false vetoes on non-resume documents.
 */
const RESUME_MARKER_THRESHOLD = 2;

/**
 * AG-DATA2-066: Detect resume/CV context.
 * Returns true if sufficient resume markers are present.
 */
function hasResumeContext(textContent: string): boolean {
  if (!textContent || textContent.length < 100) return false;

  let markerCount = 0;
  for (const marker of RESUME_CONTEXT_MARKERS) {
    marker.lastIndex = 0;
    if (marker.test(textContent)) {
      markerCount++;
      if (markerCount >= RESUME_MARKER_THRESHOLD) {
        return true;
      }
    }
  }
  return false;
}

/**
 * AG-DATA2-066: M&A signal IDs that should be vetoed in resume context.
 * These signals can trigger on innocuous resume phrases like "talent acquisition".
 */
const MA_SIGNAL_IDS_FOR_RESUME_VETO = new Set([
  'global-ma-terms',
  'global-ma-valuation-context',
]);

/**
 * AG-PROMPT-155: Generic keyword signal IDs that should be suppressed in
 * template/governance document context. These signals fire on keywords that
 * describe data processing activities rather than containing actual personal data.
 *
 * HR signals: fire on "employee", "salary", "performance" in ROPA/policy language
 * Financial signals: fire on "SWIFT", "financial statement" in governance docs
 * M&A signals: "due diligence" is generic governance terminology
 */
const GENERIC_KEYWORD_SIGNAL_IDS = new Set([
  'registry-hr-employee',
  'english-hr-performance',
  'english-hr-compensation',
  'global-swift',
  'english-financial-statement',
  'nordic-financial-terms',
  'global-ma-terms',
  'global-ma-valuation-context',
]);

/**
 * AG-DATA2-066: Check if an M&A signal should be vetoed in resume context.
 * Only M&A signals are affected - PII and other sensitive signals remain.
 */
function shouldVetoMASignalInResume(signal: RiskSignal, textContent?: string): boolean {
  const signalId = signal.id;
  if (!signalId) return false;

  // Only veto M&A-related signals
  if (!MA_SIGNAL_IDS_FOR_RESUME_VETO.has(signalId)) {
    return false;
  }

  // Check for resume context
  if (textContent && hasResumeContext(textContent)) {
    return true;
  }

  return false;
}

/**
 * AG-PROMPT-5 Item 7: Detect ticket/travel document context.
 * Returns true if sufficient ticket markers are present in the text.
 */
function hasTicketContext(textContent: string): boolean {
  if (!textContent || textContent.length < 50) return false;

  let markerCount = 0;
  for (const marker of TICKET_CONTEXT_MARKERS) {
    if (marker.test(textContent)) {
      markerCount++;
      if (markerCount >= TICKET_MARKER_THRESHOLD) {
        return true;
      }
    }
  }
  return false;
}

/**
 * AG-PROMPT-5 Item 7: Check if a signal should be suppressed in ticket context.
 * Only applies when documentClass is null (no sensitive class detected).
 *
 * AG-PROMPT-6 C1: Safety hatch - if bank transfer context is detected,
 * IBAN signals are NOT suppressed even in ticket context (anti-scam protection).
 *
 * @param signal - The signal to check
 * @param textContent - Optional text content for bank transfer context check
 * @returns true if the signal should be suppressed
 */
function isNoisyInTicketContext(signal: RiskSignal, textContent?: string): boolean {
  const signalId = signal.id;
  if (!signalId) return false;

  // Check if this is a ticket-noise signal
  if (!NOISY_PATTERNS.ticketNoise.has(signalId)) {
    return false;
  }

  // AG-PROMPT-6 C1: Safety hatch for IBAN with bank transfer context
  // If IBAN is present AND bank transfer intent is detected, do NOT suppress
  // This protects against scam "tickets" that ask victims to wire money
  if (signalId === 'financial.iban' || signalId === 'global-iban') {
    if (textContent && hasBankTransferContext(textContent)) {
      return false; // Do NOT suppress - bank transfer context detected
    }
  }

  return true;
}

// ============================================================================
// CLASSIFICATION FUNCTIONS
// ============================================================================

/**
 * Strong payroll keywords that are sufficient on their own.
 * These are unambiguous indicators of a payroll document.
 * AG-PHASE-5E-061: Added Spanish/LatAm strong payroll keywords.
 */
const STRONG_PAYROLL_KEYWORDS = [
  /\bpayslip\b/i,
  /\bpay\s*stub\b/i,
  /\bpayroll\b/i,
  // AG-PHASE-5E-061: Spanish/LatAm payroll document indicators
  // AG-PHASE-5E-064: Unicode-safe boundaries for accented characters
  /(?<!\p{L})n[oó]mina(?!\p{L})/iu,                              // nómina/nomina (Spain/LatAm payslip)
  /(?<!\p{L})liquidaci[oó]n\s+de\s+sueldo(?!\p{L})/iu,           // liquidación de sueldo (LatAm payroll)
  /(?<!\p{L})recibo\s+de\s+n[oó]mina(?!\p{L})/iu,                // recibo de nómina (payroll receipt)
];

/**
 * Check if text contains payroll keywords.
 */
function hasPayrollKeywords(text: string): { found: boolean; count: number } {
  let count = 0;

  // First check for strong keywords - any single one is enough
  for (const pattern of STRONG_PAYROLL_KEYWORDS) {
    pattern.lastIndex = 0;
    if (pattern.test(text)) {
      // Strong keyword found - definitely a payroll document
      return { found: true, count: 3 }; // Return high count to boost score
    }
  }

  // Otherwise count regular keywords
  for (const pattern of PAYROLL_INDICATORS.keywords) {
    // Reset lastIndex for global patterns
    pattern.lastIndex = 0;
    if (pattern.test(text)) {
      count++;
    }
  }
  return { found: count >= 2, count }; // Need at least 2 keyword matches
}

/**
 * Strong HR keywords that are sufficient on their own.
 * AG-PHASE-5E-061: Added Spanish/LatAm strong HR keywords.
 */
const STRONG_HR_KEYWORDS = [
  /\bemployment\s*contract\b/i,
  /\bperformance\s*review\b/i,
  /\btermination\s*notice\b/i,
  // AG-PHASE-5E-061: Spanish/LatAm employment contract indicators
  // AG-PHASE-5E-064: Unicode-safe boundaries for accented characters
  /\bcontrato\s+(?:de\s+)?trabajo\b/i,           // contrato de trabajo / contrato trabajo
  /\bcontrato\s+individual\s+de\s+trabajo\b/i,   // contrato individual de trabajo (LatAm)
  /\bcontrato\s+laboral\b/i,                     // contrato laboral
  /(?<!\p{L})relaci[oó]n\s+laboral(?!\p{L})/iu,                  // relación laboral
];

/**
 * Check if text contains HR record keywords.
 */
function hasHRRecordKeywords(text: string): { found: boolean; count: number } {
  let count = 0;

  // Check for strong keywords first
  for (const pattern of STRONG_HR_KEYWORDS) {
    pattern.lastIndex = 0;
    if (pattern.test(text)) {
      return { found: true, count: 3 };
    }
  }

  // Count regular keywords
  for (const pattern of HR_RECORD_INDICATORS.keywords) {
    // Reset lastIndex for global patterns
    pattern.lastIndex = 0;
    if (pattern.test(text)) {
      count++;
    }
  }
  return { found: count >= 2, count };
}

/**
 * AG-PHASE-5C-056: Check if text contains insurance policy keywords.
 */
function hasInsuranceKeywords(text: string): { found: boolean; count: number } {
  let count = 0;
  for (const pattern of INSURANCE_POLICY_INDICATORS.keywords) {
    pattern.lastIndex = 0;
    if (pattern.test(text)) {
      count++;
    }
  }
  return { found: count >= 2, count };
}

/**
 * Strong medical keywords that are sufficient on their own.
 * AG-PROMPT-043: Added Danish/Nordic strong medical keywords.
 */
const STRONG_MEDICAL_KEYWORDS = [
  // English
  /\bmedical\s*(record|history)\b/i,
  /\bpatient\s*(id|record|name)\b/i,
  /\bhipaa\b/i,
  /\bdiagnosis\b/i,
  // AG-PROMPT-043: Danish/Nordic
  // AG-PHASE-5E-064: Unicode-safe boundaries for non-ASCII keywords
  /\bpatientjournal\b/i,
  /\bsundhedsdata\b/i,
  /\bsygejournal\b/i,
  /(?<!\p{L})lægejournal(?!\p{L})/iu,
  /\bepikrise\b/i,
  // ICD-10 code pattern (A00.0 - Z99.9)
  /\b[A-Z]\d{2}\.\d{1,2}\b/,
];

/**
 * Check if text contains medical record keywords.
 *
 * AG-PROMPT-077: Normalizes text before matching by replacing underscores with spaces.
 * This handles filenames like "Sundhedsdata_Patientjournal.pdf" where words are
 * separated by underscores. In JavaScript regex, _ is a word character (\w includes
 * [A-Za-z0-9_]), so \b doesn't match between _ and the next character.
 */
function hasMedicalKeywords(text: string): { found: boolean; count: number } {
  let count = 0;

  // AG-PROMPT-077: Normalize text - replace underscores with spaces for word boundary matching
  const normalizedText = text.replace(/_/g, ' ');

  // Check for strong keywords first
  for (const pattern of STRONG_MEDICAL_KEYWORDS) {
    pattern.lastIndex = 0;
    if (pattern.test(normalizedText)) {
      return { found: true, count: 3 };
    }
  }

  // Count regular keywords
  for (const pattern of MEDICAL_RECORD_INDICATORS.keywords) {
    // Reset lastIndex for global patterns
    pattern.lastIndex = 0;
    if (pattern.test(normalizedText)) {
      count++;
    }
  }
  return { found: count >= 2, count };
}

/**
 * AG-PROMPT-056, AG-PROMPT-077: Check if text, signals, or filename indicate patient-level context.
 *
 * Patient context means the document is about a SPECIFIC PERSON's health,
 * not just clinical/medical content in general.
 *
 * Required for "medical record" classification when only clinical anchors are present.
 *
 * AG-PROMPT-077 FIX: Now also checks filename for patient context keywords.
 * A file named "Patientjournal.pdf" should trigger patient context detection
 * even if the body text doesn't contain those keywords.
 *
 * @param signalIds - Set of signal IDs from detection
 * @param text - Optional text content to check for keywords
 * @param filename - Optional filename to check for keywords
 * @returns Whether patient context indicators are present
 */
function hasPatientContext(signalIds: Set<string>, text?: string, filename?: string): boolean {
  // Check signal IDs for patient context
  for (const signalId of signalIds) {
    if (PATIENT_CONTEXT_INDICATORS.signals.has(signalId)) {
      return true;
    }
  }

  // Check text for patient context keywords
  if (text) {
    for (const pattern of PATIENT_CONTEXT_INDICATORS.keywords) {
      pattern.lastIndex = 0;
      if (pattern.test(text)) {
        return true;
      }
    }
  }

  // AG-PROMPT-077: Check filename for patient context keywords
  // Filenames like "Patientjournal.pdf" or "Sundhedsdata_CPR.pdf" are strong patient context
  // Normalize underscores to spaces for word boundary matching (JS regex treats _ as word char)
  if (filename) {
    const normalizedFilename = filename.replace(/_/g, ' ');
    for (const pattern of PATIENT_CONTEXT_INDICATORS.keywords) {
      pattern.lastIndex = 0;
      if (pattern.test(normalizedFilename)) {
        return true;
      }
    }
  }

  return false;
}

// ============================================================================
// INVOICE MARKERS (AG-PROMPT-175)
// ============================================================================

/**
 * AG-PROMPT-175: Invoice keyword detection.
 *
 * Invoices share structural patterns with legal contracts (numbered items,
 * date fields) but have distinct financial markers. This pre-filter runs
 * BEFORE legal structural inference to prevent misclassification.
 *
 * Scoring: strong markers = 3 points, weak markers = 1 point.
 * Threshold: score >= 4 AND at least 1 strong marker.
 */

interface InvoiceScoreResult {
  isInvoice: boolean;
  score: number;
  matchedMarkers: string[];
  indicators: ClassificationIndicator[];
}

const INVOICE_STRONG_MARKERS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /\binvoice\s*(?:number|no\.?|#|nr)\b/i, label: 'invoice-number' },
  { pattern: /\breceipt\s*(?:number|no\.?|#|nr)\b/i, label: 'receipt-number' },
  { pattern: /\bfaktura(?:nummer|nr|dato)?\b/i, label: 'faktura' },
  { pattern: /\brechnung(?:snummer|sdatum)?\b/i, label: 'Rechnung' },
  { pattern: /\bfactura\b/i, label: 'factura' },
  { pattern: /\binvoice\s*date\b/i, label: 'invoice-date' },
  { pattern: /\bbill\s*(?:to|number|no\.?)\b/i, label: 'bill-to' },
];

const INVOICE_WEAK_MARKERS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /\btotal\s*(?:amount|due|excl|incl)\b/i, label: 'total-amount' },
  { pattern: /\bsubtotal\b/i, label: 'subtotal' },
  { pattern: /\bvat\b/i, label: 'VAT' },
  { pattern: /\bmoms\b/i, label: 'moms' },
  { pattern: /\bpayment\s*(?:due|terms|method)\b/i, label: 'payment-terms' },
  { pattern: /\bdue\s*date\b/i, label: 'due-date' },
  { pattern: /\bitem\s*description\b/i, label: 'item-description' },
  { pattern: /\bunit\s*price\b/i, label: 'unit-price' },
  { pattern: /\bquantity\b/i, label: 'quantity' },
  { pattern: /(?<!\p{L})beløb(?!\p{L})/iu, label: 'beløb' },
  { pattern: /\biban\b/i, label: 'IBAN' },
  { pattern: /\bbank\s*(?:account|transfer)\b/i, label: 'bank-account' },
];

function scoreInvoiceMarkers(text: string): InvoiceScoreResult {
  if (!text || text.length < 50) {
    return { isInvoice: false, score: 0, matchedMarkers: [], indicators: [] };
  }

  let score = 0;
  const matchedMarkers: string[] = [];
  const indicators: ClassificationIndicator[] = [];
  let hasStrong = false;

  for (const m of INVOICE_STRONG_MARKERS) {
    m.pattern.lastIndex = 0;
    if (m.pattern.test(text)) {
      score += 3;
      hasStrong = true;
      matchedMarkers.push(m.label);
      indicators.push({ signalId: `invoice.${m.label}`, weight: 'primary', category: 'keyword' });
    }
  }

  for (const m of INVOICE_WEAK_MARKERS) {
    m.pattern.lastIndex = 0;
    if (m.pattern.test(text)) {
      score += 1;
      matchedMarkers.push(m.label);
      indicators.push({ signalId: `invoice.${m.label}`, weight: 'supporting', category: 'keyword' });
    }
  }

  return {
    isInvoice: score >= 4 && hasStrong,
    score,
    matchedMarkers,
    indicators,
  };
}

// ============================================================================
// HEALTH CERTIFICATE MARKERS (AG-PROMPT-175)
// ============================================================================

/**
 * AG-PROMPT-175: Health certificate / vaccination record detection.
 *
 * COVID vaccination certificates, test results, and health passports contain
 * patient identifiers (CPR/SSN) but lack clinical keywords (diagnosis, treatment)
 * so they miss doc.medical_record. This catches certificate-like health documents.
 *
 * Note: spaced-character PDFs may have "C O V I D" which doesn't collapse
 * (5 chars < SPACED_COLLAPSE_MIN_LENGTH=6). Markers here use patterns that
 * tolerate optional inter-character spacing for short keywords.
 *
 * Scoring: strong markers = 3 points, weak markers = 1 point.
 * Threshold: score >= 4 AND at least 1 strong marker.
 */

interface HealthCertificateScoreResult {
  isHealthCertificate: boolean;
  score: number;
  matchedMarkers: string[];
  indicators: ClassificationIndicator[];
}

// Patterns that tolerate optional single-space between characters for short words
// e.g., "C O V I D" or "COVID" both match
const HEALTH_CERT_STRONG_MARKERS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /C\s*O\s*V\s*I\s*D/i, label: 'COVID' },
  { pattern: /\bvaccin(?:ation|e|ering|erings?bevis)?\b/i, label: 'vaccination' },
  { pattern: /\btest\s*(?:result|certificate|bevis|attest)\b/i, label: 'test-result' },
  { pattern: /(?<!\p{L})prøvesvar(?!\p{L})/iu, label: 'prøvesvar' },
  { pattern: /(?<!\p{L})testresultat(?!\p{L})/iu, label: 'testresultat' },
  { pattern: /\bcoronapass\b/i, label: 'coronapass' },
  { pattern: /\bhealth\s*certificate\b/i, label: 'health-certificate' },
  { pattern: /\bimmuni(?:ty|zation)\s*(?:record|certificate|card)\b/i, label: 'immunization-record' },
];

const HEALTH_CERT_WEAK_MARKERS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /P\s*C\s*R/i, label: 'PCR' },
  { pattern: /\bantigen\b/i, label: 'antigen' },
  { pattern: /\bpassport\b/i, label: 'passport' },
  { pattern: /P\s*A\s*S\s*S?\s*P\s*O\s*R\s*T/i, label: 'PASSPORT-spaced' },
  { pattern: /(?<!\p{L})fødselsdato(?!\p{L})/iu, label: 'fødselsdato' },
  { pattern: /\bdate\s*of\s*birth\b/i, label: 'date-of-birth' },
  { pattern: /\bdose\b/i, label: 'dose' },
  { pattern: /\bbooster\b/i, label: 'booster' },
  { pattern: /\bsurname\b/i, label: 'surname' },
  { pattern: /\bgiven\s*name\b/i, label: 'given-name' },
];

function scoreHealthCertificateMarkers(text: string): HealthCertificateScoreResult {
  if (!text || text.length < 50) {
    return { isHealthCertificate: false, score: 0, matchedMarkers: [], indicators: [] };
  }

  let score = 0;
  const matchedMarkers: string[] = [];
  const indicators: ClassificationIndicator[] = [];
  let hasStrong = false;

  for (const m of HEALTH_CERT_STRONG_MARKERS) {
    m.pattern.lastIndex = 0;
    if (m.pattern.test(text)) {
      score += 3;
      hasStrong = true;
      matchedMarkers.push(m.label);
      indicators.push({ signalId: `health-cert.${m.label}`, weight: 'primary', category: 'keyword' });
    }
  }

  for (const m of HEALTH_CERT_WEAK_MARKERS) {
    m.pattern.lastIndex = 0;
    if (m.pattern.test(text)) {
      score += 1;
      matchedMarkers.push(m.label);
      indicators.push({ signalId: `health-cert.${m.label}`, weight: 'supporting', category: 'keyword' });
    }
  }

  return {
    isHealthCertificate: score >= 4 && hasStrong,
    score,
    matchedMarkers,
    indicators,
  };
}

// ============================================================================
// LEGAL CONTRACT STRUCTURAL INFERENCE (AG-PROMPT-097C)
// ============================================================================

/**
 * AG-PROMPT-097C: Legal Contract Structural Inference
 *
 * Language-agnostic structural patterns to identify legal contracts:
 * - Clause numbering density: patterns like 1., 1.1, §, Article
 * - Signature block markers: underscore lines, party blocks
 * - E-signature indicators: DocuSign, signature ID patterns
 *
 * These are STRUCTURAL patterns that work across languages.
 * The inference is conservative to avoid false positives on
 * random documents with numbered lists.
 */
export interface LegalContractStructuralResult {
  /** Whether structural contract patterns were detected */
  isLegalContract: boolean;
  /** Confidence score (0-10) */
  score: number;
  /** Which structural indicators were found */
  indicators: string[];
}

/**
 * Clause numbering patterns (language-agnostic structural markers).
 */
const CLAUSE_NUMBERING_PATTERNS = [
  /\b\d+\.\d+\.\d+\b/g,       // Deep numbering: 1.2.3
  /\b\d+\.\d+(?!\.\d)\b/g,    // Two-level numbering: 1.2 (not followed by .digit)
  /^\s*\d+\.\s+[A-Z]/gm,      // Section start: "1. PARTIES"
  /§\s*\d+/g,                 // Section symbol: §1, § 42
  /\bArticle\s+\d+/gi,        // Article N (English but common in contracts)
  /\bArtikel\s+\d+/gi,        // Artikel N (German/Danish/Dutch)
  /\bClause\s+\d+/gi,         // Clause N
  /\bKlausul\s+\d+/gi,        // Klausul N (Danish/Swedish)
  /\bPunkt\s+\d+/gi,          // Punkt N (German/Nordic)
];

/**
 * Signature block structural patterns (language-agnostic).
 */
const SIGNATURE_BLOCK_PATTERNS = [
  /_{5,}/g,                   // Underscore signature lines (5+ chars)
  /\bx{3,}_{2,}/gi,           // X___ signature line
  /Date:\s*[_\/\-\s]+/gi,     // Date: ___
  /Dato:\s*[_\/\-\s]+/gi,     // Dato: ___ (Danish/Norwegian)
  /Datum:\s*[_\/\-\s]+/gi,    // Datum: ___ (German/Dutch/Swedish)
];

/**
 * E-signature platform indicators (brand names, common across languages).
 */
const ESIGNATURE_INDICATORS = [
  /docusign/i,
  /\bsignature\s*id\b/i,
  /\benvelope\s*id\b/i,
  /\badobesign\b/i,
  /\bhelloSign\b/i,
  /\bpandadoc\b/i,
  /\bsigneasy\b/i,
];

/**
 * Party/agreement structural patterns (language-agnostic where possible).
 */
const PARTY_BLOCK_PATTERNS = [
  /\bparty\s*[ab12]\b/gi,       // Party A, Party B, Party 1
  /\bpart\s*[ab12]\b/gi,        // Part A (Danish/Swedish)
  /\bfirst\s*party\b/gi,        // First Party
  /\bsecond\s*party\b/gi,       // Second Party
  /\bhereinafter\b/gi,          // "hereinafter referred to as"
  /\bherefter\s*kaldet\b/gi,    // Danish equivalent
];

/**
 * AG-PROMPT-097C: Infer legal contract classification from structural patterns.
 *
 * This function uses STRUCTURAL patterns (not keywords) to identify contracts:
 * - High clause numbering density (6+ distinct numbered clauses)
 * - Signature blocks (underscore lines + date patterns)
 * - E-signature platform markers (DocuSign, etc.)
 * - Party block patterns
 *
 * Conservative threshold to avoid false positives on numbered lists.
 *
 * @param text - Document text content
 * @param filename - Optional filename
 * @returns Structural inference result
 */
export function inferLegalContractFromStructure(
  text: string | undefined,
  filename?: string
): LegalContractStructuralResult {
  if (!text || text.length < 200) {
    return { isLegalContract: false, score: 0, indicators: [] };
  }

  const indicators: string[] = [];
  let score = 0;

  // 1. Count distinct clause numbering patterns
  const clauseMatches = new Set<string>();
  for (const pattern of CLAUSE_NUMBERING_PATTERNS) {
    pattern.lastIndex = 0;
    const matches = text.match(pattern);
    if (matches) {
      for (const m of matches) {
        clauseMatches.add(m);
      }
    }
  }
  const clauseCount = clauseMatches.size;

  // High clause numbering density (6+ distinct) = strong signal
  if (clauseCount >= 10) {
    score += 4;
    indicators.push(`clause-numbering-high:${clauseCount}`);
  } else if (clauseCount >= 6) {
    score += 3;
    indicators.push(`clause-numbering-medium:${clauseCount}`);
  } else if (clauseCount >= 3) {
    score += 1;
    indicators.push(`clause-numbering-low:${clauseCount}`);
  }

  // 2. Check for signature block markers
  let signatureMarkers = 0;
  for (const pattern of SIGNATURE_BLOCK_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(text)) {
      signatureMarkers++;
    }
  }
  if (signatureMarkers >= 2) {
    score += 3;
    indicators.push(`signature-blocks:${signatureMarkers}`);
  } else if (signatureMarkers >= 1) {
    score += 1;
    indicators.push(`signature-block:${signatureMarkers}`);
  }

  // 3. Check for e-signature platform indicators (strong signal)
  for (const pattern of ESIGNATURE_INDICATORS) {
    pattern.lastIndex = 0;
    if (pattern.test(text)) {
      score += 2;
      indicators.push('esignature-platform');
      break; // Only count once
    }
  }

  // 4. Check filename for contract indicators
  if (filename) {
    const normalizedFilename = filename.toLowerCase().replace(/_/g, ' ');
    if (/contract|kontrakt|avtale|aftale|agreement|vertrag/i.test(normalizedFilename)) {
      score += 2;
      indicators.push('filename-contract');
    }
    // E-signature in filename
    if (/docusign|hellosign|adobesign|pandadoc/i.test(normalizedFilename)) {
      score += 2;
      indicators.push('filename-esignature');
    }
  }

  // 5. Check for party block patterns (supporting)
  let partyMatches = 0;
  for (const pattern of PARTY_BLOCK_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(text)) {
      partyMatches++;
    }
  }
  if (partyMatches >= 2) {
    score += 2;
    indicators.push(`party-blocks:${partyMatches}`);
  } else if (partyMatches >= 1) {
    score += 1;
    indicators.push(`party-block:${partyMatches}`);
  }

  // Conservative threshold: score >= 5 required
  // This means we need multiple structural markers, not just one.
  // Examples that pass:
  // - 6+ clauses (3) + signature block (1) + party (1) = 5
  // - 10+ clauses (4) + e-signature (2) = 6
  // - filename-contract (2) + signature (3) + clauses (1) = 6
  const isLegalContract = score >= 5;

  return { isLegalContract, score, indicators };
}

/**
 * Classify a document based on signals, text content, and filename.
 *
 * AG-PROMPT-077: Now also checks filename for classification keywords.
 * A file named "Patientjournal.pdf" should trigger medical classification
 * even if the body text doesn't contain those keywords.
 *
 * AG-PROMPT-097C: Now includes structural legal contract inference.
 */
export function classifyDocument(
  signals: RiskSignal[],
  textContent?: string,
  filename?: string
): DocumentClassification {
  const signalIds = new Set(signals.map(s => s.id).filter((id): id is string => !!id));

  // Build indicator lists
  const payrollIndicators: ClassificationIndicator[] = [];
  const hrIndicators: ClassificationIndicator[] = [];
  const medicalIndicators: ClassificationIndicator[] = [];
  const insuranceIndicators: ClassificationIndicator[] = [];  // AG-PHASE-5C-056

  // Check signals for primary indicators
  for (const signalId of signalIds) {
    if (PAYROLL_INDICATORS.primary.has(signalId)) {
      payrollIndicators.push({ signalId, weight: 'primary', category: 'identifier' });
    }
    if (PAYROLL_INDICATORS.supporting.has(signalId)) {
      payrollIndicators.push({ signalId, weight: 'supporting', category: 'context' });
    }

    if (HR_RECORD_INDICATORS.primary.has(signalId)) {
      hrIndicators.push({ signalId, weight: 'primary', category: 'identifier' });
    }
    if (HR_RECORD_INDICATORS.supporting.has(signalId)) {
      hrIndicators.push({ signalId, weight: 'supporting', category: 'context' });
    }

    // AG-PHASE-5C-056: Insurance policy indicators
    if (INSURANCE_POLICY_INDICATORS.primary.has(signalId)) {
      insuranceIndicators.push({ signalId, weight: 'primary', category: 'identifier' });
    }
    if (INSURANCE_POLICY_INDICATORS.supporting.has(signalId)) {
      insuranceIndicators.push({ signalId, weight: 'supporting', category: 'context' });
    }

    if (MEDICAL_RECORD_INDICATORS.primary.has(signalId)) {
      medicalIndicators.push({ signalId, weight: 'primary', category: 'identifier' });
    }
    if (MEDICAL_RECORD_INDICATORS.supporting.has(signalId)) {
      medicalIndicators.push({ signalId, weight: 'supporting', category: 'context' });
    }
  }

  // Check text content for keywords
  // Keyword matches are strong indicators - if multiple keywords match, it's a strong signal
  if (textContent) {
    const payrollKeywords = hasPayrollKeywords(textContent);
    if (payrollKeywords.found) {
      // Add primary indicator for keyword matches
      payrollIndicators.push({
        signalId: 'text.payroll_keywords',
        weight: 'primary',
        category: 'keyword',
      });
      // Add supporting indicators for each additional keyword beyond threshold
      if (payrollKeywords.count > 2) {
        payrollIndicators.push({
          signalId: 'text.payroll_keywords_additional',
          weight: 'supporting',
          category: 'keyword',
        });
      }
    }

    const hrKeywords = hasHRRecordKeywords(textContent);
    if (hrKeywords.found) {
      hrIndicators.push({
        signalId: 'text.hr_keywords',
        weight: 'primary',
        category: 'keyword',
      });
      if (hrKeywords.count > 2) {
        hrIndicators.push({
          signalId: 'text.hr_keywords_additional',
          weight: 'supporting',
          category: 'keyword',
        });
      }
    }

    // AG-PHASE-5C-056: Insurance keyword detection
    const insuranceKeywords = hasInsuranceKeywords(textContent);
    if (insuranceKeywords.found) {
      insuranceIndicators.push({
        signalId: 'text.insurance_keywords',
        weight: 'primary',
        category: 'keyword',
      });
      if (insuranceKeywords.count > 2) {
        insuranceIndicators.push({
          signalId: 'text.insurance_keywords_additional',
          weight: 'supporting',
          category: 'keyword',
        });
      }
    }

    const medicalKeywords = hasMedicalKeywords(textContent);
    if (medicalKeywords.found) {
      medicalIndicators.push({
        signalId: 'text.medical_keywords',
        weight: 'primary',
        category: 'keyword',
      });
      if (medicalKeywords.count > 2) {
        medicalIndicators.push({
          signalId: 'text.medical_keywords_additional',
          weight: 'supporting',
          category: 'keyword',
        });
      }
    }

    // AG-PROMPT-043: Check clinical ontology anchors (structural medical patterns)
    // These are language-agnostic structural patterns that identify medical documents
    // even when anonymized (no patient names, no keywords in native language)
    const clinicalAnchors = hasClinicalOntologyAnchors(textContent);
    if (clinicalAnchors.isMedical) {
      // ICD codes are standalone triggers (HIGH confidence)
      if (clinicalAnchors.confidence === 'high') {
        medicalIndicators.push({
          signalId: CLINICAL_ONTOLOGY_RULE_IDS.ICD_CODE_STANDALONE,
          weight: 'primary',
          category: 'structure',
        });
      }
      // Unit clusters and unit+range proximity are MEDIUM confidence
      if (clinicalAnchors.confidence === 'medium' || clinicalAnchors.confidence === 'high') {
        // Add structural indicators based on what was detected
        if (clinicalAnchors.stats.unitClusterFound) {
          medicalIndicators.push({
            signalId: CLINICAL_ONTOLOGY_RULE_IDS.UNIT_CLUSTER,
            weight: 'primary',
            category: 'structure',
          });
        }
        if (clinicalAnchors.stats.unitRangeProximityFound) {
          medicalIndicators.push({
            signalId: CLINICAL_ONTOLOGY_RULE_IDS.UNIT_RANGE_PROXIMITY,
            weight: 'primary',
            category: 'structure',
          });
        }
      }
    }
  }

  // AG-PROMPT-077/085: Check filename for medical keywords (OUTSIDE textContent block)
  //
  // WHY FILENAME-BASED MEDICAL DETECTION IS ALLOWED:
  // 1. PDF extraction may fail (encrypted, scanned, image-only)
  // 2. Medical terminology may be in non-European languages we don't detect
  // 3. Filename often contains explicit classification (e.g., "lab_results.pdf")
  // 4. Users name files descriptively - this is valuable metadata
  //
  // Filenames like "Patientjournal.pdf", "lab_results.pdf", or "Sundhedsdata.pdf"
  // are strong indicators even when body text doesn't contain those keywords.
  // This prevents false negatives on documents where text extraction fails.
  if (filename) {
    const filenameKeywords = hasMedicalKeywords(filename);
    if (filenameKeywords.found) {
      medicalIndicators.push({
        signalId: 'filename.medical_keywords',
        weight: 'primary',
        category: 'keyword',
      });
    }
  }

  // Score each class - primary indicators count more (3 points), supporting count 1
  const payrollScore = payrollIndicators.filter(i => i.weight === 'primary').length * 3 +
    payrollIndicators.filter(i => i.weight === 'supporting').length;

  const hrScore = hrIndicators.filter(i => i.weight === 'primary').length * 3 +
    hrIndicators.filter(i => i.weight === 'supporting').length;

  const medicalScore = medicalIndicators.filter(i => i.weight === 'primary').length * 3 +
    medicalIndicators.filter(i => i.weight === 'supporting').length;

  // Classification thresholds
  const CLASSIFICATION_THRESHOLD = 3; // Need at least this score to classify

  // Medical takes priority (most sensitive), then payroll, then HR
  // AG-PROMPT-056: Medical record classification requires patient-level context
  // when driven only by clinical ontology anchors (structure category)
  if (medicalScore >= CLASSIFICATION_THRESHOLD &&
      medicalIndicators.some(i => i.weight === 'primary')) {

    // Check if all primary medical indicators are structural (ontology anchors)
    const primaryMedicalIndicators = medicalIndicators.filter(i => i.weight === 'primary');
    const hasOnlyStructuralIndicators = primaryMedicalIndicators.every(
      i => i.category === 'structure'
    );

    // AG-PROMPT-056, AG-PROMPT-077: If only structural indicators (ICD codes, clinical units),
    // require patient-level context to classify as medical record
    // AG-PROMPT-077: Now also checks filename for patient context
    if (hasOnlyStructuralIndicators) {
      const patientContextFound = hasPatientContext(signalIds, textContent, filename);
      if (!patientContextFound) {
        // Clinical anchors without patient context = sensitive regulated data,
        // NOT a medical record. Fall through to no classification.
        // The signals are still detected; severity is still applied.
        // Only the "Medical record" label is avoided.
      } else {
        // Patient context found - this IS a medical record
        return {
          documentClass: 'doc.medical_record',
          indicators: medicalIndicators,
          baselineSeverity: DOCUMENT_CLASS_BASELINES['doc.medical_record'],
          reason: `Medical record: clinical anchors + patient context (score: ${medicalScore})`,
        };
      }
    } else {
      // AG-PROMPT-SIGNAL-BYPASS-FIX-028: Keyword-based indicators also require
      // patient context. Keywords like "diagnosis" or "treatment" can appear in
      // insurance policies without making them medical records.
      const patientContextFound = hasPatientContext(signalIds, textContent, filename);
      if (patientContextFound) {
        return {
          documentClass: 'doc.medical_record',
          indicators: medicalIndicators,
          baselineSeverity: DOCUMENT_CLASS_BASELINES['doc.medical_record'],
          reason: `Medical record: keyword indicators + patient context (score: ${medicalScore})`,
        };
      }
      // Keywords without patient context = medical terminology, NOT medical record.
      // Fall through to no classification. Signals are still detected.
    }
  }

  // AG-PHASE-5E-061: Compare payroll vs HR scores when both have primary indicators.
  // Employment contracts often mention compensation/salary, so we need to disambiguate.
  // If HR has strong contract keywords AND scores >= payroll, prefer HR.
  const payrollPasses = payrollScore >= CLASSIFICATION_THRESHOLD &&
    payrollIndicators.some(i => i.weight === 'primary');
  const hrPasses = hrScore >= CLASSIFICATION_THRESHOLD &&
    hrIndicators.some(i => i.weight === 'primary');

  if (payrollPasses && hrPasses) {
    // Both qualify - compare scores. HR wins ties when it has employment contract keywords.
    if (hrScore > payrollScore) {
      return {
        documentClass: 'doc.hr_record',
        indicators: hrIndicators,
        baselineSeverity: DOCUMENT_CLASS_BASELINES['doc.hr_record'],
        reason: `HR record (score ${hrScore} > payroll ${payrollScore})`,
      };
    } else if (payrollScore > hrScore) {
      return {
        documentClass: 'doc.payroll',
        indicators: payrollIndicators,
        baselineSeverity: DOCUMENT_CLASS_BASELINES['doc.payroll'],
        reason: `Payroll document (score ${payrollScore} > HR ${hrScore})`,
      };
    } else {
      // Scores equal - prefer HR if it has employment contract keywords
      // (employment contracts naturally mention compensation)
      return {
        documentClass: 'doc.hr_record',
        indicators: hrIndicators,
        baselineSeverity: DOCUMENT_CLASS_BASELINES['doc.hr_record'],
        reason: `HR record (tie-breaker: contracts mention compensation)`,
      };
    }
  }

  if (payrollPasses) {
    return {
      documentClass: 'doc.payroll',
      indicators: payrollIndicators,
      baselineSeverity: DOCUMENT_CLASS_BASELINES['doc.payroll'],
      reason: `Payroll document indicators detected (score: ${payrollScore})`,
    };
  }

  if (hrPasses) {
    return {
      documentClass: 'doc.hr_record',
      indicators: hrIndicators,
      baselineSeverity: DOCUMENT_CLASS_BASELINES['doc.hr_record'],
      reason: `HR record indicators detected (score: ${hrScore})`,
    };
  }

  // AG-PHASE-5C-056: Insurance policy classification
  // Runs AFTER medical/payroll/HR since those are more specific.
  // Insurance documents contain policy numbers, coverage terms, personal details.
  const insuranceScore = insuranceIndicators.filter(i => i.weight === 'primary').length * 3 +
    insuranceIndicators.filter(i => i.weight === 'supporting').length;

  if (insuranceScore >= CLASSIFICATION_THRESHOLD &&
      insuranceIndicators.some(i => i.weight === 'primary')) {
    return {
      documentClass: 'doc.insurance_policy',
      indicators: insuranceIndicators,
      baselineSeverity: DOCUMENT_CLASS_BASELINES['doc.insurance_policy'],
      reason: `Insurance policy indicators detected (score: ${insuranceScore})`,
    };
  }

  // AG-PROMPT-175: Invoice pre-filter — runs BEFORE legal structural inference
  // to prevent invoices with numbered line items from being misclassified as
  // legal contracts via clause-numbering pattern collision.
  if (textContent) {
    const invoiceScore = scoreInvoiceMarkers(textContent);
    if (invoiceScore.isInvoice) {
      return {
        documentClass: 'doc.invoice',
        indicators: invoiceScore.indicators,
        baselineSeverity: DOCUMENT_CLASS_BASELINES['doc.invoice'],
        reason: `Invoice markers detected (score: ${invoiceScore.score}, markers: ${invoiceScore.matchedMarkers.join(', ')})`,
      };
    }
  }

  // AG-PROMPT-175: Health certificate classification — runs BEFORE legal structural
  // inference. COVID/vaccination certificates contain patient identifiers (CPR) but
  // no clinical keywords, so they miss doc.medical_record. This catches them.
  if (textContent) {
    const healthCertScore = scoreHealthCertificateMarkers(textContent);
    if (healthCertScore.isHealthCertificate) {
      return {
        documentClass: 'doc.health_certificate',
        indicators: healthCertScore.indicators,
        baselineSeverity: DOCUMENT_CLASS_BASELINES['doc.health_certificate'],
        reason: `Health certificate markers detected (score: ${healthCertScore.score}, markers: ${healthCertScore.matchedMarkers.join(', ')})`,
      };
    }
  }

  // AG-PROMPT-097C: Check for legal contract structural patterns
  // This runs AFTER medical/payroll/HR/insurance/invoice/health-cert since those are more specific.
  // Legal contract classification uses structural inference (clause numbering,
  // signature blocks, party patterns) rather than keyword-based detection.
  const legalStructure = inferLegalContractFromStructure(textContent, filename);
  if (legalStructure.isLegalContract) {
    const legalIndicators: ClassificationIndicator[] = legalStructure.indicators.map(ind => ({
      signalId: `structure.${ind.split(':')[0]}`,
      weight: 'primary' as const,
      category: 'structure' as const,
    }));

    return {
      documentClass: 'doc.legal_contract',
      indicators: legalIndicators,
      baselineSeverity: DOCUMENT_CLASS_BASELINES['doc.legal_contract'],
      reason: `Legal contract structural patterns detected (score: ${legalStructure.score}, indicators: ${legalStructure.indicators.join(', ')})`,
    };
  }

  // No classification
  return {
    documentClass: null,
    indicators: [],
    baselineSeverity: null,
    reason: 'No document class detected',
  };
}

// ============================================================================
// AG-PROMPT-DOCUMENT-IDENTITY-THRESHOLDS-026: IDENTITY CONFIDENCE
// ============================================================================

/**
 * Corroborating signal IDs for each document class.
 * These strengthen identity claims beyond single-signal classification.
 */
const CORROBORATING_SIGNALS: Record<DocumentClass, Set<string>> = {
  'doc.medical_record': new Set([
    SIG_NATIONAL_ID,
    SIG_LEGACY_DK_CPR,
    SIG_LEGACY_SE_PERSONNUMMER,
    SIG_LEGACY_NO_FNR,
    SIG_LEGACY_FI_HETU,
    'pii.ssn_us',
    'pii.national_id',
    'pii.name',
    'COA-001-icd-standalone',
    'COA-002-unit-cluster',
    'COA-003-unit-range-proximity',
  ]),
  'doc.legal_contract': new Set([
    'structure.clause_numbering',
    'structure.signature_block',
    'structure.party_pattern',
    'structure.esignature',
    'legal.nda',
    'pii.name',
  ]),
  'doc.hr_record': new Set([
    SIG_NATIONAL_ID,
    'pii.compensation',
    'hr-compensation',
    'english-hr-compensation',   // AG-PHASE-5C-056: Pack-produced signal ID
    'english-hr-performance',    // AG-PHASE-5C-056: Pack-produced signal ID
    'registry-hr-employee',      // AG-PHASE-5C-056: Pack-produced signal ID
    'pii.ssn_us',
    'pii.national_id',
    'pii.employee',
    'pii.name',
    'financial.banking',
    'english-financial-banking', // AG-PHASE-5C-056: Pack-produced signal ID
    'registry-banking-terms',    // AG-PHASE-5C-056: Pack-produced signal ID
  ]),
  'doc.payroll': new Set([
    SIG_NATIONAL_ID,
    'pii.compensation',
    'hr-compensation',
    'english-hr-compensation',   // AG-PHASE-5C-056: Pack-produced signal ID
    'registry-hr-employee',      // AG-PHASE-5C-056: Pack-produced signal ID
    'pii.ssn_us',
    'pii.national_id',
    'pii.employee',
    'pii.name',
    'financial.banking',
    'english-financial-banking', // AG-PHASE-5C-056: Pack-produced signal ID
    'registry-banking-terms',    // AG-PHASE-5C-056: Pack-produced signal ID
  ]),
  'doc.insurance_policy': new Set([
    SIG_NATIONAL_ID,
    'global-dob',
    'pii.name',
    'pii.address',
    'pii.ssn_us',
    'pii.national_id',
    'global-insurance-terms',
    'global-insurance-policy-number',
  ]),
  'doc.invoice': new Set([  // AG-PROMPT-175
    SIG_NATIONAL_ID,
    'pii.name',
    'pii.address',
    'financial.banking',
    'registry-banking-terms',
    'global-iban',
  ]),
  'doc.health_certificate': new Set([  // AG-PROMPT-175
    SIG_NATIONAL_ID,
    SIG_LEGACY_DK_CPR,
    SIG_LEGACY_SE_PERSONNUMMER,
    SIG_LEGACY_NO_FNR,
    SIG_LEGACY_FI_HETU,
    'pii.name',
    'global-dob',
  ]),
};

/**
 * Compute identity confidence for a document classification.
 *
 * Strong confidence requires:
 * - Medical: patient context (CPR, SSN, name) OR 2+ structural indicators
 * - Legal: signature blocks + party patterns OR 2+ legal indicators
 * - HR/Payroll: compensation data + employee ID OR 2+ HR indicators
 *
 * Single-signal classifications → weak confidence → terminology labels only.
 */
function computeIdentityConfidence(
  classification: DocumentClassification,
  hasPatientContext: boolean,
  signals: RiskSignal[]
): IdentityConfidence {
  const docClass = classification.documentClass;
  if (!docClass) return 'none';

  const signalIds = new Set(signals.map(s => s.id).filter((id): id is string => !!id));
  const corroboratingSet = CORROBORATING_SIGNALS[docClass];

  // Count corroborating signals
  let corroboratingCount = 0;
  for (const signalId of signalIds) {
    if (corroboratingSet.has(signalId)) {
      corroboratingCount++;
    }
  }

  // Medical: requires patient context OR 2+ corroborating signals
  if (docClass === 'doc.medical_record') {
    if (hasPatientContext || corroboratingCount >= 2) {
      return 'strong';
    }
    // Single medical keyword without patient context = weak
    return 'weak';
  }

  // Legal: requires 2+ corroborating signals (structural patterns)
  if (docClass === 'doc.legal_contract') {
    if (corroboratingCount >= 2) {
      return 'strong';
    }
    return 'weak';
  }

  // HR/Payroll: requires compensation data OR 2+ corroborating signals
  if (docClass === 'doc.hr_record' || docClass === 'doc.payroll') {
    const hasCompensation = signalIds.has('pii.compensation') ||
                            signalIds.has('hr-compensation');
    if (hasCompensation || corroboratingCount >= 2) {
      return 'strong';
    }
    return 'weak';
  }

  // Insurance: requires policy number + PII OR 2+ corroborating signals
  if (docClass === 'doc.insurance_policy') {
    const hasPolicyNumber = signalIds.has('global-insurance-policy-number');
    if (hasPolicyNumber || corroboratingCount >= 2) {
      return 'strong';
    }
    return 'weak';
  }

  // Default: strong if any corroboration, weak otherwise
  return corroboratingCount >= 1 ? 'strong' : 'weak';
}

// ============================================================================
// NOISE SUPPRESSION
// ============================================================================

/**
 * Check if a signal is noisy within a sensitive document context.
 *
 * Noisy patterns inside payroll/HR/medical docs:
 * - Payment card patterns without anchors (expiry, CVV, cardholder)
 * - URL-with-credentials heuristics
 * - SWIFT/BIC without personal account context
 */
function isNoisyInSensitiveDocument(
  signal: RiskSignal,
  documentClass: DocumentClass,
  allSignals: RiskSignal[]
): boolean {
  const signalId = signal.id;
  if (!signalId) return false;

  // Check card noise
  if (NOISY_PATTERNS.cardNoise.has(signalId)) {
    // Card pattern is noise if there's no anchor (CVV, expiry, cardholder)
    const hasCardAnchor = allSignals.some(s =>
      s.id && (
        s.id.includes('cvv') ||
        s.id.includes('expiry') ||
        s.id.includes('cardholder') ||
        /card\s*holder/i.test(s.description)
      )
    );
    if (!hasCardAnchor) {
      return true; // Suppress card pattern without anchors
    }
  }

  // Check URL/credential noise - always suppress in HR/payroll
  if (NOISY_PATTERNS.urlNoise.has(signalId)) {
    if (documentClass === 'doc.payroll' || documentClass === 'doc.hr_record') {
      return true;
    }
  }

  // SWIFT/BIC without personal context
  if (NOISY_PATTERNS.swiftNoise.has(signalId)) {
    // Only suppress if it's just banking terms without personal identifiers
    const hasPersonalContext = allSignals.some(s =>
      s.id && (
        s.id.includes('pii.') ||
        s.id.includes('employee') ||
        s.id.includes('name')
      )
    );
    // Don't suppress if there's personal context
    if (!hasPersonalContext) {
      return true;
    }
  }

  return false;
}

// ============================================================================
// MAIN PROCESSING FUNCTION
// ============================================================================

/**
 * Input for document class anchor processing.
 */
export interface DocumentClassInput {
  /** Signals from previous pipeline stages */
  signals: RiskSignal[];

  /** Optional text content for keyword classification */
  textContent?: string;

  /** File metadata for additional context */
  filename?: string;
}

/**
 * Apply document class anchors to the signal set.
 *
 * This is the main entry point for AG-PROMPT-041.
 * Should be called AFTER human heuristics (AG-039), BEFORE severity aggregation (AG-035).
 *
 * Actions:
 * 1. Classify document based on signal combinations and text keywords
 * 2. If classified, apply baseline severity floor
 * 3. Suppress noisy patterns within sensitive documents
 * 4. Add document class anchor signal
 *
 * @param input - Signals and optional text content
 * @returns DocumentClassResult with processed signals and classification
 */
export function applyDocumentClassAnchors(input: DocumentClassInput): DocumentClassResult {
  const { signals, textContent, filename } = input;

  const auditLog: DocumentClassAuditEntry[] = [];
  const stats: DocumentClassStats = {
    inputSignalCount: signals.length,
    outputSignalCount: 0,
    noiseSuppressed: 0,
    classDetected: false,
    baselineApplied: false,
  };

  // AG-ARCHETYPE-073: Detect document archetypes for supplementary classification evidence
  const archetypeMatches = textContent ? detectDocumentArchetypes(textContent) : [];

  // AG-PROMPT-155 / AG-PROMPT-162: Pre-filter generic keyword signals in
  // template/governance and policy/standard documents.
  // This must run BEFORE classification to prevent generic HR/M&A/financial keywords
  // from triggering doc.hr_record classification on ROPA/policy/questionnaire/standard documents.
  let effectiveSignals = signals;
  const templatePrefilterSuppressed: RiskSignal[] = [];
  const genericKeywordVetoMatch = archetypeMatches.find(
    m => (m.archetypeId === 'template_governance' || m.archetypeId === 'policy_standard' || m.archetypeId === 'aggregate_hr_finance')
         && m.confidence === 'strong'
  );
  if (genericKeywordVetoMatch) {
    const effects = getArchetypeEffects(genericKeywordVetoMatch.archetypeId);
    if (effects.mayVetoGenericKeywords) {
      effectiveSignals = signals.filter(signal => {
        const sid = signal.id;
        if (!sid) return true;
        if (isProtectedSignal(sid)) return true;
        if (GENERIC_KEYWORD_SIGNAL_IDS.has(sid)) {
          templatePrefilterSuppressed.push(signal);
          return false;
        }
        return true;
      });

      if (templatePrefilterSuppressed.length > 0) {
        const ruleId = genericKeywordVetoMatch.archetypeId === 'policy_standard'
          ? 'AG-PROMPT-162-POLICY-STANDARD-GENERIC-VETO'
          : genericKeywordVetoMatch.archetypeId === 'aggregate_hr_finance'
          ? 'AG-PROMPT-162-AGGREGATE-HR-FINANCE-GENERIC-VETO'
          : 'AG-PROMPT-155-TEMPLATE-GENERIC-VETO';
        auditLog.push({
          ruleId,
          action: 'noise_suppressed',
          details: `Pre-filtered ${templatePrefilterSuppressed.length} generic keyword signals in ${genericKeywordVetoMatch.archetypeId} context (${genericKeywordVetoMatch.matchedMarkers.slice(0, 3).join(', ')})`,
          affectedSignalIds: templatePrefilterSuppressed.map(s => s.id).filter((id): id is string => !!id),
        });
        stats.noiseSuppressed += templatePrefilterSuppressed.length;
      }
    }
  }

  // Step 1: Classify the document (using effective signals after template pre-filter)
  // AG-PROMPT-077: Pass filename for medical keyword detection
  const classification = classifyDocument(effectiveSignals, textContent, filename);

  // AG-PROMPT-187: Archetype-based class suppression (HARD VETO ONLY).
  // AG-PROMPT-188: Doctrine lock — this is binary veto, not score reduction.
  // If a strong archetype fires and the assigned class is in its veto list,
  // suppress the class. This affects only the class label and downstream framing.
  // Protected signals, severity floors, and signal truth are untouched.
  // No soft-veto, weighted suppression, or hybrid mode is permitted in this generation.
  if (classification.documentClass) {
    const classVetoMatch = archetypeMatches.find(m => {
      if (m.confidence !== 'strong') return false;
      const effects = getArchetypeEffects(m.archetypeId);
      return effects.mayVetoClasses?.includes(classification.documentClass!) ?? false;
    });
    if (classVetoMatch) {
      const suppressedClass = classification.documentClass;
      classification.documentClass = null;
      classification.baselineSeverity = null;
      classification.reason = `Class ${suppressedClass} suppressed by archetype ${classVetoMatch.archetypeId} (${classVetoMatch.matchedMarkers.slice(0, 3).join(', ')})`;
      auditLog.push({
        ruleId: 'AG-PROMPT-187-ARCHETYPE-CLASS-VETO',
        action: 'class_suppressed',
        details: `Suppressed ${suppressedClass} — archetype ${classVetoMatch.archetypeId} (confidence: ${classVetoMatch.confidence}, markers: ${classVetoMatch.markerCount})`,
        affectedSignalIds: [suppressedClass],
      });
    }
  }

  // AG-PROMPT-070, AG-PROMPT-077: Check for patient-level context
  // This is needed for medical record awareness escalation enforcement
  // AG-PROMPT-077 FIX: Now also checks filename for patient context keywords
  const signalIds = new Set(signals.map(s => s.id).filter((id): id is string => !!id));
  const patientContextFound = hasPatientContext(signalIds, textContent, filename);

  if (!classification.documentClass) {
    // No document class detected
    // AG-PROMPT-5 Item 7: Check for ticket context and suppress noise
    // AG-PROMPT-6 C1: Pass textContent for bank transfer safety hatch
    if (textContent && hasTicketContext(textContent)) {
      const ticketSuppressed: RiskSignal[] = [];
      const ticketFiltered = effectiveSignals.filter(signal => {
        if (isNoisyInTicketContext(signal, textContent)) {
          ticketSuppressed.push(signal);
          return false;
        }
        return true;
      });

      if (ticketSuppressed.length > 0) {
        auditLog.push({
          ruleId: DOCUMENT_CLASS_RULE_IDS.SUPPRESS_TICKET_NOISE,
          action: 'noise_suppressed',
          details: `Suppressed ${ticketSuppressed.length} noisy signals in ticket/travel document context`,
          affectedSignalIds: ticketSuppressed.map(s => s.id).filter((id): id is string => !!id),
        });
        stats.noiseSuppressed = ticketSuppressed.length;
      }

      stats.outputSignalCount = ticketFiltered.length;
      return {
        classification,
        signals: ticketFiltered,
        anchorSignal: null,
        suppressedSignals: [...templatePrefilterSuppressed, ...ticketSuppressed],
        auditLog,
        stats,
        hasPatientContext: patientContextFound,
        identityConfidence: 'none',
        archetypeMatches,
      };
    }

    // AG-DATA2-066: Check for resume context and veto M&A signals
    if (textContent && hasResumeContext(textContent)) {
      const resumeSuppressed: RiskSignal[] = [];
      const resumeFiltered = effectiveSignals.filter(signal => {
        if (shouldVetoMASignalInResume(signal, textContent)) {
          resumeSuppressed.push(signal);
          return false;
        }
        return true;
      });

      if (resumeSuppressed.length > 0) {
        auditLog.push({
          ruleId: 'AG-DATA2-066-RESUME-MA-VETO',
          action: 'noise_suppressed',
          details: `Vetoed ${resumeSuppressed.length} M&A signals in resume/CV context`,
          affectedSignalIds: resumeSuppressed.map(s => s.id).filter((id): id is string => !!id),
        });
        stats.noiseSuppressed = resumeSuppressed.length;
      }

      stats.outputSignalCount = resumeFiltered.length;
      return {
        classification,
        signals: resumeFiltered,
        anchorSignal: null,
        suppressedSignals: [...templatePrefilterSuppressed, ...resumeSuppressed],
        auditLog,
        stats,
        hasPatientContext: patientContextFound,
        identityConfidence: 'none',
        archetypeMatches,
      };
    }

    // No ticket context either - return effective signals (may have template pre-filter applied)
    stats.outputSignalCount = effectiveSignals.length;
    return {
      classification,
      signals: effectiveSignals,
      anchorSignal: null,
      suppressedSignals: templatePrefilterSuppressed,
      auditLog,
      stats,
      hasPatientContext: patientContextFound,
      identityConfidence: 'none',
      archetypeMatches,
    };
  }

  stats.classDetected = true;

  // Log classification
  auditLog.push({
    ruleId: getClassificationRuleId(classification.documentClass),
    action: 'classified',
    details: classification.reason,
    affectedSignalIds: classification.indicators.map(i => i.signalId),
  });

  // Step 2: Suppress noisy patterns
  const processedSignals: RiskSignal[] = [];
  const suppressedSignals: RiskSignal[] = [];

  for (const signal of effectiveSignals) {
    if (isNoisyInSensitiveDocument(signal, classification.documentClass, effectiveSignals)) {
      suppressedSignals.push(signal);
      stats.noiseSuppressed++;
    } else {
      processedSignals.push(signal);
    }
  }

  // Log noise suppression
  if (suppressedSignals.length > 0) {
    auditLog.push({
      ruleId: DOCUMENT_CLASS_RULE_IDS.SUPPRESS_CARD_NOISE,
      action: 'noise_suppressed',
      details: `Suppressed ${suppressedSignals.length} noisy signals in ${classification.documentClass}`,
      affectedSignalIds: suppressedSignals.map(s => s.id).filter((id): id is string => !!id),
    });
  }

  // Step 3: Create document class anchor signal
  // AG-PROMPT-DOCUMENT-IDENTITY-THRESHOLDS-026: Compute identity confidence
  const identityConf = computeIdentityConfidence(
    classification,
    patientContextFound,
    signals
  );
  const anchorSignal = createDocumentClassSignal(classification, identityConf);
  processedSignals.push(anchorSignal);

  // Log baseline floor application
  auditLog.push({
    ruleId: DOCUMENT_CLASS_RULE_IDS.BASELINE_FLOOR,
    action: 'floor_applied',
    details: `Applied baseline ${classification.baselineSeverity} for ${classification.documentClass}`,
  });
  stats.baselineApplied = true;

  stats.outputSignalCount = processedSignals.length;

  return {
    classification,
    signals: processedSignals,
    anchorSignal,
    suppressedSignals: [...templatePrefilterSuppressed, ...suppressedSignals],
    auditLog,
    stats,
    hasPatientContext: patientContextFound,
    identityConfidence: identityConf,
    archetypeMatches,
  };
}

/**
 * Create a RiskSignal for the document class anchor.
 *
 * AG-PROMPT-DOCUMENT-IDENTITY-THRESHOLDS-026: Uses identity-gated labels
 * based on corroboration level. Identity labels only shown when corroborated.
 */
function createDocumentClassSignal(
  classification: DocumentClassification,
  identityConfidence: IdentityConfidence = 'strong'
): RiskSignal {
  const docClass = classification.documentClass!;
  const baseline = classification.baselineSeverity!;

  // Use identity-gated labels based on corroboration
  const description = getIdentityGatedDocumentLabel(docClass, identityConfidence);
  const detail = getIdentityGatedDocumentHeadline(docClass, identityConfidence);

  return {
    id: docClass,
    type: 'sensitive',
    description,
    severity: baseline,
    detail,
    source: 'content',
    detectedAt: Date.now(),
  };
}

/**
 * Get the rule ID for a document class classification.
 */
function getClassificationRuleId(docClass: DocumentClass): string {
  switch (docClass) {
    case 'doc.payroll':
      return DOCUMENT_CLASS_RULE_IDS.CLASSIFY_PAYROLL;
    case 'doc.hr_record':
      return DOCUMENT_CLASS_RULE_IDS.CLASSIFY_HR_RECORD;
    case 'doc.medical_record':
      return DOCUMENT_CLASS_RULE_IDS.CLASSIFY_MEDICAL;
    case 'doc.legal_contract':
      return DOCUMENT_CLASS_RULE_IDS.CLASSIFY_LEGAL_CONTRACT;
    case 'doc.insurance_policy':
      return DOCUMENT_CLASS_RULE_IDS.CLASSIFY_INSURANCE_POLICY;
    case 'doc.invoice':
      return DOCUMENT_CLASS_RULE_IDS.CLASSIFY_INVOICE;
    case 'doc.health_certificate':
      return DOCUMENT_CLASS_RULE_IDS.CLASSIFY_HEALTH_CERTIFICATE;
  }
}

// ============================================================================
// SEVERITY FLOOR ENFORCEMENT
// ============================================================================

/**
 * Apply document class baseline floor to aggregated severity.
 *
 * Call this AFTER aggregateSeverity() to enforce the floor.
 *
 * @param aggregatedSeverity - The severity from aggregation
 * @param documentClass - The detected document class (or null)
 * @returns The effective severity (at least baseline if classified)
 */
export function applyBaselineFloor(
  aggregatedSeverity: Severity | 'none',
  documentClass: DocumentClass | null
): { severity: Severity | 'none'; elevated: boolean; reason: string } {
  if (!documentClass) {
    return {
      severity: aggregatedSeverity,
      elevated: false,
      reason: 'No document class detected',
    };
  }

  const baseline = DOCUMENT_CLASS_BASELINES[documentClass];
  const severityOrder: Array<Severity | 'none'> = ['none', 'low', 'medium', 'high', 'critical'];
  const aggregatedIndex = severityOrder.indexOf(aggregatedSeverity);
  const baselineIndex = severityOrder.indexOf(baseline);

  if (aggregatedIndex < baselineIndex) {
    return {
      severity: baseline,
      elevated: true,
      reason: `Elevated from ${aggregatedSeverity} to ${baseline} due to ${documentClass} baseline`,
    };
  }

  return {
    severity: aggregatedSeverity,
    elevated: false,
    reason: `Aggregated severity ${aggregatedSeverity} meets or exceeds ${documentClass} baseline`,
  };
}

// ============================================================================
// HELPER EXPORTS
// ============================================================================

/**
 * Check if a document class was detected.
 */
export function hasDocumentClass(result: DocumentClassResult): boolean {
  return result.classification.documentClass !== null;
}

/**
 * Get the baseline severity for a document class.
 */
export function getBaselineSeverity(docClass: DocumentClass): Severity {
  return DOCUMENT_CLASS_BASELINES[docClass];
}

/**
 * Get the label for a document class.
 */
export function getDocumentClassLabel(docClass: DocumentClass): string {
  return DOCUMENT_CLASS_LABELS[docClass];
}

/**
 * Get the headline for a document class.
 */
export function getDocumentClassHeadline(docClass: DocumentClass): string {
  return DOCUMENT_CLASS_HEADLINES[docClass];
}

/**
 * AG-PROMPT-DOCUMENT-IDENTITY-THRESHOLDS-026: Identity confidence type.
 */
export type IdentityConfidence = 'none' | 'weak' | 'strong';

/**
 * AG-PROMPT-DOCUMENT-IDENTITY-THRESHOLDS-026: Get identity-gated label.
 *
 * Returns identity label if confidence is strong, terminology label if weak.
 *
 * @param docClass - The document class
 * @param identityConfidence - The identity confidence level
 * @returns Appropriate label based on confidence
 */
export function getIdentityGatedDocumentLabel(
  docClass: DocumentClass,
  identityConfidence: IdentityConfidence
): string {
  if (identityConfidence === 'strong') {
    return DOCUMENT_CLASS_LABELS[docClass];
  }
  return DOCUMENT_CLASS_TERMINOLOGY_LABELS[docClass];
}

/**
 * AG-PROMPT-DOCUMENT-IDENTITY-THRESHOLDS-026: Get identity-gated headline.
 *
 * Returns identity headline if confidence is strong, terminology headline if weak.
 *
 * @param docClass - The document class
 * @param identityConfidence - The identity confidence level
 * @returns Appropriate headline based on confidence
 */
export function getIdentityGatedDocumentHeadline(
  docClass: DocumentClass,
  identityConfidence: IdentityConfidence
): string {
  if (identityConfidence === 'strong') {
    return DOCUMENT_CLASS_HEADLINES[docClass];
  }
  return DOCUMENT_CLASS_TERMINOLOGY_HEADLINES[docClass];
}

// ============================================================================
// EXPORTS
// ============================================================================

export {
  PAYROLL_INDICATORS,
  HR_RECORD_INDICATORS,
  MEDICAL_RECORD_INDICATORS,
  NOISY_PATTERNS,
};
