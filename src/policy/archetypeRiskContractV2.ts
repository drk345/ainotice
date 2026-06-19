/**
 * AG-ARCHETYPE-RISK-CONTRACT-V2-CALIBRATION-AND-VERIFICATION-075
 *
 * Archetype Risk Contract v2 - DATA ONLY
 *
 * This file contains ONLY data definitions with no logic.
 * It is the machine-readable mirror of docs/policy/archetype-risk-contract-v2.md
 *
 * DO NOT add business logic here. This is configuration data.
 *
 * CORE PRINCIPLES:
 * - Signals are facts, not judgment
 * - Archetypes define expectation, not suppression
 * - Identity signals are never hidden
 * - Anchors override all de-escalation
 * - No ML, no probabilistic inference
 *
 * SEVERITY PHILOSOPHY:
 * - CRITICAL: Confidence-gated — reachable by secrets, validated payment cards, and confirmed-confidence signals
 * - HIGH: Identity anchors (national ID, passport, personal financial)
 * - MEDIUM: Confidential-by-nature documents
 * - LOW: Expected/public-ish/transactional
 */

import type { DocumentArchetypeId } from './documentArchetypes';

// ============================================================================
// TYPES
// ============================================================================

/**
 * Severity levels in ascending order.
 */
export type SeverityLevel = 'none' | 'low' | 'medium' | 'high' | 'critical';

/**
 * Mobility determines how archetype baseline interacts with signal severity.
 *
 * - downward_noop: Theoretically allows de-escalation, but NOT IMPLEMENTED (safety).
 *                  Treated as neutral in practice until proven safe and test-covered.
 * - neutral: Baseline is informational; no de-escalation
 * - upward: Baseline is a FLOOR; signals can only raise severity
 * - static: No movement allowed; baseline IS the minimum
 *
 * NOTE: 'downward' is deprecated. Use 'downward_noop' to make no-op explicit.
 */
export type SeverityMobility = 'downward' | 'downward_noop' | 'neutral' | 'upward' | 'static';

/**
 * Signal group identifiers for anchor rules.
 *
 * NOTE: minor_sensitive is defined but EMPTY - no deterministic signals exist.
 * This is explicitly marked as FUTURE work. Do NOT fake it with NER/keywords.
 */
export type SignalGroup =
  | 'identity_strong'
  | 'identity_basic'
  | 'health_sensitive'
  | 'financial_sensitive'
  | 'employment_sensitive'
  | 'minor_sensitive';  // FUTURE: No deterministic signals exist yet

/**
 * Anchor rule: when signals from specified groups are present, enforce minimum severity.
 */
export interface AnchorRule {
  /** Signal groups that trigger this anchor (ANY match triggers) */
  whenPresent: SignalGroup[];
  /** If true, ALL groups must be present (AND logic); otherwise ANY (OR logic) */
  requireAll?: boolean;
  /** Minimum severity to enforce when anchor fires */
  minSeverity: SeverityLevel;
}

/**
 * Complete risk contract for an archetype.
 */
export interface ArchetypeRiskContract {
  /** Archetype identifier */
  archetypeId: DocumentArchetypeId;
  /** Human-readable name */
  name: string;
  /** Default severity when archetype detected without strong signals */
  baselineSeverity: SeverityLevel;
  /** How baseline interacts with signal severity */
  mobility: SeverityMobility;
  /** Anchor rules that enforce minimum severity floors */
  anchors: AnchorRule[];
  /** Signal groups that may be de-escalated in this context (only when mobility=downward) */
  allowedDeescalation: SignalGroup[];
  /** Invariants that must always hold (for documentation/testing) */
  invariants: string[];
}

// ============================================================================
// SIGNAL GROUP MAPPINGS (Real Signal IDs from this codebase)
// ============================================================================

/**
 * Map signal groups to actual signal IDs used in AgentGuard.
 * This is the AUTHORITATIVE mapping between contract concepts and implementation.
 */
export const SIGNAL_GROUP_MEMBERS: Record<SignalGroup, readonly string[]> = {
  identity_strong: [
    'global-national-id',
    'global-dk-cpr',
    'global-se-personnummer',
    'global-no-fnr',
    'registry-ssn-us',
    'registry-dk-cpr',
    'registry-se-personnummer',
    'registry-no-fnr',
  ],
  identity_basic: [
    'global-email',
    'english-phone-us-formatted',
    'english-phone-intl-prefix',
    'english-phone-uk-format',
    'nordic-phone-dk-intl',
    'nordic-phone-se-intl',
    'nordic-phone-no-intl',
    'nordic-phone-fi-intl',
    'nordic-phone-labeled',
  ],
  health_sensitive: [
    'registry-medical-content',
    'registry-icd10-code',
    'english-health-phi',
  ],
  financial_sensitive: [
    'global-iban',
    'global-credit-card',
    'registry-credit-card-spaced',
    'global-swift',
  ],
  employment_sensitive: [
    'registry-hr-employee',
    'english-hr-compensation',
    'english-hr-performance',
    'nordic-payroll-terms',
    'nordic-hr-terms',
  ],
  // FUTURE: No deterministic minor signals exist. Do NOT add NER/keyword-based signals.
  // This group is reserved for future work when proper minor detection exists.
  minor_sensitive: [],
} as const;

/**
 * Reverse lookup: signal ID → signal groups it belongs to.
 * Built at module load time for O(1) lookups.
 */
export const SIGNAL_TO_GROUPS: Map<string, SignalGroup[]> = new Map();

// Build reverse mapping
for (const [group, signalIds] of Object.entries(SIGNAL_GROUP_MEMBERS)) {
  for (const signalId of signalIds) {
    const existing = SIGNAL_TO_GROUPS.get(signalId) || [];
    existing.push(group as SignalGroup);
    SIGNAL_TO_GROUPS.set(signalId, existing);
  }
}

// ============================================================================
// ARCHETYPE RISK CONTRACTS (Frozen Data)
// ============================================================================

/**
 * Risk contract for resume_cv archetype.
 *
 * Framing: Informational - standard recruitment identifiers expected.
 */
export const RESUME_CV_CONTRACT: ArchetypeRiskContract = {
  archetypeId: 'resume_cv',
  name: 'Resume/CV',
  baselineSeverity: 'low',
  mobility: 'downward_noop',  // De-escalation not implemented (safety)
  anchors: [
    {
      whenPresent: ['identity_strong'],
      minSeverity: 'high',
    },
    {
      // Global safety override: health_sensitive alone → CRITICAL
      whenPresent: ['health_sensitive'],
      minSeverity: 'critical',
    },
    // FUTURE: minor_sensitive would anchor to critical when deterministic signals exist
  ],
  allowedDeescalation: ['identity_basic'],  // Allowed but NOT IMPLEMENTED
  invariants: [
    'Identity signals are ALWAYS visible in output',
    'M&A signals may be vetoed (existing behavior)',
    'No suppression of identity_strong signals',
    'Never reduce below LOW if only identity_basic present',
  ],
};

/**
 * Risk contract for ticket_booking archetype.
 *
 * Framing: Administrative - transactional data detected; avoid panic for names alone.
 *
 * IBAN HANDLING: IBAN may be suppressed to NONE in tickets ONLY when:
 * - Ticket markers are strong AND
 * - Anti-scam hatch remains active (existing behavior)
 * This contract does NOT force HIGH for IBAN alone; requires payment card or identity.
 */
export const TICKET_BOOKING_CONTRACT: ArchetypeRiskContract = {
  archetypeId: 'ticket_booking',
  name: 'Ticket/Booking',
  baselineSeverity: 'low',
  mobility: 'downward_noop',  // De-escalation not implemented (safety)
  anchors: [
    {
      whenPresent: ['identity_strong'],
      minSeverity: 'high',
    },
    // NOTE: financial_sensitive anchor REMOVED for IBAN alone.
    // Payment card (global-credit-card) still forces HIGH via signal severity.
    // IBAN alone in tickets is handled by existing ticket suppressor.
  ],
  allowedDeescalation: ['identity_basic', 'financial_sensitive'],  // Allowed but NOT IMPLEMENTED
  invariants: [
    'Payment card signals force HIGH (via signal severity)',
    'Passport/national ID forces HIGH (via anchor)',
    'IBAN may be suppressed by existing ticket suppressor (scam safety hatch)',
    'Never suppress identity_strong signals',
  ],
};

/**
 * Risk contract for invoice_receipt archetype.
 *
 * Framing: Commercial - business-related identifiers; risk depends on personal vs business context.
 *
 * IBAN CORROBORATION:
 * - IBAN alone does NOT force HIGH
 * - IBAN + personal context (identity_basic or identity_strong) → HIGH
 * - B2B markers (VAT, org number, company suffixes) suppress forced HIGH
 *
 * NOTE: B2B detection uses deterministic markers only, NOT NER.
 */
export const INVOICE_RECEIPT_CONTRACT: ArchetypeRiskContract = {
  archetypeId: 'invoice_receipt',
  name: 'Invoice/Receipt',
  baselineSeverity: 'low',
  mobility: 'neutral',
  anchors: [
    {
      whenPresent: ['identity_strong'],
      minSeverity: 'high',
    },
    // NOTE: IBAN + identity_basic corroboration is handled in severityAggregation.ts
    // This anchor only covers identity_strong (national IDs).
  ],
  allowedDeescalation: ['identity_basic'],  // For clearly B2B contexts (NOT IMPLEMENTED)
  invariants: [
    'Business context does not hide personal IDs',
    'IBAN + personal context → HIGH',
    'IBAN + strong B2B markers → NOT forced HIGH',
    'Do not attempt B2B vs B2C inference via NER',
  ],
};

/**
 * Risk contract for employment_hr archetype.
 *
 * Framing: Confidential - internal HR sensitivity even with basic identifiers.
 */
export const EMPLOYMENT_HR_CONTRACT: ArchetypeRiskContract = {
  archetypeId: 'employment_hr',
  name: 'Employment/HR',
  baselineSeverity: 'medium',
  mobility: 'upward',
  anchors: [
    {
      whenPresent: ['employment_sensitive'],
      minSeverity: 'high',
    },
    {
      whenPresent: ['identity_strong'],
      minSeverity: 'high',
    },
    {
      // Global safety override: health disclosure in HR = CRITICAL
      whenPresent: ['health_sensitive'],
      minSeverity: 'critical',
    },
  ],
  allowedDeescalation: [],  // Never reduce below MEDIUM
  invariants: [
    'Internal document presumption',
    'Salary/compensation = HIGH',
    'Employee medical disclosure = CRITICAL',
    'Never reduce below MEDIUM',
  ],
};

/**
 * Risk contract for insurance archetype.
 *
 * Framing: Variable - depends on whether claims/health information is present.
 */
export const INSURANCE_CONTRACT: ArchetypeRiskContract = {
  archetypeId: 'insurance',
  name: 'Insurance',
  baselineSeverity: 'medium',
  mobility: 'upward',
  anchors: [
    {
      whenPresent: ['identity_strong'],
      minSeverity: 'high',
    },
    {
      // Global safety override: health-related insurance = CRITICAL
      whenPresent: ['health_sensitive'],
      minSeverity: 'critical',
    },
  ],
  allowedDeescalation: [],  // Never reduce below MEDIUM
  invariants: [
    'Medical data drives severity to critical',
    'Car/property insurance without health = medium',
    'No attempt to split car vs health insurance by filename heuristics',
  ],
};

/**
 * Risk contract for medical_record archetype (CANONICAL).
 *
 * Framing: Protected - medical context. Treat sharing as highly sensitive.
 *
 * This is the CANONICAL medical archetype. Use this ID for new code.
 */
export const MEDICAL_RECORD_CONTRACT: ArchetypeRiskContract = {
  archetypeId: 'medical_record',
  name: 'Medical Record',
  baselineSeverity: 'high',
  mobility: 'static',
  anchors: [
    {
      // Patient identity + health content = CRITICAL
      whenPresent: ['health_sensitive', 'identity_basic'],
      requireAll: true,
      minSeverity: 'critical',
    },
    {
      // Strong identity alone in medical context = CRITICAL
      whenPresent: ['health_sensitive', 'identity_strong'],
      requireAll: true,
      minSeverity: 'critical',
    },
  ],
  allowedDeescalation: [],  // NEVER reduce - static mobility
  invariants: [
    'NO de-escalation allowed - medical is always HIGH minimum',
    'Patient identity + diagnosis = CRITICAL',
    'Never reduce below HIGH',
  ],
};

/**
 * Risk contract for medical_health archetype (DEPRECATED ALIAS).
 *
 * @deprecated Use medical_record instead. This alias exists for backward compatibility.
 *
 * Shares the same contract as medical_record.
 */
export const MEDICAL_HEALTH_CONTRACT: ArchetypeRiskContract = {
  ...MEDICAL_RECORD_CONTRACT,
  archetypeId: 'medical_health',
  name: 'Medical/Health (deprecated alias)',
};

/**
 * Risk contract for education_school archetype.
 *
 * Framing: Protective - student records can involve minors and sensitive evaluations.
 */
export const EDUCATION_SCHOOL_CONTRACT: ArchetypeRiskContract = {
  archetypeId: 'education_school',
  name: 'Education/School',
  baselineSeverity: 'medium',
  mobility: 'upward',
  anchors: [
    {
      whenPresent: ['identity_strong'],
      minSeverity: 'high',
    },
    // FUTURE: minors_sensitive would anchor to critical
    // Currently no deterministic minor signals exist.
    // Do NOT fake this with NER/keywords.
    {
      // Health notes in school records = CRITICAL (special needs, etc.)
      whenPresent: ['health_sensitive'],
      minSeverity: 'critical',
    },
  ],
  allowedDeescalation: [],  // Never reduce below MEDIUM
  invariants: [
    'Protective framing for potential minor data',
    'High duty of care assumed',
    'Special needs / health notes = CRITICAL',
    'Never reduce below MEDIUM',
  ],
};

/**
 * AG-PROMPT-155: Risk contract for template_governance archetype.
 *
 * Framing: Governance document — describes data processing activities, not actual personal data.
 * Generic keyword suppression handles HR/M&A/financial noise in documentClassAnchors.ts.
 */
export const TEMPLATE_GOVERNANCE_CONTRACT: ArchetypeRiskContract = {
  archetypeId: 'template_governance',
  name: 'Governance/Compliance Template',
  baselineSeverity: 'none',
  mobility: 'downward_noop',
  anchors: [
    {
      whenPresent: ['identity_strong'],
      minSeverity: 'high',
    },
    {
      whenPresent: ['health_sensitive'],
      minSeverity: 'critical',
    },
  ],
  allowedDeescalation: [],
  invariants: [
    'Generic HR/M&A/financial keywords are suppressed (they describe processing, not data)',
    'Identity, national-id, email, phone, payment signals are NEVER suppressed',
    'If real PII is present in a template, it still fires normally',
  ],
};

/**
 * AG-PROMPT-162-3A: Risk contract for policy_standard archetype.
 *
 * Framing: Information security policy, data protection policy, acceptable use policy.
 * These documents DESCRIBE rules about data handling — they don't contain actual personal data.
 * Same suppression logic as template_governance: generic keywords are noise.
 */
export const POLICY_STANDARD_CONTRACT: ArchetypeRiskContract = {
  archetypeId: 'policy_standard',
  name: 'Policy / Standard Document',
  baselineSeverity: 'none',
  mobility: 'downward_noop',
  anchors: [
    {
      whenPresent: ['identity_strong'],
      minSeverity: 'high',
    },
    {
      whenPresent: ['health_sensitive'],
      minSeverity: 'critical',
    },
  ],
  allowedDeescalation: [],
  invariants: [
    'Generic HR/M&A/financial keywords are suppressed (they describe processing, not data)',
    'Identity, national-id, email, phone, payment signals are NEVER suppressed',
    'If real PII is present in a policy document, it still fires normally',
  ],
};

/**
 * AG-PROMPT-162-AREA1: Risk contract for clinical_reference archetype.
 *
 * Framing: Clinical reference material (drug guides, treatment protocols, ICD code tables).
 * These documents describe medical knowledge, not patient data.
 * The clinicalReferenceBypass skips medical escalation UNLESS real PII is detected
 * within a 500-char window of medical terms.
 */
export const CLINICAL_REFERENCE_CONTRACT: ArchetypeRiskContract = {
  archetypeId: 'clinical_reference',
  name: 'Clinical Reference Material',
  baselineSeverity: 'none',
  mobility: 'downward_noop',
  anchors: [
    {
      whenPresent: ['identity_strong'],
      minSeverity: 'high',
    },
    {
      whenPresent: ['health_sensitive'],
      minSeverity: 'critical',
    },
  ],
  allowedDeescalation: [],
  invariants: [
    'Medical reference content without patient PII does not trigger medical escalation',
    'Real patient identifiers (name+DOB, SSN near diagnosis) still escalate',
    'Clinical terminology alone is NOT evidence of patient data',
  ],
};

/**
 * AG-PROMPT-162-2A: Risk contract for aggregate_hr_finance archetype.
 *
 * Framing: Aggregate report — headcount summaries, budget dashboards, workforce analytics.
 * These documents describe aggregate metrics, not individual employee data.
 * Severity capped at medium when no protected PII signals are present.
 */
export const AGGREGATE_HR_FINANCE_CONTRACT: ArchetypeRiskContract = {
  archetypeId: 'aggregate_hr_finance',
  name: 'Aggregate HR/Finance Report',
  baselineSeverity: 'none',
  mobility: 'downward_noop',
  anchors: [
    {
      whenPresent: ['identity_strong'],
      minSeverity: 'high',
    },
  ],
  allowedDeescalation: [],
  invariants: [
    'Severity capped at medium when only generic HR/financial keywords are present',
    'Individual PII (SSN, name+salary, national ID) overrides the cap',
    'Generic HR/financial keywords are suppressed (they describe metrics, not data)',
  ],
};

/**
 * All archetype contracts indexed by archetype ID.
 *
 * NOTE: medical_record is CANONICAL; medical_health is a deprecated alias.
 * Both map to equivalent contracts for backward compatibility.
 */
export const ARCHETYPE_CONTRACTS: Record<DocumentArchetypeId, ArchetypeRiskContract> = {
  resume_cv: RESUME_CV_CONTRACT,
  ticket_booking: TICKET_BOOKING_CONTRACT,
  invoice_receipt: INVOICE_RECEIPT_CONTRACT,
  medical_record: MEDICAL_RECORD_CONTRACT,      // CANONICAL
  medical_health: MEDICAL_HEALTH_CONTRACT,      // DEPRECATED ALIAS
  legal_authority: RESUME_CV_CONTRACT,          // Uses resume rules (low baseline, downward_noop)
  employment_hr: EMPLOYMENT_HR_CONTRACT,
  insurance: INSURANCE_CONTRACT,
  education_school: EDUCATION_SCHOOL_CONTRACT,
  template_governance: TEMPLATE_GOVERNANCE_CONTRACT,
  policy_standard: POLICY_STANDARD_CONTRACT,
  clinical_reference: CLINICAL_REFERENCE_CONTRACT,
  aggregate_hr_finance: AGGREGATE_HR_FINANCE_CONTRACT,
};

// ============================================================================
// SEVERITY UTILITIES (Data only - no logic)
// ============================================================================

/**
 * Severity levels in ascending order for comparison.
 */
export const SEVERITY_ORDER: readonly SeverityLevel[] = [
  'none',
  'low',
  'medium',
  'high',
  'critical',
] as const;

/**
 * Numeric index for severity comparison.
 */
export const SEVERITY_INDEX: Record<SeverityLevel, number> = {
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

// ============================================================================
// GLOBAL CONTRACT RULES (Documented assertions)
// ============================================================================

/**
 * Contract rules that apply globally.
 * These are documented assertions, not runtime checks.
 *
 * Priority order (highest first):
 * 1. CRITICAL overrides everything
 * 2. HIGH identity anchors override low-baseline archetypes
 * 3. Archetype baseline floors (e.g., employment_hr => >= medium)
 * 4. Signal max severity (aggregateSeverity) remains auditable fact layer
 * 5. Never suppress protected signals
 */
export const GLOBAL_CONTRACT_RULES = [
  'Archetypes do not remove detected signals',
  'Framing changes tone, not detection',
  'Anchors override archetype baseline',
  'Absence of archetype means neutral context — pure signal-driven assessment',
  'Protected signals (identity_strong, health_sensitive) are never hidden',
  'CRITICAL is confidence-gated — reachable by secrets, validated payment cards, and confirmed-confidence signals',
  'HIGH reserved for identity anchors (national ID, passport, personal financial)',
  'Downward mobility is NO-OP until proven safe and test-covered',
  'Multiple archetypes → take maximum severity (most conservative)',
] as const;

/**
 * Non-goals of this contract.
 * These are explicitly out of scope.
 */
export const CONTRACT_NON_GOALS = [
  'Fraud detection — we detect data governance risk, not malicious intent',
  'Intent inference',
  'Behavioral prediction',
  'ML-based entity recognition',
  'Name/address detection (would require NER)',
  'B2B vs B2C inference via NER — use deterministic markers only',
  'Minor detection via keywords — requires deterministic signals (FUTURE)',
] as const;

/**
 * IBAN corroboration rules.
 * IBAN alone does NOT force HIGH severity.
 */
export const IBAN_CORROBORATION_RULES = {
  /** IBAN forces HIGH only when personal context is present */
  requiresPersonalContext: true,
  /** Signal groups that indicate personal context */
  personalContextGroups: ['identity_basic', 'identity_strong'] as SignalGroup[],
  /** B2B markers that suppress forced HIGH (deterministic only) */
  b2bMarkerPatterns: [
    /\bVAT\b/i,
    /\bCVR\b/i,        // Danish company number
    /\bOrg\.?\s*(?:nr|nummer)\b/i,  // Scandinavian org number
    /\bInc\b/i,
    /\bLtd\b/i,
    /\bGmbH\b/i,
    /\bApS\b/i,        // Danish
    /\bA\/S\b/i,       // Danish
    /\bAB\b/,          // Swedish (case-sensitive)
    /\bAS\b/,          // Norwegian (case-sensitive)
    /\bSARL\b/i,       // French
    /\bSL\b/,          // Spanish (case-sensitive)
    /\bAG\b/,          // German/Swiss (case-sensitive)
  ],
} as const;
