/**
 * Contextual Severity Cap (AG-PROMPT-152)
 *
 * STATUS: REFERENCE / NON-LIVE CODE (AG-PROMPT-164/WS-05)
 * Registered as a reserved/non-live surface in
 * docs/governance/AG-RESERVED-SURFACES.md (AG-PROMPT-211).
 * This module is NOT called from the live pipeline. The active aggregate
 * HR/finance cap and archetype-based severity capping are implemented
 * directly in the live path at src/content/index.ts (search for
 * "AGGREGATE HR/FINANCE SEVERITY CAP" and "SEVERITY LADDER CAPS").
 * The gold harness (scripts/run-gold-harness.ts) uses computeContextAwareSeverity()
 * for offline severity scoring, but this is NOT the production cap engine.
 *
 * When strong PII signals (national IDs, DOBs) appear alongside document-family
 * context signals, the document-level severity can be capped below the raw signal
 * maximum. This reflects that certain PII types are *expected* in specific document
 * families and should not drive maximum severity in those contexts.
 *
 * Design principles:
 * - Signals remain detected and visible (recall is never affected)
 * - Only the document-level severity interpretation is capped
 * - Caps only apply when BOTH a strong signal AND a family-context signal co-occur
 * - Standalone strong signals (no family context) remain at their original severity
 * - Secrets, credentials, and non-PII critical signals are NEVER capped
 */

// ============================================================================
// TYPES
// ============================================================================

export interface ContextualCapInput {
  /** All detected signals with id and severity */
  signals: ReadonlyArray<{ id: string; severity: string }>;
  /** Optional archetype matches from document text analysis */
  archetypes?: ReadonlyArray<{ archetypeId: string; confidence: string }>;
}

export interface ContextualCapResult {
  /** The capped severity (may equal rawMaxSeverity if no cap applied) */
  severity: string;
  /** Whether a cap was applied */
  capped: boolean;
  /** Human-readable reason for the cap */
  reason: string | null;
  /** The raw max severity before capping */
  rawMaxSeverity: string;
}

// ============================================================================
// CONSTANTS
// ============================================================================

const SEVERITY_ORDER = ['low', 'medium', 'high', 'critical'] as const;

/** National ID signal IDs that may be capped in context */
const NATIONAL_ID_SIGNALS = new Set([
  'global-national-id',
  'global-dk-cpr',
  'global-se-personnummer',
  'global-no-fnr',
  'global-fi-hetu',
  'global-de-steuer-id',
  'global-nl-bsn',
  'global-be-nrn',
  'global-fr-nir',
  'global-it-codice-fiscale',
  'global-es-nie',
  'global-pl-pesel',
  'global-pt-nif',
  'global-ro-cnp',
  'global-cz-rc',
  'global-sk-rc',
  'global-hu-taj',
  'global-br-cpf',
  'global-mx-rfc',
  'global-us-ssn',
  'global-uk-nin',
]);

/** Signals that NEVER get capped (secrets, credentials, M&A) */
const UNCAPPABLE_SIGNALS = new Set([
  'global-api-key-sk',
  'global-aws-access-key',
  'global-bearer-token',
  'global-private-key',
  'global-password-assignment',
  'global-url-query-credentials',
  'global-ma-terms',
]);

/** Medical context signals — indicate the document is a medical record */
const MEDICAL_CONTEXT = new Set([
  'registry-medical-content',
  'registry-icd10-code',
]);

/** Employment/HR context signals — indicate an employment document */
const EMPLOYMENT_CONTEXT = new Set([
  'registry-hr-employee',
  'english-hr-compensation',
  'english-hr-performance',
  'nordic-payroll-terms',
]);

/** Insurance context signals — indicate an insurance document */
const INSURANCE_CONTEXT = new Set([
  'global-insurance-terms',
  'global-insurance-policy-number',
]);

/** DOB signal that may be capped in insurance context */
const DOB_SIGNALS = new Set([
  'global-dob',
]);

/** Incidental financial signals that are low-risk in resume/CV context */
const INCIDENTAL_FINANCIAL_SIGNALS = new Set([
  'global-swift',
  'nordic-financial-terms',
  'english-financial-statement',
]);

// ============================================================================
// CORE LOGIC
// ============================================================================

function sevIndex(sev: string): number {
  return SEVERITY_ORDER.indexOf(sev as typeof SEVERITY_ORDER[number]);
}

function maxSev(a: string, b: string): string {
  return sevIndex(a) >= sevIndex(b) ? a : b;
}

/**
 * Compute a context-aware severity that accounts for document family.
 *
 * When a national ID (critical) co-occurs with medical, employment, or insurance
 * context signals, the document-level severity is capped at HIGH. This reflects
 * that national IDs are *expected* in these document families, and the overall
 * document risk is high but not critical.
 *
 * Signals that are never capped (secrets, credentials) bypass this logic entirely.
 */
export function computeContextAwareSeverity(input: ContextualCapInput): ContextualCapResult {
  const { signals, archetypes } = input;

  // Step 1: Compute raw max severity
  let rawMax = 'low';
  for (const s of signals) {
    rawMax = maxSev(rawMax, s.severity);
    if (rawMax === 'critical') break;
  }

  // Step 2: If no signals, return immediately
  if (signals.length === 0) {
    return { severity: rawMax, capped: false, reason: null, rawMaxSeverity: rawMax };
  }

  // Step 3: Check if any uncappable signal is present at critical
  const hasUncappableCritical = signals.some(
    s => s.severity === 'critical' && UNCAPPABLE_SIGNALS.has(s.id)
  );
  if (hasUncappableCritical) {
    return { severity: 'critical', capped: false, reason: null, rawMaxSeverity: 'critical' };
  }

  const signalIds = new Set(signals.map(s => s.id));
  const archetypeIds = new Set((archetypes ?? []).map(a => a.archetypeId));

  // === CRITICAL → HIGH: National IDs in document family context ===
  if (rawMax === 'critical') {
    const criticalSignals = signals.filter(s => s.severity === 'critical');
    const allCriticalAreNationalId = criticalSignals.every(
      s => NATIONAL_ID_SIGNALS.has(s.id)
    );
    if (!allCriticalAreNationalId) {
      return { severity: 'critical', capped: false, reason: null, rawMaxSeverity: 'critical' };
    }

    const hasMedicalSignal = [...MEDICAL_CONTEXT].some(id => signalIds.has(id));
    const hasMedicalArchetype = archetypeIds.has('medical_record') || archetypeIds.has('medical_health');
    const hasMedical = hasMedicalSignal || hasMedicalArchetype;
    const hasEmployment = [...EMPLOYMENT_CONTEXT].some(id => signalIds.has(id));
    const hasInsurance = [...INSURANCE_CONTEXT].some(id => signalIds.has(id));

    if (hasMedical || hasEmployment || hasInsurance) {
      const context = hasMedical ? 'medical' : hasEmployment ? 'employment' : 'insurance';
      return {
        severity: 'high',
        capped: true,
        reason: `National ID severity capped to HIGH in ${context} document context (expected PII)`,
        rawMaxSeverity: 'critical',
      };
    }

    // No document context — national ID in isolation remains critical
    return { severity: 'critical', capped: false, reason: null, rawMaxSeverity: 'critical' };
  }

  // === HIGH → MEDIUM: DOB in insurance context ===
  // DOB is expected in insurance documents (coverage dates, age-based policies).
  // When insurance context is present and DOB is the only HIGH driver, cap to medium.
  if (rawMax === 'high') {
    const highSignals = signals.filter(s => s.severity === 'high');
    const allHighAreDob = highSignals.every(s => DOB_SIGNALS.has(s.id));
    const hasInsurance = [...INSURANCE_CONTEXT].some(id => signalIds.has(id));

    if (allHighAreDob && hasInsurance) {
      return {
        severity: 'medium',
        capped: true,
        reason: 'DOB severity capped to MEDIUM in insurance document context (expected data)',
        rawMaxSeverity: 'high',
      };
    }
  }

  // === MEDIUM → LOW: Incidental financial signals in resume/CV archetype ===
  // SWIFT codes and financial terms are incidental noise in CVs (bank details
  // sections, financial experience mentions). When a resume_cv archetype is
  // detected and ONLY incidental financial signals drive medium, cap to low.
  if (rawMax === 'medium' && archetypeIds.has('resume_cv')) {
    const mediumSignals = signals.filter(s => s.severity === 'medium');
    const allMediumAreIncidentalFinancial = mediumSignals.every(
      s => INCIDENTAL_FINANCIAL_SIGNALS.has(s.id)
    );

    if (allMediumAreIncidentalFinancial) {
      return {
        severity: 'low',
        capped: true,
        reason: 'Incidental financial signals capped to LOW in resume/CV context',
        rawMaxSeverity: 'medium',
      };
    }
  }

  // No cap applicable
  return { severity: rawMax, capped: false, reason: null, rawMaxSeverity: rawMax };
}
