import {
  SIG_CREDIT_CARD_SPACED, SIG_LEGACY_CREDIT_CARD, SIG_HR_EMPLOYEE,
  SIG_MEDICAL_CONTENT, SIG_ICD10_CODE, SIG_NATIONAL_ID,
  SIG_LEGACY_DK_CPR, SIG_LEGACY_SE_PERSONNUMMER, SIG_LEGACY_NO_FNR, SIG_LEGACY_FI_HETU,
} from '../detection/signalManifest';

/**
 * AgentGuard Signal Dominance Resolution (AG-PROMPT-078)
 *
 * When multiple regulated signals are detected, ensures the user-facing
 * explanation reflects the most plausible domain-correct risk rather than
 * a technically matched but misleading signal.
 *
 * Problem: In HR/legal documents, numeric patterns (e.g. CPR numbers) are
 * sometimes misclassified as payment card signals, resulting in incorrect
 * "Payment card" explanations even though the dominant risk is HR/legal.
 *
 * Solution: Signal dominance resolution step before building explanations:
 * - When document context indicates HR/legal/medical, prefer those signals
 * - financial.card / pii.credit_card are deprioritized in these contexts
 * - Does NOT suppress signals internally (kept for logging/analytics)
 * - Only adjusts which signal is surfaced as primary explanation
 *
 * Rules:
 * 1. Document class HR/payroll/contract → prefer HR/PII signals over financial.card
 * 2. Document class medical → prefer medical/PII signals over financial.card
 * 3. No document class or financial context → no change (all signals equal)
 * 4. True payment card documents still surface financial.card
 *
 * @see AG-PROMPT-078: Regulated Signal Dominance & Explanation Correction
 */

import type { DocumentClass } from './documentClassAnchors';

// ============================================================================
// TYPES
// ============================================================================

/**
 * Input for signal dominance resolution.
 */
export interface SignalDominanceInput {
  /** Signal IDs at the driving severity level */
  drivingSignalIds: string[];

  /** Document class (if classified) */
  documentClass: DocumentClass | null;

  /** All signal IDs for context (not just driving) */
  allSignalIds?: string[];

  /** AG-PROMPT-080: Text content for context inference when docClass is null */
  textContent?: string;
}

/**
 * Result of signal dominance resolution.
 */
export interface SignalDominanceResult {
  /** Reordered driving signal IDs (preferred first) */
  prioritizedSignalIds: string[];

  /** Whether any reordering was applied */
  reordered: boolean;

  /** Which signal was promoted to primary (if any) */
  promotedSignal: string | null;

  /** Which signal was demoted (if any) */
  demotedSignal: string | null;

  /** Rule that was applied */
  ruleId: string;

  /** Human-readable reason */
  reason: string;
}

// ============================================================================
// SIGNAL CATEGORIES
// ============================================================================

/**
 * Signal IDs that indicate payment card detection.
 * These may be false positives in HR/legal contexts.
 */
const FINANCIAL_CARD_SIGNALS = new Set([
  'financial.credit_card',
  'pii.credit_card',
  SIG_CREDIT_CARD_SPACED,
  SIG_LEGACY_CREDIT_CARD,
]);

/**
 * Signal IDs that indicate HR/personnel/employment context.
 * These should be preferred over card signals in HR documents.
 */
const HR_PERSONNEL_SIGNALS = new Set([
  'pii.employee',
  'pii.compensation',
  'hr-compensation',
  'hr-performance',
  'hr-medical',
  'hr.employee_data',
  SIG_HR_EMPLOYEE,
  'doc.payroll',
  'doc.hr_record',
]);

/**
 * Signal IDs that indicate legal/contract context.
 * AG-PROMPT-097C: Added doc.legal_contract document class.
 */
const LEGAL_CONTRACT_SIGNALS = new Set([
  'legal.contract',
  'legal.agreement',
  'legal.nda',
  'legal.privileged',
  'doc.legal_contract',  // AG-PROMPT-097C: Document class from structural inference
]);

/**
 * Signal IDs that indicate medical context.
 */
const MEDICAL_SIGNALS = new Set([
  'doc.medical_record',
  'hr-medical',
  SIG_MEDICAL_CONTENT,
  SIG_ICD10_CODE,
  'COA-001-icd-standalone',
  'COA-002-unit-cluster',
  'COA-003-unit-range-proximity',
]);

/**
 * Signal IDs that indicate PII (personal identifiable information).
 * These should be preferred over card signals in personnel documents.
 */
const PII_SIGNALS = new Set([
  SIG_NATIONAL_ID,
  'pii.ssn',
  'pii.ssn_us',
  'pii.national_id',
  'pii.name',
  'pii.phone',
  'pii.email',
  'pii.address',
  SIG_LEGACY_DK_CPR,
  SIG_LEGACY_SE_PERSONNUMMER,
  SIG_LEGACY_NO_FNR,
  SIG_LEGACY_FI_HETU,
]);

// ============================================================================
// TEXT-BASED CONTEXT INFERENCE (AG-PROMPT-080)
// ============================================================================

/**
 * Keywords that strongly indicate HR/employment context.
 * Used when document classification fails but text clearly indicates HR content.
 */
const HR_CONTEXT_PATTERNS: RegExp[] = [
  /\bemployment\s*agreement\b/i,
  /\bemployee\s*number\b/i,
  /\bhr\s*service\s*cent(re|er)\b/i,
  /\bpeople\s*services?\b/i,
  /\bcompensation\s*&?\s*benefits\b/i,
  /\bemployment\s*contract\b/i,
  /\bsalary\b/i,
  /\bbonus\b/i,
  /\bonnboarding\b/i,
  /\btermination\b/i,
  /\bprobation(ary)?\s*period\b/i,
];

/**
 * Keywords that strongly indicate legal/contract context.
 */
const LEGAL_CONTEXT_PATTERNS: RegExp[] = [
  /\bdocusign\s*envelope\s*id\b/i,
  /\bsigned\s*(?:by|on)\b/i,
  /\bcontract(?:ual)?\s*(?:terms?|agreement)\b/i,
  /\bwhereas\b/i,
  /\bhereby\b/i,
  /\bindemnif(?:y|ication)\b/i,
  /\bjurisdiction\b/i,
  /\bgoverning\s*law\b/i,
  /\bconfidential(?:ity)?\s*(?:agreement|clause)\b/i,
];

/**
 * Pattern for Danish CPR numbers (used to infer PII context).
 */
const CPR_PATTERN = /\b\d{6}-?\d{4}\b/;

/**
 * Inferred context type from text analysis.
 */
export type InferredContext = 'hr' | 'legal' | 'pii' | null;

/**
 * Infer document context from text content.
 * AG-PROMPT-080: Used when formal document classification returns null
 * but text clearly indicates HR/legal/PII content.
 *
 * @param text - Text content to analyze
 * @returns Inferred context type or null
 */
export function inferContextFromText(text: string | undefined): {
  context: InferredContext;
  matchedPatterns: string[];
} {
  if (!text) {
    return { context: null, matchedPatterns: [] };
  }

  const matchedPatterns: string[] = [];

  // Check HR context patterns
  let hrMatches = 0;
  for (const pattern of HR_CONTEXT_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(text)) {
      hrMatches++;
      matchedPatterns.push(`hr:${pattern.source.slice(0, 30)}`);
    }
  }

  // Check legal context patterns
  let legalMatches = 0;
  for (const pattern of LEGAL_CONTEXT_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(text)) {
      legalMatches++;
      matchedPatterns.push(`legal:${pattern.source.slice(0, 30)}`);
    }
  }

  // Check for CPR-like pattern (Danish national ID)
  const hasCPR = CPR_PATTERN.test(text);
  if (hasCPR) {
    matchedPatterns.push('pii:cpr-like-pattern');
  }

  // Determine context: HR context if 2+ HR patterns OR 1 HR + 1 legal (contract)
  // Legal context if 2+ legal patterns
  // PII context if CPR found with at least 1 HR or legal pattern
  // (CPR alone without HR/legal context might be a legitimate financial identifier)
  if (hrMatches >= 2 || (hrMatches >= 1 && legalMatches >= 1)) {
    return { context: 'hr', matchedPatterns };
  }
  if (legalMatches >= 2) {
    return { context: 'legal', matchedPatterns };
  }
  // Single HR pattern + CPR = HR context (employment document)
  if (hrMatches >= 1 && hasCPR) {
    return { context: 'hr', matchedPatterns };
  }
  // Single legal pattern + CPR = legal context (contract with ID)
  if (legalMatches >= 1 && hasCPR) {
    return { context: 'legal', matchedPatterns };
  }
  // CPR alone without other context = PII context
  if (hasCPR) {
    return { context: 'pii', matchedPatterns };
  }

  return { context: null, matchedPatterns };
}

// ============================================================================
// RULE IDS
// ============================================================================

export const SIGNAL_DOMINANCE_RULE_IDS = {
  /** HR context: prefer HR/PII signals over financial.card */
  HR_CONTEXT_DOMINANCE: 'SID-001-hr-context-dominance',
  /** Medical context: prefer medical/PII signals over financial.card */
  MEDICAL_CONTEXT_DOMINANCE: 'SID-002-medical-context-dominance',
  /** Legal context: prefer legal/PII signals over financial.card */
  LEGAL_CONTEXT_DOMINANCE: 'SID-003-legal-context-dominance',
  /** AG-PROMPT-080: HR context inferred from text content */
  HR_CONTEXT_INFERRED: 'SID-004-hr-context-inferred',
  /** AG-PROMPT-080: Legal context inferred from text content */
  LEGAL_CONTEXT_INFERRED: 'SID-005-legal-context-inferred',
  /** AG-PROMPT-080: PII context inferred from text content */
  PII_CONTEXT_INFERRED: 'SID-006-pii-context-inferred',
  /** No dominance needed - all signals equal */
  NO_DOMINANCE: 'SID-010-no-dominance',
  /** No card signals present - no dominance needed */
  NO_CARD_SIGNALS: 'SID-011-no-card-signals',
} as const;

// ============================================================================
// DOMINANCE RESOLUTION
// ============================================================================

/**
 * Resolve signal dominance for user-facing explanations.
 *
 * This function reorders driving signals so that domain-appropriate signals
 * appear first in the explanation, pushing potentially misleading signals
 * (like card patterns in HR docs) to the end.
 *
 * Key properties:
 * - Deterministic: Same inputs → same output
 * - Non-destructive: All signals preserved (just reordered)
 * - Context-aware: Uses document class to determine preferred signals
 * - Auditable: Returns reason and rule ID for debugging
 *
 * @param input - Driving signals and document context
 * @returns Prioritized signal list with audit info
 */
export function resolveSignalDominance(
  input: SignalDominanceInput
): SignalDominanceResult {
  const { drivingSignalIds, documentClass, allSignalIds, textContent } = input;

  // Edge case: empty or single signal - no reordering needed
  if (!drivingSignalIds || drivingSignalIds.length <= 1) {
    return {
      prioritizedSignalIds: drivingSignalIds || [],
      reordered: false,
      promotedSignal: null,
      demotedSignal: null,
      ruleId: SIGNAL_DOMINANCE_RULE_IDS.NO_DOMINANCE,
      reason: 'Single or no driving signals - no dominance resolution needed',
    };
  }

  // Check if any card signals are present in driving signals
  const cardSignals = drivingSignalIds.filter(id => FINANCIAL_CARD_SIGNALS.has(id));
  if (cardSignals.length === 0) {
    return {
      prioritizedSignalIds: drivingSignalIds,
      reordered: false,
      promotedSignal: null,
      demotedSignal: null,
      ruleId: SIGNAL_DOMINANCE_RULE_IDS.NO_CARD_SIGNALS,
      reason: 'No card signals in driving set - no dominance resolution needed',
    };
  }

  // Determine context-appropriate signals based on document class
  let preferredSignals: Set<string>;
  let ruleId: string;
  let contextName: string;
  let useInferredContext = false;

  switch (documentClass) {
    case 'doc.payroll':
    case 'doc.hr_record':
      preferredSignals = new Set([...HR_PERSONNEL_SIGNALS, ...PII_SIGNALS]);
      ruleId = SIGNAL_DOMINANCE_RULE_IDS.HR_CONTEXT_DOMINANCE;
      contextName = 'HR/payroll';
      break;

    case 'doc.medical_record':
      preferredSignals = new Set([...MEDICAL_SIGNALS, ...PII_SIGNALS]);
      ruleId = SIGNAL_DOMINANCE_RULE_IDS.MEDICAL_CONTEXT_DOMINANCE;
      contextName = 'medical';
      break;

    // AG-PROMPT-097C: Legal contract document class
    case 'doc.legal_contract':
      preferredSignals = new Set([...LEGAL_CONTRACT_SIGNALS, ...PII_SIGNALS]);
      ruleId = SIGNAL_DOMINANCE_RULE_IDS.LEGAL_CONTEXT_DOMINANCE;
      contextName = 'legal/contract';
      break;

    // AG-PHASE-5C-056: Insurance policy document class
    case 'doc.insurance_policy':
      preferredSignals = new Set([...PII_SIGNALS]);
      ruleId = SIGNAL_DOMINANCE_RULE_IDS.HR_CONTEXT_DOMINANCE;
      contextName = 'insurance';
      break;

    default:
      // No specific document class - check if signals suggest HR/legal context
      const hasHRSignals = drivingSignalIds.some(id => HR_PERSONNEL_SIGNALS.has(id));
      const hasLegalSignals = drivingSignalIds.some(id => LEGAL_CONTRACT_SIGNALS.has(id));
      const hasPIISignals = drivingSignalIds.some(id => PII_SIGNALS.has(id));

      if (hasHRSignals || (hasPIISignals && !documentClass)) {
        // HR/personnel signals present - prefer them over card
        preferredSignals = new Set([...HR_PERSONNEL_SIGNALS, ...PII_SIGNALS]);
        ruleId = SIGNAL_DOMINANCE_RULE_IDS.HR_CONTEXT_DOMINANCE;
        contextName = 'HR/personnel';
      } else if (hasLegalSignals) {
        // Legal signals present - prefer them over card
        preferredSignals = new Set([...LEGAL_CONTRACT_SIGNALS, ...PII_SIGNALS]);
        ruleId = SIGNAL_DOMINANCE_RULE_IDS.LEGAL_CONTEXT_DOMINANCE;
        contextName = 'legal';
      } else {
        // AG-PROMPT-080: No signal-based context - try text-based inference
        const inferred = inferContextFromText(textContent);
        if (inferred.context) {
          useInferredContext = true;
          switch (inferred.context) {
            case 'hr':
              preferredSignals = new Set([...HR_PERSONNEL_SIGNALS, ...PII_SIGNALS]);
              ruleId = SIGNAL_DOMINANCE_RULE_IDS.HR_CONTEXT_INFERRED;
              contextName = 'HR/contract (inferred)';
              break;
            case 'legal':
              preferredSignals = new Set([...LEGAL_CONTRACT_SIGNALS, ...PII_SIGNALS]);
              ruleId = SIGNAL_DOMINANCE_RULE_IDS.LEGAL_CONTEXT_INFERRED;
              contextName = 'legal (inferred)';
              break;
            case 'pii':
              preferredSignals = new Set([...PII_SIGNALS]);
              ruleId = SIGNAL_DOMINANCE_RULE_IDS.PII_CONTEXT_INFERRED;
              contextName = 'PII (inferred)';
              break;
          }
        } else {
          // No clear context - no reordering
          return {
            prioritizedSignalIds: drivingSignalIds,
            reordered: false,
            promotedSignal: null,
            demotedSignal: null,
            ruleId: SIGNAL_DOMINANCE_RULE_IDS.NO_DOMINANCE,
            reason: 'No HR/legal/medical context - card signal may be legitimate',
          };
        }
      }
  }

  // Check if any preferred signals are present in driving set
  const preferredInDriving = drivingSignalIds.filter(id => preferredSignals.has(id));

  // AG-PROMPT-080: For inferred context, demote card signals even if no preferred signals
  // in driving set. The non-card signals should be shown instead.
  if (preferredInDriving.length === 0 && !useInferredContext) {
    // No preferred signals in driving set and not using inferred context - cannot demote card
    return {
      prioritizedSignalIds: drivingSignalIds,
      reordered: false,
      promotedSignal: null,
      demotedSignal: null,
      ruleId: SIGNAL_DOMINANCE_RULE_IDS.NO_DOMINANCE,
      reason: `${contextName} context but no preferred signals in driving set`,
    };
  }

  // Reorder: preferred signals first, card signals last, others in between
  const preferred: string[] = [];
  const others: string[] = [];
  const demoted: string[] = [];

  for (const id of drivingSignalIds) {
    if (preferredSignals.has(id)) {
      preferred.push(id);
    } else if (FINANCIAL_CARD_SIGNALS.has(id)) {
      demoted.push(id);
    } else {
      others.push(id);
    }
  }

  // AG-PROMPT-080: For inferred context, if no preferred signals in driving,
  // put 'others' first, then demoted cards
  const prioritizedSignalIds = preferred.length > 0
    ? [...preferred, ...others, ...demoted]
    : [...others, ...demoted];

  // Determine what changed
  const promotedSignal = preferred[0] || others[0] || null;
  const demotedSignal = demoted[0] || null;
  const wasReordered = drivingSignalIds[0] !== prioritizedSignalIds[0];

  return {
    prioritizedSignalIds,
    reordered: wasReordered,
    promotedSignal: wasReordered ? promotedSignal : null,
    demotedSignal: wasReordered ? demotedSignal : null,
    ruleId,
    reason: wasReordered
      ? `${contextName} context: promoted ${promotedSignal}, demoted ${demotedSignal}`
      : `${contextName} context but no reordering needed`,
  };
}

// ============================================================================
// HELPERS
// ============================================================================

/**
 * Check if a signal ID is a financial card signal.
 */
export function isCardSignal(signalId: string): boolean {
  return FINANCIAL_CARD_SIGNALS.has(signalId);
}

/**
 * Check if a signal ID is an HR/personnel signal.
 */
export function isHRSignal(signalId: string): boolean {
  return HR_PERSONNEL_SIGNALS.has(signalId);
}

/**
 * Check if a signal ID is a PII signal.
 */
export function isPIISignal(signalId: string): boolean {
  return PII_SIGNALS.has(signalId);
}
