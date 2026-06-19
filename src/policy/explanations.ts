/**
 * AgentGuard Risk Explanation Model
 *
 * Provides structured "why" data for each signal and overall risk.
 * Data-only layer - no UI changes, no behavior changes.
 *
 * Privacy: No document content in explanations. Only counts, booleans,
 * locale, department, and source identifiers.
 *
 * Tone: Calm, informative, non-judgmental (per USER-WARNING-MODEL.md)
 *
 * @see ADR-015: Risk Explanation Model
 */

import type { PolicyContext, LocaleKey, DepartmentId } from './policy';
import { getExplainabilityCopy, type ExplainabilityCopyEntry } from './explainabilityCopy';
import {
  resolveMapper,
  deriveLocaleGroup,
  mapExplanationIdToSignalType,
  type UiEscalation,
  type PolicyMapperContext,
} from './policyMapper';
import type { RiskSignal, Severity, SignalType, SignalSource } from '../types/riskSignal';

// Re-export for external use
export type { ExplainabilityCopyEntry };
export type { UiEscalation };

// ============================================================================
// TYPES (re-exported from canonical source)
// ============================================================================

/**
 * Re-export canonical RiskSignal and related types from src/types/riskSignal.ts
 * @see AG-PROMPT-033B for centralization history
 */
export type { RiskSignal, Severity, SignalType, SignalSource } from '../types/riskSignal';

/**
 * Structured explanation for a signal or overall risk
 *
 * Privacy-safe: No document content, only counts and metadata.
 */
export interface RiskExplanation {
  /** Stable key for this explanation (e.g., "pii.phone.density") */
  id: string;

  /** Short human-readable title */
  title: string;

  /** Plain language explanation of why this matters */
  why: string;

  /**
   * Short, non-sensitive evidence items
   * Examples: ["count=94", "locale=EU-NORDICS", "source=content"]
   */
  evidence: string[];

  /** Optional generic guidance text */
  suggestedAction?: string;

  /** References to related ADRs or policies */
  policyRefs?: string[];

  /** Human-authored copy from versioned library (if available) */
  copy?: ExplainabilityCopyEntry;

  /** UI escalation hint from PolicyMapper (for future progressive disclosure) */
  uiEscalation?: UiEscalation;
}

/**
 * Statistics for explanation generation
 */
export interface ExplanationStats {
  phoneCount?: number;
  emailCount?: number;
  ssnCount?: number;
  totalSignals?: number;
  signalsByType?: Record<string, number>;
  signalsBySeverity?: Record<Severity, number>;
}

/**
 * Container for all explanations attached to an assessment
 */
export interface ExplanationBundle {
  overall: RiskExplanation;
  perSignal: Record<string, RiskExplanation>;
}

// ============================================================================
// SIGNAL KEY GENERATION
// ============================================================================

/**
 * Generate a stable, deterministic key for a signal
 *
 * Format: `{type}:{description_normalized}:{severity}:{source}`
 *
 * Used for:
 * - Deduplication
 * - Explanation lookup
 * - Future analytics (if enabled)
 */
export function getSignalKey(signal: RiskSignal): string {
  // Normalize description: lowercase, collapse whitespace, limit length
  const normalizedDesc = signal.description
    .toLowerCase()
    .replace(/\s+/g, '_')
    .replace(/[^a-z0-9_]/g, '')
    .slice(0, 50);

  return `${signal.type}:${normalizedDesc}:${signal.severity}:${signal.source}`;
}

// ============================================================================
// SIGNAL EXPLANATION MAPPINGS
// ============================================================================

/**
 * Get pattern category from signal description
 * Matches logic in policy.ts getPatternKey()
 */
function getPatternCategory(signal: RiskSignal): string {
  const desc = signal.description.toLowerCase();

  // Secrets
  if (desc.includes('api key') || desc.includes('access token')) return 'secret.api_key';
  if (desc.includes('aws') && desc.includes('key')) return 'secret.aws_key';
  if (desc.includes('password')) return 'secret.password';
  if (desc.includes('private key')) return 'secret.private_key';

  // Critical PII
  if (desc.includes('ssn') || desc.includes('social security')) return 'pii.ssn';
  if (desc.includes('credit card') || desc.includes('payment card')) return 'pii.credit_card';

  // Contact info
  if (desc.includes('phone')) return 'pii.phone';
  if (desc.includes('email')) return 'pii.email';

  // Financial
  if (desc.includes('iban')) return 'financial.iban';
  if (desc.includes('banking') || desc.includes('wire')) return 'financial.banking';
  if (desc.includes('financial') || desc.includes('budget')) return 'financial.data';

  // Legal
  if (desc.includes('legal') || desc.includes('contract') || desc.includes('agreement')) return 'legal.contract';
  if (desc.includes('nda') || desc.includes('non-disclosure')) return 'legal.nda';

  // Confidential
  if (desc.includes('confidential') || desc.includes('secret') || desc.includes('classified')) return 'confidential.marker';
  if (desc.includes('m&a') || desc.includes('merger') || desc.includes('acquisition')) return 'confidential.ma';

  // Dictionary matches
  if (desc.includes('dictionary match')) return 'dictionary.match';

  // HR
  if (desc.includes('employee') || desc.includes('hr') || desc.includes('personnel')) return 'pii.employee';
  if (desc.includes('salary') || desc.includes('compensation')) return 'pii.compensation';

  // IP
  if (desc.includes('patent') || desc.includes('trade secret')) return 'ip.content';

  // Default
  return 'other';
}

/**
 * Extract count from signal description if present
 */
function extractCount(description: string): number | null {
  const match = description.match(/(\d+)\s+(email|phone|address)/i);
  return match ? parseInt(match[1], 10) : null;
}

/**
 * Attach human-authored copy to an explanation if available
 *
 * @param explanation - The RiskExplanation to enrich
 * @returns The same explanation with copy attached (if found)
 */
function attachCopy(explanation: RiskExplanation): RiskExplanation {
  const copyEntry = getExplainabilityCopy(explanation.id);
  if (copyEntry) {
    return { ...explanation, copy: copyEntry };
  }
  return explanation;
}

// ============================================================================
// EXPLANATION GENERATORS
// ============================================================================

/**
 * Generate explanation for a single signal
 *
 * @param signal - The risk signal to explain
 * @param ctx - Policy context (locale, department, etc.)
 * @param stats - Optional statistics for density/threshold explanations
 * @returns RiskExplanation or null if no specific explanation available
 */
export function explainSignal(
  signal: RiskSignal,
  ctx: PolicyContext,
  stats?: ExplanationStats
): RiskExplanation | null {
  const category = getPatternCategory(signal);
  const evidence: string[] = [];

  // Build evidence from context
  if (ctx.locale && ctx.locale !== 'unknown') {
    evidence.push(`locale=${ctx.locale}`);
  }
  if (ctx.department && ctx.department !== 'default') {
    evidence.push(`department=${ctx.department}`);
  }
  evidence.push(`source=${signal.source}`);

  // Add count evidence if available
  const count = extractCount(signal.description);
  if (count !== null) {
    evidence.push(`count=${count}`);
  }

  // Generate explanation based on category
  switch (category) {
    // === SECRETS (invariant - cannot be downgraded) ===
    case 'secret.api_key':
      return {
        id: 'secret.api_key',
        title: 'API Key Detected',
        why: 'API keys provide programmatic access to services. If exposed, they could allow unauthorized access to accounts or resources.',
        evidence: [...evidence, 'invariant=true'],
        suggestedAction: 'Remove or rotate the key before uploading. Use environment variables or a secrets manager.',
        policyRefs: ['ADR-009', 'ADR-014'],
      };

    case 'secret.aws_key':
      return {
        id: 'secret.aws_key',
        title: 'AWS Access Key Detected',
        why: 'AWS access keys grant access to cloud resources. Exposure could lead to unauthorized usage or data access.',
        evidence: [...evidence, 'invariant=true'],
        suggestedAction: 'Rotate this key immediately if it was ever shared. Never include AWS keys in documents.',
        policyRefs: ['ADR-009', 'ADR-014'],
      };

    case 'secret.password':
      return {
        id: 'secret.password',
        title: 'Password Detected',
        why: 'Passwords provide direct access to accounts. Sharing them externally creates security risk.',
        evidence: [...evidence, 'invariant=true'],
        suggestedAction: 'Remove password references before uploading.',
        policyRefs: ['ADR-009', 'ADR-014'],
      };

    case 'secret.private_key':
      return {
        id: 'secret.private_key',
        title: 'Private Key Detected',
        why: 'Private keys are used for encryption and authentication. If exposed, they could compromise secure communications.',
        evidence: [...evidence, 'invariant=true'],
        suggestedAction: 'Never share private key files. Generate new keys if this one was exposed.',
        policyRefs: ['ADR-009', 'ADR-014'],
      };

    // === PII ===
    case 'pii.ssn':
      if (ctx.locale && ctx.locale !== 'US' && ctx.locale !== 'unknown') {
        return {
          id: 'pii.ssn.locale_gated',
          title: 'Number Pattern (Non-US)',
          why: `This pattern resembles a US Social Security Number, but the document appears to be from ${ctx.locale}. It may be a reference number or local ID format instead.`,
          evidence: [...evidence, 'locale_downgrade=true'],
          suggestedAction: 'Verify if this is actually sensitive data for your region.',
          policyRefs: ['ADR-010'],
        };
      }
      return {
        id: 'pii.ssn',
        title: 'Social Security Number',
        why: 'SSNs are critical personal identifiers in the US. Exposure could enable identity theft or fraud.',
        evidence,
        suggestedAction: 'Redact SSN before uploading.',
        policyRefs: ['ADR-009'],
      };

    case 'pii.credit_card':
      return {
        id: 'pii.credit_card',
        title: 'Payment Card Number',
        why: 'Payment card numbers are regulated under PCI-DSS. Sharing them externally may violate compliance requirements.',
        evidence,
        suggestedAction: 'Never share full card numbers. Redact or mask before uploading.',
        policyRefs: ['ADR-009'],
      };

    case 'pii.phone':
      return {
        id: count && count > 10 ? 'pii.phone.density' : 'pii.phone',
        title: count && count > 10 ? `Phone Numbers (${count})` : 'Phone Number(s)',
        why: count && count > 10
          ? 'This document contains many phone numbers. High density may indicate a contact list or customer data.'
          : 'Phone numbers are personal contact information that may be subject to privacy requirements.',
        evidence,
        suggestedAction: count && count > 10
          ? 'Review whether this contact list should be shared externally.'
          : 'Consider whether these phone numbers need to be included.',
        policyRefs: ['ADR-009', 'ADR-010'],
      };

    case 'pii.email':
      return {
        id: count && count > 5 ? 'pii.email.density' : 'pii.email',
        title: count && count > 5 ? `Email Addresses (${count})` : 'Email Address(es)',
        why: count && count > 5
          ? 'This document contains multiple email addresses. This may indicate a mailing list or employee directory.'
          : 'Email addresses are personal contact information.',
        evidence,
        suggestedAction: 'Consider whether these email addresses should be shared externally.',
        policyRefs: ['ADR-009'],
      };

    case 'pii.employee':
    case 'pii.compensation':
      return {
        id: category,
        title: 'Employee/HR Information',
        why: 'Employee data including compensation details is typically confidential and may be protected by employment laws.',
        evidence,
        suggestedAction: 'HR data should generally not be shared externally without proper authorization.',
        policyRefs: ['ADR-009', 'ADR-012'],
      };

    // === FINANCIAL ===
    case 'financial.iban':
      return {
        id: 'financial.iban',
        title: 'Bank Account (IBAN)',
        why: 'IBANs identify bank accounts and could be used for fraudulent transactions.',
        evidence,
        suggestedAction: 'Verify if sharing this banking information externally is appropriate.',
        policyRefs: ['ADR-009'],
      };

    case 'financial.banking':
      return {
        id: 'financial.banking',
        title: 'Banking Information',
        why: 'Banking details including routing numbers and account information should be protected.',
        evidence,
        suggestedAction: 'Consider redacting banking information before uploading.',
        policyRefs: ['ADR-009'],
      };

    case 'financial.data':
      return {
        id: 'financial.data',
        title: 'Financial Data',
        why: 'Financial projections and business data may be confidential.',
        evidence,
        policyRefs: ['ADR-009'],
      };

    // === LEGAL ===
    case 'legal.contract':
      return {
        id: 'legal.contract',
        title: 'Legal Agreement',
        why: 'Legal documents often contain confidential terms and obligations.',
        evidence,
        suggestedAction: 'Check if sharing legal documents externally is permitted.',
        policyRefs: ['ADR-009'],
      };

    case 'legal.nda':
      return {
        id: 'legal.nda',
        title: 'Non-Disclosure Agreement',
        why: 'NDAs contain confidentiality obligations that may prevent external sharing.',
        evidence,
        suggestedAction: 'Review NDA terms before sharing any related information.',
        policyRefs: ['ADR-009'],
      };

    // === CONFIDENTIAL ===
    case 'confidential.marker':
      return {
        id: 'confidential.marker',
        title: 'Confidentiality Marker',
        why: 'This document is explicitly marked as confidential, indicating it should not be widely shared.',
        evidence,
        suggestedAction: 'Respect the confidentiality marking.',
        policyRefs: ['ADR-009'],
      };

    case 'confidential.ma':
      return {
        id: 'confidential.ma',
        title: 'M&A Content',
        why: 'Merger and acquisition information is typically highly confidential and market-sensitive.',
        evidence,
        suggestedAction: 'M&A content should not be shared externally without explicit authorization.',
        policyRefs: ['ADR-009'],
      };

    // === DICTIONARY MATCHES ===
    case 'dictionary.match':
      return {
        id: ctx.department ? `dictionary.${ctx.department}` : 'dictionary.match',
        title: 'Department-Specific Term',
        why: ctx.department
          ? `This document contains terms monitored by the ${ctx.department} department.`
          : 'This document contains terms flagged by policy configuration.',
        evidence,
        policyRefs: ['ADR-012'],
      };

    // === IP ===
    case 'ip.content':
      return {
        id: 'ip.content',
        title: 'Intellectual Property',
        why: 'This may contain proprietary information, trade secrets, or patentable innovations.',
        evidence,
        suggestedAction: 'IP content should be reviewed by legal before external sharing.',
        policyRefs: ['ADR-009'],
      };

    // === DEFAULT ===
    default:
      // Return null for categories without specific explanations
      return null;
  }
}

/**
 * Generate explanation for overall risk assessment
 *
 * @param signals - All risk signals in the assessment
 * @param overallRisk - Computed overall risk level
 * @param ctx - Policy context
 * @param stats - Optional statistics
 * @returns RiskExplanation for the overall assessment
 */
export function explainOverallRisk(
  signals: RiskSignal[],
  overallRisk: Severity,
  ctx: PolicyContext,
  stats?: ExplanationStats
): RiskExplanation {
  const evidence: string[] = [];

  // Basic stats
  evidence.push(`signals=${signals.length}`);
  if (ctx.locale && ctx.locale !== 'unknown') {
    evidence.push(`locale=${ctx.locale}`);
  }
  if (ctx.department && ctx.department !== 'default') {
    evidence.push(`department=${ctx.department}`);
  }
  if (ctx.isTransactional) {
    evidence.push('transactional=true');
  }

  // Count by severity
  const severityCounts: Record<Severity, number> = { low: 0, medium: 0, high: 0, critical: 0 };
  for (const signal of signals) {
    severityCounts[signal.severity]++;
  }

  if (severityCounts.critical > 0) evidence.push(`critical=${severityCounts.critical}`);
  if (severityCounts.high > 0) evidence.push(`high=${severityCounts.high}`);
  if (severityCounts.medium > 0) evidence.push(`medium=${severityCounts.medium}`);

  // Check for secrets (invariant signals)
  const hasSecrets = signals.some(s => {
    const desc = s.description.toLowerCase();
    return desc.includes('api key') || desc.includes('aws') || desc.includes('password') || desc.includes('private key');
  });
  if (hasSecrets) {
    evidence.push('contains_secrets=true');
  }

  // Generate explanation based on overall risk level
  switch (overallRisk) {
    case 'critical':
      return {
        id: 'overall.critical',
        title: 'High-Risk Content Detected',
        why: hasSecrets
          ? 'This document contains credentials or secrets that should never be shared externally. These are flagged at the highest level regardless of other settings.'
          : 'This document contains multiple high-severity signals indicating sensitive content that may be subject to legal or compliance requirements.',
        evidence,
        suggestedAction: 'Review each signal carefully. Consider whether this upload is necessary and authorized.',
        policyRefs: ['ADR-009', 'ADR-014'],
      };

    case 'high':
      return {
        id: 'overall.high',
        title: 'Sensitive Content Detected',
        why: 'This document contains signals indicating sensitive information. Uploading may conflict with company policy or data protection requirements.',
        evidence,
        suggestedAction: 'Review the signals and consider redacting sensitive information before uploading.',
        policyRefs: ['ADR-009'],
      };

    case 'medium':
      return {
        id: 'overall.medium',
        title: 'Some Indicators Detected',
        why: 'This document contains some personal or internal indicators. While not necessarily sensitive, review is recommended.',
        evidence,
        suggestedAction: 'Review the flagged content to ensure you are comfortable sharing it.',
        policyRefs: ['ADR-009'],
      };

    case 'low':
    default:
      return {
        id: 'overall.low',
        title: 'Low-Risk Indicators',
        why: 'Only low-risk patterns were detected. This file will still be shared with an external service.',
        evidence,
        suggestedAction: 'Proceed if you are comfortable sharing this information externally.',
        policyRefs: ['ADR-009'],
      };
  }
}

/**
 * Build complete explanation bundle for an assessment
 *
 * @param signals - All risk signals
 * @param overallRisk - Computed overall risk
 * @param ctx - Policy context
 * @param stats - Optional statistics
 * @returns ExplanationBundle with overall and per-signal explanations
 */
export function buildExplanationBundle(
  signals: RiskSignal[],
  overallRisk: Severity,
  ctx: PolicyContext,
  stats?: ExplanationStats
): ExplanationBundle {
  const perSignal: Record<string, RiskExplanation> = {};

  // Build PolicyMapper context from PolicyContext
  // destination is not available yet - default to 'unknown'
  const mapperCtx: PolicyMapperContext = {
    department: ctx.department,
    destination: 'unknown',
    localeProfile: ctx.locale,
    localeGroup: deriveLocaleGroup(ctx.locale),
  };

  let mapperAttached = 0;

  for (const signal of signals) {
    const key = getSignalKey(signal);
    const explanation = explainSignal(signal, ctx, stats);
    if (explanation) {
      // Attach human-authored copy if available
      let enriched = attachCopy(explanation);

      // Attach PolicyMapper routing (uiEscalation hint)
      // Map explanation ID to canonical signal type, then resolve
      const signalType = mapExplanationIdToSignalType(explanation.id);
      const mappingResult = resolveMapper(signalType, mapperCtx);
      enriched = {
        ...enriched,
        uiEscalation: mappingResult.uiEscalation,
      };
      mapperAttached++;

      perSignal[key] = enriched;
    }
  }

  // Build and enrich overall explanation
  let overallExplanation = explainOverallRisk(signals, overallRisk, ctx, stats);
  overallExplanation = attachCopy(overallExplanation);

  // Attach mapper to overall explanation (overall.* signal types not in mapper, uses fallback)
  const overallSignalType = mapExplanationIdToSignalType(`overall.${overallRisk}`);
  const overallMapping = resolveMapper(overallSignalType, mapperCtx);
  overallExplanation = {
    ...overallExplanation,
    uiEscalation: overallMapping.uiEscalation,
  };

  // Debug log: counts only, no content
  if (mapperAttached > 0) {
    console.log(`[AgentGuard] PolicyMapper attached: ${mapperAttached} explanations`);
  }

  return {
    overall: overallExplanation,
    perSignal,
  };
}
