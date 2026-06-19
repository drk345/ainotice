/**
 * AgentGuard Policy Contract v1.0
 *
 * Defines the versioned schema for policy configuration.
 * Supports locale overlays from day one for global deployment.
 *
 * Privacy: No content fields. All thresholds are numeric.
 * Local-only: Policies are evaluated entirely in the browser.
 */

// AG-PROMPT-231: canonical severity rank — replaces the local 4-level SEVERITY_ORDER constant.
import { SEVERITY_ORDER_NO_NONE as SEVERITY_ORDER } from './severityRank';

// ============================================================================
// VERSION
// ============================================================================

export const CURRENT_POLICY_VERSION = '1.0';

// ============================================================================
// CORE TYPES
// ============================================================================

/** Severity levels in ascending order */
export type Severity = 'low' | 'medium' | 'high' | 'critical';

/** Locale groups for overlay targeting */
export type LocaleGroup =
  | 'US'
  | 'UK'
  | 'EU-NORDICS'    // DK, NO, SE, FI, IS
  | 'EU-DACH'       // DE, AT, CH
  | 'EU-WESTERN'    // FR, BE, NL, LU
  | 'EU-SOUTHERN'   // ES, IT, PT, GR
  | 'EU-EASTERN'    // PL, CZ, SK, HU, RO, BG
  | 'EN-COMMONWEALTH' // CA, AU, NZ, IE
  | 'LATAM'         // MX, AR, CO, CL, PE, BR
  | 'unknown';      // Fallback

/** Signal identifiers for policy configuration */
export type SignalId =
  // PII
  | 'pii.phone'
  | 'pii.email'
  | 'pii.ssn_us'
  | 'pii.national_id'
  | 'pii.name'
  // Secrets (mandatory - cannot disable)
  | 'secrets.api_key'
  | 'secrets.aws_key'
  | 'secrets.password'
  | 'secrets.private_key'
  | 'secrets.bearer_token'
  | 'secrets.connection_string'
  // Financial
  | 'financial.credit_card'
  | 'financial.iban'
  | 'financial.banking'
  // Confidential
  | 'confidential.marker'
  | 'confidential.ma_terms'
  // Legal / HR
  | 'legal.agreement'
  | 'hr.employee_data';

// ============================================================================
// SIGNAL POLICY
// ============================================================================

/**
 * Configuration for a single signal type
 */
export interface SignalPolicy {
  /** Whether this signal is enabled (false = filtered out) */
  enabled: boolean;

  /** Base severity before any escalation */
  baseSeverity: Severity;

  /**
   * Maximum severity this signal can reach (caps all escalation)
   * Critical for preventing phone/email noise from becoming CRITICAL
   */
  maxSeverity?: Severity;

  /**
   * Density thresholds for count-based escalation
   * Key = count threshold, Value = severity at that threshold
   * Applied in descending order (highest threshold first)
   */
  densityThresholds?: Record<number, Severity>;

  /**
   * If true, this signal cannot be downgraded below baseSeverity
   * Used for secrets to ensure they stay HIGH/CRITICAL
   */
  mandatory?: boolean;

  /**
   * If true, apply transactional document downgrade (-1 level)
   * For receipts/invoices where contact info is expected
   */
  transactionalDowngrade?: boolean;
}

// ============================================================================
// COOCCURRENCE RULES
// ============================================================================

/**
 * Rule for escalating severity when multiple signal types appear together
 */
export interface CooccurrenceRule {
  /** Unique identifier for this rule */
  id: string;

  /** Human-readable description */
  description: string;

  /** Conditions that must ALL be met to trigger */
  conditions: {
    signalId: SignalId;
    minCount: number;
  }[];

  /** Which signals to escalate when triggered */
  affects: SignalId[];

  /** How many severity levels to bump (1 = low→medium) */
  severityBump: number;

  /** Maximum severity after this rule applies */
  maxSeverity: Severity;
}

// ============================================================================
// LOCALE OVERLAY
// ============================================================================

/**
 * Partial policy override for a specific locale group
 * Only specified fields are overridden; others inherit from base
 */
export interface LocaleOverlay {
  /** Which locale groups this overlay applies to */
  locales: LocaleGroup[];

  /** Signal overrides (partial - only override what's specified) */
  signals?: Partial<Record<SignalId, Partial<SignalPolicy>>>;

  /** Override cooccurrence rules (replaces base rules if specified) */
  cooccurrenceOverrides?: CooccurrenceRule[];

  /** Locale-specific escalation threshold multiplier (1.0 = no change) */
  escalationMultiplier?: number;
}

// ============================================================================
// POLICY CONTRACT
// ============================================================================

/**
 * Complete policy contract (versioned)
 */
export interface PolicyContract {
  /** Schema version for compatibility checking */
  version: string;

  /**
   * How locale is determined:
   * - 'auto': detect from document content/metadata
   * - 'fixed': use fixedLocale value
   */
  localeMode: 'auto' | 'fixed';

  /** Fixed locale when localeMode='fixed' */
  fixedLocale?: LocaleGroup;

  /** Base signal policies (applied when no overlay matches) */
  signals: Record<SignalId, SignalPolicy>;

  /** Base cooccurrence rules */
  cooccurrence: CooccurrenceRule[];

  /** Locale-specific overrides (merged on top of base) */
  localeOverlays: LocaleOverlay[];

  /**
   * Invariants that MUST be enforced regardless of config:
   * - secrets.* signals are mandatory (cannot disable)
   * - secrets.* signals cannot go below HIGH severity
   */
  invariants: {
    /** Signal IDs that cannot be disabled */
    mandatorySignals: SignalId[];
    /** Minimum severity for mandatory signals */
    mandatoryMinSeverity: Severity;
  };
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// Severity ordering for comparison imported from ./severityRank (AG-PROMPT-231)

/** Compare severities: returns true if a >= b */
export function severityGte(a: Severity, b: Severity): boolean {
  return SEVERITY_ORDER.indexOf(a) >= SEVERITY_ORDER.indexOf(b);
}

/** Get the higher of two severities */
export function maxSeverity(a: Severity, b: Severity): Severity {
  return severityGte(a, b) ? a : b;
}

/** Get the lower of two severities */
export function minSeverity(a: Severity, b: Severity): Severity {
  return severityGte(a, b) ? b : a;
}

/** Bump severity by N levels (capped at critical) */
export function bumpSeverity(severity: Severity, levels: number): Severity {
  const idx = SEVERITY_ORDER.indexOf(severity);
  const newIdx = Math.min(idx + levels, SEVERITY_ORDER.length - 1);
  return SEVERITY_ORDER[newIdx];
}

/** Reduce severity by N levels (floored at low) */
export function reduceSeverity(severity: Severity, levels: number): Severity {
  const idx = SEVERITY_ORDER.indexOf(severity);
  const newIdx = Math.max(idx - levels, 0);
  return SEVERITY_ORDER[newIdx];
}

/** Cap severity at a maximum */
export function capSeverity(severity: Severity, max: Severity): Severity {
  return severityGte(severity, max) ? max : severity;
}
