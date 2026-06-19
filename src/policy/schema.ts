/**
 * AgentGuard Policy Schema v1.0
 *
 * JSON-serializable policy schema for admin configuration.
 * Designed to be editable via future Admin UI without code changes.
 *
 * Schema Layers (applied in order):
 * 1. Global defaults
 * 2. Locale-specific overrides
 * 3. Department-specific overrides
 * 4. (Future) Team/User overrides
 *
 * Design Principles:
 * - Fully JSON-serializable
 * - Additive overrides (only specified fields are changed)
 * - Invariants cannot be overridden (secrets stay critical)
 * - Backward compatible (new fields have defaults)
 *
 * @see ADR-011: Policy Administration & Governance
 * @see ADR-013: Admin-Configurable Risk Policy
 */

import type { LocaleKey } from './locale';
import type { DepartmentId } from './policy';

// ============================================================================
// SCHEMA TYPES
// ============================================================================

/**
 * Severity levels
 */
export type Severity = 'low' | 'medium' | 'high' | 'critical';

/**
 * Signal categories
 */
export type SignalCategory =
  | 'pii'
  | 'confidential'
  | 'financial'
  | 'legal'
  | 'sensitive'
  | 'ip';

/**
 * Signal configuration (per signal type)
 */
export interface SignalConfig {
  /** Whether detection is enabled */
  enabled: boolean;

  /** Base severity when detected */
  baseSeverity: Severity;

  /** Maximum severity cap */
  maxSeverity?: Severity;

  /** If true, cannot be disabled or downgraded (secrets) */
  mandatory?: boolean;

  /** Minimum count to trigger detection */
  minCount?: number;

  /** Count threshold for severity escalation */
  escalationThreshold?: number;

  /** Escalated severity when threshold exceeded */
  escalatedSeverity?: Severity;
}

/**
 * Locale-specific overrides
 */
export interface LocaleOverride {
  /** Locale this override applies to */
  locale: LocaleKey;

  /** Signal overrides (only specified signals are changed) */
  signals?: Partial<Record<string, Partial<SignalConfig>>>;

  /** Phone detection override */
  phone?: {
    escalationThreshold?: number;
    maxSeverity?: Severity;
  };

  /** National ID override */
  nationalId?: {
    enabled?: boolean;
    baseSeverity?: Severity;
  };

  /** Notes for admin */
  notes?: string;
}

/**
 * Department-specific overrides
 */
export interface DepartmentOverride {
  /** Department this override applies to */
  department: DepartmentId;

  /** Dictionary entries to enable/disable */
  dictionaries?: {
    enabled: boolean;
    entries?: string[];  // Entry IDs to enable
  };

  /** Signal overrides */
  signals?: Partial<Record<string, Partial<SignalConfig>>>;

  /** Notes for admin */
  notes?: string;
}

/**
 * Cooccurrence rule for escalation
 */
export interface CooccurrenceRule {
  /** Unique identifier */
  id: string;

  /** Human-readable description */
  description: string;

  /** Signals that must all be present */
  requires: {
    signalId: string;
    minCount: number;
  }[];

  /** Signals to escalate when rule triggers */
  escalates: string[];

  /** Severity levels to add */
  severityBump: number;

  /** Maximum severity after bump */
  maxSeverity: Severity;

  /** Whether rule is enabled */
  enabled: boolean;
}

/**
 * Invariants that CANNOT be overridden
 */
export interface PolicyInvariants {
  /** Signals that cannot be disabled */
  mandatorySignals: string[];

  /** Minimum severity for mandatory signals */
  mandatoryMinSeverity: Severity;

  /** Signals that are always critical */
  alwaysCritical: string[];
}

/**
 * Complete policy schema (v1)
 */
export interface PolicySchema {
  /** Schema version for compatibility */
  version: '1.0';

  /** Policy name/identifier */
  name: string;

  /** Policy description */
  description?: string;

  /** Global signal defaults */
  signals: Record<string, SignalConfig>;

  /** Locale-specific overrides */
  localeOverrides: LocaleOverride[];

  /** Department-specific overrides */
  departmentOverrides: DepartmentOverride[];

  /** Cooccurrence escalation rules */
  cooccurrenceRules: CooccurrenceRule[];

  /** System invariants (cannot be changed) */
  invariants: PolicyInvariants;

  /** Metadata */
  metadata?: {
    createdAt?: string;
    updatedAt?: string;
    createdBy?: string;
    lastModifiedBy?: string;
  };
}

// ============================================================================
// DEFAULT POLICY SCHEMA
// ============================================================================

/**
 * Default policy schema - baseline behavior
 */
export const DEFAULT_POLICY_SCHEMA: PolicySchema = {
  version: '1.0',
  name: 'Ai Notice Default Policy',
  description: 'Conservative defaults with locale-aware adjustments',

  signals: {
    // === PII ===
    'pii.phone': {
      enabled: true,
      baseSeverity: 'low',
      maxSeverity: 'medium',
      minCount: 1,
      escalationThreshold: 20,
      escalatedSeverity: 'medium',
    },
    'pii.email': {
      enabled: true,
      baseSeverity: 'low',
      maxSeverity: 'medium',
      minCount: 5,
    },
    'pii.ssn_us': {
      enabled: true,
      baseSeverity: 'critical',
      mandatory: true,
    },
    'pii.national_id': {
      enabled: true,
      baseSeverity: 'high',
    },
    'pii.name': {
      enabled: true,
      baseSeverity: 'low',
      maxSeverity: 'medium',
    },
    'pii.hr_employee': {
      enabled: true,
      baseSeverity: 'high',
    },

    // === SECRETS (all mandatory, cannot downgrade) ===
    'secrets.api_key': {
      enabled: true,
      baseSeverity: 'critical',
      mandatory: true,
    },
    'secrets.aws_key': {
      enabled: true,
      baseSeverity: 'critical',
      mandatory: true,
    },
    'secrets.password': {
      enabled: true,
      baseSeverity: 'critical',
      mandatory: true,
    },
    'secrets.private_key': {
      enabled: true,
      baseSeverity: 'critical',
      mandatory: true,
    },
    'secrets.bearer_token': {
      enabled: true,
      baseSeverity: 'critical',
      mandatory: true,
    },
    'secrets.connection_string': {
      enabled: true,
      baseSeverity: 'critical',
      mandatory: true,
    },

    // === FINANCIAL ===
    'financial.credit_card': {
      enabled: true,
      baseSeverity: 'critical',
      mandatory: true,
    },
    'financial.iban': {
      enabled: true,
      baseSeverity: 'high',
    },
    'financial.banking': {
      enabled: true,
      baseSeverity: 'high',
    },

    // === CONFIDENTIAL ===
    'confidential.marker': {
      enabled: true,
      baseSeverity: 'high',
      mandatory: true,
    },
    'confidential.ma_terms': {
      enabled: true,
      baseSeverity: 'critical',
      mandatory: true,
    },

    // === LEGAL ===
    'legal.agreement': {
      enabled: true,
      baseSeverity: 'medium',
      maxSeverity: 'high',
    },
    'legal.language': {
      enabled: true,
      baseSeverity: 'medium',
      maxSeverity: 'high',
    },
  },

  localeOverrides: [
    // EU-NORDICS: Conservative phone/SSN handling
    {
      locale: 'EU-NORDICS',
      phone: {
        escalationThreshold: 50,
        maxSeverity: 'medium',
      },
      nationalId: {
        enabled: true,
        baseSeverity: 'high',
      },
      signals: {
        'pii.ssn_us': {
          baseSeverity: 'low',  // SSN format is likely false positive
          mandatory: false,
        },
      },
      notes: 'Nordic receipts contain many number sequences that look like phones.',
    },

    // US: SSN is critical
    {
      locale: 'US',
      signals: {
        'pii.ssn_us': {
          baseSeverity: 'critical',
          mandatory: true,
        },
      },
    },

    // UK: SSN format is false positive
    {
      locale: 'UK',
      signals: {
        'pii.ssn_us': {
          baseSeverity: 'low',
          mandatory: false,
        },
      },
    },

    // EU-DACH: Similar to UK
    {
      locale: 'EU-DACH',
      phone: {
        escalationThreshold: 30,
      },
      signals: {
        'pii.ssn_us': {
          baseSeverity: 'low',
          mandatory: false,
        },
      },
    },

    // EN-COMMONWEALTH: SSN format is false positive
    {
      locale: 'EN-COMMONWEALTH',
      signals: {
        'pii.ssn_us': {
          baseSeverity: 'low',
          mandatory: false,
        },
      },
    },

    // LATAM
    {
      locale: 'LATAM',
      phone: {
        escalationThreshold: 25,
      },
      signals: {
        'pii.ssn_us': {
          baseSeverity: 'low',
          mandatory: false,
        },
      },
    },
  ],

  departmentOverrides: [
    // Finance department
    {
      department: 'finance',
      dictionaries: {
        enabled: true,
        entries: [
          'finance-banking',
          'finance-confidential',
          'finance-transactions',
          'finance-tax',
        ],
      },
      notes: 'Finance department dictionary enabled',
    },

    // HR department
    {
      department: 'hr',
      dictionaries: {
        enabled: true,
        entries: [
          'hr-medical',
          'hr-compensation',
          'hr-performance',
          'hr-recruiting',
        ],
      },
      notes: 'HR department dictionary enabled',
    },

    // Legal department
    {
      department: 'legal',
      dictionaries: {
        enabled: true,
        entries: [
          'legal-privilege',
          'legal-litigation',
          'legal-contracts',
          'legal-regulatory',
        ],
      },
      notes: 'Legal department dictionary enabled',
    },
  ],

  cooccurrenceRules: [
    {
      id: 'contact_list',
      description: 'Phone + email together suggests contact list',
      requires: [
        { signalId: 'pii.phone', minCount: 5 },
        { signalId: 'pii.email', minCount: 5 },
      ],
      escalates: ['pii.phone', 'pii.email'],
      severityBump: 1,
      maxSeverity: 'medium',
      enabled: true,
    },
  ],

  invariants: {
    mandatorySignals: [
      'secrets.api_key',
      'secrets.aws_key',
      'secrets.password',
      'secrets.private_key',
      'secrets.bearer_token',
      'secrets.connection_string',
      'financial.credit_card',
      'confidential.marker',
      'confidential.ma_terms',
    ],
    mandatoryMinSeverity: 'high',
    alwaysCritical: [
      'secrets.api_key',
      'secrets.aws_key',
      'secrets.password',
      'financial.credit_card',
    ],
  },
};

// ============================================================================
// SCHEMA VALIDATION
// ============================================================================

/**
 * Validate a policy schema
 */
export function validateSchema(schema: PolicySchema): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  // Check version
  if (schema.version !== '1.0') {
    errors.push(`Unsupported schema version: ${schema.version}`);
  }

  // Check mandatory signals are not disabled
  for (const signalId of schema.invariants.mandatorySignals) {
    const config = schema.signals[signalId];
    if (config && config.enabled === false) {
      errors.push(`Mandatory signal cannot be disabled: ${signalId}`);
    }
  }

  // Check severity constraints
  for (const signalId of schema.invariants.alwaysCritical) {
    const config = schema.signals[signalId];
    if (config && config.baseSeverity !== 'critical') {
      errors.push(`Signal must be critical: ${signalId}`);
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Merge schema overrides (locale or department) with base config
 */
export function mergeSignalConfig(
  base: SignalConfig,
  override: Partial<SignalConfig>
): SignalConfig {
  return {
    ...base,
    ...override,
  };
}

/**
 * Get effective signal config after applying overrides
 */
export function getEffectiveSignalConfig(
  schema: PolicySchema,
  signalId: string,
  locale?: LocaleKey,
  department?: DepartmentId
): SignalConfig | undefined {
  // Start with base config
  let config = schema.signals[signalId];
  if (!config) {
    return undefined;
  }

  // Apply locale override
  if (locale) {
    const localeOverride = schema.localeOverrides.find(o => o.locale === locale);
    if (localeOverride?.signals?.[signalId]) {
      config = mergeSignalConfig(config, localeOverride.signals[signalId]!);
    }
  }

  // Apply department override
  if (department) {
    const deptOverride = schema.departmentOverrides.find(o => o.department === department);
    if (deptOverride?.signals?.[signalId]) {
      config = mergeSignalConfig(config, deptOverride.signals[signalId]!);
    }
  }

  // Enforce invariants
  if (schema.invariants.mandatorySignals.includes(signalId)) {
    config.enabled = true;
    if (severityToNumber(config.baseSeverity) < severityToNumber(schema.invariants.mandatoryMinSeverity)) {
      config.baseSeverity = schema.invariants.mandatoryMinSeverity;
    }
  }

  if (schema.invariants.alwaysCritical.includes(signalId)) {
    config.baseSeverity = 'critical';
  }

  return config;
}

/**
 * Convert severity to numeric value for comparison
 */
function severityToNumber(severity: Severity): number {
  const order: Record<Severity, number> = {
    low: 0,
    medium: 1,
    high: 2,
    critical: 3,
  };
  return order[severity];
}

// ============================================================================
// EXPORTS
// ============================================================================

export {
  severityToNumber,
};
