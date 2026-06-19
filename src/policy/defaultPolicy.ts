/**
 * AgentGuard Default Policy v1.0
 *
 * Provides sensible defaults for signal severity mapping with locale overlays.
 *
 * Philosophy:
 * - Secrets (API keys, passwords, etc.) are ALWAYS high/critical - mandatory
 * - Phone/email have CAPS - can never exceed MEDIUM regardless of count
 * - Locale overlays adjust thresholds for regional false positive patterns
 * - Transactional documents (receipts, invoices) get contact info downgraded
 */

import {
  CURRENT_POLICY_VERSION,
  PolicyContract,
  SignalPolicy,
  SignalId,
  CooccurrenceRule,
  LocaleOverlay,
  Severity,
} from './contract';

// ============================================================================
// BASE SIGNAL POLICIES
// ============================================================================

const BASE_SIGNALS: Record<SignalId, SignalPolicy> = {
  // === PII SIGNALS (low base, capped at medium) ===
  'pii.phone': {
    enabled: true,
    baseSeverity: 'low',
    maxSeverity: 'medium',  // NEVER goes above medium
    transactionalDowngrade: true,
    densityThresholds: {
      10: 'medium',   // 10+ phones in non-Nordic locales
      // No higher thresholds - medium is the max
    },
  },
  'pii.email': {
    enabled: true,
    baseSeverity: 'low',
    maxSeverity: 'medium',
    transactionalDowngrade: true,
    densityThresholds: {
      5: 'medium',    // 5+ emails
    },
  },
  'pii.ssn_us': {
    enabled: true,
    baseSeverity: 'critical',
    mandatory: true,  // Cannot disable or downgrade
  },
  'pii.national_id': {
    enabled: true,
    baseSeverity: 'high',
  },
  'pii.name': {
    enabled: true,
    baseSeverity: 'low',
    maxSeverity: 'medium',
    transactionalDowngrade: true,
  },

  // === SECRETS (mandatory - cannot disable or downgrade) ===
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

  // === FINANCIAL (high severity) ===
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

  // === CONFIDENTIAL MARKERS ===
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

  // === LEGAL / HR ===
  'legal.agreement': {
    enabled: true,
    baseSeverity: 'medium',
  },
  'hr.employee_data': {
    enabled: true,
    baseSeverity: 'high',
  },
};

// ============================================================================
// COOCCURRENCE RULES
// ============================================================================

const BASE_COOCCURRENCE: CooccurrenceRule[] = [
  {
    id: 'contact_list',
    description: 'Phone + email together suggests contact list (higher risk)',
    conditions: [
      { signalId: 'pii.phone', minCount: 5 },
      { signalId: 'pii.email', minCount: 5 },
    ],
    affects: ['pii.phone', 'pii.email'],
    severityBump: 1,
    maxSeverity: 'medium',  // Still capped at medium
  },
];

// ============================================================================
// LOCALE OVERLAYS
// ============================================================================

const LOCALE_OVERLAYS: LocaleOverlay[] = [
  // --- EU-NORDICS: Very conservative phone detection ---
  // Nordic documents have many number sequences (IKEA codes, order numbers, prices)
  // that match generic phone patterns. Higher thresholds to avoid noise.
  {
    locales: ['EU-NORDICS'],
    signals: {
      'pii.phone': {
        densityThresholds: {
          20: 'medium',   // Require 20+ phones to escalate (vs 10 default)
          // 50+ could go higher but cap prevents it
        },
      },
      // SSN pattern in Nordic context is likely CPR or reference number
      'pii.ssn_us': {
        baseSeverity: 'low',  // Downgrade - likely false positive
        mandatory: false,      // Allow downgrade in Nordic context
      },
    },
    escalationMultiplier: 1.5,  // Raise all thresholds by 50%
  },

  // --- US: Standard patterns work well ---
  {
    locales: ['US'],
    signals: {
      // SSN remains critical in US context
      'pii.ssn_us': {
        baseSeverity: 'critical',
        mandatory: true,
      },
    },
  },

  // --- UK: Similar to US but different national ID ---
  {
    locales: ['UK'],
    signals: {
      // UK NI number is different format - SSN pattern is likely false positive
      'pii.ssn_us': {
        baseSeverity: 'low',
        mandatory: false,
      },
    },
  },

  // --- EU-DACH (German-speaking): Conservative approach ---
  {
    locales: ['EU-DACH'],
    signals: {
      'pii.phone': {
        densityThresholds: {
          15: 'medium',
        },
      },
      'pii.ssn_us': {
        baseSeverity: 'low',
        mandatory: false,
      },
    },
  },

  // --- EU-WESTERN (FR, BE, NL, LU) ---
  {
    locales: ['EU-WESTERN'],
    signals: {
      'pii.ssn_us': {
        baseSeverity: 'low',
        mandatory: false,
      },
    },
  },

  // --- EU-SOUTHERN (ES, IT, PT, GR) ---
  {
    locales: ['EU-SOUTHERN'],
    signals: {
      'pii.ssn_us': {
        baseSeverity: 'low',
        mandatory: false,
      },
    },
  },

  // --- EU-EASTERN (PL, CZ, SK, etc.) ---
  {
    locales: ['EU-EASTERN'],
    signals: {
      'pii.ssn_us': {
        baseSeverity: 'low',
        mandatory: false,
      },
    },
  },

  // --- EN-COMMONWEALTH (CA, AU, NZ, IE) ---
  {
    locales: ['EN-COMMONWEALTH'],
    signals: {
      // Similar patterns to UK - SSN format doesn't apply
      'pii.ssn_us': {
        baseSeverity: 'low',
        mandatory: false,
      },
    },
  },

  // --- LATAM ---
  {
    locales: ['LATAM'],
    signals: {
      'pii.phone': {
        densityThresholds: {
          15: 'medium',  // Different phone formats
        },
      },
      'pii.ssn_us': {
        baseSeverity: 'low',
        mandatory: false,
      },
    },
  },
];

// ============================================================================
// DEFAULT POLICY CONTRACT
// ============================================================================

export const DEFAULT_POLICY: PolicyContract = {
  version: CURRENT_POLICY_VERSION,
  localeMode: 'auto',
  signals: BASE_SIGNALS,
  cooccurrence: BASE_COOCCURRENCE,
  localeOverlays: LOCALE_OVERLAYS,
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
  },
};

// ============================================================================
// HELPER: Get effective policy for a locale
// ============================================================================

/**
 * Merge base policy with locale overlay to get effective policy
 */
export function getEffectivePolicy(
  locale: string,
  basePolicy: PolicyContract = DEFAULT_POLICY
): PolicyContract {
  // Find matching overlay
  const overlay = basePolicy.localeOverlays.find(o =>
    o.locales.includes(locale as any)
  );

  if (!overlay) {
    return basePolicy;
  }

  // Deep merge signals
  const mergedSignals = { ...basePolicy.signals };
  if (overlay.signals) {
    for (const [signalId, overrides] of Object.entries(overlay.signals)) {
      if (mergedSignals[signalId as SignalId]) {
        mergedSignals[signalId as SignalId] = {
          ...mergedSignals[signalId as SignalId],
          ...overrides,
        };
      }
    }
  }

  // Merge cooccurrence rules (overlay replaces if specified)
  const mergedCooccurrence = overlay.cooccurrenceOverrides || basePolicy.cooccurrence;

  return {
    ...basePolicy,
    signals: mergedSignals,
    cooccurrence: mergedCooccurrence,
  };
}

/**
 * Map legacy pattern key to new SignalId
 */
export function legacyKeyToSignalId(key: string): SignalId | null {
  const mapping: Record<string, SignalId> = {
    'phone': 'pii.phone',
    'email': 'pii.email',
    'ssn': 'pii.ssn_us',
    'api-key': 'secrets.api_key',
    'aws-key': 'secrets.aws_key',
    'password': 'secrets.password',
    'credit-card': 'financial.credit_card',
    'iban': 'financial.iban',
    'banking': 'financial.banking',
    'confidential-marker': 'confidential.marker',
    'ma-terms': 'confidential.ma_terms',
    'legal-agreement': 'legal.agreement',
    'hr-data': 'hr.employee_data',
    'author-name': 'pii.name',
    'company-name': 'pii.name',
  };
  return mapping[key] || null;
}
