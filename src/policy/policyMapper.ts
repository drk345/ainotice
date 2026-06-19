/**
 * AgentGuard Policy Mapper v1.1 (Rosetta Stone)
 *
 * Maps (signal + context) → (explanationId + uiEscalation).
 * This is a data-only resolver that routes signals to explanation IDs
 * and UI escalation hints based on PolicyContext.
 *
 * CRITICAL: Does NOT control severity. Severity remains owned by
 * Policy Contract (applyPolicyContract). The mapper only influences:
 * - Which explanationId to use for copy lookup
 * - UI escalation hints (none/inline/modal) for future progressive disclosure
 *
 * Privacy: No content, no telemetry. Pure function, no side effects.
 *
 * @see ADR-016: Policy Mapper Resolver
 */

import type { DepartmentId } from './policy';
import { deriveDestination, isPublicAiHost, type DestinationType } from './destination';

// Static import of policy mapper JSON
import policyMapperData from '../../docs/policy/policy-mapper-v1.1.json';

// Re-export destination types and functions
export { deriveDestination, isPublicAiHost, type DestinationType } from './destination';

// ============================================================================
// TYPES
// ============================================================================

/**
 * UI escalation hint for future progressive disclosure
 * - 'none': No UI indication needed
 * - 'inline': Show inline indicator (subtle)
 * - 'modal': Show in modal prominently
 */
export type UiEscalation = 'none' | 'inline' | 'modal';

/**
 * Locale group for broad regional matching
 */
export type LocaleGroup = 'EU' | 'US' | 'UK' | 'EN' | 'LATAM' | 'UNKNOWN';

/**
 * Context for policy mapping resolution (PolicyContextLike)
 */
export interface PolicyMapperContext {
  /** Department scope (existing DepartmentId) */
  department?: DepartmentId;

  /** Destination type (inferred from URL) */
  destination?: DestinationType;

  /** Intent placeholder (future use, currently 'unknown') */
  intent?: string;

  /** Broad locale group */
  localeGroup?: LocaleGroup;

  /** Specific locale profile ID (e.g., "EU-NORDICS", "US") */
  localeProfile?: string;
}

/**
 * Result from policy mapping resolution
 */
export interface PolicyMappingResult {
  /** Explanation ID to use for copy lookup */
  explanationId: string;

  /** UI escalation hint */
  uiEscalation: UiEscalation;
}

// ============================================================================
// INTERNAL TYPES (from JSON structure)
// ============================================================================

interface OverrideCondition {
  department?: string;
  destination?: string;
  intent?: string;
  localeGroup?: string;
  localeProfile?: string;
}

interface MappingOverride {
  condition: OverrideCondition;
  explanationId?: string;
  uiEscalation?: string;
}

interface PolicyMapping {
  signalType: string;
  default: {
    explanationId: string;
    uiEscalation: string;
  };
  overrides?: MappingOverride[];
}

interface PolicyMapperJSON {
  version: string;
  name: string;
  matchingPrecedence: string;
  mappings: PolicyMapping[];
}

// ============================================================================
// LOCALE GROUP DERIVATION
// ============================================================================

/**
 * Derive locale group from locale profile
 *
 * @param localeProfile - Specific locale profile (e.g., "EU-NORDICS", "US")
 * @returns LocaleGroup for broad matching
 */
export function deriveLocaleGroup(localeProfile: string | undefined): LocaleGroup {
  if (!localeProfile) return 'UNKNOWN';

  const profile = localeProfile.toUpperCase();

  if (profile === 'US') return 'US';
  if (profile === 'UK') return 'UK';
  if (profile.startsWith('EU-') || ['EU-NORDICS', 'EU-DACH', 'EU-SOUTHERN', 'EU-WESTERN', 'EU-EASTERN'].includes(profile)) {
    return 'EU';
  }
  if (profile === 'EN-COMMONWEALTH' || profile.startsWith('EN-')) return 'EN';
  if (profile === 'LATAM') return 'LATAM';

  return 'UNKNOWN';
}

// ============================================================================
// RESOLVER
// ============================================================================

// Type assertion for imported JSON
const mapperData = policyMapperData as PolicyMapperJSON;

// Build lookup map for O(1) access
const mappingsBySignalType = new Map<string, PolicyMapping>();
for (const mapping of mapperData.mappings) {
  mappingsBySignalType.set(mapping.signalType, mapping);
}

/**
 * Check if all condition keys match the context (strict matching)
 *
 * @param condition - Override condition to check
 * @param ctx - Policy mapper context
 * @returns true if ALL provided condition keys equal ctx values
 */
function conditionMatches(condition: OverrideCondition, ctx: PolicyMapperContext): boolean {
  // Check each condition key if present - ALL must match
  if (condition.department !== undefined && condition.department !== ctx.department) {
    return false;
  }
  if (condition.destination !== undefined && condition.destination !== ctx.destination) {
    return false;
  }
  if (condition.intent !== undefined && condition.intent !== ctx.intent) {
    return false;
  }
  if (condition.localeGroup !== undefined && condition.localeGroup !== ctx.localeGroup) {
    return false;
  }
  if (condition.localeProfile !== undefined && condition.localeProfile !== ctx.localeProfile) {
    return false;
  }

  // All provided conditions matched
  return true;
}

/**
 * Resolve policy mapping for a signal type
 *
 * Resolution rules:
 * 1. Find mapping by signalType
 * 2. Check overrides in order; match if ALL condition keys equal ctx
 * 3. First matching override wins
 * 4. If no override matches, return mapping.default
 * 5. If signalType unknown, return safe fallback
 *
 * @param signalType - Signal type key (e.g., "secret.api_key", "pii.phone")
 * @param ctx - Policy mapper context
 * @returns PolicyMappingResult with explanationId and uiEscalation
 */
export function resolveMapper(
  signalType: string,
  ctx: PolicyMapperContext = {}
): PolicyMappingResult {
  // Find mapping for this signal type
  const mapping = mappingsBySignalType.get(signalType);

  if (!mapping) {
    // Safe fallback for unknown signal types
    return {
      explanationId: signalType || 'gen.generic',
      uiEscalation: 'inline',
    };
  }

  // Check overrides in order (first match wins)
  if (mapping.overrides) {
    for (const override of mapping.overrides) {
      if (conditionMatches(override.condition, ctx)) {
        // Override matched - merge with default
        return {
          explanationId: override.explanationId ?? mapping.default.explanationId,
          uiEscalation: (override.uiEscalation ?? mapping.default.uiEscalation) as UiEscalation,
        };
      }
    }
  }

  // No override matched - return default
  return {
    explanationId: mapping.default.explanationId,
    uiEscalation: mapping.default.uiEscalation as UiEscalation,
  };
}

/**
 * Get the policy mapper version
 */
export function getPolicyMapperVersion(): string {
  return mapperData.version;
}

/**
 * Get the policy mapper name
 */
export function getPolicyMapperName(): string {
  return mapperData.name;
}

/**
 * Get all mapped signal types
 * Useful for testing and validation
 */
export function getMappedSignalTypes(): string[] {
  return Array.from(mappingsBySignalType.keys());
}

// ============================================================================
// SIGNAL TYPE ADAPTER
// ============================================================================

/**
 * Map internal explanation ID to mapper signal type
 *
 * This adapter bridges between our internal explanation IDs (from getPatternCategory)
 * and the canonical mapper signal types in the JSON.
 *
 * @param explanationId - Internal explanation ID (e.g., "secret.api_key", "pii.ssn")
 * @returns Mapper signal type for lookup
 */
export function mapExplanationIdToSignalType(explanationId: string): string {
  // Most IDs map directly
  const directMappings: Record<string, string> = {
    // Secrets
    'secret.api_key': 'secret.api_key',
    'secret.aws_key': 'secret.aws_key',
    'secret.password': 'secret.password',
    'secret.private_key': 'secret.password', // Map to generic password

    // PII
    'pii.ssn': 'pii.ssn',
    'pii.ssn.locale_gated': 'pii.ssn',
    'pii.credit_card': 'pii.ssn', // High-risk PII, treat similarly
    'pii.phone': 'pii.phone',
    'pii.phone.density': 'pii.contact_batch',
    'pii.email': 'pii.phone', // Low-risk contact info
    'pii.email.density': 'pii.email_batch',
    'pii.employee': 'dict.hr.salary',
    'pii.compensation': 'dict.hr.salary',

    // Financial
    'financial.iban': 'pii.iban',
    'financial.banking': 'dict.finance.banking',
    'financial.data': 'dict.finance.projections',

    // Legal
    'legal.contract': 'dict.legal.language',
    'legal.nda': 'dict.legal.privilege',

    // Confidential
    'confidential.marker': 'dict.legal.privilege',
    'confidential.ma': 'dict.finance.projections',

    // Dictionary
    'dictionary.finance': 'dict.finance.banking',
    'dictionary.hr': 'dict.hr.salary',
    'dictionary.legal': 'dict.legal.privilege',
    'dictionary.match': 'dict.legal.language',

    // IP
    'ip.content': 'dict.legal.privilege',
  };

  return directMappings[explanationId] || explanationId;
}
