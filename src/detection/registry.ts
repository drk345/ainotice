/**
 * AgentGuard Detection Registry — Deprecated Shim
 *
 * AG-PHASE-3-048: This file is a backward-compatibility shim.
 * All active code has been moved to purpose-built modules:
 *
 * - Card validation: paymentCardValidation.ts
 *   (luhnValidate, checkIssuerPrefix, assessCardMatchQuality)
 *
 * - Quality gates: qualityGates.ts
 *   (assessUrlCredentialMatchQuality, assessConfidentialMatchQuality)
 *
 * - Detection: packRegistry.ts runDetection()
 *
 * This shim re-exports symbols so existing scripts continue to compile.
 * Scripts should migrate imports to the canonical modules (P3-2).
 *
 * @deprecated Use the purpose-built modules listed above.
 */

import type { LocaleKey } from '../policy/locale';

// ============================================================================
// RE-EXPORTS: Card validation (canonical home: paymentCardValidation.ts)
// ============================================================================

export {
  luhnValidate,
  checkIssuerPrefix,
  assessCardMatchQuality,
  type CardMatchQuality,
  type CardMatchQualityResult,
} from './paymentCardValidation';

// ============================================================================
// RE-EXPORTS: Quality gates (canonical home: qualityGates.ts)
// ============================================================================

export {
  URL_CREDENTIAL_PATTERN_IDS,
  assessUrlCredentialMatchQuality,
  type UrlCredentialMatchQuality,
  type UrlCredentialMatchQualityResult,
  CONFIDENTIAL_PATTERN_IDS,
  assessConfidentialMatchQuality,
  type ConfidentialMatchQuality,
  type ConfidentialMatchQualityResult,
} from './qualityGates';

// ============================================================================
// DEPRECATED TYPES (kept for script backward compatibility)
// ============================================================================

export type SignalType = 'pii' | 'confidential' | 'sensitive' | 'ip' | 'financial' | 'legal';
export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface ContentDetectionContext {
  text: string;
  locale: LocaleKey;
  source: 'content' | 'metadata' | 'filename';
}

export interface ContentDetectionResult {
  matches: never[];
  patternsRun: number;
  patternsMatched: number;
}

export interface RegistryPattern {
  id: string;
  type: SignalType;
  pattern: RegExp;
  description: string;
  detail: string;
  defaultSeverity: Severity;
  hardFloor?: boolean;
  maxSeverity?: Severity;
  countMatches?: boolean;
  minCount?: number;
  countDescription?: string;
  applicableLocales?: LocaleKey[];
  excludedLocales?: LocaleKey[];
  enabled?: boolean;
  validate?: (matchString: string) => boolean;
}

// ============================================================================
// DEPRECATED FUNCTIONS (all return empty/no-op results)
// ============================================================================

/**
 * @deprecated AG-PHASE-2-046: Returns empty results. Use runDetection() from packRegistry.ts.
 */
export function runContentDetection(_context: ContentDetectionContext): ContentDetectionResult {
  return { matches: [], patternsRun: 0, patternsMatched: 0 };
}

/**
 * @deprecated AG-PHASE-3-048: Returns empty array. All patterns are in pack-based detection.
 */
export function getRegisteredPatterns(): RegistryPattern[] {
  return [];
}

// Re-export LocaleKey for scripts that import it from here
export type { LocaleKey } from '../policy/locale';
