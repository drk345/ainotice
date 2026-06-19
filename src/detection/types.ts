/**
 * AgentGuard Detection Pack Types
 *
 * Defines the structure for locale-aware detection packs.
 * See ADR010 for architectural decisions.
 *
 * Privacy: All detection happens locally. No language detection or telemetry.
 */

import type { RiskSignal, Severity, SignalType, SignalSource } from '../types/riskSignal';

// ============================================================================
// CORE TYPES (re-exported from canonical source)
// ============================================================================

/**
 * Re-export canonical RiskSignal and related types from src/types/riskSignal.ts
 * @see AG-PROMPT-033B for centralization history
 */
export type {
  RiskSignal,
  Severity,
  SignalType,
  SignalSource,
} from '../types/riskSignal';

// ============================================================================
// LOCALE CONFIDENCE TYPES
// ============================================================================

/** 
 * Locale confidence level
 * Determines which packs run:
 * - 'low': Only GlobalPack runs (safest, avoids false positives)
 * - 'medium': GlobalPack + explicitly enabled language packs
 * - 'high': GlobalPack + all enabled language packs + country packs if enabled
 */
export type LocaleConfidence = 'low' | 'medium' | 'high';

/**
 * Locale hint derived from document metadata
 * Used to infer locale confidence without language detection
 */
export interface LocaleHint {
  /** ISO language code from metadata (e.g., 'en-US', 'da-DK') */
  languageTag?: string;
  
  /** Creator application (e.g., 'Microsoft Word', 'Adobe InDesign') */
  creator?: string;
  
  /** Producer application */
  producer?: string;
  
  /** Inferred country from metadata patterns */
  inferredCountry?: string;
  
  /** Overall confidence in locale inference */
  confidence: LocaleConfidence;

  /** AG-PHASE-5-053: True if confidence was boosted by keyword density analysis */
  keywordDensityBoost?: boolean;
}

// ============================================================================
// DETECTION PATTERN TYPES
// ============================================================================

/** A single detection pattern */
export interface DetectionPattern {
  /** Unique identifier for this pattern */
  id: string;
  
  /** Human-readable name */
  name: string;
  
  /** Regex pattern to match */
  pattern: RegExp;
  
  /** Signal type category */
  type: SignalType;
  
  /** Default severity before policy adjustments */
  defaultSeverity: Severity;
  
  /** Detailed description for UI */
  description: string;
  
  /** Explanation shown to user */
  detail: string;
  
  /** 
   * Short rationale for why this pattern exists
   * Used for admin UI tooltips and documentation
   */
  rationale?: string;
  
  /** 
   * Which pack this pattern belongs to
   * Useful for admin UI filtering
   */
  pack?: string;
  
  /** 
   * If true, count matches instead of just detecting presence
   * Used for patterns like "X email addresses found"
   */
  countMatches?: boolean;
  
  /**
   * Minimum count to trigger signal (only if countMatches is true)
   * Default is 1
   */
  minCount?: number;
  
  /**
   * Description template when counting
   * Use {count} placeholder, e.g., "{count} email addresses"
   */
  countDescription?: string;
  
  /**
   * If true, this pattern has a hard severity floor (e.g., secrets)
   * Policy cannot reduce below defaultSeverity
   */
  hardFloor?: boolean;
  
  /**
   * Maximum severity this pattern can reach
   * Used to cap escalation for noisy patterns like phones
   */
  maxSeverity?: Severity;
  
  /**
   * Tags for filtering and categorization
   */
  tags?: string[];
  
  /**
   * Minimum locale confidence required to run this pattern
   * Patterns with 'high' won't run unless locale is highly confident
   * Default: 'low' (always runs)
   */
  minLocaleConfidence?: LocaleConfidence;
}

// ============================================================================
// DETECTION PACK TYPES
// ============================================================================

/** Pack layer determines loading priority and default state */
export type PackLayer = 'global' | 'language' | 'country';

/** Language family identifiers */
export type LanguageFamily = 'english' | 'romance' | 'germanic' | 'nordic' | 'slavic' | 'cjk';

/** Country codes (ISO 3166-1 alpha-2) */
export type CountryCode = 'US' | 'UK' | 'CA' | 'AU' | 'DE' | 'FR' | 'ES' | 'IT' | 'DK' | 'NO' | 'SE' | 'FI' | string;

/** Detection pack metadata */
export interface PackMetadata {
  /** Unique pack identifier */
  id: string;
  
  /** Human-readable name */
  name: string;
  
  /** Pack layer (global, language, country) */
  layer: PackLayer;
  
  /** Version for compatibility tracking */
  version: string;
  
  /** Brief description */
  description: string;
  
  /** Language family (if language pack) */
  languageFamily?: LanguageFamily;
  
  /** Country code (if country pack) */
  countryCode?: CountryCode;
  
  /** Countries covered by this pack */
  coverageCountries?: CountryCode[];
  
  /** 
   * Whether this pack is enabled by default
   * - global: always true
   * - language: true (but gated by locale confidence)
   * - country: false (must be explicitly enabled)
   */
  enabledByDefault: boolean;
  
  /**
   * Minimum locale confidence required to run this pack
   * - global: 'low' (always runs)
   * - language: 'medium' (requires some confidence)
   * - country: 'high' (requires high confidence or explicit enable)
   */
  minLocaleConfidence?: LocaleConfidence;
}

/** A complete detection pack */
export interface DetectionPack {
  /** Pack metadata */
  metadata: PackMetadata;
  
  /** Detection patterns included in this pack */
  patterns: DetectionPattern[];
}

// ============================================================================
// PACK CONFIGURATION TYPES
// ============================================================================

/** Configuration for pack selection */
export interface PackConfig {
  /** Global pack settings (cannot be fully disabled) */
  global?: {
    /** Specific patterns to disable */
    disabledPatterns?: string[];
  };
  
  /** Language pack settings */
  languagePacks?: {
    [key in LanguageFamily]?: boolean | {
      enabled: boolean;
      disabledPatterns?: string[];
    };
  };
  
  /** Country pack settings */
  countryPacks?: {
    [key in CountryCode]?: boolean | {
      enabled: boolean;
      disabledPatterns?: string[];
    };
  };
  
  /**
   * Override locale confidence (for testing or explicit user choice)
   * If set, this bypasses automatic locale inference
   */
  localeConfidenceOverride?: LocaleConfidence;
}

// ============================================================================
// DETECTION RESULT TYPES
// ============================================================================

/** Result from running detection patterns */
export interface DetectionResult {
  /** Detected signals */
  signals: RiskSignal[];
  
  /** Packs that were executed */
  packsExecuted: string[];
  
  /** Pattern match counts (for debugging) */
  matchCounts?: Record<string, number>;
  
  /** Locale confidence used for this detection */
  localeConfidence?: LocaleConfidence;
}

/** Context passed to detection */
export interface DetectionContext {
  /** Text content to scan */
  text: string;
  
  /** Source of the content */
  source: SignalSource;
  
  /** Filename (for filename-based detection) */
  filename?: string;
  
  /** File MIME type */
  mimeType?: string;
  
  /** Document metadata hints for locale inference */
  metadata?: {
    author?: string;
    creator?: string;
    producer?: string;
    language?: string;
  };
  
  /** 
   * Explicit locale confidence (overrides inference)
   * Default: 'low' (conservative - only global pack runs)
   */
  localeConfidence?: LocaleConfidence;
}

// ============================================================================
// HELPER TYPE GUARDS
// ============================================================================

/** Check if a pack is a global pack */
export function isGlobalPack(pack: DetectionPack): boolean {
  return pack.metadata.layer === 'global';
}

/** Check if a pack is a language pack */
export function isLanguagePack(pack: DetectionPack): boolean {
  return pack.metadata.layer === 'language';
}

/** Check if a pack is a country pack */
export function isCountryPack(pack: DetectionPack): boolean {
  return pack.metadata.layer === 'country';
}

/** 
 * Compare locale confidence levels
 * Returns true if `actual` meets or exceeds `required`
 */
export function meetsLocaleConfidence(actual: LocaleConfidence, required: LocaleConfidence): boolean {
  const order: LocaleConfidence[] = ['low', 'medium', 'high'];
  return order.indexOf(actual) >= order.indexOf(required);
}