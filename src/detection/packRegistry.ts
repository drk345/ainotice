/**
 * AgentGuard Detection Pack Registry
 * 
 * Resolves which detection packs are active based on:
 * 1. Policy configuration (admin overrides)
 * 2. Locale confidence (automatic gating)
 * 
 * Locale Confidence Gating:
 * - LOW:    Only GlobalPack runs (safest, avoids false positives)
 * - MEDIUM: GlobalPack + enabled language packs
 * - HIGH:   All enabled packs including country-specific
 * 
 * Privacy: All detection happens locally. No telemetry.
 */

import {
  DetectionPack,
  DetectionPattern,
  DetectionContext,
  DetectionResult,
  PackConfig,
  RiskSignal,
  LanguageFamily,
  CountryCode,
  LocaleConfidence,
  LocaleHint,
  meetsLocaleConfidence,
} from './types';

// Import all packs
import { GlobalPack } from './packs/global';
import { EnglishPack } from './packs/english';
import { RomancePack } from './packs/romance';
import { NordicPack } from './packs/nordic';

// AG-PROMPT-044: Debug diagnostics
import {
  isDebugMode,
  debugLog,
  logDetectionInvocation,
  logPackLoadingDiagnostics,
  type DetectionInvocationDiagnostics,
  type PackLoadingDiagnostics,
} from '../debug/diagnostics';

// AG-PROMPT-URL-FALSEPOS-005: URL credential quality assessment
// AG-PROMPT-CONFIDENTIAL-QUALITY-007: Confidentiality marker quality assessment
// AG-PHASE-3-048: Imported from qualityGates (extracted from registry)
import {
  URL_CREDENTIAL_PATTERN_IDS,
  assessUrlCredentialMatchQuality,
  CONFIDENTIAL_PATTERN_IDS,
  assessConfidentialMatchQuality,
} from './qualityGates';

// AG-PROMPT-SIGNAL-VALIDATION-GATES-024: Payment card validation gates
import {
  PAYMENT_CARD_PATTERN_IDS,
  validatePaymentCard,
} from './paymentCardValidation';

// AG-PROMPT-032: SWIFT/BIC validation gates
import {
  SWIFT_BIC_PATTERN_IDS,
  validateSwiftBic,
} from './swiftBicValidation';

// AG-XLSX-HARDENING-PLAN-001: IBAN Mod97 gate
import { mod97Iban } from './checksums';
import { scoreProximity, IBAN_ANCHORS, adjustConfidenceByDomainAnchors } from './proximityScorer';
/** Pattern IDs that require IBAN Mod97 validation */
const IBAN_PATTERN_IDS = new Set(['global-iban']);

// AG-PROMPT-035: Unified national ID validation gates (replaces CPR-only)
import {
  NATIONAL_ID_PATTERN_IDS,
  NATIONAL_ID_SIGNAL_ID,
  hasInsuranceContext,
  hasInvoiceFinancialContext,
  hasNationalIdLabelProximity,
} from './nationalIdValidation';

// AG-PROMPT-126: Bare-ID anchor requirement for overlap-prone validators.
// These validators have SOFT context gates (checksum-only is_valid) and
// emit on bare digit sequences in generic business text. Requiring anchor
// proximity (confidence >= 0.65) suppresses FPs in invoice/order/reference contexts.
const ANCHOR_REQUIRED_PATTERN_IDS = new Set([
  'global-nl-bsn',      // NL BSN: 9-digit, soft context, overlaps PT NIF
  'global-pt-nif',      // PT NIF: 9-digit, soft context, overlaps NL BSN
  'global-de-steuer-id', // DE Steuer-ID: 11-digit, soft context, overlaps PL PESEL
  'global-pl-pesel',    // PL PESEL: 11-digit, soft context, overlaps DE Steuer-ID
]);
const ANCHOR_REQUIRED_MIN_CONFIDENCE = 0.65;

// AG-PROMPT-127: Structured-data exception anchors per pattern.
// When a match is suppressed by AG-126 anchor-required gating, check if an
// anchor keyword appears on the same line or the line immediately above
// (tabular header context). This handles structured/tabular documents where
// the anchor is a column header separated from the data row.
import {
  NL_BSN_ANCHORS, PT_NIF_ANCHORS,
  DE_STEUER_ID_ANCHORS, PL_PESEL_ANCHORS,
} from './proximityScorer';

const STRUCTURED_CONTEXT_ANCHORS = new Map<string, string[]>([
  ['global-nl-bsn', [...NL_BSN_ANCHORS]],
  ['global-pt-nif', [...PT_NIF_ANCHORS]],
  ['global-de-steuer-id', [...DE_STEUER_ID_ANCHORS]],
  ['global-pl-pesel', [...PL_PESEL_ANCHORS]],
]);

/**
 * AG-PROMPT-127: Check for structured/tabular label context.
 * Returns true if an anchor keyword appears on the same line as the match
 * OR on the line immediately above (handles table headers).
 * Only uses market-specific anchor keywords — generic prose does not qualify.
 */
function hasStructuredLabelContext(
  text: string,
  matchIndex: number,
  matchLength: number,
  patternId: string,
): boolean {
  const anchors = STRUCTURED_CONTEXT_ANCHORS.get(patternId);
  if (!anchors) return false;

  // Extract the current line and the line above
  const lineStart = text.lastIndexOf('\n', matchIndex - 1) + 1;
  const prevLineStart = lineStart > 0
    ? text.lastIndexOf('\n', lineStart - 2) + 1
    : 0;
  const lineEnd = text.indexOf('\n', matchIndex + matchLength);
  const endIdx = lineEnd === -1 ? text.length : lineEnd;

  const currentLine = text.slice(lineStart, endIdx).toLowerCase();
  const prevLine = lineStart > 0
    ? text.slice(prevLineStart, lineStart).toLowerCase()
    : '';

  for (const anchor of anchors) {
    const lower = anchor.toLowerCase();
    if (currentLine.includes(lower) || prevLine.includes(lower)) {
      return true;
    }
  }

  return false;
}

// AG-PROMPT-031: Evidence tracing
import { AG_DEBUG_EVIDENCE, createEvidence } from './evidenceCapture';
import type { EvidenceItem } from '../types/riskSignal';

// AG-PROMPT-4: Text normalization for detection reliability
import { normalizeForDetection } from '../normalization';

// ============================================================================
// CONFIGURATION
// ============================================================================

/** Enable debug logging (counts only, no content) */
const DEBUG_PACKS = false;

/** AG-PROMPT-044: Track if packs have been logged at startup */
let packsLoggedAtStartup = false;

/** 
 * Default locale confidence when not specified
 * Set to LOW to be conservative and avoid false positives
 */
const DEFAULT_LOCALE_CONFIDENCE: LocaleConfidence = 'low';

// ============================================================================
// PACK REGISTRY
// ============================================================================

/** All available language packs */
const LANGUAGE_PACKS: Record<LanguageFamily, DetectionPack> = {
  english: EnglishPack,
  romance: RomancePack,
  nordic: NordicPack,
  // Stubs for future implementation
  germanic: createStubPack('germanic', 'Germanic Language Pack', ['DE', 'AT', 'CH', 'NL', 'BE']),
  slavic: createStubPack('slavic', 'Slavic Language Pack', ['PL', 'CZ', 'SK', 'RU', 'UA']),
  cjk: createStubPack('cjk', 'CJK Language Pack', ['CN', 'JP', 'KR', 'TW', 'HK']),
};

/** All available country packs (disabled by default) */
const COUNTRY_PACKS: Record<CountryCode, DetectionPack> = {
  // US SSN pack - example of country-specific pack
  US: createCountryPack('US', 'United States', [
    {
      id: 'us-ssn',
      name: 'US Social Security Number',
      pattern: /\b\d{3}-\d{2}-\d{4}\b/,
      type: 'pii',
      defaultSeverity: 'critical',
      description: 'SSN pattern detected',
      detail: 'File contains text matching Social Security Number format (XXX-XX-XXXX).',
      rationale: 'SSN is the primary US national identifier. Exposure enables identity theft.',
      pack: 'country-us',
      hardFloor: true,
      tags: ['pii', 'ssn', 'us', 'national-id'],
      minLocaleConfidence: 'medium', // Requires at least medium confidence
    },
  ]),
  // Other country packs are stubs
  UK: createCountryPack('UK', 'United Kingdom', []),
  CA: createCountryPack('CA', 'Canada', []),
  AU: createCountryPack('AU', 'Australia', []),
  DE: createCountryPack('DE', 'Germany', []),
  FR: createCountryPack('FR', 'France', []),
  ES: createCountryPack('ES', 'Spain', []),
  IT: createCountryPack('IT', 'Italy', []),
  DK: createCountryPack('DK', 'Denmark', []),
  NO: createCountryPack('NO', 'Norway', []),
  SE: createCountryPack('SE', 'Sweden', []),
  FI: createCountryPack('FI', 'Finland', []),
};

// ============================================================================
// PACK CREATION HELPERS
// ============================================================================

/** Create a stub language pack for future implementation */
function createStubPack(id: LanguageFamily, name: string, countries: CountryCode[]): DetectionPack {
  return {
    metadata: {
      id,
      name,
      layer: 'language',
      version: '0.0.1',
      description: `${name} - STUB, not yet implemented`,
      languageFamily: id,
      coverageCountries: countries,
      enabledByDefault: true,
      minLocaleConfidence: 'medium',
    },
    patterns: [],
  };
}

/** Create a country-specific pack */
function createCountryPack(code: CountryCode, name: string, patterns: DetectionPattern[]): DetectionPack {
  return {
    metadata: {
      id: `country-${code.toLowerCase()}`,
      name: `${name} Country Pack`,
      layer: 'country',
      version: '1.0.0',
      description: `Country-specific patterns for ${name}. Disabled by default.`,
      countryCode: code,
      enabledByDefault: false, // Country packs are OFF by default
      minLocaleConfidence: 'high', // Requires high confidence
    },
    patterns: patterns.map(p => ({ ...p, pack: `country-${code.toLowerCase()}` })),
  };
}

// ============================================================================
// LOCALE CONFIDENCE INFERENCE
// ============================================================================

/**
 * Infer locale confidence from document metadata and content.
 *
 * Sources (in priority order):
 * 1. Explicit language tag in PDF metadata → medium/high
 * 2. AG-PHASE-5-053: Keyword density boost from document text → medium
 * 3. Default: low (only global pack runs)
 *
 * @param context Detection context with metadata and text
 * @returns Locale hint with confidence level
 */
export function inferLocaleConfidence(context: DetectionContext): LocaleHint {
  const metadata = context.metadata;

  // Default: low confidence (only global pack runs)
  const hint: LocaleHint = {
    confidence: 'low',
  };

  // Source 1: Explicit language tag in metadata (highest priority)
  if (metadata?.language) {
    hint.languageTag = metadata.language;
    // Explicit language tag gives medium confidence
    hint.confidence = 'medium';

    // Extract country from language tag if present (e.g., 'en-US' -> 'US')
    const countryMatch = metadata.language.match(/^[a-z]{2}-([A-Z]{2})$/i);
    if (countryMatch) {
      hint.inferredCountry = countryMatch[1].toUpperCase();
      hint.confidence = 'high'; // Full locale tag gives high confidence
    }
  }

  // Store creator/producer for potential future use
  if (metadata?.creator) {
    hint.creator = metadata.creator;
  }
  if (metadata?.producer) {
    hint.producer = metadata.producer;
  }

  // Source 2: AG-PHASE-5-053 — Keyword density boost from document text.
  // If metadata didn't provide locale, check if the text has strong English signal.
  // This is NOT unconditional — requires evidence from function word density.
  if (hint.confidence === 'low' && context.text && context.text.length >= 200) {
    const boost = computeKeywordDensityBoost(context.text);
    if (boost) {
      hint.confidence = 'medium';
      hint.keywordDensityBoost = true;
    }
  }

  return hint;
}

// ============================================================================
// AG-PHASE-5-053: KEYWORD DENSITY BOOST
// ============================================================================

/**
 * Common English function words. These are language-specific and rarely appear
 * in non-English text at high density. We use these (not content words) to avoid
 * false positive locale detection from borrowed English technical terms.
 */
const ENGLISH_FUNCTION_WORDS = new Set([
  'the', 'and', 'for', 'that', 'with', 'this', 'from', 'are', 'was',
  'not', 'but', 'have', 'has', 'been', 'were', 'will', 'can', 'its',
  'your', 'their', 'which', 'would', 'should', 'could', 'into', 'than',
  'other', 'these', 'those', 'each', 'does', 'did', 'about', 'between',
]);

/**
 * AG-PHASE-5-053A: Nordic function words (Danish/Norwegian/Swedish).
 * Shared across Scandinavian languages. Used to detect Nordic-language text
 * and activate the Nordic language pack.
 */
const NORDIC_FUNCTION_WORDS = new Set([
  'og', 'er', 'den', 'det', 'til', 'med', 'som', 'har', 'kan',
  'vil', 'ikke', 'eller', 'fra', 'ved', 'der', 'alle', 'blev', 'skal',
  'efter', 'også', 'kun', 'sig', 'samt', 'hvis', 'mere', 'sin',
  'sit', 'sine', 'hans', 'hele',
]);

/** Minimum text length to attempt keyword density boost */
const KDB_MIN_TEXT_LENGTH = 200;

/** Minimum unique function words found */
const KDB_MIN_UNIQUE_WORDS = 8;

/** Minimum ratio of function word tokens to total words */
const KDB_MIN_DENSITY = 0.03;

/**
 * Check if text has strong function word density for a language family.
 * Returns true if the text is very likely in the target language, false otherwise.
 *
 * This is intentionally conservative:
 * - Requires 8+ unique function words (not just one repeated)
 * - Requires 3%+ of total words to be function words
 * - Only checks function words (not content/technical terms that appear across languages)
 */
function checkFunctionWordDensity(text: string, wordSet: Set<string>): boolean {
  // AG-PHASE-5-053A: Strip non-printable chars before sampling. Partial-quality PDFs
  // (e.g., CIDFont without ToUnicode) can have binary noise at the start that pushes
  // readable text beyond the sample window. Stripping first ensures the sample
  // captures actual words, not font table bytes.
  const cleaned = text.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\ufffd]/g, ' ');
  const sample = cleaned.slice(0, 5000).toLowerCase();
  const words = sample.split(/\s+/).filter(w => w.length > 0);
  if (words.length < 30) return false;

  const foundUnique = new Set<string>();
  let matchCount = 0;

  for (const word of words) {
    // Strip trailing punctuation for matching
    const clean = word.replace(/[.,;:!?)'"]+$/, '').replace(/^['"(]+/, '');
    if (wordSet.has(clean)) {
      foundUnique.add(clean);
      matchCount++;
    }
  }

  return foundUnique.size >= KDB_MIN_UNIQUE_WORDS && (matchCount / words.length) >= KDB_MIN_DENSITY;
}

/**
 * Check if text should receive a keyword density boost.
 * Returns true if the text is clearly English OR Nordic prose.
 */
function computeKeywordDensityBoost(text: string): boolean {
  return checkFunctionWordDensity(text, ENGLISH_FUNCTION_WORDS)
    || checkFunctionWordDensity(text, NORDIC_FUNCTION_WORDS);
}

// ============================================================================
// PACK RESOLUTION
// ============================================================================

/** Default pack configuration */
export const DEFAULT_PACK_CONFIG: PackConfig = {
  global: {
    disabledPatterns: [],
  },
  languagePacks: {
    english: true,
    romance: false, // AG-PHASE-5E-060: Stub pack disabled by default
    nordic: true,
    germanic: true,
    slavic: true,
    cjk: true,
  },
  countryPacks: {
    // All country packs disabled by default
    US: false,
    UK: false,
    CA: false,
    AU: false,
    DE: false,
    FR: false,
    ES: false,
    IT: false,
    DK: false,
    NO: false,
    SE: false,
    FI: false,
  },
};

/**
 * Resolve which packs should be active based on configuration AND locale confidence
 * 
 * @param config Pack configuration (admin overrides)
 * @param localeConfidence Current locale confidence level
 * @returns Array of active detection packs
 */
export function resolveActivePacks(
  config: PackConfig = DEFAULT_PACK_CONFIG,
  localeConfidence: LocaleConfidence = DEFAULT_LOCALE_CONFIDENCE
): DetectionPack[] {
  const activePacks: DetectionPack[] = [];
  
  // Use override if specified
  const effectiveConfidence = config.localeConfidenceOverride ?? localeConfidence;
  
  // Global pack is ALWAYS included (no gating)
  activePacks.push(GlobalPack);
  
  // Language packs are gated by locale confidence
  // Only run if confidence >= 'medium' OR explicitly enabled with override
  if (meetsLocaleConfidence(effectiveConfidence, 'medium')) {
    for (const [family, pack] of Object.entries(LANGUAGE_PACKS)) {
      const familyConfig = config.languagePacks?.[family as LanguageFamily];
      
      // Check if enabled (default is true for language packs)
      const isEnabled = familyConfig === undefined 
        ? pack.metadata.enabledByDefault 
        : (typeof familyConfig === 'boolean' ? familyConfig : familyConfig.enabled);
      
      if (isEnabled) {
        // Check pack-level locale confidence requirement
        const packMinConfidence = pack.metadata.minLocaleConfidence ?? 'medium';
        if (meetsLocaleConfidence(effectiveConfidence, packMinConfidence)) {
          activePacks.push(pack);
        }
      }
    }
  }
  
  // Country packs require HIGH confidence AND explicit enable
  if (meetsLocaleConfidence(effectiveConfidence, 'high')) {
    for (const [code, pack] of Object.entries(COUNTRY_PACKS)) {
      const countryConfig = config.countryPacks?.[code as CountryCode];
      
      // Country packs default to OFF - must be explicitly enabled
      const isEnabled = typeof countryConfig === 'boolean' 
        ? countryConfig 
        : (countryConfig?.enabled ?? false);
      
      if (isEnabled) {
        activePacks.push(pack);
      }
    }
  }
  
  if (DEBUG_PACKS) {
    console.log(`[AgentGuard] Locale confidence: ${effectiveConfidence}`);
    console.log(`[AgentGuard] Active packs: ${activePacks.map(p => p.metadata.id).join(', ')}`);
  }
  
  return activePacks;
}

/**
 * Get all patterns from active packs, filtered by locale confidence and disabled patterns
 */
export function getActivePatterns(
  config: PackConfig = DEFAULT_PACK_CONFIG,
  localeConfidence: LocaleConfidence = DEFAULT_LOCALE_CONFIDENCE
): DetectionPattern[] {
  const packs = resolveActivePacks(config, localeConfidence);
  const patterns: DetectionPattern[] = [];
  const disabledGlobal = new Set(config.global?.disabledPatterns || []);
  
  for (const pack of packs) {
    for (const pattern of pack.patterns) {
      // Skip if pattern is globally disabled
      if (disabledGlobal.has(pattern.id)) {
        continue;
      }
      
      // Skip if pattern requires higher locale confidence than we have
      const patternMinConfidence = pattern.minLocaleConfidence ?? 'low';
      if (!meetsLocaleConfidence(localeConfidence, patternMinConfidence)) {
        continue;
      }
      
      // Skip if pattern is disabled in its specific pack config
      const packConfig = pack.metadata.layer === 'language'
        ? config.languagePacks?.[pack.metadata.languageFamily as LanguageFamily]
        : config.countryPacks?.[pack.metadata.countryCode as CountryCode];
      
      if (typeof packConfig === 'object' && packConfig.disabledPatterns?.includes(pattern.id)) {
        continue;
      }
      
      patterns.push(pattern);
    }
  }
  
  return patterns;
}

// ============================================================================
// DETECTION EXECUTION
// ============================================================================

/**
 * Run detection patterns against content
 *
 * @param context Detection context (text, source, metadata)
 * @param config Pack configuration
 * @returns Detection result with signals and metadata
 */
export function runDetection(
  context: DetectionContext,
  config: PackConfig = DEFAULT_PACK_CONFIG
): DetectionResult {
  // Determine locale confidence
  const localeHint = inferLocaleConfidence(context);
  const localeConfidence = context.localeConfidence ?? config.localeConfidenceOverride ?? localeHint.confidence;

  // Resolve active packs based on confidence
  const packs = resolveActivePacks(config, localeConfidence);
  const signals: RiskSignal[] = [];
  const matchCounts: Record<string, number> = {};
  const packsExecuted: string[] = packs.map(p => p.metadata.id);

  // AG-PROMPT-044: Log pack loading diagnostics at first use
  if (isDebugMode() && !packsLoggedAtStartup) {
    packsLoggedAtStartup = true;
    const packDiag: PackLoadingDiagnostics = {
      packCount: packs.length,
      packIds: packsExecuted,
      localeRouting: localeHint.languageTag ?? 'auto',
      localeConfidence,
      localeMatchesPack: packs.some(p =>
        p.metadata.layer === 'language' || p.metadata.layer === 'country'
      ),
    };
    logPackLoadingDiagnostics(packDiag);
  }

  // AG-PROMPT-044: Log detection invocation entry point
  if (isDebugMode()) {
    const invocationDiag: DetectionInvocationDiagnostics = {
      docId: context.filename ?? '<unknown>',
      locale: localeHint.languageTag ?? 'unknown',
      localeConfidence,
      textLength: context.text?.length ?? 0,
    };
    logDetectionInvocation(invocationDiag);
  }

  if (DEBUG_PACKS) {
    console.log(`[AgentGuard] Running detection with locale confidence: ${localeConfidence}`);
  }

  // AG-PROMPT-4: Normalize text before detection
  // This addresses DATA2 false negatives from spaced-text, zero-width chars, etc.
  const normalizedText = normalizeForDetection(context.text);

  for (const pack of packs) {
    for (const pattern of pack.patterns) {
      // Check if pattern should be skipped (disabled)
      const disabledGlobal = config.global?.disabledPatterns || [];
      if (disabledGlobal.includes(pattern.id)) continue;

      // Check pattern-level locale confidence
      const patternMinConfidence = pattern.minLocaleConfidence ?? 'low';
      if (!meetsLocaleConfidence(localeConfidence, patternMinConfidence)) {
        continue;
      }

      // Run the pattern against normalized text
      const result = runPattern(pattern, normalizedText, context.source);
      
      if (result) {
        signals.push(result.signal);
        matchCounts[pattern.id] = result.count;
      }
    }
  }
  
  if (DEBUG_PACKS) {
    console.log(`[AgentGuard] Detection complete: ${signals.length} signals from ${packsExecuted.length} packs`);
  }

  // AG-PROMPT-044: Log detection result (raw signal count)
  if (isDebugMode()) {
    debugLog('DetectionResult', `rawSignals=${signals.length} packs=${packsExecuted.length}`, {
      signalsByType: signals.reduce((acc, s) => {
        acc[s.type] = (acc[s.type] ?? 0) + 1;
        return acc;
      }, {} as Record<string, number>),
    });
  }

  return {
    signals,
    packsExecuted,
    matchCounts,
    localeConfidence,
  };
}

/**
 * Run a single pattern against text
 * AG-PROMPT-URL-FALSEPOS-005: Applies quality heuristics for URL credential patterns
 * AG-PROMPT-CONFIDENTIAL-QUALITY-007: Applies quality heuristics for confidentiality markers
 */
function runPattern(
  pattern: DetectionPattern,
  text: string,
  source: RiskSignal['source']
): { signal: RiskSignal; count: number } | null {
  // Reset regex lastIndex for global patterns
  if (pattern.pattern.global) {
    pattern.pattern.lastIndex = 0;
  }

  // AG-PROMPT-URL-FALSEPOS-005: Check if this pattern needs quality assessment
  const isUrlCredentialPattern = URL_CREDENTIAL_PATTERN_IDS.has(pattern.id);
  // AG-PROMPT-CONFIDENTIAL-QUALITY-007: Check if this pattern needs confidentiality quality assessment
  const isConfidentialPattern = CONFIDENTIAL_PATTERN_IDS.has(pattern.id);

  if (pattern.countMatches) {
    // Count all matches - need to iterate with exec for URL credential quality checks
    pattern.pattern.lastIndex = 0;
    const rawMatches: string[] = [];

    if (isUrlCredentialPattern) {
      // AG-PROMPT-URL-FALSEPOS-005: Use exec to get matches and apply quality filter
      if (pattern.pattern.global) {
        // Global pattern: iterate through all matches
        let execMatch: RegExpExecArray | null;
        while ((execMatch = pattern.pattern.exec(text)) !== null) {
          const qualityResult = assessUrlCredentialMatchQuality(execMatch[0]);
          if (!qualityResult.shouldReject) {
            rawMatches.push(execMatch[0]);
          }
        }
      } else {
        // Non-global pattern: can only find one match
        const execMatch = pattern.pattern.exec(text);
        if (execMatch) {
          const qualityResult = assessUrlCredentialMatchQuality(execMatch[0]);
          if (!qualityResult.shouldReject) {
            rawMatches.push(execMatch[0]);
          }
        }
      }
    } else {
      // Standard match counting
      const matches = text.match(pattern.pattern) || [];
      rawMatches.push(...matches);
    }

    const count = rawMatches.length;

    // Check minimum count threshold
    const minCount = pattern.minCount ?? 1;
    if (count < minCount) {
      return null;
    }

    // Build description with count
    const description = pattern.countDescription
      ? pattern.countDescription.replace('{count}', String(count))
      : `${count} ${pattern.name}`;

    // AG-PROMPT-031: Evidence capture for count path
    let evidence: EvidenceItem[] | undefined;
    if (AG_DEBUG_EVIDENCE && rawMatches.length > 0) {
      // Get first match position via exec for evidence
      pattern.pattern.lastIndex = 0;
      const evidenceExec = pattern.pattern.exec(text);
      if (evidenceExec) {
        const ev = createEvidence({
          signal_id: pattern.id,
          origin_path: 'pack',
          producer: 'packRegistry.runPattern/count',
          rule_id: pattern.id,
          matched_text: evidenceExec[0],
          start_index: evidenceExec.index,
          end_index: evidenceExec.index + evidenceExec[0].length,
          full_text: text,
          location: source === 'content' ? 'CONTENT' : source === 'metadata' ? 'METADATA' : 'FILENAME',
          field: null,
        });
        if (ev) evidence = [ev];
      }
      pattern.pattern.lastIndex = 0;
    }

    return {
      signal: {
        id: pattern.id, // AG-PROMPT-SIGNAL-PARITY-029: preserve signal ID
        type: pattern.type,
        description,
        severity: pattern.defaultSeverity,
        detail: pattern.detail,
        source,
        detectedAt: Date.now(),
        evidence,
      },
      count,
    };
  } else {
    // Simple presence detection
    // AG-PROMPT-URL-FALSEPOS-005: For URL credential patterns, use exec and quality check
    if (isUrlCredentialPattern) {
      pattern.pattern.lastIndex = 0;

      // For non-global patterns, exec() always starts from the beginning,
      // so we can only find one match. For global patterns, we can iterate.
      if (pattern.pattern.global) {
        // Global pattern: iterate through all matches to find a valid one
        let execMatch: RegExpExecArray | null;
        while ((execMatch = pattern.pattern.exec(text)) !== null) {
          const qualityResult = assessUrlCredentialMatchQuality(execMatch[0]);
          if (!qualityResult.shouldReject) {
            // Found a valid match
            pattern.pattern.lastIndex = 0;
            // AG-PROMPT-031: Evidence capture
            let evidence: EvidenceItem[] | undefined;
            if (AG_DEBUG_EVIDENCE) {
              const ev = createEvidence({
                signal_id: pattern.id,
                origin_path: 'pack',
                producer: 'packRegistry.runPattern/url-cred-global',
                rule_id: pattern.id,
                matched_text: execMatch[0],
                start_index: execMatch.index,
                end_index: execMatch.index + execMatch[0].length,
                full_text: text,
                location: source === 'content' ? 'CONTENT' : source === 'metadata' ? 'METADATA' : 'FILENAME',
                field: null,
              });
              if (ev) evidence = [ev];
            }
            return {
              signal: {
                id: pattern.id, // AG-PROMPT-SIGNAL-PARITY-029
                type: pattern.type,
                description: pattern.description,
                severity: pattern.defaultSeverity,
                detail: pattern.detail,
                source,
                detectedAt: Date.now(),
                evidence,
              },
              count: 1,
            };
          }
        }
      } else {
        // Non-global pattern: can only find one match
        const execMatch = pattern.pattern.exec(text);
        if (execMatch) {
          const qualityResult = assessUrlCredentialMatchQuality(execMatch[0]);
          if (!qualityResult.shouldReject) {
            // AG-PROMPT-031: Evidence capture
            let evidence: EvidenceItem[] | undefined;
            if (AG_DEBUG_EVIDENCE) {
              const ev = createEvidence({
                signal_id: pattern.id,
                origin_path: 'pack',
                producer: 'packRegistry.runPattern/url-cred-nonglobal',
                rule_id: pattern.id,
                matched_text: execMatch[0],
                start_index: execMatch.index,
                end_index: execMatch.index + execMatch[0].length,
                full_text: text,
                location: source === 'content' ? 'CONTENT' : source === 'metadata' ? 'METADATA' : 'FILENAME',
                field: null,
              });
              if (ev) evidence = [ev];
            }
            return {
              signal: {
                id: pattern.id, // AG-PROMPT-SIGNAL-PARITY-029
                type: pattern.type,
                description: pattern.description,
                severity: pattern.defaultSeverity,
                detail: pattern.detail,
                source,
                detectedAt: Date.now(),
                evidence,
              },
              count: 1,
            };
          }
        }
      }
      // No valid matches found
      return null;
    }

    // AG-PROMPT-CONFIDENTIAL-QUALITY-007: For confidentiality patterns, use exec and quality check
    if (isConfidentialPattern) {
      pattern.pattern.lastIndex = 0;

      // Confidentiality patterns are non-global, use exec to get match and index
      const execMatch = pattern.pattern.exec(text);
      if (execMatch) {
        const matchIndex = execMatch.index;
        const qualityResult = assessConfidentialMatchQuality(execMatch[0], text, matchIndex);

        if (!qualityResult.shouldReject) {
          // Quality check passed - emit signal with hardFloor applied
          // AG-PROMPT-031: Evidence capture
          let evidence: EvidenceItem[] | undefined;
          if (AG_DEBUG_EVIDENCE) {
            const ev = createEvidence({
              signal_id: pattern.id,
              origin_path: 'pack',
              producer: 'packRegistry.runPattern/confidential',
              rule_id: pattern.id,
              matched_text: execMatch[0],
              start_index: matchIndex,
              end_index: matchIndex + execMatch[0].length,
              full_text: text,
              location: source === 'content' ? 'CONTENT' : source === 'metadata' ? 'METADATA' : 'FILENAME',
              field: null,
            });
            if (ev) evidence = [ev];
          }
          return {
            signal: {
              id: pattern.id, // AG-PROMPT-SIGNAL-PARITY-029
              type: pattern.type,
              description: pattern.description,
              severity: pattern.defaultSeverity,
              detail: pattern.detail,
              source,
              detectedAt: Date.now(),
              evidence,
            },
            count: 1,
          };
        }
        // Quality check failed - reject this match entirely
        // Do NOT downgrade, do NOT emit signal
      }
      return null;
    }

    // AG-PROMPT-SIGNAL-VALIDATION-GATES-024: Payment card validation gates
    // Validate payment card matches through Luhn + issuer prefix + context gates
    const isPaymentCardPattern = PAYMENT_CARD_PATTERN_IDS.has(pattern.id);
    if (isPaymentCardPattern) {
      pattern.pattern.lastIndex = 0;

      // Use exec to get match index for context proximity check
      const execMatch = pattern.pattern.exec(text);
      if (execMatch) {
        const matchIndex = execMatch.index;
        const validationResult = validatePaymentCard(execMatch[0], text, matchIndex);

        if (validationResult.isValidCard) {
          // All gates passed - emit payment card signal
          // AG-PROMPT-031: Evidence capture
          let evidence: EvidenceItem[] | undefined;
          if (AG_DEBUG_EVIDENCE) {
            const ev = createEvidence({
              signal_id: pattern.id,
              origin_path: 'pack',
              producer: 'packRegistry.runPattern/payment-card',
              rule_id: pattern.id,
              matched_text: execMatch[0],
              start_index: matchIndex,
              end_index: matchIndex + execMatch[0].length,
              full_text: text,
              location: source === 'content' ? 'CONTENT' : source === 'metadata' ? 'METADATA' : 'FILENAME',
              field: null,
            });
            if (ev) evidence = [ev];
          }
          return {
            signal: {
              id: pattern.id, // AG-PROMPT-SIGNAL-PARITY-029
              type: pattern.type,
              description: pattern.description,
              severity: pattern.defaultSeverity,
              detail: pattern.detail,
              source,
              detectedAt: Date.now(),
              evidence,
            },
            count: 1,
          };
        }
        // Validation failed - do NOT emit payment card signal
        // The numeric sequence might be a policy number, ID, etc.
      }
      return null;
    }

    // AG-PROMPT-032: SWIFT/BIC validation gates
    // Validate SWIFT/BIC matches through country code + PDF substrate gates
    const isSwiftBicPattern = SWIFT_BIC_PATTERN_IDS.has(pattern.id);
    if (isSwiftBicPattern) {
      pattern.pattern.lastIndex = 0;

      const execMatch = pattern.pattern.exec(text);
      if (execMatch) {
        const matchIndex = execMatch.index;
        const validationResult = validateSwiftBic(execMatch[0], text, matchIndex);

        if (validationResult.isValidBic) {
          // All gates passed - emit SWIFT/BIC signal
          // AG-PROMPT-031: Evidence capture
          let evidence: EvidenceItem[] | undefined;
          if (AG_DEBUG_EVIDENCE) {
            const ev = createEvidence({
              signal_id: pattern.id,
              origin_path: 'pack',
              producer: 'packRegistry.runPattern/swift-bic',
              rule_id: pattern.id,
              matched_text: execMatch[0],
              start_index: matchIndex,
              end_index: matchIndex + execMatch[0].length,
              full_text: text,
              location: source === 'content' ? 'CONTENT' : source === 'metadata' ? 'METADATA' : 'FILENAME',
              field: null,
            });
            if (ev) evidence = [ev];
          }
          return {
            signal: {
              id: pattern.id, // AG-PROMPT-SIGNAL-PARITY-029
              type: pattern.type,
              description: pattern.description,
              severity: pattern.defaultSeverity,
              detail: pattern.detail,
              source,
              detectedAt: Date.now(),
              evidence,
            },
            count: 1,
          };
        }
        // Validation failed - do NOT emit SWIFT/BIC signal
        // The uppercase sequence is likely noise from PDF substrate or invalid country code
      }
      return null;
    }

    // AG-XLSX-HARDENING-PLAN-001: IBAN Mod97 gate
    if (IBAN_PATTERN_IDS.has(pattern.id)) {
      pattern.pattern.lastIndex = 0;
      const execMatch = pattern.pattern.exec(text);
      if (execMatch) {
        const matchIndex = execMatch.index;
        const ibanStr = execMatch[0].replace(/\s+/g, '');
        if (!mod97Iban(ibanStr)) {
          return null; // Mod97 failed — not a valid IBAN
        }
        const score = scoreProximity(text, matchIndex, execMatch[0].length, IBAN_ANCHORS, true);
        return {
          signal: {
            id: pattern.id,
            type: pattern.type,
            description: pattern.description,
            severity: pattern.defaultSeverity,
            detail: pattern.detail,
            source,
            detectedAt: Date.now(),
            confidence: score.confidence,
          },
          count: 1,
        };
      }
      return null;
    }

    // AG-PROMPT-035: Unified national ID validation gates
    // Validate national ID matches (DK CPR, SE personnummer, NO fødselsnummer, FI HETU)
    const nationalIdValidator = NATIONAL_ID_PATTERN_IDS.get(pattern.id);
    if (nationalIdValidator) {
      pattern.pattern.lastIndex = 0;

      const execMatch = pattern.pattern.exec(text);
      if (execMatch) {
        const matchIndex = execMatch.index;
        const validationResult = nationalIdValidator(execMatch[0], text, matchIndex);

        if (validationResult.is_valid) {
          // AG-PROMPT-041: Insurance context gate
          // In insurance documents, require explicit national-ID label proximity
          // to avoid numeric collisions (policy numbers matching CPR pattern)
          if (hasInsuranceContext(text) && !hasNationalIdLabelProximity(text, matchIndex, execMatch[0].length)) {
            // Insurance context without explicit ID label — suppress FP
            return null;
          }

          // AG-PROMPT-185/WS-01: Invoice/financial context gate
          // In invoices, customer numbers and bank accounts match CPR format.
          // Require explicit national-ID label proximity to suppress FP.
          if (hasInvoiceFinancialContext(text) && !hasNationalIdLabelProximity(text, matchIndex, execMatch[0].length)) {
            return null;
          }

          // All hard gates passed - emit unified national ID signal

          // AG-MONSTER-HARDENING-TIERA-ENGINE-001-CONSOLIDATE-AND-GAPS Phase 4:
          // Domain anchor confidence adjustment — reduces FP for numeric patterns
          // near safe-domain anchors (SKU, Ref, Batch) without changing severity.
          let adjustedConfidence = validationResult.confidence;
          if (typeof adjustedConfidence === 'number') {
            const domainAdj = adjustConfidenceByDomainAnchors(
              text, matchIndex, execMatch[0].length, adjustedConfidence
            );
            adjustedConfidence = domainAdj.confidence;
          }

          // AG-PROMPT-126: Suppress bare-ID emission for overlap-prone validators
          // when no anchor keyword was found in the proximity window.
          // Confidence 0.60 = checksum-only (no anchor) → suppressed
          // Confidence 0.30 = checksum + safe-domain downgrade → suppressed
          // Confidence 0.99 = checksum + anchor → emits
          // AG-PROMPT-127: Exception for structured/tabular contexts where the
          // anchor keyword appears on the same line or the line above (header row).
          if (ANCHOR_REQUIRED_PATTERN_IDS.has(pattern.id) &&
              typeof adjustedConfidence === 'number' &&
              adjustedConfidence < ANCHOR_REQUIRED_MIN_CONFIDENCE) {
            if (!hasStructuredLabelContext(text, matchIndex, execMatch[0].length, pattern.id)) {
              return null;
            }
            // Structured label found — emit at reduced confidence (0.60)
            // to distinguish from fully-anchored matches (0.99)
          }

          // AG-PROMPT-031: Evidence capture
          let evidence: EvidenceItem[] | undefined;
          if (AG_DEBUG_EVIDENCE) {
            const ev = createEvidence({
              signal_id: NATIONAL_ID_SIGNAL_ID,
              origin_path: 'pack',
              producer: `packRegistry.runPattern/national-id/${validationResult.subtype}`,
              rule_id: pattern.id,
              matched_text: execMatch[0],
              start_index: matchIndex,
              end_index: matchIndex + execMatch[0].length,
              full_text: text,
              location: source === 'content' ? 'CONTENT' : source === 'metadata' ? 'METADATA' : 'FILENAME',
              field: null,
            });
            if (ev) evidence = [ev];
          }
          return {
            signal: {
              id: NATIONAL_ID_SIGNAL_ID,
              type: pattern.type,
              description: pattern.description,
              severity: pattern.defaultSeverity,
              detail: pattern.detail,
              source,
              detectedAt: Date.now(),
              evidence,
              // AG-XLSX-HARDENING-PLAN-001: Gate & Boost confidence
              // AG-MONSTER-HARDENING-TIERA-ENGINE-001-CONSOLIDATE-AND-GAPS: domain-adjusted
              confidence: adjustedConfidence,
            },
            count: 1,
          };
        }
        // Validation failed - do NOT emit national ID signal
      }
      return null;
    }

    // Standard presence detection for other patterns
    // AG-PROMPT-031: Use exec() instead of test() when evidence is enabled
    if (AG_DEBUG_EVIDENCE) {
      pattern.pattern.lastIndex = 0;
      const execMatch = pattern.pattern.exec(text);
      if (execMatch) {
        pattern.pattern.lastIndex = 0;
        let evidence: EvidenceItem[] | undefined;
        const ev = createEvidence({
          signal_id: pattern.id,
          origin_path: 'pack',
          producer: 'packRegistry.runPattern/standard',
          rule_id: pattern.id,
          matched_text: execMatch[0],
          start_index: execMatch.index,
          end_index: execMatch.index + execMatch[0].length,
          full_text: text,
          location: source === 'content' ? 'CONTENT' : source === 'metadata' ? 'METADATA' : 'FILENAME',
          field: null,
        });
        if (ev) evidence = [ev];
        return {
          signal: {
            id: pattern.id, // AG-PROMPT-SIGNAL-PARITY-029
            type: pattern.type,
            description: pattern.description,
            severity: pattern.defaultSeverity,
            detail: pattern.detail,
            source,
            detectedAt: Date.now(),
            evidence,
          },
          count: 1,
        };
      }
    } else if (pattern.pattern.test(text)) {
      // Reset lastIndex after test
      pattern.pattern.lastIndex = 0;

      return {
        signal: {
          id: pattern.id, // AG-PROMPT-SIGNAL-PARITY-029
          type: pattern.type,
          description: pattern.description,
          severity: pattern.defaultSeverity,
          detail: pattern.detail,
          source,
          detectedAt: Date.now(),
        },
        count: 1,
      };
    }
  }

  return null;
}

// ============================================================================
// EXPORTS
// ============================================================================

export {
  GlobalPack,
  EnglishPack,
  RomancePack,
  NordicPack,
  LANGUAGE_PACKS,
  COUNTRY_PACKS,
  DEFAULT_LOCALE_CONFIDENCE,
};