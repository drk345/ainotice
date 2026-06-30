/**
 * AgentGuard Locale Awareness Layer
 *
 * Provides heuristic locale detection to reduce false positives
 * in phone numbers and personal IDs across different regions.
 *
 * Design Principles:
 * - HEURISTIC, not perfect - errs on the side of caution
 * - Local-only, no telemetry
 * - If unsure, returns 'unknown' (falls back to generic behavior)
 * - Cost-conscious: simple pattern matching, no NLP/ML
 *
 * Privacy: No content logging. Only locale key + confidence in debug.
 *
 * @see localeProfiles.ts for admin-configurable settings
 */

import {
  getLocaleProfileConfig,
  type LocaleProfileConfig,
} from './localeProfiles';

// ============================================================================
// CONFIGURATION
// ============================================================================

/** Enable debug logging (locale key + confidence only, no content) */
const DEBUG_LOCALE = false;

/** Track if locale profiles have been validated */
let localeProfilesValidated = false;

// ============================================================================
// TYPES
// ============================================================================

/** Supported locale keys */
export type LocaleKey = 
  | 'US'
  | 'UK'
  | 'EU-NORDICS'
  | 'EU-DACH'
  | 'EU-SOUTHERN'
  | 'EU-WESTERN'
  | 'EU-EASTERN'
  | 'EN-COMMONWEALTH'
  | 'LATAM'
  | 'unknown';

/** Confidence level in locale detection */
export type LocaleConfidence = 'high' | 'medium' | 'low' | 'none';

/** Result of locale detection */
export interface LocaleDetectionResult {
  locale: LocaleKey;
  confidence: LocaleConfidence;
  signals: string[];  // Which signals triggered detection (for debugging)
}

/** Locale profile with region-specific settings */
export interface LocaleProfile {
  key: LocaleKey;
  name: string;
  countries: string[];  // ISO 3166-1 alpha-2 codes
  
  /** Phone number patterns for this locale */
  phonePatterns: RegExp[];
  
  /** Patterns that should NOT be treated as phones in this locale */
  phoneExclusions?: RegExp[];
  
  /** National ID patterns (SSN, CPR, NIF, etc.) */
  nationalIdPatterns?: RegExp[];
  
  /** Minimum phone count before escalation (higher = more tolerant) */
  phoneEscalationThreshold: number;
}

/** Context for locale detection */
export interface LocaleContext {
  text?: string;
  sourceUrl?: string;
  metadata?: {
    author?: string;
    creator?: string;
    language?: string;
  };
}

// ============================================================================
// DETECTION PATTERNS
// ============================================================================

/** TLD to locale mapping */
export const TLD_LOCALE_MAP: Record<string, LocaleKey> = {
  // US
  '.us': 'US',
  '.gov': 'US',
  '.mil': 'US',
  
  // UK
  '.uk': 'UK',
  '.co.uk': 'UK',
  
  // EU-NORDICS
  '.dk': 'EU-NORDICS',
  '.no': 'EU-NORDICS',
  '.se': 'EU-NORDICS',
  '.fi': 'EU-NORDICS',
  '.is': 'EU-NORDICS',
  
  // EU-DACH
  '.de': 'EU-DACH',
  '.at': 'EU-DACH',
  '.ch': 'EU-DACH',
  
  // EU-SOUTHERN
  '.es': 'EU-SOUTHERN',
  '.it': 'EU-SOUTHERN',
  '.pt': 'EU-SOUTHERN',
  '.gr': 'EU-SOUTHERN',
  
  // EU-WESTERN
  '.fr': 'EU-WESTERN',
  '.be': 'EU-WESTERN',
  '.nl': 'EU-WESTERN',
  '.lu': 'EU-WESTERN',
  
  // EU-EASTERN
  '.pl': 'EU-EASTERN',
  '.cz': 'EU-EASTERN',
  '.sk': 'EU-EASTERN',
  '.hu': 'EU-EASTERN',
  '.ro': 'EU-EASTERN',
  '.bg': 'EU-EASTERN',
  
  // EN-COMMONWEALTH
  '.ca': 'EN-COMMONWEALTH',
  '.au': 'EN-COMMONWEALTH',
  '.nz': 'EN-COMMONWEALTH',
  '.ie': 'EN-COMMONWEALTH',
  
  // LATAM
  '.mx': 'LATAM',
  '.ar': 'LATAM',
  '.co': 'LATAM',
  '.cl': 'LATAM',
  '.pe': 'LATAM',
  '.br': 'LATAM',
};

/** Currency patterns for locale detection */
export const CURRENCY_PATTERNS: Record<LocaleKey, RegExp[]> = {
  'US': [/\$\d+/, /USD/i, /\bUS\s*dollars?\b/i],
  'UK': [/£\d+/, /GBP/i, /\bpounds?\s*sterling\b/i],
  'EU-NORDICS': [/\b\d+\s*(kr|DKK|NOK|SEK)\b/i, /\bkroner?\b/i],
  'EU-DACH': [/€\d+/, /EUR/i, /\bCHF\b/],
  'EU-SOUTHERN': [/€\d+/, /EUR/i],
  'EU-WESTERN': [/€\d+/, /EUR/i],
  'EU-EASTERN': [/€\d+/, /EUR/i, /\bPLN\b/, /\bCZK\b/, /\bHUF\b/],
  'EN-COMMONWEALTH': [/\$\d+/, /CAD/i, /AUD/i, /NZD/i],
  'LATAM': [/\bMXN\b/, /\bARS\b/, /\bBRL\b/, /R\$\d+/],
  'unknown': [],
};

/** Language markers for locale detection */
export const LANGUAGE_PATTERNS: Record<LocaleKey, RegExp[]> = {
  'US': [/\b(color|center|organization|realize)\b/i],
  'UK': [/\b(colour|centre|organisation|realise)\b/i],
  'EU-NORDICS': [
    /\b(og|eller|med|til|fra|af|på|for|den|det|de|en|et)\b/,  // Danish/Norwegian
    /\b(och|eller|med|till|från|av|på|för|den|det|de|en|ett)\b/,  // Swedish
    /\b(moms|faktura|kvittering|bestilling|levering)\b/i,  // Nordic commerce
  ],
  'EU-DACH': [
    /\b(und|oder|mit|zu|von|auf|für|der|die|das|ein|eine)\b/,
    /\b(Rechnung|Bestellung|Lieferung|MwSt)\b/i,
  ],
  'EU-SOUTHERN': [
    /\b(y|o|con|de|para|el|la|los|las|un|una)\b/,  // Spanish
    /\b(e|o|con|di|per|il|la|i|le|un|una)\b/,  // Italian
  ],
  'EU-WESTERN': [
    /\b(et|ou|avec|de|pour|le|la|les|un|une)\b/,  // French
    /\b(en|of|met|van|voor|de|het|een)\b/,  // Dutch
  ],
  'EU-EASTERN': [
    /\b(i|lub|z|do|dla|ten|ta|to)\b/,  // Polish
  ],
  'EN-COMMONWEALTH': [/\b(colour|centre|organisation|realise|honour)\b/i],
  'LATAM': [
    /\b(y|o|con|de|para|el|la|los|las|un|una)\b/,  // Spanish
    /\b(e|ou|com|de|para|o|a|os|as|um|uma)\b/,  // Portuguese
  ],
  'unknown': [],
};

/** IBAN country prefixes for locale detection */
export const IBAN_PATTERNS: Record<string, LocaleKey> = {
  'DK': 'EU-NORDICS',
  'NO': 'EU-NORDICS',
  'SE': 'EU-NORDICS',
  'FI': 'EU-NORDICS',
  'DE': 'EU-DACH',
  'AT': 'EU-DACH',
  'CH': 'EU-DACH',
  'ES': 'EU-SOUTHERN',
  'IT': 'EU-SOUTHERN',
  'PT': 'EU-SOUTHERN',
  'GR': 'EU-SOUTHERN',
  'FR': 'EU-WESTERN',
  'BE': 'EU-WESTERN',
  'NL': 'EU-WESTERN',
  'LU': 'EU-WESTERN',
  'PL': 'EU-EASTERN',
  'CZ': 'EU-EASTERN',
  'GB': 'UK',
  'IE': 'EN-COMMONWEALTH',
};

// ============================================================================
// DEFAULT LOCALE PROFILES
// ============================================================================

export const DefaultLocaleProfiles: Record<LocaleKey, LocaleProfile> = {
  'US': {
    key: 'US',
    name: 'United States',
    countries: ['US'],
    phonePatterns: [
      /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g,  // Standard US format
      /\(\d{3}\)\s*\d{3}[-.]?\d{4}\b/g,  // (555) 555-5555
      /\b1[-.]?\d{3}[-.]?\d{3}[-.]?\d{4}\b/g,  // 1-555-555-5555
    ],
    nationalIdPatterns: [
      /\b\d{3}[-]?\d{2}[-]?\d{4}\b/g,  // SSN: 123-45-6789
    ],
    phoneEscalationThreshold: 20,
  },
  
  'UK': {
    key: 'UK',
    name: 'United Kingdom',
    countries: ['GB'],
    phonePatterns: [
      /\b0\d{4}\s?\d{6}\b/g,  // 01onal, 02xxxx
      /\b\+44\s?\d{4}\s?\d{6}\b/g,  // International
      /\b07\d{3}\s?\d{6}\b/g,  // Mobile
    ],
    nationalIdPatterns: [
      /\b[A-Z]{2}\d{6}[A-Z]?\b/g,  // National Insurance
    ],
    phoneEscalationThreshold: 20,
  },
  
  'EU-NORDICS': {
    key: 'EU-NORDICS',
    name: 'Nordic Countries',
    countries: ['DK', 'NO', 'SE', 'FI', 'IS'],
    phonePatterns: [
      /\b\+45\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{2}\b/g,  // Danish international
      /\b\d{2}\s?\d{2}\s?\d{2}\s?\d{2}\b/g,  // Danish local (8 digits)
      /\b\+46\s?\d{2,3}[-\s]?\d{6,7}\b/g,  // Swedish
      /\b\+47\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{2}\b/g,  // Norwegian
    ],
    phoneExclusions: [
      /\b\d{3}\.\d{3}\.\d{2}\b/,  // IKEA product codes: 123.456.78
      /\b\d+[.,]\d{2}\s*(kr|DKK|NOK|SEK)?\b/,  // Prices: 1.599,00 kr
      /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/,  // Card numbers
    ],
    nationalIdPatterns: [
      /\b\d{6}[-]?\d{4}\b/g,  // Danish CPR: DDMMYY-XXXX
    ],
    phoneEscalationThreshold: 50,  // Higher threshold for Nordic receipts
  },
  
  'EU-DACH': {
    key: 'EU-DACH',
    name: 'Germany, Austria, Switzerland',
    countries: ['DE', 'AT', 'CH'],
    phonePatterns: [
      /\b\+49\s?\d{3,4}[-\s]?\d{6,8}\b/g,  // German
      /\b0\d{3,4}[-\s/]?\d{6,8}\b/g,  // German local
      /\b\+43\s?\d{3,4}[-\s]?\d{6,8}\b/g,  // Austrian
      /\b\+41\s?\d{2}[-\s]?\d{3}[-\s]?\d{2}[-\s]?\d{2}\b/g,  // Swiss
    ],
    nationalIdPatterns: [
      /\b\d{2}\s?\d{6}\s?[A-Z]\s?\d{3}\b/g,  // German ID
    ],
    phoneEscalationThreshold: 30,
  },
  
  'EU-SOUTHERN': {
    key: 'EU-SOUTHERN',
    name: 'Southern Europe',
    countries: ['ES', 'IT', 'PT', 'GR'],
    phonePatterns: [
      /\b\+34\s?\d{3}[-\s]?\d{3}[-\s]?\d{3}\b/g,  // Spanish
      /\b\+39\s?\d{2,3}[-\s]?\d{6,7}\b/g,  // Italian
      /\b\+351\s?\d{3}[-\s]?\d{3}[-\s]?\d{3}\b/g,  // Portuguese
    ],
    nationalIdPatterns: [
      /\b\d{8}[A-Z]\b/g,  // Spanish DNI
      /\b[A-Z]{2}\d{7}[A-Z]\b/g,  // Italian CF (partial)
    ],
    phoneEscalationThreshold: 25,
  },
  
  'EU-WESTERN': {
    key: 'EU-WESTERN',
    name: 'Western Europe',
    countries: ['FR', 'BE', 'NL', 'LU'],
    phonePatterns: [
      /\b\+33\s?\d[-\s]?\d{2}[-\s]?\d{2}[-\s]?\d{2}[-\s]?\d{2}\b/g,  // French
      /\b0\d[-\s]?\d{2}[-\s]?\d{2}[-\s]?\d{2}[-\s]?\d{2}\b/g,  // French local
      /\b\+32\s?\d{3}[-\s]?\d{2}[-\s]?\d{2}[-\s]?\d{2}\b/g,  // Belgian
      /\b\+31\s?\d[-\s]?\d{8}\b/g,  // Dutch
    ],
    nationalIdPatterns: [
      /\b\d[-\s]?\d{2}[-\s]?\d{2}[-\s]?\d{3}[-\s]?\d{3}[-\s]?\d{2}\b/g,  // French INSEE
    ],
    phoneEscalationThreshold: 25,
  },
  
  'EU-EASTERN': {
    key: 'EU-EASTERN',
    name: 'Eastern Europe',
    countries: ['PL', 'CZ', 'SK', 'HU', 'RO', 'BG'],
    phonePatterns: [
      /\b\+48\s?\d{3}[-\s]?\d{3}[-\s]?\d{3}\b/g,  // Polish
      /\b\+420\s?\d{3}[-\s]?\d{3}[-\s]?\d{3}\b/g,  // Czech
      /\b\+36\s?\d{2}[-\s]?\d{3}[-\s]?\d{4}\b/g,  // Hungarian
    ],
    nationalIdPatterns: [
      /\b\d{11}\b/g,  // Polish PESEL
    ],
    phoneEscalationThreshold: 25,
  },
  
  'EN-COMMONWEALTH': {
    key: 'EN-COMMONWEALTH',
    name: 'English Commonwealth',
    countries: ['CA', 'AU', 'NZ', 'IE'],
    phonePatterns: [
      /\b\+1[-\s]?\d{3}[-\s]?\d{3}[-\s]?\d{4}\b/g,  // Canadian (same as US)
      /\b\+61\s?\d[-\s]?\d{4}[-\s]?\d{4}\b/g,  // Australian
      /\b\+64\s?\d[-\s]?\d{3}[-\s]?\d{4}\b/g,  // NZ
      /\b\+353\s?\d{2,3}[-\s]?\d{6,7}\b/g,  // Irish
    ],
    nationalIdPatterns: [
      /\b\d{3}[-\s]?\d{3}[-\s]?\d{3}\b/g,  // Canadian SIN
    ],
    phoneEscalationThreshold: 20,
  },
  
  'LATAM': {
    key: 'LATAM',
    name: 'Latin America',
    countries: ['MX', 'AR', 'CO', 'CL', 'PE', 'BR'],
    phonePatterns: [
      /\b\+52\s?\d{2,3}[-\s]?\d{3}[-\s]?\d{4}\b/g,  // Mexican
      /\b\+54\s?\d{2,3}[-\s]?\d{4}[-\s]?\d{4}\b/g,  // Argentine
      /\b\+55\s?\d{2}[-\s]?\d{4,5}[-\s]?\d{4}\b/g,  // Brazilian
      /\b\+56\s?\d[-\s]?\d{4}[-\s]?\d{4}\b/g,  // Chilean
    ],
    nationalIdPatterns: [
      /\b\d{3}\.\d{3}\.\d{3}[-]?\d{2}\b/g,  // Brazilian CPF
      /\b\d{2}\.\d{3}\.\d{3}[-]?\d\b/g,  // Argentine CUIL
    ],
    phoneEscalationThreshold: 25,
  },
  
  'unknown': {
    key: 'unknown',
    name: 'Unknown/Generic',
    countries: [],
    phonePatterns: [
      /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g,  // Generic 10-digit
      /\b\+\d{1,3}[-\s]?\d{6,12}\b/g,  // International format
    ],
    phoneEscalationThreshold: 20,  // Default threshold
  },
};

// ============================================================================
// LOCALE DETECTION
// ============================================================================

/**
 * Detect likely locale from available context
 * 
 * @param context - Detection context (text, URL, metadata)
 * @returns Locale detection result with confidence
 */
export function detectLikelyLocale(context: LocaleContext): LocaleDetectionResult {
  const signals: string[] = [];
  const scores: Partial<Record<LocaleKey, number>> = {};
  
  // Helper to add score
  const addScore = (locale: LocaleKey, points: number, signal: string) => {
    scores[locale] = (scores[locale] || 0) + points;
    signals.push(signal);
  };
  
  // 1. Check URL TLD (high confidence)
  if (context.sourceUrl) {
    for (const [tld, locale] of Object.entries(TLD_LOCALE_MAP)) {
      if (context.sourceUrl.includes(tld)) {
        addScore(locale, 3, `TLD: ${tld}`);
        break;
      }
    }
  }
  
  // 2. Check metadata language
  if (context.metadata?.language) {
    const lang = context.metadata.language.toLowerCase();
    if (lang.startsWith('en-us') || lang === 'en') {
      addScore('US', 2, `metadata.language: ${lang}`);
    } else if (lang.startsWith('en-gb')) {
      addScore('UK', 2, `metadata.language: ${lang}`);
    } else if (lang.startsWith('da') || lang.startsWith('no') || lang.startsWith('sv') || lang.startsWith('fi')) {
      addScore('EU-NORDICS', 2, `metadata.language: ${lang}`);
    } else if (lang.startsWith('de')) {
      addScore('EU-DACH', 2, `metadata.language: ${lang}`);
    } else if (lang.startsWith('es') || lang.startsWith('it') || lang.startsWith('pt')) {
      // Could be Southern Europe or LATAM
      addScore('EU-SOUTHERN', 1, `metadata.language: ${lang}`);
      addScore('LATAM', 1, `metadata.language: ${lang}`);
    } else if (lang.startsWith('fr') || lang.startsWith('nl')) {
      addScore('EU-WESTERN', 2, `metadata.language: ${lang}`);
    } else if (lang.startsWith('pl') || lang.startsWith('cs') || lang.startsWith('hu')) {
      addScore('EU-EASTERN', 2, `metadata.language: ${lang}`);
    }
  }
  
  // 3. Check text content for language and currency markers
  if (context.text) {
    const textSample = context.text.substring(0, 5000);  // Limit for performance
    
    // Check currency patterns
    for (const [locale, patterns] of Object.entries(CURRENCY_PATTERNS)) {
      for (const pattern of patterns) {
        if (pattern.test(textSample)) {
          addScore(locale as LocaleKey, 2, `currency: ${pattern.source}`);
          break;  // Only count once per locale
        }
      }
    }
    
    // Check language patterns
    for (const [locale, patterns] of Object.entries(LANGUAGE_PATTERNS)) {
      let matchCount = 0;
      for (const pattern of patterns) {
        const matches = textSample.match(pattern);
        if (matches) {
          matchCount += matches.length;
        }
      }
      if (matchCount >= 3) {
        addScore(locale as LocaleKey, Math.min(matchCount, 5), `language markers: ${matchCount}`);
      }
    }
    
    // Check for IBAN prefixes
    const ibanMatch = textSample.match(/\b([A-Z]{2})\d{2}[A-Z0-9]{4,}/);
    if (ibanMatch) {
      const countryCode = ibanMatch[1];
      const locale = IBAN_PATTERNS[countryCode];
      if (locale) {
        addScore(locale, 2, `IBAN prefix: ${countryCode}`);
      }
    }
  }
  
  // Find highest scoring locale
  // AG-PROMPT-081: Tie-breaking order prefers EU locales over LATAM
  // Rationale: EU has stricter data protection (GDPR), so conservative choice
  const LOCALE_PRIORITY: LocaleKey[] = [
    'EU-NORDICS',   // Highest priority (strong GDPR + distinct signals)
    'EU-DACH',
    'EU-WESTERN',
    'EU-SOUTHERN',
    'EU-EASTERN',
    'UK',
    'EN-COMMONWEALTH',
    'US',
    'LATAM',        // Lowest priority for ties
    'unknown',
  ];

  let detectedLocale: LocaleKey = 'unknown';
  let highestScore = 0;

  for (const [locale, score] of Object.entries(scores)) {
    if (score > highestScore) {
      highestScore = score;
      detectedLocale = locale as LocaleKey;
    } else if (score === highestScore && score > 0) {
      // Tie-breaker: prefer locale with higher priority (lower index)
      const currentPriority = LOCALE_PRIORITY.indexOf(detectedLocale);
      const newPriority = LOCALE_PRIORITY.indexOf(locale as LocaleKey);
      if (newPriority !== -1 && (currentPriority === -1 || newPriority < currentPriority)) {
        detectedLocale = locale as LocaleKey;
      }
    }
  }
  
  // Determine confidence based on score
  let confidence: LocaleConfidence;
  if (highestScore >= 5) {
    confidence = 'high';
  } else if (highestScore >= 3) {
    confidence = 'medium';
  } else if (highestScore >= 1) {
    confidence = 'low';
  } else {
    confidence = 'none';
    detectedLocale = 'unknown';
  }
  
  if (DEBUG_LOCALE) {
    console.log(`[Ai Notice] Locale detected: ${detectedLocale} (confidence=${confidence})`);
  }
  
  return {
    locale: detectedLocale,
    confidence,
    signals,
  };
}

/**
 * Get locale profile by key
 */
export function getLocaleProfile(locale: LocaleKey): LocaleProfile {
  return DefaultLocaleProfiles[locale] || DefaultLocaleProfiles['unknown'];
}

/**
 * Check if a text matches phone patterns for a locale, excluding false positives
 * 
 * @param text - Text to check
 * @param locale - Locale key
 * @returns Array of phone matches
 */
export function findPhoneNumbers(text: string, locale: LocaleKey): string[] {
  const profile = getLocaleProfile(locale);
  const matches: string[] = [];
  
  // Find all phone matches
  for (const pattern of profile.phonePatterns) {
    pattern.lastIndex = 0;
    const found = text.match(pattern) || [];
    matches.push(...found);
  }
  
  // Filter out exclusions (e.g., product codes, prices)
  if (profile.phoneExclusions) {
    return matches.filter(match => {
      for (const exclusion of profile.phoneExclusions!) {
        if (exclusion.test(match)) {
          return false;
        }
      }
      return true;
    });
  }
  
  return matches;
}

/**
 * Check if a phone count should trigger escalation for this locale
 * Uses localeProfiles.ts as source-of-truth for thresholds
 */
export function shouldEscalatePhones(count: number, locale: LocaleKey): boolean {
  // Use localeProfiles config as source-of-truth
  const profileConfig = getLocaleProfileConfig(locale);
  return count >= profileConfig.phone.escalationThreshold;
}

/**
 * Get the admin-configurable locale profile config
 * This is the source-of-truth for locale settings
 */
export function getLocaleConfig(locale: LocaleKey): LocaleProfileConfig {
  return getLocaleProfileConfig(locale);
}

/**
 * Validate locale profiles are loaded (called once at startup)
 */
export function validateLocaleProfiles(): boolean {
  if (localeProfilesValidated) return true;

  try {
    // Quick validation: ensure we can load a profile
    const testProfile = getLocaleProfileConfig('US');
    localeProfilesValidated = testProfile.id === 'US';
    return localeProfilesValidated;
  } catch {
    return false;
  }
}

// Note: TLD_LOCALE_MAP, CURRENCY_PATTERNS, LANGUAGE_PATTERNS, IBAN_PATTERNS
// are exported inline with their declarations above.