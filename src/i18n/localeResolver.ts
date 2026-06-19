/**
 * Ai Notice Canonical Locale Resolver (AG-PROMPT-176)
 *
 * Resolves the UI language for all Ai Notice surfaces.
 * Implements the doctrine defined in docs/governance/LOCALE-GOVERNANCE.md.
 *
 * Resolution order:
 *   1. Admin-enforced locale (managed policy)
 *   2. User-selected locale (persisted preference)
 *   3. Browser UI locale (chrome.i18n.getUILanguage or navigator.languages)
 *   4. Supported base-locale fallback (fr-CA → fr)
 *   5. English fallback
 *
 * This resolver is deterministic and side-effect free.
 * It does NOT detect page language, OS language, or infer locale from content.
 */

// ============================================================================
// SUPPORTED LOCALES
// ============================================================================

/**
 * Locales with UI string files in src/i18n/.
 * Add entries here as translation files are added.
 */
export const SUPPORTED_UI_LOCALES: readonly string[] = [
  'en',
  'sv-SE',
] as const;

/** Type-safe supported locale */
export type SupportedUILocale = typeof SUPPORTED_UI_LOCALES[number];

/** Default fallback locale */
export const DEFAULT_LOCALE: SupportedUILocale = 'en';

// ============================================================================
// RESOLVER CONFIG
// ============================================================================

export interface LocaleResolverConfig {
  /** Admin-enforced locale from managed policy (highest priority) */
  adminLocale?: string;
  /** Whether admin locale is locked (cannot be overridden by user) */
  adminLocaleLocked?: boolean;
  /** User-selected locale from Ai Notice settings */
  userLocale?: string;
  /** Browser locale list (from chrome.i18n.getUILanguage or navigator.languages) */
  browserLocales?: readonly string[];
  /** Supported locales (defaults to SUPPORTED_UI_LOCALES) */
  supportedLocales?: readonly string[];
}

export interface LocaleResolverResult {
  /** Resolved locale code */
  locale: SupportedUILocale;
  /** Source that determined the locale */
  source: 'admin' | 'user' | 'browser' | 'fallback';
  /** Original input value that matched (before normalization) */
  matchedInput?: string;
}

// ============================================================================
// NORMALIZATION
// ============================================================================

/**
 * Normalize a locale tag to a supported locale.
 *
 * Attempts exact match first, then base language fallback:
 *   fr-CA → fr (if fr is supported)
 *   en-GB → en (if en is supported)
 *   sv-SE → sv-SE (exact match)
 *
 * Case-insensitive matching (BCP 47 tags are case-insensitive).
 *
 * @returns The matching supported locale, or null if no match.
 */
export function normalizeSupportedLocale(
  locale: string,
  supported: readonly string[],
): string | null {
  if (!locale) return null;

  const lower = locale.toLowerCase();

  // Exact match (case-insensitive)
  for (const s of supported) {
    if (s.toLowerCase() === lower) return s;
  }

  // Base language fallback: fr-CA → fr
  const base = lower.split('-')[0];
  for (const s of supported) {
    if (s.toLowerCase() === base) return s;
  }

  // Reverse match: if input is "sv" and supported has "sv-SE", match it
  for (const s of supported) {
    if (s.toLowerCase().split('-')[0] === base) return s;
  }

  return null;
}

// ============================================================================
// RESOLVER
// ============================================================================

/**
 * Resolve the UI locale for Ai Notice.
 *
 * Deterministic, side-effect free. Does not read storage, browser APIs,
 * or perform any I/O. All inputs must be provided by the caller.
 *
 * @see docs/governance/LOCALE-GOVERNANCE.md
 */
export function resolveAiNoticeLocale(config: LocaleResolverConfig): LocaleResolverResult {
  const supported = config.supportedLocales ?? SUPPORTED_UI_LOCALES;

  // Priority 1: Admin-enforced locale
  if (config.adminLocaleLocked && config.adminLocale) {
    const normalized = normalizeSupportedLocale(config.adminLocale, supported);
    return {
      locale: (normalized ?? DEFAULT_LOCALE) as SupportedUILocale,
      source: 'admin',
      matchedInput: config.adminLocale,
    };
  }

  // Priority 2: User-selected locale
  if (config.userLocale) {
    const normalized = normalizeSupportedLocale(config.userLocale, supported);
    if (normalized) {
      return {
        locale: normalized as SupportedUILocale,
        source: 'user',
        matchedInput: config.userLocale,
      };
    }
    // User selected an unsupported locale — fall through to browser
  }

  // Priority 3: Browser UI locale
  if (config.browserLocales && config.browserLocales.length > 0) {
    for (const browserLocale of config.browserLocales) {
      const normalized = normalizeSupportedLocale(browserLocale, supported);
      if (normalized) {
        return {
          locale: normalized as SupportedUILocale,
          source: 'browser',
          matchedInput: browserLocale,
        };
      }
    }
  }

  // Priority 4: English fallback
  return {
    locale: DEFAULT_LOCALE,
    source: 'fallback',
  };
}

// ============================================================================
// BROWSER INTEGRATION HELPERS
// ============================================================================

/**
 * Get browser locale list from available APIs.
 * Safe for content script, background script, and popup contexts.
 *
 * Uses chrome.i18n.getUILanguage() as primary source, then navigator.languages.
 */
export function getBrowserLocales(): string[] {
  const locales: string[] = [];

  // chrome.i18n.getUILanguage() — extension-specific, most reliable
  try {
    if (typeof chrome !== 'undefined' && chrome.i18n?.getUILanguage) {
      const uiLang = chrome.i18n.getUILanguage();
      if (uiLang) locales.push(uiLang);
    }
  } catch {
    // Not available in this context
  }

  // navigator.languages — broader browser locale list
  try {
    if (typeof navigator !== 'undefined' && navigator.languages) {
      for (const lang of navigator.languages) {
        if (!locales.includes(lang)) locales.push(lang);
      }
    } else if (typeof navigator !== 'undefined' && navigator.language) {
      if (!locales.includes(navigator.language)) locales.push(navigator.language);
    }
  } catch {
    // Not available in this context
  }

  return locales;
}
