/**
 * Ai Notice i18n module.
 *
 * Exports the canonical locale resolver and supported locale constants.
 * UI string loading is deferred to a future pass.
 */

export {
  resolveAiNoticeLocale,
  normalizeSupportedLocale,
  getBrowserLocales,
  SUPPORTED_UI_LOCALES,
  DEFAULT_LOCALE,
  type SupportedUILocale,
  type LocaleResolverConfig,
  type LocaleResolverResult,
} from './localeResolver';
