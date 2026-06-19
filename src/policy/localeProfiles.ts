/**
 * AgentGuard Locale Profiles - Thin Loader/Lookup Engine
 *
 * Loads locale profile configuration from JSON files and provides
 * deterministic lookup functions for policy-driven detection.
 *
 * Design Principles:
 * - JSON-serializable config (loaded from src/data/locale-profiles/)
 * - Conservative defaults (avoid false positives)
 * - Local-only, no telemetry
 * - Deterministic behavior only
 *
 * @see ADR-010: Locale-Aware Detection
 * @see ADR-013: Admin-Configurable Risk Policy
 * @see AG-PROMPT-063: Datafy locale profiles
 */

import type { LocaleKey, LocaleConfidence } from './locale';
import { ALL_LOCALE_PROFILE_DATA } from '../data/locale-profiles';

// ============================================================================
// TYPES
// ============================================================================

/** Severity levels (matches RiskSignal.severity) */
export type Severity = 'low' | 'medium' | 'high' | 'critical';

/** Phone detection configuration per locale */
export interface PhoneConfig {
  enabled: boolean;
  minCount: number;
  escalationThreshold: number;
  maxSeverity: Severity;
  notes?: string;
}

/** National ID detection configuration per locale */
export interface NationalIdConfig {
  enabled: boolean;
  idType: string;
  description: string;
  baseSeverity: Severity;
  maxSeverity: Severity;
  notes?: string;
}

/** Email detection configuration per locale */
export interface EmailConfig {
  enabled: boolean;
  minCount: number;
  maxSeverity: Severity;
}

/** Complete locale profile for policy-driven detection */
export interface LocaleProfileConfig {
  id: LocaleKey;
  name: string;
  countries: string[];
  tldHints: string[];
  phone: PhoneConfig;
  nationalId: NationalIdConfig;
  email: EmailConfig;
  notes?: string;
}

// ============================================================================
// PROFILE LOADING
// ============================================================================

/** Build profile registry from JSON data */
function buildProfileRegistry(): Record<LocaleKey, LocaleProfileConfig> {
  const registry: Partial<Record<LocaleKey, LocaleProfileConfig>> = {};

  for (const data of ALL_LOCALE_PROFILE_DATA) {
    registry[data.id as LocaleKey] = data as LocaleProfileConfig;
  }

  return registry as Record<LocaleKey, LocaleProfileConfig>;
}

/** All locale profiles indexed by LocaleKey */
export const DEFAULT_LOCALE_PROFILES: Record<LocaleKey, LocaleProfileConfig> = buildProfileRegistry();

// ============================================================================
// EXPORTED PROFILE CONSTANTS (for backward compatibility)
// ============================================================================

export const EU_NORDICS_PROFILE = DEFAULT_LOCALE_PROFILES['EU-NORDICS'];
export const US_PROFILE = DEFAULT_LOCALE_PROFILES['US'];
export const UK_PROFILE = DEFAULT_LOCALE_PROFILES['UK'];
export const EU_DACH_PROFILE = DEFAULT_LOCALE_PROFILES['EU-DACH'];
export const EU_WESTERN_PROFILE = DEFAULT_LOCALE_PROFILES['EU-WESTERN'];
export const EU_SOUTHERN_PROFILE = DEFAULT_LOCALE_PROFILES['EU-SOUTHERN'];
export const EU_EASTERN_PROFILE = DEFAULT_LOCALE_PROFILES['EU-EASTERN'];
export const EN_COMMONWEALTH_PROFILE = DEFAULT_LOCALE_PROFILES['EN-COMMONWEALTH'];
export const LATAM_PROFILE = DEFAULT_LOCALE_PROFILES['LATAM'];
export const UNKNOWN_PROFILE = DEFAULT_LOCALE_PROFILES['unknown'];

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/** Get locale profile by key */
export function getLocaleProfileConfig(locale: LocaleKey): LocaleProfileConfig {
  return DEFAULT_LOCALE_PROFILES[locale] || DEFAULT_LOCALE_PROFILES['unknown'];
}

/** Check if phone detection should trigger for this locale and count */
export function shouldDetectPhones(locale: LocaleKey, count: number): boolean {
  const profile = getLocaleProfileConfig(locale);
  return profile.phone.enabled && count >= profile.phone.minCount;
}

/** Check if phone count exceeds escalation threshold for locale */
export function shouldEscalatePhonesByProfile(locale: LocaleKey, count: number): boolean {
  const profile = getLocaleProfileConfig(locale);
  return count >= profile.phone.escalationThreshold;
}

/** Check if national ID detection is enabled for locale */
export function isNationalIdEnabled(locale: LocaleKey): boolean {
  const profile = getLocaleProfileConfig(locale);
  return profile.nationalId.enabled;
}

/** Get phone severity cap for locale */
export function getPhoneSeverityCap(locale: LocaleKey): Severity {
  const profile = getLocaleProfileConfig(locale);
  return profile.phone.maxSeverity;
}

/** Get national ID severity for locale */
export function getNationalIdSeverity(locale: LocaleKey): Severity {
  const profile = getLocaleProfileConfig(locale);
  return profile.nationalId.baseSeverity;
}

/**
 * Check if US SSN detection should be enabled based on locale.
 * SSN format (XXX-XX-XXXX) is only valid in US context.
 */
export function isUSSSNApplicable(locale: LocaleKey): boolean {
  return locale === 'US' || locale === 'unknown';
}
