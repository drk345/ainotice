import {
  SIG_NATIONAL_ID, SIG_LEGACY_DK_CPR, SIG_LEGACY_SE_PERSONNUMMER,
  SIG_LEGACY_NO_FNR, SIG_LEGACY_FI_HETU,
} from '../detection/signalManifest';

/**
 * AgentGuard Interpretation Calibration (AG-PROMPT-038)
 *
 * Calibrates interpretation of detected signals to reduce false positives
 * while preserving decision quality across regions and languages.
 *
 * Design principles:
 * - Deterministic: Same inputs → same output (no ML, no confidence scores)
 * - Policy-layer only: Does NOT modify detection or scanning
 * - Auditor-obvious: Simple tiering and threshold rules
 * - Privacy-safe: Local-only, no telemetry
 *
 * Signal Tiers:
 * - UNIVERSAL: Always decision-driving (secrets, critical PII)
 * - REGION_SENSITIVE: Modified by locale (national IDs, specific regulations)
 * - CONTEXTUAL: Suppressed unless threshold/proximity met (emails, phones)
 *
 * @see ADR-020: Interpretation Calibration
 * @see AG-PROMPT-038
 */

import type { RiskSignal, Severity, SignalSource } from '../types/riskSignal';
import type { PolicyContext, LocaleKey, DepartmentId, DestinationType } from './policy';
// AG-PROMPT-227: regulated-signal predicates centralized in a single source of truth.
import {
  REGULATED_PREFIXES,
  isRegulatedSignalId,
  isRegulatedSignal,
} from './regulatedSignals';

// ============================================================================
// CONFIGURATION
// ============================================================================

/** Enable debug logging for calibration decisions */
const DEBUG_CALIBRATION = false;

/** Proximity threshold: contextual signals within N chars of universal signal get promoted */
const PROXIMITY_THRESHOLD_CHARS = 200;

/** Boilerplate repetition threshold: if same match appears > K times, consider boilerplate */
const BOILERPLATE_REPETITION_THRESHOLD = 5;

/** Default count threshold for contextual signal promotion */
const DEFAULT_CONTEXTUAL_COUNT_THRESHOLD = 3;

// ============================================================================
// TYPES
// ============================================================================

/**
 * Signal interpretation tier.
 *
 * - UNIVERSAL: Cannot be downgraded, always decision-driving
 * - REGION_SENSITIVE: Modified by locale rules
 * - CONTEXTUAL: Suppressed by default, promoted by threshold/proximity
 */
export type SignalTier = 'universal' | 'region_sensitive' | 'contextual';

/**
 * Decision role after calibration.
 *
 * - DRIVING: Contributes to severity aggregation and appears in details
 * - SUPPORTING: May appear in expanded details but doesn't drive severity
 * - SUPPRESSED: Hidden from decision payload (still in raw signals)
 */
export type DecisionRole = 'driving' | 'supporting' | 'suppressed';

/**
 * Reason for calibration decision (for audit/debug).
 */
export type CalibrationReason =
  | 'universal_immutable'
  | 'region_sensitive_promoted'
  | 'region_sensitive_demoted'
  | 'contextual_count_threshold'
  | 'contextual_proximity_anchor'
  | 'contextual_suppressed_default'
  | 'boilerplate_repetition'
  | 'regulated_rescue'  // AG-PROMPT-060: Promoted to prevent zero-visibility on regulated content
  | 'single_strong_awareness';  // AG-PROMPT-061: Single strong regulated signal awareness

/**
 * Calibrated signal wrapper.
 * Does NOT modify RiskSignal structure - wraps it with calibration metadata.
 */
export interface CalibratedSignal {
  /** Original signal (unchanged) */
  signal: RiskSignal;

  /** Interpretation tier */
  tier: SignalTier;

  /** Decision role after calibration */
  role: DecisionRole;

  /** Calibrated severity (may differ from signal.severity) */
  calibratedSeverity: Severity;

  /** Reason for this calibration */
  reason: CalibrationReason;

  /** Whether this signal was promoted by proximity to a universal signal */
  promotedByProximity?: boolean;

  /** Whether this signal was promoted by count threshold */
  promotedByCount?: boolean;
}

/**
 * Result of interpretation calibration.
 */
export interface CalibrationResult {
  /** All calibrated signals */
  calibratedSignals: CalibratedSignal[];

  /** Signals that are decision-driving (role === 'driving') */
  drivingSignals: CalibratedSignal[];

  /** Suppression metadata for audit */
  suppressionLog: SuppressionEntry[];

  /** Promotion metadata for audit */
  promotionLog: PromotionEntry[];

  /** Stats for diagnostics */
  stats: CalibrationStats;
}

/**
 * Entry in suppression log (for audit).
 */
export interface SuppressionEntry {
  signalId: string;
  reason: CalibrationReason;
  originalSeverity: Severity;
}

/**
 * Entry in promotion log (for audit).
 */
export interface PromotionEntry {
  signalId: string;
  reason: CalibrationReason;
  promotedFrom: DecisionRole;
  anchorSignalId?: string;
  countThreshold?: number;
}

/**
 * Calibration statistics.
 */
export interface CalibrationStats {
  totalSignals: number;
  universalCount: number;
  regionSensitiveCount: number;
  contextualCount: number;
  drivingCount: number;
  supportingCount: number;
  suppressedCount: number;
  promotedByProximity: number;
  promotedByCount: number;
  suppressedAsBoilerplate: number;
  rescuedRegulated: number;  // AG-PROMPT-060: Signals rescued by regulated rescue rule
  singleStrongAwareness: number;  // AG-PROMPT-061: Single strong regulated signal awareness
}

// ============================================================================
// SIGNAL TIER MAPS
// ============================================================================

/**
 * Universal immutable signals.
 * These are ALWAYS decision-driving regardless of locale/context.
 * Cannot be downgraded by any rule.
 */
export const UNIVERSAL_IMMUTABLE_IDS = new Set<string>([
  // Secrets (high-entropy, technical format = real risk)
  'secret.api_key',
  'secret.aws_key',
  'secret.password',
  'secret.private_key',
  'secret.bearer_token',
  'secret.connection_string',
  'secrets.api_key',
  'secrets.aws_key',
  'secrets.password',
  'secrets.private_key',
  'secrets.bearer_token',
  'secrets.connection_string',

  // Critical PII (universal regulatory concern)
  'pii.credit_card',
  'financial.credit_card',

  // Confidential markers (explicit classification)
  'confidential.ma_terms',
  'confidential.ma',
]);

/**
 * Region-sensitive signals.
 * These may be promoted/demoted based on locale.
 */
export const REGION_SENSITIVE_IDS = new Set<string>([
  // National IDs vary by jurisdiction
  'pii.ssn',
  'pii.ssn_us',
  'pii.national_id',

  // Financial (IBAN more relevant in EU, routing numbers in US)
  'financial.iban',
  'financial.banking',

  // Legal agreements (different weight by jurisdiction)
  'legal.agreement',
  'legal.contract',
  'legal.nda',
  'legal.privileged',
]);

/**
 * Contextual signals (noisy by default).
 * Suppressed unless threshold/proximity rules promote them.
 */
export const CONTEXTUAL_BY_DEFAULT_IDS = new Set<string>([
  // Contact info (common, often benign)
  'pii.phone',
  'pii.email',
  'pii.phone.density',
  'pii.email.density',

  // Names (very common in documents)
  'pii.name',
  'pii.author',
  'pii.employee',

  // Metadata artifacts
  'metadata.author',
  'metadata.creator',

  // Common confidential markers (often boilerplate)
  'confidential.marker',

  // Dictionary matches (often false positives)
  'dictionary.match',
  'dictionary.finance',
  'dictionary.hr',
  'dictionary.legal',
]);

// ============================================================================
// AG-PROMPT-060: REGULATED SIGNAL RESCUE
// ============================================================================

/**
 * Pattern prefixes that indicate regulated/sensitive content.
 * If signals matching these patterns would ALL be suppressed, at least one
 * must be rescued to ensure user visibility.
 *
 * This prevents the "zero-visibility" bug where regulated content is detected
 * but the user sees no warning.
 */
// AG-PROMPT-227: kept as the original export name for backward compatibility,
// now aliasing the centralized list in ./regulatedSignals (single source of truth).
export const REGULATED_SIGNAL_PREFIXES = REGULATED_PREFIXES;

/**
 * Minimum total signals required to trigger rescue.
 * Single signals may be false positives; multiple regulated signals indicate real risk.
 */
const REGULATED_RESCUE_MIN_SIGNALS = 2;

/**
 * Minimum regulated signals required to trigger rescue.
 * Ensures we only rescue when there's genuine regulated content, not noise.
 */
const REGULATED_RESCUE_MIN_REGULATED = 1;

// AG-PROMPT-227: isRegulatedSignalId / isRegulatedSignal now live in
// ./regulatedSignals (single source of truth). Re-exported here to preserve the
// existing `from './interpretationCalibration'` import path. The rescue mechanism
// below calls the imported predicates directly.
export { isRegulatedSignalId, isRegulatedSignal };

// ============================================================================
// AG-PROMPT-061: STRONG REGULATED SIGNALS (SINGLE SIGNAL AWARENESS)
// ============================================================================

/**
 * Signal IDs that are "structurally strong" and should ALWAYS be visible,
 * even when only a single instance is present.
 *
 * These are signals with high structural confidence (national ID formats,
 * registry-validated patterns) that warrant user awareness regardless of count.
 *
 * Contrast with "noisy" regulated signals (e.g., confidential.marker) which
 * require multiple occurrences to warrant visibility.
 */
export const STRONG_REGULATED_SIGNAL_IDS = new Set<string>([
  // AG-PROMPT-035: Unified national ID signal (pack-validated, high structural confidence)
  SIG_NATIONAL_ID,

  // Nordic national IDs (registry-validated, backward compat)
  SIG_LEGACY_DK_CPR,
  SIG_LEGACY_SE_PERSONNUMMER,
  SIG_LEGACY_NO_FNR,
  SIG_LEGACY_FI_HETU,

  // US national IDs
  'pii.ssn_us',
  'pii.ssn',

  // Other high-confidence national ID patterns
  'pii.national_id',

  // Financial identifiers with strong structure
  'financial.credit_card',
  'pii.credit_card',

  // Secrets (always high risk regardless of count)
  'secret.api_key',
  'secret.aws_key',
  'secret.password',
  'secret.private_key',
  'secret.bearer_token',
  'secret.connection_string',
  'secrets.api_key',
  'secrets.aws_key',
  'secrets.password',
  'secrets.private_key',
  'secrets.bearer_token',
  'secrets.connection_string',
]);

/**
 * Check if a signal ID is a "strong" regulated signal that should always be visible.
 * Used by single-signal awareness rule (AG-PROMPT-061).
 */
export function isStrongRegulatedSignalId(signalId: string | undefined): boolean {
  if (!signalId) return false;
  return STRONG_REGULATED_SIGNAL_IDS.has(signalId);
}

// ============================================================================
// LOCALE MODIFIERS
// ============================================================================

/**
 * Locale modifier for region-sensitive signals.
 */
export interface LocaleModifier {
  /** Severity cap (cannot exceed this) */
  maxSeverity?: Severity;
  /** Minimum severity (floor) */
  minSeverity?: Severity;
  /** Override decision role */
  role?: DecisionRole;
  /** Custom count threshold for contextual promotion */
  countThreshold?: number;
}

/**
 * Locale modifier table.
 * Maps signal ID → locale → modifier.
 */
export const LOCALE_MODIFIERS: Record<string, Partial<Record<LocaleKey, LocaleModifier>>> = {
  // SSN is US-specific; demote in other regions
  'pii.ssn': {
    'US': { minSeverity: 'high', role: 'driving' },
    'unknown': { maxSeverity: 'medium', role: 'supporting' },
    'UK': { maxSeverity: 'low', role: 'suppressed' },
    'EU-NORDICS': { maxSeverity: 'low', role: 'suppressed' },
    'EU-DACH': { maxSeverity: 'low', role: 'suppressed' },
    'EU-WESTERN': { maxSeverity: 'low', role: 'suppressed' },
    'EU-SOUTHERN': { maxSeverity: 'low', role: 'suppressed' },
    'EU-EASTERN': { maxSeverity: 'low', role: 'suppressed' },
    'EN-COMMONWEALTH': { maxSeverity: 'low', role: 'suppressed' },
    'LATAM': { maxSeverity: 'low', role: 'suppressed' },
  },
  'pii.ssn_us': {
    'US': { minSeverity: 'high', role: 'driving' },
    'unknown': { maxSeverity: 'medium', role: 'supporting' },
    'UK': { maxSeverity: 'low', role: 'suppressed' },
    'EU-NORDICS': { maxSeverity: 'low', role: 'suppressed' },
    'EU-DACH': { maxSeverity: 'low', role: 'suppressed' },
  },

  // IBAN is more relevant in EU regions
  'financial.iban': {
    'US': { maxSeverity: 'medium', role: 'supporting' },
    'EU-NORDICS': { minSeverity: 'high', role: 'driving' },
    'EU-DACH': { minSeverity: 'high', role: 'driving' },
    'EU-WESTERN': { minSeverity: 'high', role: 'driving' },
    'EU-SOUTHERN': { minSeverity: 'high', role: 'driving' },
    'EU-EASTERN': { minSeverity: 'high', role: 'driving' },
    'UK': { minSeverity: 'medium', role: 'driving' },
  },

  // Phone numbers: higher threshold in EU-NORDICS (more common in documents)
  'pii.phone': {
    'EU-NORDICS': { countThreshold: 10 },
    'EU-DACH': { countThreshold: 8 },
    'US': { countThreshold: 5 },
  },

  // Email addresses: higher threshold everywhere
  'pii.email': {
    'US': { countThreshold: 5 },
    'EU-NORDICS': { countThreshold: 8 },
    'unknown': { countThreshold: 5 },
  },
};

// ============================================================================
// TIER CLASSIFICATION
// ============================================================================

/**
 * Get the interpretation tier for a signal.
 *
 * @param signalId - Canonical signal ID
 * @returns SignalTier
 */
export function getSignalTier(signalId: string | undefined): SignalTier {
  if (!signalId) {
    return 'contextual';
  }

  if (UNIVERSAL_IMMUTABLE_IDS.has(signalId)) {
    return 'universal';
  }

  if (REGION_SENSITIVE_IDS.has(signalId)) {
    return 'region_sensitive';
  }

  if (CONTEXTUAL_BY_DEFAULT_IDS.has(signalId)) {
    return 'contextual';
  }

  // Unknown signals default to contextual (safer)
  return 'contextual';
}

/**
 * Get locale modifier for a signal.
 *
 * @param signalId - Canonical signal ID
 * @param locale - Current locale
 * @returns LocaleModifier or undefined
 */
export function getLocaleModifier(
  signalId: string | undefined,
  locale: LocaleKey
): LocaleModifier | undefined {
  if (!signalId) return undefined;

  const modifiers = LOCALE_MODIFIERS[signalId];
  if (!modifiers) return undefined;

  // Try exact locale match first, then 'unknown' as fallback
  return modifiers[locale] ?? modifiers['unknown'];
}

// ============================================================================
// THRESHOLD & PROXIMITY LOGIC
// ============================================================================

/**
 * Count signals by canonical ID.
 * Uses signal.id for counting (not description).
 */
function countSignalsById(signals: RiskSignal[]): Map<string, number> {
  const counts = new Map<string, number>();
  for (const signal of signals) {
    const id = signal.id ?? 'unknown';
    counts.set(id, (counts.get(id) ?? 0) + 1);
  }
  return counts;
}

/**
 * Count signals by match value (for boilerplate detection).
 */
function countSignalsByMatch(signals: RiskSignal[]): Map<string, RiskSignal[]> {
  const groups = new Map<string, RiskSignal[]>();
  for (const signal of signals) {
    const match = signal.match ?? signal.id ?? 'unknown';
    const group = groups.get(match) ?? [];
    group.push(signal);
    groups.set(match, group);
  }
  return groups;
}

/**
 * Get count threshold for a contextual signal.
 */
function getCountThreshold(signalId: string | undefined, locale: LocaleKey): number {
  const modifier = getLocaleModifier(signalId, locale);
  return modifier?.countThreshold ?? DEFAULT_CONTEXTUAL_COUNT_THRESHOLD;
}

/**
 * Check if a contextual signal is within proximity of any universal signal.
 */
function isWithinProximityOfUniversal(
  signal: RiskSignal,
  universalSignals: RiskSignal[]
): { inProximity: boolean; anchorId?: string } {
  if (signal.offset === undefined) {
    return { inProximity: false };
  }

  for (const universal of universalSignals) {
    if (universal.offset === undefined) continue;

    const distance = Math.abs(signal.offset - universal.offset);
    if (distance <= PROXIMITY_THRESHOLD_CHARS) {
      return { inProximity: true, anchorId: universal.id };
    }
  }

  return { inProximity: false };
}

/**
 * Detect boilerplate repetition pattern.
 * Returns true if signals appear to be boilerplate (repeated identical matches).
 */
function isBoilerplatePattern(signals: RiskSignal[]): boolean {
  if (signals.length < BOILERPLATE_REPETITION_THRESHOLD) {
    return false;
  }

  // Check for evenly-spaced repetition (footer/header pattern)
  if (signals.length >= 3 && signals.every(s => s.offset !== undefined)) {
    const offsets = signals.map(s => s.offset!).sort((a, b) => a - b);
    const gaps: number[] = [];
    for (let i = 1; i < offsets.length; i++) {
      gaps.push(offsets[i] - offsets[i - 1]);
    }

    // If gaps are roughly similar (within 20% variance), likely boilerplate
    if (gaps.length >= 2) {
      const avgGap = gaps.reduce((a, b) => a + b, 0) / gaps.length;
      const variance = gaps.every(g => Math.abs(g - avgGap) < avgGap * 0.3);
      if (variance && avgGap > 500) {
        // Regular pattern with significant spacing = likely boilerplate
        return true;
      }
    }
  }

  // Simple repetition count check
  return signals.length >= BOILERPLATE_REPETITION_THRESHOLD;
}

// ============================================================================
// SEVERITY HELPERS
// ============================================================================

const SEVERITY_ORDER: Severity[] = ['low', 'medium', 'high', 'critical'];

function severityIndex(severity: Severity): number {
  return SEVERITY_ORDER.indexOf(severity);
}

function applySeverityCap(severity: Severity, cap: Severity): Severity {
  return severityIndex(severity) > severityIndex(cap) ? cap : severity;
}

function applySeverityFloor(severity: Severity, floor: Severity): Severity {
  return severityIndex(severity) < severityIndex(floor) ? floor : severity;
}

// ============================================================================
// MAIN CALIBRATION FUNCTION
// ============================================================================

/**
 * Calibrate interpretation of detected signals.
 *
 * This is the main entry point for interpretation calibration.
 * Should be called post-dedupe, pre-decision explanation.
 *
 * @param signals - Deduplicated RiskSignal array
 * @param context - Policy context (locale, counts, etc.)
 * @returns CalibrationResult with calibrated signals and audit logs
 */
export function calibrateInterpretation(
  signals: RiskSignal[],
  context: PolicyContext
): CalibrationResult {
  const calibratedSignals: CalibratedSignal[] = [];
  const suppressionLog: SuppressionEntry[] = [];
  const promotionLog: PromotionEntry[] = [];
  const stats: CalibrationStats = {
    totalSignals: signals.length,
    universalCount: 0,
    regionSensitiveCount: 0,
    contextualCount: 0,
    drivingCount: 0,
    supportingCount: 0,
    suppressedCount: 0,
    promotedByProximity: 0,
    promotedByCount: 0,
    suppressedAsBoilerplate: 0,
    rescuedRegulated: 0,
    singleStrongAwareness: 0,
  };

  if (!signals || signals.length === 0) {
    return { calibratedSignals, drivingSignals: [], suppressionLog, promotionLog, stats };
  }

  const locale = context.locale ?? 'unknown';

  // Pre-compute counts and groups
  const countById = countSignalsById(signals);
  const groupsByMatch = countSignalsByMatch(signals);

  // First pass: identify universal signals (for proximity anchoring)
  const universalSignals = signals.filter(
    s => getSignalTier(s.id) === 'universal'
  );

  // Detect boilerplate patterns
  const boilerplateMatches = new Set<string>();
  for (const [match, group] of groupsByMatch) {
    if (isBoilerplatePattern(group)) {
      boilerplateMatches.add(match);
    }
  }

  // Main calibration loop
  for (const signal of signals) {
    const signalId = signal.id ?? 'unknown';
    const tier = getSignalTier(signalId);
    let role: DecisionRole = 'suppressed';
    let calibratedSeverity: Severity = signal.severity;
    let reason: CalibrationReason = 'contextual_suppressed_default';
    let promotedByProximity = false;
    let promotedByCount = false;

    // Update tier stats
    if (tier === 'universal') stats.universalCount++;
    else if (tier === 'region_sensitive') stats.regionSensitiveCount++;
    else stats.contextualCount++;

    // Apply tier-specific rules
    switch (tier) {
      case 'universal':
        // Universal signals are always decision-driving
        role = 'driving';
        reason = 'universal_immutable';
        break;

      case 'region_sensitive':
        // Apply locale modifier
        const modifier = getLocaleModifier(signalId, locale);
        if (modifier) {
          // Apply severity bounds
          if (modifier.maxSeverity) {
            calibratedSeverity = applySeverityCap(calibratedSeverity, modifier.maxSeverity);
          }
          if (modifier.minSeverity) {
            calibratedSeverity = applySeverityFloor(calibratedSeverity, modifier.minSeverity);
          }
          // Apply role override
          if (modifier.role) {
            role = modifier.role;
            reason = role === 'driving' ? 'region_sensitive_promoted' : 'region_sensitive_demoted';
          } else {
            role = 'driving'; // Default for region-sensitive
            reason = 'region_sensitive_promoted';
          }
        } else {
          // No modifier, default to driving
          role = 'driving';
          reason = 'region_sensitive_promoted';
        }
        break;

      case 'contextual':
        // Check for boilerplate suppression
        const matchKey = signal.match ?? signalId;
        if (boilerplateMatches.has(matchKey)) {
          role = 'suppressed';
          reason = 'boilerplate_repetition';
          stats.suppressedAsBoilerplate++;
          suppressionLog.push({
            signalId,
            reason: 'boilerplate_repetition',
            originalSeverity: signal.severity,
          });
          break;
        }

        // Check count threshold
        const count = countById.get(signalId) ?? 1;
        const threshold = getCountThreshold(signalId, locale);
        if (count >= threshold) {
          role = 'driving';
          reason = 'contextual_count_threshold';
          promotedByCount = true;
          stats.promotedByCount++;
          promotionLog.push({
            signalId,
            reason: 'contextual_count_threshold',
            promotedFrom: 'suppressed',
            countThreshold: threshold,
          });
          break;
        }

        // Check proximity to universal signal
        const proximity = isWithinProximityOfUniversal(signal, universalSignals);
        if (proximity.inProximity) {
          role = 'supporting';
          reason = 'contextual_proximity_anchor';
          promotedByProximity = true;
          stats.promotedByProximity++;
          promotionLog.push({
            signalId,
            reason: 'contextual_proximity_anchor',
            promotedFrom: 'suppressed',
            anchorSignalId: proximity.anchorId,
          });
          break;
        }

        // Default: suppress contextual signal
        role = 'suppressed';
        reason = 'contextual_suppressed_default';
        suppressionLog.push({
          signalId,
          reason: 'contextual_suppressed_default',
          originalSeverity: signal.severity,
        });
        break;
    }

    // Update role stats
    if (role === 'driving') stats.drivingCount++;
    else if (role === 'supporting') stats.supportingCount++;
    else stats.suppressedCount++;

    calibratedSignals.push({
      signal,
      tier,
      role,
      calibratedSeverity,
      reason,
      promotedByProximity,
      promotedByCount,
    });
  }

  // =========================================================================
  // AG-PROMPT-060: REGULATED SIGNAL RESCUE
  // =========================================================================
  // If ALL signals are suppressed but some are regulated, rescue one.
  // This prevents the "zero-visibility" bug where regulated content is detected
  // but the user sees no warning.
  //
  // Trigger conditions:
  // 1. Total signals >= REGULATED_RESCUE_MIN_SIGNALS (default: 2)
  // 2. At least REGULATED_RESCUE_MIN_REGULATED regulated signals present
  // 3. drivingCount === 0 (all signals would be suppressed)
  // =========================================================================

  if (
    stats.totalSignals >= REGULATED_RESCUE_MIN_SIGNALS &&
    stats.drivingCount === 0
  ) {
    // Find suppressed regulated signals
    // AG-PROMPT-075: Use isRegulatedSignal to check both ID and type
    const suppressedRegulated = calibratedSignals.filter(
      cs => cs.role === 'suppressed' && isRegulatedSignal(cs.signal)
    );

    if (suppressedRegulated.length >= REGULATED_RESCUE_MIN_REGULATED) {
      // Sort by severity (highest first) to rescue the most important signal
      const severityOrder: Record<Severity, number> = {
        'critical': 4,
        'high': 3,
        'medium': 2,
        'low': 1,
      };

      suppressedRegulated.sort((a, b) => {
        const aScore = severityOrder[a.signal.severity] ?? 0;
        const bScore = severityOrder[b.signal.severity] ?? 0;
        return bScore - aScore;
      });

      // Rescue the highest-severity regulated signal
      const toRescue = suppressedRegulated[0];
      toRescue.role = 'driving';
      toRescue.reason = 'regulated_rescue';

      // Update stats
      stats.drivingCount++;
      stats.suppressedCount--;
      stats.rescuedRegulated++;

      // Add to promotion log
      promotionLog.push({
        signalId: toRescue.signal.id ?? 'unknown',
        reason: 'regulated_rescue',
        promotedFrom: 'suppressed',
      });

      if (DEBUG_CALIBRATION) {
        console.log(
          `[Ai Notice][Calibration] Regulated rescue: promoted ${toRescue.signal.id} (${toRescue.signal.severity}) to driving`
        );
      }
    }
  }

  // =========================================================================
  // AG-PROMPT-061: SINGLE STRONG REGULATED SIGNAL AWARENESS
  // =========================================================================
  // If exactly ONE signal is present and it's a "strong" regulated signal,
  // promote it to driving for awareness visibility.
  //
  // This handles the case where a single national ID (CPR, personnummer, SSN)
  // or similar high-confidence pattern is present but would otherwise be
  // suppressed due to being contextual.
  //
  // Trigger conditions:
  // 1. Total signals === 1
  // 2. The single signal is a "strong" regulated signal
  // 3. drivingCount === 0 (would otherwise be suppressed)
  // =========================================================================

  if (
    stats.totalSignals === 1 &&
    stats.drivingCount === 0
  ) {
    const singleSignal = calibratedSignals[0];
    if (singleSignal && isStrongRegulatedSignalId(singleSignal.signal.id)) {
      singleSignal.role = 'driving';
      singleSignal.reason = 'single_strong_awareness';

      // Update stats
      stats.drivingCount++;
      stats.suppressedCount--;
      stats.singleStrongAwareness++;

      // Add to promotion log
      promotionLog.push({
        signalId: singleSignal.signal.id ?? 'unknown',
        reason: 'single_strong_awareness',
        promotedFrom: 'suppressed',
      });

      if (DEBUG_CALIBRATION) {
        console.log(
          `[Ai Notice][Calibration] Single strong awareness: promoted ${singleSignal.signal.id} (${singleSignal.signal.severity}) to driving`
        );
      }
    }
  }

  // =========================================================================
  // AG-PROMPT-075: FINAL REGULATED SIGNAL GUARDRAIL
  // =========================================================================
  // INVARIANT: If ANY regulated signal exists, at least ONE must survive.
  // This is the final safety net that runs after all other rescue/promotion logic.
  //
  // Unlike AG-PROMPT-060 (requires totalSignals >= 2) and AG-PROMPT-061 (requires
  // "strong" signal), this guardrail has NO preconditions except:
  // 1. At least one regulated signal exists
  // 2. drivingCount === 0 (all signals would be suppressed)
  // =========================================================================

  if (stats.drivingCount === 0) {
    // Find any suppressed regulated signals (checking both ID and type)
    const suppressedRegulatedFinal = calibratedSignals.filter(
      cs => cs.role === 'suppressed' && isRegulatedSignal(cs.signal)
    );

    if (suppressedRegulatedFinal.length > 0) {
      // Sort by severity (highest first) to rescue the most important signal
      const severityOrder: Record<Severity, number> = {
        'critical': 4,
        'high': 3,
        'medium': 2,
        'low': 1,
      };

      suppressedRegulatedFinal.sort((a, b) => {
        const aScore = severityOrder[a.signal.severity] ?? 0;
        const bScore = severityOrder[b.signal.severity] ?? 0;
        return bScore - aScore;
      });

      // Rescue the highest-severity regulated signal
      const toRescue = suppressedRegulatedFinal[0];
      toRescue.role = 'driving';
      toRescue.reason = 'regulated_rescue';

      // Update stats
      stats.drivingCount++;
      stats.suppressedCount--;
      stats.rescuedRegulated++;

      // Add to promotion log
      promotionLog.push({
        signalId: toRescue.signal.id ?? toRescue.signal.type,
        reason: 'regulated_rescue',
        promotedFrom: 'suppressed',
      });

      if (DEBUG_CALIBRATION) {
        console.log(
          `[Ai Notice][Calibration] AG-PROMPT-075 final guardrail: rescued ${toRescue.signal.id ?? toRescue.signal.type} (${toRescue.signal.severity}) to driving`
        );
      }
    }
  }

  // Extract driving signals
  const drivingSignals = calibratedSignals.filter(cs => cs.role === 'driving');

  // Debug logging
  if (DEBUG_CALIBRATION) {
    console.log(`[Ai Notice][Calibration] locale=${locale} total=${stats.totalSignals} driving=${stats.drivingCount} suppressed=${stats.suppressedCount}`);
    if (stats.promotedByProximity > 0) {
      console.log(`[Ai Notice][Calibration] Promoted by proximity: ${stats.promotedByProximity}`);
    }
    if (stats.promotedByCount > 0) {
      console.log(`[Ai Notice][Calibration] Promoted by count: ${stats.promotedByCount}`);
    }
    if (stats.suppressedAsBoilerplate > 0) {
      console.log(`[Ai Notice][Calibration] Suppressed as boilerplate: ${stats.suppressedAsBoilerplate}`);
    }
    if (stats.rescuedRegulated > 0) {
      console.log(`[Ai Notice][Calibration] Rescued regulated: ${stats.rescuedRegulated}`);
    }
    if (stats.singleStrongAwareness > 0) {
      console.log(`[Ai Notice][Calibration] Single strong awareness: ${stats.singleStrongAwareness}`);
    }
  }

  return { calibratedSignals, drivingSignals, suppressionLog, promotionLog, stats };
}

// ============================================================================
// HELPERS FOR INTEGRATION
// ============================================================================

/**
 * Extract RiskSignals from calibrated driving signals.
 * Use this to pass to severity aggregation.
 */
export function extractDrivingSignals(result: CalibrationResult): RiskSignal[] {
  return result.drivingSignals.map(cs => ({
    ...cs.signal,
    severity: cs.calibratedSeverity,
  }));
}

/**
 * Extract driving signal IDs for decision explanation.
 */
export function extractDrivingSignalIds(result: CalibrationResult): string[] {
  return result.drivingSignals
    .map(cs => cs.signal.id)
    .filter((id): id is string => id !== undefined);
}

/**
 * Check if a signal ID is universal (immutable).
 */
export function isUniversalSignal(signalId: string | undefined): boolean {
  return signalId !== undefined && UNIVERSAL_IMMUTABLE_IDS.has(signalId);
}

/**
 * Check if a signal ID is region-sensitive.
 */
export function isRegionSensitiveSignal(signalId: string | undefined): boolean {
  return signalId !== undefined && REGION_SENSITIVE_IDS.has(signalId);
}

/**
 * Check if a signal ID is contextual by default.
 */
export function isContextualSignal(signalId: string | undefined): boolean {
  return signalId !== undefined && CONTEXTUAL_BY_DEFAULT_IDS.has(signalId);
}

// ============================================================================
// EXPORTS
// ============================================================================

export {
  PROXIMITY_THRESHOLD_CHARS,
  BOILERPLATE_REPETITION_THRESHOLD,
  DEFAULT_CONTEXTUAL_COUNT_THRESHOLD,
};
