/**
 * AgentGuard Human Heuristic Anchors (AG-PROMPT-039)
 *
 * Implements deterministic heuristics that align with how humans judge documents.
 * Runs in the Policy/Interpretation layer AFTER calibration, BEFORE severity aggregation.
 *
 * Three anchors:
 * 1. PROXIMITY_ANCHOR: Relationship over Record - signals near each other matter more
 * 2. ZONE_ANCHOR: Role-Based Identity - header/footer/metadata signals are less actionable
 * 3. FINALITY_ANCHOR: Finality & Authority - legal markers interact with other signals
 *
 * Design principles:
 * - Deterministic: Same inputs → same output (no ML, no probabilistic scoring)
 * - Auditor-obvious: Clear rule IDs and reasons in audit trail
 * - Region/language aware: Uses locale context, not English-only assumptions
 * - Local-only: No telemetry, no network calls
 *
 * @see AG-PROMPT-039
 */

import type { RiskSignal, Severity, SignalSource } from '../types/riskSignal';
import type { LocaleKey } from './policy';

// ============================================================================
// CONFIGURATION
// ============================================================================

/** Enable debug logging for heuristic decisions */
const DEBUG_HEURISTICS = false;

// PROXIMITY ANCHOR configuration
/** Default proximity window in characters */
export const PROXIMITY_WINDOW_CHARS = 200;

// ZONE ANCHOR configuration
/** Document start window (header zone) in characters */
export const DOC_START_WINDOW_CHARS = 1500;
/** Document end window (footer zone) in characters */
export const DOC_END_WINDOW_CHARS = 1500;
/** Minimum repetitions to consider as boilerplate (complements calibration) */
export const ZONE_BOILERPLATE_THRESHOLD = 3;

// LIST ANCHOR configuration
/** Minimum distinct values to be considered a "contact list" */
export const LIST_DISTINCT_THRESHOLD = 5;
/** Maximum character range for distinct values to be considered a "list" */
export const LIST_RANGE_MAX_CHARS = 2000;

// FINALITY ANCHOR configuration
/** Legal boilerplate signal IDs that are suppressed when alone */
export const LEGAL_BOILERPLATE_IDS = new Set<string>([
  'legal.contract',
  'legal.agreement',
  'legal.nda',
  'legal.privileged',
  'dictionary.legal',
]);

/** Confidentiality marker signal IDs that can amplify other signals */
export const CONFIDENTIALITY_MARKER_IDS = new Set<string>([
  'confidential.marker',
  'confidential.ma',
  'confidential.ma_terms',
]);

// ============================================================================
// RULE IDS (for audit trail)
// ============================================================================

export const RULE_IDS = {
  // Proximity anchor
  PROXIMITY_PROMOTION: 'HHA-001-proximity-promotion',
  PROXIMITY_AMPLIFY: 'HHA-002-proximity-amplify',

  // Zone anchor
  ZONE_HEADER_SUPPRESS: 'HHA-010-zone-header',
  ZONE_FOOTER_SUPPRESS: 'HHA-011-zone-footer',
  ZONE_METADATA_SUPPRESS: 'HHA-012-metadata-role',
  ZONE_BOILERPLATE_SUPPRESS: 'HHA-013-zone-boilerplate',

  // List anchor
  LIST_PROMOTION: 'HHA-020-list-promotion',
  LIST_DISTINCT_VALUES: 'HHA-021-list-distinct',

  // Finality anchor
  FINALITY_LEGAL_SUPPRESS: 'HHA-030-legal-alone',
  FINALITY_MARKER_AMPLIFY: 'HHA-031-marker-amplify',
  FINALITY_MARKER_KEEP: 'HHA-032-marker-with-sensitive',
} as const;

// ============================================================================
// TYPES
// ============================================================================

/**
 * Locale context for heuristic decisions.
 */
export interface HeuristicLocaleContext {
  locale: LocaleKey;
  confidence?: number | string;
}

/**
 * Destination context for heuristic decisions.
 */
export interface HeuristicDestination {
  hostname: string;
  category?: 'public_ai' | 'internal_ai' | 'unknown';
}

/**
 * Input for the human heuristics function.
 */
export interface HeuristicInput {
  /** Signals to process (typically from calibration's driving signals) */
  signals: RiskSignal[];

  /** Locale context */
  locale: HeuristicLocaleContext;

  /** Optional destination context */
  destination?: HeuristicDestination;

  /** Optional document length for zone calculations */
  documentLength?: number;

  /** All original signals (for context, e.g., checking for universal signals) */
  allSignals?: RiskSignal[];
}

/**
 * Audit trail entry for a heuristic decision.
 */
export interface AuditEntry {
  /** Rule ID that fired */
  ruleId: string;
  /** Human-readable reason */
  reason: string;
  /** Signal IDs affected by this rule */
  affectedSignalIds: string[];
  /** Optional additional context */
  context?: Record<string, unknown>;
}

/**
 * Result of applying human heuristics.
 */
export interface HeuristicResult {
  /** Signals that remain decision-driving after heuristics */
  signals: RiskSignal[];
  /** Signals that were suppressed (for diagnostics only) */
  suppressed: RiskSignal[];
  /** Audit trail of all decisions */
  audit: AuditEntry[];
  /** Statistics for diagnostics */
  stats: HeuristicStats;
}

/**
 * Statistics from heuristic processing.
 */
export interface HeuristicStats {
  inputCount: number;
  outputCount: number;
  suppressedCount: number;
  promotedCount: number;
  proximityPromotions: number;
  zoneSuppressed: number;
  listPromotions: number;
  finalitySuppressed: number;
}

// ============================================================================
// SIGNAL CLASSIFICATION (for heuristic decisions)
// ============================================================================

/**
 * Universal signal IDs that are always decision-driving.
 * These anchor other signals via proximity.
 */
const UNIVERSAL_ANCHOR_IDS = new Set<string>([
  // Secrets
  'secret.api_key',
  'secret.aws_key',
  'secret.password',
  'secret.private_key',
  'secret.bearer_token',
  'secret.connection_string',
  'secrets.api_key',
  'secrets.aws_key',

  // Critical PII
  'pii.credit_card',
  'financial.credit_card',

  // High-value confidential
  'confidential.ma_terms',
]);

/**
 * Contextual signal IDs that can be promoted by proximity/list detection.
 */
const CONTEXTUAL_PROMOTABLE_IDS = new Set<string>([
  'pii.email',
  'pii.phone',
  'pii.name',
  'pii.employee',
  'financial.swift',
  'financial.bic',
  'financial.iban',
  'metadata.author',
  'metadata.creator',
]);

/**
 * Check if a signal ID is a universal anchor.
 */
export function isUniversalAnchor(signalId: string | undefined): boolean {
  return signalId !== undefined && UNIVERSAL_ANCHOR_IDS.has(signalId);
}

/**
 * Check if a signal ID is contextual and promotable.
 */
export function isContextualPromotable(signalId: string | undefined): boolean {
  return signalId !== undefined && CONTEXTUAL_PROMOTABLE_IDS.has(signalId);
}

// ============================================================================
// PROXIMITY ANCHOR (Anchor #1)
// ============================================================================

/**
 * Find signals within proximity of universal anchors.
 * Returns map of signal index → anchor signal ID.
 */
function findProximityPromotions(
  signals: RiskSignal[],
  allSignals?: RiskSignal[]
): Map<number, string> {
  const promotions = new Map<number, string>();

  // Find universal anchors (in input signals or all signals)
  const signalsToCheck = allSignals ?? signals;
  const anchors = signalsToCheck.filter(s => isUniversalAnchor(s.id) && s.offset !== undefined);

  if (anchors.length === 0) {
    return promotions;
  }

  // Sort anchors by offset for efficient searching
  const sortedAnchors = [...anchors].sort((a, b) => (a.offset ?? 0) - (b.offset ?? 0));

  // Check each contextual signal for proximity to anchors
  for (let i = 0; i < signals.length; i++) {
    const signal = signals[i];
    if (!isContextualPromotable(signal.id) || signal.offset === undefined) {
      continue;
    }

    // Binary search for nearby anchors (O(log n))
    const signalOffset = signal.offset;
    let nearestAnchor: RiskSignal | undefined;
    let nearestDistance = Infinity;

    // Simple linear scan (signals are typically few, O(n) is fine)
    for (const anchor of sortedAnchors) {
      const distance = Math.abs(signalOffset - (anchor.offset ?? 0));
      if (distance < nearestDistance) {
        nearestDistance = distance;
        nearestAnchor = anchor;
      }
    }

    if (nearestAnchor && nearestDistance <= PROXIMITY_WINDOW_CHARS) {
      promotions.set(i, nearestAnchor.id ?? 'unknown');
    }
  }

  return promotions;
}

// ============================================================================
// ZONE ANCHOR (Anchor #2)
// ============================================================================

/**
 * Determine if a signal is in the header zone.
 */
function isInHeaderZone(offset: number | undefined): boolean {
  if (offset === undefined) return false;
  return offset < DOC_START_WINDOW_CHARS;
}

/**
 * Determine if a signal is in the footer zone.
 */
function isInFooterZone(offset: number | undefined, docLength?: number): boolean {
  if (offset === undefined) return false;
  if (docLength === undefined) return false;
  return offset > (docLength - DOC_END_WINDOW_CHARS);
}

/**
 * Find signals that should be suppressed due to zone (header/footer/metadata).
 * Returns set of signal indices to suppress.
 */
function findZoneSuppression(
  signals: RiskSignal[],
  documentLength?: number,
  hasUniversalAnchors?: boolean
): { indices: Set<number>; reasons: Map<number, string> } {
  const indices = new Set<number>();
  const reasons = new Map<number, string>();

  for (let i = 0; i < signals.length; i++) {
    const signal = signals[i];
    const signalId = signal.id ?? 'unknown';

    // Never suppress universal anchors
    if (isUniversalAnchor(signalId)) {
      continue;
    }

    // Suppress metadata-only signals (author, creator) unless near universal
    if (signal.source === 'metadata' && isContextualPromotable(signalId)) {
      // Only suppress if no universal anchors in document
      if (!hasUniversalAnchors) {
        indices.add(i);
        reasons.set(i, RULE_IDS.ZONE_METADATA_SUPPRESS);
        continue;
      }
    }

    // Check header zone
    if (isInHeaderZone(signal.offset) && isContextualPromotable(signalId)) {
      indices.add(i);
      reasons.set(i, RULE_IDS.ZONE_HEADER_SUPPRESS);
      continue;
    }

    // Check footer zone
    if (isInFooterZone(signal.offset, documentLength) && isContextualPromotable(signalId)) {
      indices.add(i);
      reasons.set(i, RULE_IDS.ZONE_FOOTER_SUPPRESS);
      continue;
    }
  }

  return { indices, reasons };
}

/**
 * Detect boilerplate patterns (same match repeated at regular intervals).
 * Complements calibration's boilerplate detection with zone awareness.
 */
function findZoneBoilerplate(
  signals: RiskSignal[]
): { indices: Set<number>; matchGroups: Map<string, number[]> } {
  const indices = new Set<number>();
  const matchGroups = new Map<string, number[]>();

  // Group signals by match value
  for (let i = 0; i < signals.length; i++) {
    const signal = signals[i];
    const matchKey = signal.match ?? signal.id ?? 'unknown';

    if (!matchGroups.has(matchKey)) {
      matchGroups.set(matchKey, []);
    }
    matchGroups.get(matchKey)!.push(i);
  }

  // Check for boilerplate patterns
  for (const [matchKey, group] of matchGroups) {
    if (group.length >= ZONE_BOILERPLATE_THRESHOLD) {
      // Check if all are contextual (not universal)
      const allContextual = group.every(idx => {
        const signal = signals[idx];
        return isContextualPromotable(signal.id) || !isUniversalAnchor(signal.id);
      });

      if (allContextual) {
        // Mark all as boilerplate
        for (const idx of group) {
          indices.add(idx);
        }
      }
    }
  }

  return { indices, matchGroups };
}

// ============================================================================
// LIST ANCHOR (Anchor #2 extension)
// ============================================================================

/**
 * Detect "contact list" patterns (many distinct values in a bounded range).
 * These should be promoted, not suppressed.
 */
function findListPromotions(
  signals: RiskSignal[]
): { indices: Set<number>; listType: string | undefined } {
  const indices = new Set<number>();

  // Group contextual signals by type
  const emailSignals: { idx: number; signal: RiskSignal }[] = [];
  const phoneSignals: { idx: number; signal: RiskSignal }[] = [];

  for (let i = 0; i < signals.length; i++) {
    const signal = signals[i];
    if (signal.id === 'pii.email' || signal.id === 'pii.email.density') {
      emailSignals.push({ idx: i, signal });
    } else if (signal.id === 'pii.phone' || signal.id === 'pii.phone.density') {
      phoneSignals.push({ idx: i, signal });
    }
  }

  // Check for email list
  const emailList = detectListInGroup(emailSignals);
  if (emailList.isDistinctList) {
    for (const { idx } of emailSignals) {
      indices.add(idx);
    }
    return { indices, listType: 'email_list' };
  }

  // Check for phone list
  const phoneList = detectListInGroup(phoneSignals);
  if (phoneList.isDistinctList) {
    for (const { idx } of phoneSignals) {
      indices.add(idx);
    }
    return { indices, listType: 'phone_list' };
  }

  return { indices, listType: undefined };
}

/**
 * Detect if a group of signals forms a "list" (many distinct values, bounded range).
 */
function detectListInGroup(
  group: { idx: number; signal: RiskSignal }[]
): { isDistinctList: boolean; distinctCount: number; range: number } {
  if (group.length < LIST_DISTINCT_THRESHOLD) {
    return { isDistinctList: false, distinctCount: 0, range: 0 };
  }

  // Count distinct match values
  const distinctMatches = new Set<string>();
  let minOffset = Infinity;
  let maxOffset = -Infinity;

  for (const { signal } of group) {
    const matchValue = signal.match ?? signal.id ?? 'unknown';
    distinctMatches.add(matchValue);

    if (signal.offset !== undefined) {
      minOffset = Math.min(minOffset, signal.offset);
      maxOffset = Math.max(maxOffset, signal.offset);
    }
  }

  const range = maxOffset - minOffset;
  const isDistinctList =
    distinctMatches.size >= LIST_DISTINCT_THRESHOLD &&
    (range <= LIST_RANGE_MAX_CHARS || !isFinite(range));

  return {
    isDistinctList,
    distinctCount: distinctMatches.size,
    range: isFinite(range) ? range : 0,
  };
}

// ============================================================================
// FINALITY ANCHOR (Anchor #3)
// ============================================================================

/**
 * Apply finality heuristics:
 * - Legal boilerplate alone → suppress
 * - Confidentiality marker + sensitive signals → keep/amplify
 */
function applyFinalityHeuristics(
  signals: RiskSignal[],
  allSignals?: RiskSignal[]
): { suppressIndices: Set<number>; amplifyIndices: Set<number>; reasons: Map<number, string> } {
  const suppressIndices = new Set<number>();
  const amplifyIndices = new Set<number>();
  const reasons = new Map<number, string>();

  // Check if document has universal/high-severity signals
  const signalsToCheck = allSignals ?? signals;
  const hasUniversalSignals = signalsToCheck.some(s => isUniversalAnchor(s.id));
  const hasHighSeverity = signalsToCheck.some(s => s.severity === 'high' || s.severity === 'critical');
  const hasSensitiveContent = hasUniversalSignals || hasHighSeverity;

  // Find legal boilerplate signals
  const legalIndices: number[] = [];
  const markerIndices: number[] = [];

  for (let i = 0; i < signals.length; i++) {
    const signal = signals[i];
    const signalId = signal.id ?? 'unknown';

    if (LEGAL_BOILERPLATE_IDS.has(signalId)) {
      legalIndices.push(i);
    }
    if (CONFIDENTIALITY_MARKER_IDS.has(signalId)) {
      markerIndices.push(i);
    }
  }

  // Legal boilerplate alone → suppress
  if (legalIndices.length > 0 && !hasSensitiveContent) {
    for (const idx of legalIndices) {
      suppressIndices.add(idx);
      reasons.set(idx, RULE_IDS.FINALITY_LEGAL_SUPPRESS);
    }
  }

  // Confidentiality markers with sensitive content → keep (don't suppress)
  if (markerIndices.length > 0 && hasSensitiveContent) {
    for (const idx of markerIndices) {
      amplifyIndices.add(idx);
      reasons.set(idx, RULE_IDS.FINALITY_MARKER_KEEP);
    }
  }

  // Confidentiality markers alone → suppress (contextual by default)
  if (markerIndices.length > 0 && !hasSensitiveContent) {
    for (const idx of markerIndices) {
      if (!amplifyIndices.has(idx)) {
        suppressIndices.add(idx);
        reasons.set(idx, RULE_IDS.FINALITY_LEGAL_SUPPRESS);
      }
    }
  }

  return { suppressIndices, amplifyIndices, reasons };
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

/**
 * Apply human heuristic anchors to signals.
 *
 * This is the main entry point for the heuristics module.
 * Should be called after calibration, before severity aggregation.
 *
 * @param input - Input containing signals, locale, and context
 * @returns HeuristicResult with filtered signals and audit trail
 *
 * @example
 * const result = applyHumanHeuristics({
 *   signals: drivingSignals,
 *   locale: { locale: 'US' },
 *   documentLength: 10000,
 * });
 */
export function applyHumanHeuristics(input: HeuristicInput): HeuristicResult {
  const { signals, locale, destination, documentLength, allSignals } = input;

  const audit: AuditEntry[] = [];
  const suppressed: RiskSignal[] = [];
  const stats: HeuristicStats = {
    inputCount: signals.length,
    outputCount: 0,
    suppressedCount: 0,
    promotedCount: 0,
    proximityPromotions: 0,
    zoneSuppressed: 0,
    listPromotions: 0,
    finalitySuppressed: 0,
  };

  if (!signals || signals.length === 0) {
    return { signals: [], suppressed: [], audit, stats };
  }

  // Track which signals to suppress (indices)
  const suppressedIndices = new Set<number>();
  // Track which signals were promoted (for audit)
  const promotedIndices = new Set<number>();

  // Check if document has universal anchors
  const signalsWithAll = allSignals ?? signals;
  const hasUniversalAnchors = signalsWithAll.some(s => isUniversalAnchor(s.id));

  // =========================================================================
  // ANCHOR #1: PROXIMITY
  // =========================================================================
  const proximityPromotions = findProximityPromotions(signals, allSignals);

  if (proximityPromotions.size > 0) {
    for (const [idx, anchorId] of proximityPromotions) {
      promotedIndices.add(idx);
      stats.proximityPromotions++;
    }

    audit.push({
      ruleId: RULE_IDS.PROXIMITY_PROMOTION,
      reason: `${proximityPromotions.size} contextual signals promoted by proximity to universal anchors`,
      affectedSignalIds: Array.from(proximityPromotions.keys()).map(idx => signals[idx].id ?? 'unknown'),
      context: { anchorCount: hasUniversalAnchors ? 'present' : 'none' },
    });
  }

  // =========================================================================
  // ANCHOR #2: ZONE (Header/Footer/Metadata)
  // =========================================================================
  const zoneSuppression = findZoneSuppression(signals, documentLength, hasUniversalAnchors);

  // Don't suppress if promoted by proximity
  for (const idx of zoneSuppression.indices) {
    if (!promotedIndices.has(idx)) {
      suppressedIndices.add(idx);
      stats.zoneSuppressed++;
    }
  }

  // Audit zone suppressions by type
  const headerSuppressed = Array.from(zoneSuppression.reasons.entries())
    .filter(([idx, rule]) => rule === RULE_IDS.ZONE_HEADER_SUPPRESS && suppressedIndices.has(idx));
  const footerSuppressed = Array.from(zoneSuppression.reasons.entries())
    .filter(([idx, rule]) => rule === RULE_IDS.ZONE_FOOTER_SUPPRESS && suppressedIndices.has(idx));
  const metadataSuppressed = Array.from(zoneSuppression.reasons.entries())
    .filter(([idx, rule]) => rule === RULE_IDS.ZONE_METADATA_SUPPRESS && suppressedIndices.has(idx));

  if (headerSuppressed.length > 0) {
    audit.push({
      ruleId: RULE_IDS.ZONE_HEADER_SUPPRESS,
      reason: `${headerSuppressed.length} signals suppressed (header zone, first ${DOC_START_WINDOW_CHARS} chars)`,
      affectedSignalIds: headerSuppressed.map(([idx]) => signals[idx].id ?? 'unknown'),
    });
  }

  if (footerSuppressed.length > 0) {
    audit.push({
      ruleId: RULE_IDS.ZONE_FOOTER_SUPPRESS,
      reason: `${footerSuppressed.length} signals suppressed (footer zone, last ${DOC_END_WINDOW_CHARS} chars)`,
      affectedSignalIds: footerSuppressed.map(([idx]) => signals[idx].id ?? 'unknown'),
    });
  }

  if (metadataSuppressed.length > 0) {
    audit.push({
      ruleId: RULE_IDS.ZONE_METADATA_SUPPRESS,
      reason: `${metadataSuppressed.length} metadata signals suppressed (no universal anchors)`,
      affectedSignalIds: metadataSuppressed.map(([idx]) => signals[idx].id ?? 'unknown'),
    });
  }

  // =========================================================================
  // ANCHOR #2 (cont.): LIST DETECTION
  // =========================================================================
  const listPromotions = findListPromotions(signals);

  if (listPromotions.indices.size > 0 && listPromotions.listType) {
    // Un-suppress signals that form a list
    for (const idx of listPromotions.indices) {
      if (suppressedIndices.has(idx)) {
        suppressedIndices.delete(idx);
        stats.zoneSuppressed--;
      }
      promotedIndices.add(idx);
      stats.listPromotions++;
    }

    audit.push({
      ruleId: RULE_IDS.LIST_PROMOTION,
      reason: `${listPromotions.indices.size} signals promoted as ${listPromotions.listType} (${LIST_DISTINCT_THRESHOLD}+ distinct values)`,
      affectedSignalIds: Array.from(listPromotions.indices).map(idx => signals[idx].id ?? 'unknown'),
      context: { listType: listPromotions.listType },
    });
  }

  // =========================================================================
  // ANCHOR #2 (cont.): ZONE BOILERPLATE
  // =========================================================================
  const boilerplate = findZoneBoilerplate(signals);

  for (const idx of boilerplate.indices) {
    // Don't suppress if promoted by proximity or list
    if (!promotedIndices.has(idx) && !suppressedIndices.has(idx)) {
      suppressedIndices.add(idx);
      stats.zoneSuppressed++;
    }
  }

  if (boilerplate.indices.size > 0) {
    const actualSuppressed = Array.from(boilerplate.indices).filter(idx => suppressedIndices.has(idx));
    if (actualSuppressed.length > 0) {
      audit.push({
        ruleId: RULE_IDS.ZONE_BOILERPLATE_SUPPRESS,
        reason: `${actualSuppressed.length} signals suppressed as zone boilerplate (${ZONE_BOILERPLATE_THRESHOLD}+ repetitions)`,
        affectedSignalIds: actualSuppressed.map(idx => signals[idx].id ?? 'unknown'),
      });
    }
  }

  // =========================================================================
  // ANCHOR #3: FINALITY
  // =========================================================================
  const finality = applyFinalityHeuristics(signals, allSignals);

  for (const idx of finality.suppressIndices) {
    // Don't suppress if promoted
    if (!promotedIndices.has(idx)) {
      suppressedIndices.add(idx);
      stats.finalitySuppressed++;
    }
  }

  // Audit finality decisions
  const legalSuppressed = Array.from(finality.suppressIndices)
    .filter(idx => finality.reasons.get(idx) === RULE_IDS.FINALITY_LEGAL_SUPPRESS && suppressedIndices.has(idx));

  if (legalSuppressed.length > 0) {
    audit.push({
      ruleId: RULE_IDS.FINALITY_LEGAL_SUPPRESS,
      reason: `${legalSuppressed.length} legal/marker signals suppressed (no sensitive content in document)`,
      affectedSignalIds: legalSuppressed.map(idx => signals[idx].id ?? 'unknown'),
    });
  }

  const markerKept = Array.from(finality.amplifyIndices);
  if (markerKept.length > 0) {
    audit.push({
      ruleId: RULE_IDS.FINALITY_MARKER_KEEP,
      reason: `${markerKept.length} confidentiality markers kept (sensitive content present)`,
      affectedSignalIds: markerKept.map(idx => signals[idx].id ?? 'unknown'),
    });
  }

  // =========================================================================
  // BUILD OUTPUT
  // =========================================================================
  const outputSignals: RiskSignal[] = [];

  for (let i = 0; i < signals.length; i++) {
    if (suppressedIndices.has(i)) {
      suppressed.push(signals[i]);
    } else {
      outputSignals.push(signals[i]);
    }
  }

  stats.outputCount = outputSignals.length;
  stats.suppressedCount = suppressed.length;
  stats.promotedCount = promotedIndices.size;

  // Dev-mode logging
  if (DEBUG_HEURISTICS) {
    console.log(`[Ai Notice][HHA] Input: ${stats.inputCount} signals`);
    console.log(`[Ai Notice][HHA] Output: ${stats.outputCount} signals`);
    console.log(`[Ai Notice][HHA] Suppressed: ${stats.suppressedCount}`);
    console.log(`[Ai Notice][HHA] Promoted: ${stats.promotedCount}`);
    for (const entry of audit) {
      console.log(`[Ai Notice][HHA] ${entry.ruleId}: ${entry.reason}`);
    }
  }

  return { signals: outputSignals, suppressed, audit, stats };
}

// ============================================================================
// CONVENIENCE EXPORTS
// ============================================================================

/**
 * Check if human heuristics should be applied.
 * Can be used as a feature flag.
 */
export function shouldApplyHeuristics(): boolean {
  // Always enabled in this implementation
  // Could be made configurable via constants or policy
  return true;
}

/**
 * Get the proximity window configuration.
 */
export function getProximityWindow(): number {
  return PROXIMITY_WINDOW_CHARS;
}

/**
 * Get the zone configuration.
 */
export function getZoneConfig(): { start: number; end: number } {
  return {
    start: DOC_START_WINDOW_CHARS,
    end: DOC_END_WINDOW_CHARS,
  };
}

/**
 * Get the list detection configuration.
 */
export function getListConfig(): { threshold: number; maxRange: number } {
  return {
    threshold: LIST_DISTINCT_THRESHOLD,
    maxRange: LIST_RANGE_MAX_CHARS,
  };
}
