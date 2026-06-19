/**
 * AgentGuard Severity Aggregation (Policy Judge)
 *
 * Deterministic, enterprise-safe severity aggregation for multi-signal assessments.
 * This is the FINAL AUTHORITY for overall severity determination.
 *
 * Design principles:
 * - Deterministic: Same inputs → same output (no ordering dependence)
 * - Auditor-obvious: Rules can be explained in one paragraph
 * - Explainable: Returns driving signals, not just a severity level
 * - No averaging, weighting, or voting - simple max-wins rule
 *
 * Rules (mandatory, no exceptions):
 * 1. If ANY signal is CRITICAL → overall = CRITICAL
 * 2. Else if ANY signal is HIGH → overall = HIGH
 * 3. Else if ANY signal is MEDIUM → overall = MEDIUM
 * 4. Else if signals exist → LOW
 * 5. Else (empty list) → NONE (safe)
 *
 * @see ADR-035: Deterministic Severity Aggregation
 * @see AG-PROMPT-035
 */

import type { RiskSignal, Severity, SignalSource } from '../types/riskSignal';
import type { ArchetypeMatch } from './documentArchetypes';
import {
  ARCHETYPE_CONTRACTS,
  SIGNAL_GROUP_MEMBERS,
  SIGNAL_TO_GROUPS,
  SEVERITY_INDEX as CONTRACT_SEVERITY_INDEX,
  IBAN_CORROBORATION_RULES,
  type SeverityLevel as ContractSeverityLevel,
  type SignalGroup,
  type ArchetypeRiskContract,
  type AnchorRule,
} from './archetypeRiskContractV2';

// ============================================================================
// TYPES
// ============================================================================

/**
 * Severity level including 'none' for safe/empty state
 *
 * Extends the canonical Severity with 'none' for empty signal lists.
 * This makes it explicit when no signals are present vs having only low signals.
 */
export type SeverityLevel = Severity | 'none';

/**
 * Result of severity aggregation
 *
 * Provides full explainability for audit and debugging:
 * - severity: The final aggregated severity level
 * - drivingSignalIds: Only the signals that drove the final severity (not all signals)
 * - drivingSources: Unique sources (content/metadata/filename) of driving signals
 * - signalCount: Total signal count for reference
 */
export interface AggregatedSeverityResult {
  /** Final aggregated severity level */
  severity: SeverityLevel;

  /**
   * Canonical IDs of signals responsible for the final severity.
   * Only includes signals AT the final severity level (not lower).
   * Sorted alphabetically for deterministic output.
   * Falls back to description-based key if id is not set.
   */
  drivingSignalIds: string[];

  /**
   * Unique sources where driving signals were found.
   * Sorted for deterministic output.
   */
  drivingSources: SignalSource[];

  /** Total number of signals in the assessment */
  signalCount: number;
}

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * Severity ordering from lowest to highest.
 * This defines the strict hierarchy for aggregation.
 */
const SEVERITY_ORDER: readonly Severity[] = ['low', 'medium', 'high', 'critical'] as const;

/**
 * Map severity to numeric index for comparison.
 * Higher index = higher severity.
 */
const SEVERITY_INDEX: Record<Severity, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

// ============================================================================
// CORE AGGREGATION
// ============================================================================

/**
 * Get a stable identifier for a signal.
 *
 * Uses canonical id if available, otherwise generates a deterministic key
 * from signal properties.
 */
function getSignalIdentifier(signal: RiskSignal): string {
  if (signal.id) {
    return signal.id;
  }
  // Fallback: generate key from type and description
  const normalizedDesc = signal.description
    .toLowerCase()
    .replace(/\s+/g, '_')
    .replace(/[^a-z0-9_]/g, '')
    .slice(0, 50);
  return `${signal.type}:${normalizedDesc}`;
}

/**
 * Aggregate severity from multiple risk signals.
 *
 * This is the FINAL AUTHORITY for severity determination.
 * The rules are simple and auditor-obvious:
 *
 * 1. CRITICAL wins: If any signal is CRITICAL, overall is CRITICAL
 * 2. HIGH next: If any signal is HIGH (and none CRITICAL), overall is HIGH
 * 3. MEDIUM next: If any signal is MEDIUM, overall is MEDIUM
 * 4. LOW default: If signals exist but none above, overall is LOW
 * 5. NONE safe: If no signals, overall is NONE (safe)
 *
 * The returned drivingSignalIds contain ONLY the signals at the winning
 * severity level. Lower-severity signals are excluded from drivers.
 *
 * @param signals - Array of risk signals from the assessment
 * @returns AggregatedSeverityResult with severity and driving signals
 *
 * @example
 * // Single critical signal drives result
 * aggregateSeverity([criticalSignal, lowSignal])
 * // → { severity: 'critical', drivingSignalIds: [criticalSignal.id], ... }
 *
 * @example
 * // Empty list is safe
 * aggregateSeverity([])
 * // → { severity: 'none', drivingSignalIds: [], ... }
 */
export function aggregateSeverity(signals: RiskSignal[]): AggregatedSeverityResult {
  // Edge case: empty signal list → safe/none
  if (!signals || signals.length === 0) {
    return {
      severity: 'none',
      drivingSignalIds: [],
      drivingSources: [],
      signalCount: 0,
    };
  }

  // Step 1: Find the highest severity present
  let highestSeverity: Severity = 'low';
  for (const signal of signals) {
    if (SEVERITY_INDEX[signal.severity] > SEVERITY_INDEX[highestSeverity]) {
      highestSeverity = signal.severity;
    }
    // Early exit: can't go higher than critical
    if (highestSeverity === 'critical') {
      break;
    }
  }

  // Step 2: Collect all signals at the highest severity level (drivers)
  const drivingSignals = signals.filter(s => s.severity === highestSeverity);

  // Step 3: Extract unique, sorted signal IDs from drivers
  // AG-MONSTER-ENGINE-VETTED-SPEC-AND-BACKLOG-001: SG-01 — Confidence-aware tie-breaker.
  // When severity ties, sort by highest confidence first (most likely true positive dominates).
  // Signals without confidence get a default of 0.50 (neutral).
  const confidenceBySignalId = new Map<string, number>();
  for (const s of drivingSignals) {
    const id = getSignalIdentifier(s);
    const conf = s.confidence ?? 0.50;
    const existing = confidenceBySignalId.get(id);
    if (existing === undefined || conf > existing) {
      confidenceBySignalId.set(id, conf);
    }
  }
  const drivingSignalIds = Array.from(
    new Set(drivingSignals.map(getSignalIdentifier))
  ).sort((a, b) => {
    const confA = confidenceBySignalId.get(a) ?? 0.50;
    const confB = confidenceBySignalId.get(b) ?? 0.50;
    if (confA !== confB) return confB - confA; // Higher confidence first
    return a.localeCompare(b); // Alphabetical fallback for determinism
  });

  // Step 4: Extract unique, sorted sources from drivers
  const drivingSources = Array.from(
    new Set(drivingSignals.map(s => s.source))
  ).sort() as SignalSource[];

  return {
    severity: highestSeverity,
    drivingSignalIds,
    drivingSources,
    signalCount: signals.length,
  };
}

// ============================================================================
// UTILITIES
// ============================================================================

/**
 * Check if a severity level is considered "blocking" (requires user attention).
 *
 * Blocking severities: HIGH, CRITICAL
 * Non-blocking: LOW, MEDIUM, NONE
 *
 * This is a convenience function for UI decisions.
 * @param severity - The severity level to check
 */
export function isBlockingSeverity(severity: SeverityLevel): boolean {
  return severity === 'high' || severity === 'critical';
}

/**
 * Check if a severity level requires immediate attention.
 *
 * Only CRITICAL requires immediate attention.
 * HIGH is blocking but not necessarily immediate.
 *
 * @param severity - The severity level to check
 */
export function isCriticalSeverity(severity: SeverityLevel): boolean {
  return severity === 'critical';
}

/**
 * Compare two severity levels.
 *
 * @returns negative if a < b, 0 if equal, positive if a > b
 */
export function compareSeverity(a: SeverityLevel, b: SeverityLevel): number {
  const aIndex = a === 'none' ? -1 : SEVERITY_INDEX[a];
  const bIndex = b === 'none' ? -1 : SEVERITY_INDEX[b];
  return aIndex - bIndex;
}

/**
 * Get human-readable label for severity level.
 * This is data, not UI copy - use for logging/debugging only.
 */
export function getSeverityLabel(severity: SeverityLevel): string {
  switch (severity) {
    case 'none':
      return 'Safe';
    case 'low':
      return 'Low';
    case 'medium':
      return 'Medium';
    case 'high':
      return 'High';
    case 'critical':
      return 'Critical';
  }
}

// ============================================================================
// EXPORTS
// ============================================================================

export { SEVERITY_ORDER };

// ============================================================================
// ARCHETYPE RISK CONTRACT V2 - SEVERITY CALIBRATION
// ============================================================================

/**
 * Result of archetype-based severity calibration.
 */
export interface ArchetypeCalibrationResult {
  /** Final calibrated severity */
  calibratedSeverity: SeverityLevel;
  /** Whether calibration was applied */
  calibrationApplied: boolean;
  /** Archetype that drove the calibration (if any) */
  drivingArchetype: string | null;
  /** ALL archetypes that matched (for audit trail, not just the winner) */
  allMatchedArchetypes: string[];
  /** Anchor rules that fired (if any) */
  firedAnchors: string[];
  /** Original severity before calibration */
  originalSeverity: SeverityLevel;
  /** Calibration audit trail */
  auditTrail: string[];
  /** Whether IBAN corroboration was applied */
  ibanCorroborationApplied?: boolean;
}

/**
 * Check if any signals belong to a specific signal group.
 *
 * @param signals - Array of signals to check
 * @param group - Signal group to check membership
 * @returns true if any signal belongs to the group
 */
function hasSignalInGroup(signals: RiskSignal[], group: SignalGroup): boolean {
  const groupMembers = SIGNAL_GROUP_MEMBERS[group];
  return signals.some(s => s.id && groupMembers.includes(s.id));
}

/**
 * Get all signal groups present in the signal set.
 *
 * @param signals - Array of signals
 * @returns Set of signal groups that have at least one member present
 */
function getPresentSignalGroups(signals: RiskSignal[]): Set<SignalGroup> {
  const groups = new Set<SignalGroup>();
  for (const signal of signals) {
    if (signal.id) {
      const signalGroups = SIGNAL_TO_GROUPS.get(signal.id);
      if (signalGroups) {
        for (const g of signalGroups) {
          groups.add(g);
        }
      }
    }
  }
  return groups;
}

/**
 * Check if an anchor rule fires given the present signal groups.
 *
 * @param anchor - The anchor rule to check
 * @param presentGroups - Set of signal groups present in the document
 * @returns true if the anchor rule fires
 */
function anchorFires(anchor: AnchorRule, presentGroups: Set<SignalGroup>): boolean {
  if (anchor.requireAll) {
    // AND logic: all groups must be present
    return anchor.whenPresent.every(g => presentGroups.has(g));
  } else {
    // OR logic: any group present triggers
    return anchor.whenPresent.some(g => presentGroups.has(g));
  }
}

/**
 * Convert contract severity level to aggregation severity level.
 */
function contractToAggregateSeverity(level: ContractSeverityLevel): SeverityLevel {
  return level as SeverityLevel;
}

/**
 * Check if IBAN should force HIGH severity based on personal context.
 *
 * IBAN alone does NOT force HIGH. Requires:
 * - Personal context (identity_basic or identity_strong present), AND
 * - No strong B2B markers
 *
 * @param signals - Array of signals
 * @param presentGroups - Set of signal groups present
 * @param normalizedText - Optional text for B2B marker detection
 * @returns true if IBAN should force HIGH
 */
function shouldIbanForceHigh(
  signals: RiskSignal[],
  presentGroups: Set<SignalGroup>,
  normalizedText?: string
): { shouldForce: boolean; reason: string } {
  // Check if IBAN is present
  const hasIban = signals.some(s => s.id === 'global-iban');
  if (!hasIban) {
    return { shouldForce: false, reason: 'No IBAN present' };
  }

  // Check for personal context
  const hasPersonalContext = IBAN_CORROBORATION_RULES.personalContextGroups.some(
    group => presentGroups.has(group)
  );

  if (!hasPersonalContext) {
    return { shouldForce: false, reason: 'IBAN present but no personal context (identity signals)' };
  }

  // Check for B2B markers (only if text provided)
  if (normalizedText) {
    for (const pattern of IBAN_CORROBORATION_RULES.b2bMarkerPatterns) {
      if (pattern.test(normalizedText)) {
        return {
          shouldForce: false,
          reason: `IBAN with personal context BUT B2B marker detected: ${pattern.source}`,
        };
      }
    }
  }

  return {
    shouldForce: true,
    reason: 'IBAN + personal context (no B2B markers) → HIGH',
  };
}

/**
 * Apply archetype risk contract v2 calibration.
 *
 * This function applies the frozen risk contract to calibrate severity based on:
 * 1. Archetype baseline severity
 * 2. Mobility rules (can severity be lowered?)
 * 3. Anchor rules (minimum severity floors when certain signals present)
 * 4. IBAN corroboration (IBAN alone does not force HIGH)
 *
 * INVARIANTS:
 * - Signals are never removed or hidden
 * - Protected signals always remain in output
 * - Calibration can only RAISE or MAINTAIN severity, never lower below anchors
 * - Multiple archetypes → max severity (most conservative)
 *
 * @param signals - Array of detected signals
 * @param aggregatedSeverity - Severity from aggregateSeverity()
 * @param archetypeMatches - Detected archetypes (optional)
 * @param normalizedText - Optional text for B2B marker detection
 * @returns Calibration result with final severity and audit trail
 */
export function applyArchetypeRiskContract(
  signals: RiskSignal[],
  aggregatedSeverity: SeverityLevel,
  archetypeMatches?: ArchetypeMatch[],
  normalizedText?: string
): ArchetypeCalibrationResult {
  const auditTrail: string[] = [];
  const firedAnchors: string[] = [];

  // Get present signal groups for anchor evaluation
  const presentGroups = getPresentSignalGroups(signals);

  // No archetypes detected - pure signal-driven assessment
  if (!archetypeMatches || archetypeMatches.length === 0) {
    auditTrail.push('No archetype matched — pure signal-driven assessment');
    auditTrail.push(`Present signal groups: ${Array.from(presentGroups).join(', ') || 'none'}`);

    // Check IBAN corroboration even without archetype
    const ibanCheck = shouldIbanForceHigh(signals, presentGroups, normalizedText);
    let finalSeverity = aggregatedSeverity;
    let ibanCorroborationApplied = false;

    if (ibanCheck.shouldForce && CONTRACT_SEVERITY_INDEX[aggregatedSeverity] < CONTRACT_SEVERITY_INDEX['high']) {
      finalSeverity = 'high';
      ibanCorroborationApplied = true;
      auditTrail.push(`IBAN corroboration: ${ibanCheck.reason}`);
    } else if (signals.some(s => s.id === 'global-iban')) {
      auditTrail.push(`IBAN corroboration: ${ibanCheck.reason}`);
    }

    return {
      calibratedSeverity: finalSeverity,
      calibrationApplied: finalSeverity !== aggregatedSeverity,
      drivingArchetype: null,
      allMatchedArchetypes: [],
      firedAnchors: [],
      originalSeverity: aggregatedSeverity,
      auditTrail,
      ibanCorroborationApplied,
    };
  }

  // Record ALL matched archetypes for audit
  const allMatchedArchetypes = archetypeMatches.map(m => m.archetypeId);
  auditTrail.push(`Matched archetypes: ${allMatchedArchetypes.join(', ')}`);
  auditTrail.push(`Present signal groups: ${Array.from(presentGroups).join(', ') || 'none'}`);

  // Find the archetype contract that produces the highest calibrated severity
  let highestCalibratedSeverity: SeverityLevel = aggregatedSeverity;
  let drivingArchetype: string | null = null;

  for (const match of archetypeMatches) {
    const contract = ARCHETYPE_CONTRACTS[match.archetypeId];
    if (!contract) {
      auditTrail.push(`No contract found for archetype: ${match.archetypeId}`);
      continue;
    }

    let archetypeSeverity: SeverityLevel = aggregatedSeverity;
    const archetypeFiredAnchors: string[] = [];

    // Step 1: Apply baseline based on mobility
    const baselineSeverity = contractToAggregateSeverity(contract.baselineSeverity);
    const baselineIndex = CONTRACT_SEVERITY_INDEX[baselineSeverity];
    const currentIndex = CONTRACT_SEVERITY_INDEX[aggregatedSeverity];

    switch (contract.mobility) {
      case 'static':
        // Static: baseline IS the minimum, cannot go below
        if (currentIndex < baselineIndex) {
          archetypeSeverity = baselineSeverity;
          auditTrail.push(`${contract.archetypeId}: static mobility enforces baseline ${baselineSeverity}`);
        }
        break;

      case 'upward':
        // Upward: baseline is a floor, can only go up
        if (currentIndex < baselineIndex) {
          archetypeSeverity = baselineSeverity;
          auditTrail.push(`${contract.archetypeId}: upward mobility floor applied: ${baselineSeverity}`);
        }
        break;

      case 'downward':
      case 'downward_noop':
        // Downward/downward_noop: de-escalation NOT IMPLEMENTED (safety)
        // Treated as neutral until proven safe and test-covered
        auditTrail.push(`${contract.archetypeId}: downward mobility is NO-OP (safety)`);
        break;

      case 'neutral':
        // Neutral: baseline is informational only
        auditTrail.push(`${contract.archetypeId}: neutral mobility, baseline informational`);
        break;
    }

    // Step 2: Apply anchor rules (severity floors)
    for (const anchor of contract.anchors) {
      if (anchorFires(anchor, presentGroups)) {
        const anchorSeverity = contractToAggregateSeverity(anchor.minSeverity);
        const anchorIndex = CONTRACT_SEVERITY_INDEX[anchorSeverity];
        const currentArchetypeIndex = CONTRACT_SEVERITY_INDEX[archetypeSeverity];

        if (anchorIndex > currentArchetypeIndex) {
          archetypeSeverity = anchorSeverity;
          const anchorDesc = `${anchor.whenPresent.join(anchor.requireAll ? ' AND ' : ' OR ')} → ${anchor.minSeverity}`;
          archetypeFiredAnchors.push(anchorDesc);
          auditTrail.push(`${contract.archetypeId}: anchor fired: ${anchorDesc}`);
        }
      }
    }

    // Check if this archetype produces highest severity
    const archetypeIndex = CONTRACT_SEVERITY_INDEX[archetypeSeverity];
    const highestIndex = CONTRACT_SEVERITY_INDEX[highestCalibratedSeverity];

    if (archetypeIndex > highestIndex) {
      highestCalibratedSeverity = archetypeSeverity;
      drivingArchetype = match.archetypeId;
      firedAnchors.push(...archetypeFiredAnchors);
    }
  }

  // Step 3: IBAN corroboration check (only if not already at HIGH or CRITICAL)
  let ibanCorroborationApplied = false;
  if (CONTRACT_SEVERITY_INDEX[highestCalibratedSeverity] < CONTRACT_SEVERITY_INDEX['high']) {
    const ibanCheck = shouldIbanForceHigh(signals, presentGroups, normalizedText);
    if (ibanCheck.shouldForce) {
      highestCalibratedSeverity = 'high';
      ibanCorroborationApplied = true;
      auditTrail.push(`IBAN corroboration: ${ibanCheck.reason}`);
    } else if (signals.some(s => s.id === 'global-iban')) {
      auditTrail.push(`IBAN corroboration: ${ibanCheck.reason}`);
    }
  }

  const calibrationApplied = highestCalibratedSeverity !== aggregatedSeverity;
  if (calibrationApplied) {
    auditTrail.push(`Final calibration: ${aggregatedSeverity} → ${highestCalibratedSeverity} (driven by ${drivingArchetype || 'IBAN corroboration'})`);
  } else {
    auditTrail.push(`No calibration needed; severity remains ${aggregatedSeverity}`);
  }

  return {
    calibratedSeverity: highestCalibratedSeverity,
    calibrationApplied,
    drivingArchetype,
    allMatchedArchetypes,
    firedAnchors,
    originalSeverity: aggregatedSeverity,
    auditTrail,
    ibanCorroborationApplied,
  };
}

/**
 * Aggregate severity with archetype risk contract calibration.
 *
 * This is a convenience function that combines aggregateSeverity() with
 * archetype risk contract calibration in one call.
 *
 * @param signals - Array of risk signals
 * @param archetypeMatches - Detected archetypes (optional)
 * @param normalizedText - Optional text for B2B marker detection (IBAN corroboration)
 * @returns Aggregated result with calibration applied
 */
export function aggregateSeverityWithContract(
  signals: RiskSignal[],
  archetypeMatches?: ArchetypeMatch[],
  normalizedText?: string
): AggregatedSeverityResult & { calibration: ArchetypeCalibrationResult } {
  // First, get raw aggregated severity
  const aggregated = aggregateSeverity(signals);

  // Then, apply archetype risk contract calibration
  const calibration = applyArchetypeRiskContract(signals, aggregated.severity, archetypeMatches, normalizedText);

  return {
    ...aggregated,
    severity: calibration.calibratedSeverity,
    calibration,
  };
}
