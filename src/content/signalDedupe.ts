/**
 * AgentGuard Signal Deduplication (AG-PROMPT-031, AG-PROMPT-032)
 *
 * Overlap-safe deduplication for signals produced by chunked text scanning.
 * Uses canonical IDs and absolute offsets to ensure one real-world artifact
 * produces exactly one logical signal, even if detected in overlapping chunks.
 *
 * The scheduler provides overlap for correctness; this module owns signal
 * identity and deduplication.
 *
 * @see ADR-017: Non-blocking Scan Scheduler (Addendum: Overlap-Safe Dedupe)
 */

import type { RiskSignal } from './metadataExtractor';

// ============================================================================
// CONFIGURATION
// ============================================================================

/** Enable debug logging (counts only, no content) */
const DEBUG_DEDUPE = false;

// ============================================================================
// STABLE ID DERIVATION
// ============================================================================

/**
 * Get a stable ID for a signal.
 *
 * Priority:
 * 1. signal.id (canonical pattern ID, preferred)
 * 2. Fallback: signal.type (last resort for legacy signals without ID)
 *
 * IMPORTANT: Do NOT use description in the stable ID as it may vary.
 */
function getStableId(signal: RiskSignal): string {
  // Prefer canonical ID (AG-PROMPT-032)
  if (signal.id) {
    return signal.id;
  }

  // Fallback to type (legacy signals without ID)
  return signal.type;
}

// ============================================================================
// DEDUPE KEY GENERATION
// ============================================================================

/**
 * Generate a stable deduplication key for a signal.
 *
 * Key format: `${stableId}:${absoluteOffset}:${source}`
 *
 * Where:
 * - stableId = signal.id (canonical) or signal.type (fallback)
 * - absoluteOffset = signal.offset (if positional) or 'none' (density signals)
 * - source = signal.source
 *
 * This ensures:
 * - Same pattern at same position = same key (dedupe works)
 * - Same pattern at different positions = different keys (no false dedupe)
 * - No dependency on volatile description text
 */
function generateDedupeKey(signal: RiskSignal): string {
  const stableId = getStableId(signal);
  const source = signal.source || 'content';

  // Positional signals use absolute offset
  if (signal.offset !== undefined) {
    return `${stableId}:${signal.offset}:${source}`;
  }

  // Non-positional signals (density-based) use 'none' for offset
  return `${stableId}:none:${source}`;
}

// ============================================================================
// DEDUPLICATION
// ============================================================================

/**
 * Deduplicate signals using overlap-safe keys.
 *
 * For signals with the same key:
 * - Keep the first occurrence (deterministic)
 * - This ensures idempotency: running twice yields same result
 *
 * @param signals - Array of signals (may contain duplicates from chunk overlap)
 * @returns Deduplicated array of signals
 */
export function deduplicateSignals(signals: RiskSignal[]): RiskSignal[] {
  const seen = new Map<string, RiskSignal>();

  for (const signal of signals) {
    const key = generateDedupeKey(signal);

    if (!seen.has(key)) {
      seen.set(key, signal);
    }
    // If key already exists, keep the first (deterministic)
  }

  const result = Array.from(seen.values());

  if (DEBUG_DEDUPE) {
    const duplicatesRemoved = signals.length - result.length;
    if (duplicatesRemoved > 0) {
      console.log(`[Ai Notice] SignalDedupe: removed ${duplicatesRemoved} duplicates (${signals.length} -> ${result.length})`);
    }
  }

  return result;
}

/**
 * Check if two signals are duplicates (same dedupe key).
 * Useful for testing.
 */
export function areDuplicates(a: RiskSignal, b: RiskSignal): boolean {
  return generateDedupeKey(a) === generateDedupeKey(b);
}

/**
 * Get the dedupe key for a signal (for testing/debugging).
 */
export function getDedupeKey(signal: RiskSignal): string {
  return generateDedupeKey(signal);
}
