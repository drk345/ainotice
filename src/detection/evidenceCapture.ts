/**
 * AG-PROMPT-031: Evidence Capture Utilities
 *
 * Shared helpers for attaching deterministic evidence traces to signals.
 * Evidence is ONLY captured when AG_DEBUG_EVIDENCE is true.
 *
 * Privacy: matched_text is capped at 64 chars, context_window at 220 chars.
 * No raw document content is stored beyond these windows.
 */

import type { EvidenceItem } from '../types/riskSignal';

// ============================================================================
// FLAG
// ============================================================================

/**
 * Debug evidence capture flag.
 * Default: false. Set to true manually or via test harness.
 *
 * When false, all evidence functions are no-ops and return undefined.
 */
export let AG_DEBUG_EVIDENCE = false;

/** Enable/disable evidence capture (for test harness) */
export function setEvidenceFlag(enabled: boolean): void {
  AG_DEBUG_EVIDENCE = enabled;
}

// ============================================================================
// HELPERS
// ============================================================================

const MAX_MATCHED_TEXT = 64;
const MAX_CONTEXT_WINDOW = 220;
const CONTEXT_RADIUS = 80;

/**
 * Extract a context window around a match position.
 * Returns up to MAX_CONTEXT_WINDOW chars centered on the match.
 */
export function extractContextWindow(
  text: string,
  startIndex: number,
  matchLength: number
): string {
  const beforeStart = Math.max(0, startIndex - CONTEXT_RADIUS);
  const afterEnd = Math.min(text.length, startIndex + matchLength + CONTEXT_RADIUS);
  let window = text.slice(beforeStart, afterEnd);
  if (window.length > MAX_CONTEXT_WINDOW) {
    window = window.slice(0, MAX_CONTEXT_WINDOW);
  }
  // Replace newlines with spaces for readability
  return window.replace(/[\r\n]+/g, ' ');
}

/**
 * Create an EvidenceItem for a signal emission point.
 * Returns undefined if AG_DEBUG_EVIDENCE is false.
 */
export function createEvidence(opts: {
  signal_id: string;
  origin_path: EvidenceItem['origin']['path'];
  producer: string;
  rule_id: string | null;
  matched_text: string;
  start_index: number | null;
  end_index: number | null;
  full_text: string | null;
  location: EvidenceItem['source']['location'];
  field: string | null;
}): EvidenceItem | undefined {
  if (!AG_DEBUG_EVIDENCE) return undefined;

  // Truncate matched_text
  let matchedText = opts.matched_text;
  if (matchedText.length > MAX_MATCHED_TEXT) {
    matchedText = matchedText.slice(0, MAX_MATCHED_TEXT);
  }

  // Build context window
  let contextWindow = '';
  if (opts.full_text && opts.start_index !== null) {
    contextWindow = extractContextWindow(
      opts.full_text,
      opts.start_index,
      opts.matched_text.length
    );
  } else {
    contextWindow = matchedText;
  }

  // Line hint: extract the line containing the match
  let lineHint: string | null = null;
  if (opts.full_text && opts.start_index !== null) {
    const lineStart = opts.full_text.lastIndexOf('\n', opts.start_index) + 1;
    const lineEnd = opts.full_text.indexOf('\n', opts.start_index);
    const line = opts.full_text.slice(lineStart, lineEnd === -1 ? undefined : lineEnd);
    if (line.length <= 120) {
      lineHint = line;
    } else {
      lineHint = line.slice(0, 120);
    }
  }

  return {
    signal_id: opts.signal_id,
    origin: {
      path: opts.origin_path,
      producer: opts.producer,
      rule_id: opts.rule_id,
    },
    match: {
      matched_text: matchedText,
      start_index: opts.start_index,
      end_index: opts.end_index,
      line_hint: lineHint,
      context_window: contextWindow,
    },
    source: {
      location: opts.location,
      field: opts.field,
    },
    timestamp_ms: Date.now(),
  };
}
