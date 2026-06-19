/**
 * AgentGuard Canonical RiskSignal Type
 *
 * This is the SINGLE SOURCE OF TRUTH for RiskSignal shape and semantics.
 * All other RiskSignal interfaces in the codebase MUST be type aliases
 * or re-exports of this definition.
 *
 * @see AG-PROMPT-033B for centralization history
 */

// ============================================================================
// CORE TYPES
// ============================================================================

/** Signal type categories */
export type SignalType = 'pii' | 'confidential' | 'sensitive' | 'ip' | 'financial' | 'legal';

/** Signal severity levels */
export type Severity = 'low' | 'medium' | 'high' | 'critical';

/** Source of the signal detection */
export type SignalSource = 'content' | 'metadata' | 'filename';

// ============================================================================
// EVIDENCE TRACING (AG-PROMPT-031)
// ============================================================================

/**
 * AG-PROMPT-031: Evidence trace item for deterministic signal provenance.
 *
 * Captures exact matched substring and origin for each signal emission.
 * Only populated when AG_DEBUG_EVIDENCE flag is enabled.
 * Observability-only — no behavior changes.
 */
export interface EvidenceItem {
  /** Signal ID that produced this evidence */
  signal_id: string;
  /** Where this signal was produced */
  origin: {
    path: 'pack' | 'registry' | 'dictionary' | 'metadata' | 'filename' | 'legacy';
    producer: string;
    rule_id: string | null;
  };
  /** What was matched */
  match: {
    /** Matched text, truncated to 64 chars */
    matched_text: string;
    start_index: number | null;
    end_index: number | null;
    line_hint: string | null;
    /** Surrounding context, max 220 chars */
    context_window: string;
  };
  /** Where in the document */
  source: {
    location: 'CONTENT' | 'METADATA' | 'FILENAME' | 'OTHER';
    field: string | null;
  };
  timestamp_ms: number | null;
}

// ============================================================================
// CANONICAL RISKSIGNAL INTERFACE
// ============================================================================

/**
 * CANONICAL RiskSignal Interface
 *
 * Represents a detected risk signal from document analysis.
 * All fields are designed for:
 * - Stable deduplication (id + offset + source)
 * - Temporal tracking (detectedAt)
 * - UI rendering (description, detail, severity)
 *
 * Changes to this interface require updates to all consumers.
 */
export interface RiskSignal {
  /**
   * Canonical machine-readable ID (e.g., secret.api_key, pii.ssn)
   * Used for stable deduplication across chunked scanning.
   * @see AG-PROMPT-032
   */
  id?: string;

  /** Signal type category */
  type: SignalType;

  /** Human-readable description for UI display */
  description: string;

  /** Severity level determining UI treatment */
  severity: Severity;

  /** Additional detail for expanded view */
  detail?: string;

  /** Where the signal was detected */
  source: SignalSource;

  /**
   * Absolute character offset in original text.
   * Used with id+source for overlap-safe deduplication.
   * @see AG-PROMPT-031
   */
  offset?: number;

  /**
   * Normalized matched value for deduplication.
   * @see AG-PROMPT-031
   */
  match?: string;

  /**
   * Unix timestamp (epoch ms) when signal was detected.
   * Enables temporal ordering and audit trails.
   * @see AG-PROMPT-033B
   */
  detectedAt: number;

  /**
   * AG-PROMPT-031: Evidence trace for deterministic provenance.
   * Only populated when AG_DEBUG_EVIDENCE flag is enabled.
   */
  evidence?: EvidenceItem[];

  /**
   * AG-XLSX-HARDENING-PLAN-001: Gate & Boost detection confidence (0.0 – 1.0).
   * Set by checksum + proximity scoring for Nordic national IDs and IBAN.
   * Absent for signals that do not use Gate & Boost scoring.
   */
  confidence?: number;
}
