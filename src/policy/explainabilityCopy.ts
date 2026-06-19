/**
 * AgentGuard Explainability Copy Resolver
 *
 * Provides human-authored copy for RiskExplanation enrichment.
 * Copy is versioned, static, and loaded at build time.
 *
 * Privacy: No IO, no browser APIs, no telemetry.
 * UI-agnostic: Copy is data only, not rendering.
 *
 * @see ADR-015: Risk Explanation Model
 */

// Static import of versioned copy library
import copyLibrary from '../../docs/explainability/copy-library-v0.json';

// ============================================================================
// TYPES
// ============================================================================

/**
 * A single explainability copy entry
 */
export interface ExplainabilityCopyEntry {
  /** Stable ID matching signal category */
  id: string;

  /** Human-readable title */
  title: string;

  /** Plain language explanation of why this matters */
  why: string;

  /** Actionable guidance for the user */
  suggestedAction: string;
}

/**
 * Copy library structure
 */
interface CopyLibrary {
  version: string;
  description: string;
  entries: Record<string, ExplainabilityCopyEntry>;
}

// ============================================================================
// RESOLVER
// ============================================================================

// Type assertion for imported JSON
const library = copyLibrary as CopyLibrary;

/**
 * Get explainability copy for a given signal ID
 *
 * @param id - Signal category ID (e.g., "secret.api_key", "pii.phone.density")
 * @returns ExplainabilityCopyEntry if found, null otherwise
 */
export function getExplainabilityCopy(id: string): ExplainabilityCopyEntry | null {
  const entry = library.entries[id];
  return entry ?? null;
}

/**
 * Get the copy library version
 */
export function getCopyLibraryVersion(): string {
  return library.version;
}

/**
 * Get all available copy entry IDs
 * Useful for testing and validation
 */
export function getAvailableCopyIds(): string[] {
  return Object.keys(library.entries);
}
