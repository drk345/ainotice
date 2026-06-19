/**
 * AgentGuard Debug Diagnostics (AG-PROMPT-044)
 *
 * Centralized debug infrastructure for tracking signal flow through
 * extraction → detection → policy → UI pipeline.
 *
 * Privacy: Only logs lengths, hashes, counts, and small bounded snippets
 * (<= 80 chars) when explicitly enabled. NEVER logs full content.
 *
 * Debug mode can be enabled via:
 * 1. localStorage: localStorage.setItem('ainotice.debug', 'true')  (preferred)
 *    or legacy alias: localStorage.setItem('agentguard.debug', 'true')
 * 2. URL param: ?ag_debug=true
 * 3. Compile-time: DEBUG_DIAGNOSTICS constant below
 *
 * @see docs/DEBUGGING.md for usage instructions
 */

// ============================================================================
// DEBUG CONTRACT (AG-PROMPT-050)
// ============================================================================
//
// INTENT: These diagnostics are INTENTIONAL DEBUG SCAFFOLDING introduced in
// AG-PROMPT-044 to diagnose "nothing detected" pipeline issues. They proved
// essential in identifying AG-PROMPT-046 (text file detection bypass).
//
// TEMPORALITY: This scaffolding MAY BE REMOVED OR REDUCED after pipeline
// stabilization. It is not a permanent feature.
//
// GOVERNANCE RULES:
// 1. All diagnostics MUST be gated behind isDebugMode() — no exceptions.
// 2. No new diagnostics may be added without an explicit AG-PROMPT reference.
// 3. Diagnostics must NEVER log full document content — only lengths, hashes,
//    counts, and bounded snippets (≤80 chars).
// 4. No cloud, telemetry, remote logging, or external transmission.
// 5. Diagnostics must not change detection, policy, or UI behavior.
//
// DIAGNOSTIC INVENTORY (AG-PROMPT-044):
// - Boundary counters: [A] afterDetection, [B] afterPolicy, [C] afterDedup, [D] uiReceives
// - Extraction logs: logExtractionDiagnostics() — doc ID, method, text length, warnings
// - Detection entry: logDetectionInvocation() — doc ID, locale, text length
// - Detection result: debugLog('DetectionResult') — raw signal count by type
// - Pack loading: logPackLoadingDiagnostics() — pack count, IDs, locale routing
// - Canary detection: runCanaryDetection() — debug-only pattern "DETECTION_CANARY_123"
// - Debug summary: storeDebugSummary() — programmatic access for test scripts
//
// GATING VERIFICATION:
// - All log functions check isDebugMode() at entry — confirmed AG-PROMPT-050
// - runCanaryDetection() calls shouldRunCanaryDetection() which checks isDebugMode()
// - Callers in index.ts, metadataExtractor.ts, packRegistry.ts wrap calls in if(isDebugMode())
//
// ============================================================================

// ============================================================================
// CONFIGURATION
// ============================================================================

/** Compile-time debug flag (set to true for local development) */
const DEBUG_DIAGNOSTICS = false;

/** Maximum snippet length for bounded content logging */
const MAX_SNIPPET_LENGTH = 80;

/** Prefix for all diagnostic logs */
const LOG_PREFIX = '[AgentGuard:Diag]';

// ============================================================================
// DEBUG MODE DETECTION
// ============================================================================

/**
 * Check if debug mode is enabled.
 * Cached on first call for performance.
 */
let debugModeCache: boolean | null = null;

export function isDebugMode(): boolean {
  if (debugModeCache !== null) {
    return debugModeCache;
  }

  // 1. Compile-time constant (highest priority)
  if (DEBUG_DIAGNOSTICS) {
    debugModeCache = true;
    return true;
  }

  // 2. URL param
  try {
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('ag_debug') === 'true') {
      debugModeCache = true;
      return true;
    }
  } catch {
    // URL parsing failed (e.g., not in browser context)
  }

  // 3. localStorage (current key first, then legacy alias)
  try {
    if (localStorage.getItem('ainotice.debug') === 'true' ||
        localStorage.getItem('agentguard.debug') === 'true') {
      debugModeCache = true;
      return true;
    }
  } catch {
    // localStorage not available
  }

  debugModeCache = false;
  return false;
}

/**
 * Reset debug mode cache (for testing)
 */
export function resetDebugModeCache(): void {
  debugModeCache = null;
}

/**
 * Enable debug mode via localStorage
 */
export function enableDebugMode(): void {
  try {
    localStorage.setItem('ainotice.debug', 'true');
    debugModeCache = true;
    console.log(`${LOG_PREFIX} Debug mode ENABLED. Reload page for full effect.`);
  } catch {
    console.warn(`${LOG_PREFIX} Could not enable debug mode (localStorage unavailable)`);
  }
}

/**
 * Disable debug mode
 */
export function disableDebugMode(): void {
  try {
    localStorage.removeItem('ainotice.debug');
    localStorage.removeItem('agentguard.debug'); // legacy alias cleanup
    debugModeCache = false;
    console.log(`${LOG_PREFIX} Debug mode DISABLED.`);
  } catch {
    // Ignore
  }
}

// ============================================================================
// LOGGING UTILITIES
// ============================================================================

/**
 * Log a diagnostic message (only if debug mode is enabled)
 */
export function debugLog(category: string, message: string, data?: Record<string, unknown>): void {
  if (!isDebugMode()) return;

  const formattedData = data ? ` ${JSON.stringify(data)}` : '';
  console.log(`${LOG_PREFIX} [${category}] ${message}${formattedData}`);
}

/**
 * Log a warning in debug mode
 */
export function debugWarn(category: string, message: string, data?: Record<string, unknown>): void {
  if (!isDebugMode()) return;

  const formattedData = data ? ` ${JSON.stringify(data)}` : '';
  console.warn(`${LOG_PREFIX} [${category}] ${message}${formattedData}`);
}

/**
 * Create a bounded snippet of text (for safe logging)
 * Truncates to MAX_SNIPPET_LENGTH and replaces newlines
 */
export function boundedSnippet(text: string | undefined): string {
  if (!text) return '<empty>';
  const clean = text.replace(/[\n\r\t]/g, ' ').trim();
  if (clean.length <= MAX_SNIPPET_LENGTH) {
    return clean;
  }
  return clean.slice(0, MAX_SNIPPET_LENGTH - 3) + '...';
}

/**
 * Simple FNV-1a hash for content fingerprinting (not cryptographic)
 * Used to detect if content changed without logging the content itself
 */
export function contentHash(text: string): string {
  let hash = 2166136261;
  for (let i = 0; i < text.length; i++) {
    hash ^= text.charCodeAt(i);
    hash = (hash * 16777619) >>> 0;
  }
  return hash.toString(16).padStart(8, '0');
}

// ============================================================================
// SIGNAL LIFECYCLE COUNTERS
// ============================================================================

/**
 * Signal counts by type (for per-type visibility)
 */
export interface SignalTypeCounts {
  pii: number;
  confidential: number;
  financial: number;
  legal: number;
  ip: number;
  sensitive: number;
  canary?: number;  // Debug-only canary signals
  [key: string]: number | undefined;
}

/**
 * Boundary counter snapshot for signal lifecycle tracking
 */
export interface BoundaryCounters {
  /** After detection (raw signals) */
  afterDetection: {
    total: number;
    byType: SignalTypeCounts;
  };
  /** After policy/aggregation */
  afterPolicy: {
    total: number;
    byType: SignalTypeCounts;
  };
  /** After deduplication */
  afterDedup: {
    total: number;
    removed: number;
  };
  /** What UI receives */
  uiReceives: {
    total: number;
    visible: number;
  };
}

/**
 * Create empty signal type counts
 */
export function emptyTypeCounts(): SignalTypeCounts {
  return {
    pii: 0,
    confidential: 0,
    financial: 0,
    legal: 0,
    ip: 0,
    sensitive: 0,
  };
}

/**
 * Count signals by type
 */
export function countSignalsByType(signals: Array<{ type: string }>): SignalTypeCounts {
  const counts = emptyTypeCounts();
  for (const signal of signals) {
    const type = signal.type;
    if (type in counts) {
      counts[type] = (counts[type] ?? 0) + 1;
    } else {
      // Unknown type - track it anyway
      counts[type] = (counts[type] ?? 0) + 1;
    }
  }
  return counts;
}

/**
 * Log boundary counters in a structured format
 */
export function logBoundaryCounters(counters: BoundaryCounters): void {
  if (!isDebugMode()) return;

  console.log(`${LOG_PREFIX} ========== SIGNAL LIFECYCLE COUNTERS ==========`);
  console.log(`${LOG_PREFIX} [A] After Detection:    total=${counters.afterDetection.total}`);
  logTypeCounts('    ', counters.afterDetection.byType);
  console.log(`${LOG_PREFIX} [B] After Policy:       total=${counters.afterPolicy.total}`);
  logTypeCounts('    ', counters.afterPolicy.byType);
  console.log(`${LOG_PREFIX} [C] After Dedup:        total=${counters.afterDedup.total} (removed=${counters.afterDedup.removed})`);
  console.log(`${LOG_PREFIX} [D] UI Receives:        total=${counters.uiReceives.total} visible=${counters.uiReceives.visible}`);
  console.log(`${LOG_PREFIX} ===============================================`);
}

function logTypeCounts(indent: string, counts: SignalTypeCounts): void {
  const nonZero = Object.entries(counts)
    .filter(([, v]) => v && v > 0)
    .map(([k, v]) => `${k}=${v}`)
    .join(', ');
  if (nonZero) {
    console.log(`${LOG_PREFIX} ${indent}by-type: ${nonZero}`);
  }
}

// ============================================================================
// EXTRACTION DIAGNOSTICS
// ============================================================================

export interface ExtractionDiagnostics {
  /** Document ID (filename or hash) */
  docId: string;
  /** Extraction method used */
  method: 'pdf-text' | 'pdf-ocr' | 'ooxml' | 'text' | 'unknown';
  /** Extracted text length (characters) */
  textLength: number;
  /** Whether extraction yielded near-empty result */
  nearEmpty: boolean;
  /** Duration in ms */
  durationMs: number;
  /** Any warnings */
  warnings: string[];
}

/**
 * Log extraction diagnostics
 */
export function logExtractionDiagnostics(diag: ExtractionDiagnostics): void {
  if (!isDebugMode()) return;

  const warningStr = diag.warnings.length > 0 ? ` warnings=[${diag.warnings.join(', ')}]` : '';
  const nearEmptyStr = diag.nearEmpty ? ' ⚠️ NEAR-EMPTY' : '';

  debugLog('Extraction',
    `doc="${diag.docId}" method=${diag.method} textLen=${diag.textLength} durationMs=${diag.durationMs.toFixed(1)}${nearEmptyStr}${warningStr}`
  );
}

// ============================================================================
// CHUNK DIAGNOSTICS
// ============================================================================

export interface ChunkDiagnostics {
  /** Total number of chunks */
  count: number;
  /** Minimum chunk length */
  minLength: number;
  /** Maximum chunk length */
  maxLength: number;
  /** Average chunk length */
  avgLength: number;
}

/**
 * Log chunk distribution (without content)
 */
export function logChunkDiagnostics(diag: ChunkDiagnostics): void {
  if (!isDebugMode()) return;

  debugLog('Chunking',
    `chunks=${diag.count} lengths: min=${diag.minLength} avg=${diag.avgLength.toFixed(0)} max=${diag.maxLength}`
  );
}

// ============================================================================
// DETECTION INVOCATION DIAGNOSTICS
// ============================================================================

export interface DetectionInvocationDiagnostics {
  /** Document ID */
  docId: string;
  /** Resolved locale */
  locale: string;
  /** Locale confidence */
  localeConfidence: string;
  /** Document class (if known) */
  documentClass?: string;
  /** Extracted text length */
  textLength: number;
}

/**
 * Log detection invocation entry point
 */
export function logDetectionInvocation(diag: DetectionInvocationDiagnostics): void {
  if (!isDebugMode()) return;

  const docClassStr = diag.documentClass ? ` docClass=${diag.documentClass}` : '';

  debugLog('DetectionEntry',
    `doc="${diag.docId}" locale=${diag.locale}(${diag.localeConfidence}) textLen=${diag.textLength}${docClassStr}`
  );
}

// ============================================================================
// PACK LOADING DIAGNOSTICS
// ============================================================================

export interface PackLoadingDiagnostics {
  /** Number of loaded packs */
  packCount: number;
  /** Pack names/IDs */
  packIds: string[];
  /** Active locale routing */
  localeRouting: string;
  /** Resolved locale confidence */
  localeConfidence: string;
  /** Whether locale matches any pack */
  localeMatchesPack: boolean;
}

/**
 * Log pack loading diagnostics (at startup or first use)
 */
export function logPackLoadingDiagnostics(diag: PackLoadingDiagnostics): void {
  if (!isDebugMode()) return;

  debugLog('PackLoading',
    `packs=${diag.packCount} ids=[${diag.packIds.join(', ')}] localeRouting=${diag.localeRouting}(${diag.localeConfidence}) matchesPack=${diag.localeMatchesPack}`
  );
}

// ============================================================================
// CANARY SIGNAL CONFIGURATION
// ============================================================================

/** Canary token that triggers debug-only detection */
export const CANARY_TOKEN = 'DETECTION_CANARY_123';

/** Canary signal type (cannot collide with real types) */
export const CANARY_SIGNAL_TYPE = 'debug-canary';

/** Canary signal ID */
export const CANARY_SIGNAL_ID = 'debug.canary';

/**
 * Check if canary detection should run (debug mode only)
 */
export function shouldRunCanaryDetection(): boolean {
  return isDebugMode();
}

// ============================================================================
// DEBUG SUMMARY
// ============================================================================

/**
 * Generate a summary object for programmatic access
 */
export interface DebugSummary {
  debugEnabled: boolean;
  extraction?: ExtractionDiagnostics;
  detectionInvocation?: DetectionInvocationDiagnostics;
  packLoading?: PackLoadingDiagnostics;
  chunks?: ChunkDiagnostics;
  boundaries: BoundaryCounters;
  canaryDetected: boolean;
}

/**
 * Create empty boundary counters
 */
export function emptyBoundaryCounters(): BoundaryCounters {
  return {
    afterDetection: { total: 0, byType: emptyTypeCounts() },
    afterPolicy: { total: 0, byType: emptyTypeCounts() },
    afterDedup: { total: 0, removed: 0 },
    uiReceives: { total: 0, visible: 0 },
  };
}

// ============================================================================
// GLOBAL DEBUG STATE (for test script access)
// ============================================================================

/** Last assessment's debug summary (for test verification) */
let lastDebugSummary: DebugSummary | null = null;

/**
 * Store debug summary for later retrieval
 */
export function storeDebugSummary(summary: DebugSummary): void {
  lastDebugSummary = summary;
}

/**
 * Get the last debug summary (for test scripts)
 */
export function getLastDebugSummary(): DebugSummary | null {
  return lastDebugSummary;
}

/**
 * Clear the last debug summary
 */
export function clearLastDebugSummary(): void {
  lastDebugSummary = null;
}
