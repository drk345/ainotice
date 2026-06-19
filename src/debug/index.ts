/**
 * AgentGuard Debug Module (AG-PROMPT-044)
 *
 * Central exports for debug instrumentation.
 * All debug features are gated behind debug mode flag.
 */

export {
  // Debug mode control
  isDebugMode,
  enableDebugMode,
  disableDebugMode,
  resetDebugModeCache,

  // Logging utilities
  debugLog,
  debugWarn,
  boundedSnippet,
  contentHash,

  // Signal lifecycle counters
  type SignalTypeCounts,
  type BoundaryCounters,
  emptyTypeCounts,
  countSignalsByType,
  logBoundaryCounters,
  emptyBoundaryCounters,

  // Extraction diagnostics
  type ExtractionDiagnostics,
  logExtractionDiagnostics,

  // Chunk diagnostics
  type ChunkDiagnostics,
  logChunkDiagnostics,

  // Detection diagnostics
  type DetectionInvocationDiagnostics,
  logDetectionInvocation,

  // Pack loading diagnostics
  type PackLoadingDiagnostics,
  logPackLoadingDiagnostics,

  // Canary signal configuration
  CANARY_TOKEN,
  CANARY_SIGNAL_TYPE,
  CANARY_SIGNAL_ID,
  shouldRunCanaryDetection,

  // Debug summary
  type DebugSummary,
  storeDebugSummary,
  getLastDebugSummary,
  clearLastDebugSummary,
} from './diagnostics';

export { runCanaryDetection, createCanaryTestContent } from './canary';
