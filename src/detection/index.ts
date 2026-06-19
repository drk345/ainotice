/**
 * AgentGuard Detection Module
 * 
 * Locale-aware detection pack system for signal extraction.
 * See ADR010 for architectural decisions.
 * 
 * Key Features:
 * - Locale confidence gating (LOW = global only, MEDIUM = + language, HIGH = + country)
 * - Conservative phone detection (never escalates beyond MEDIUM)
 * - Admin-ready pattern structure (id, rationale, pack, tags)
 * 
 * Usage:
 * ```typescript
 * import { runDetection, DEFAULT_PACK_CONFIG } from './detection';
 * 
 * // Default: LOW confidence, only GlobalPack runs
 * const result = runDetection({
 *   text: documentContent,
 *   source: 'content',
 * });
 * 
 * // With higher confidence (e.g., from metadata hints)
 * const result = runDetection({
 *   text: documentContent,
 *   source: 'content',
 *   localeConfidence: 'medium',  // Enables language packs
 * });
 * 
 * // result.signals contains detected RiskSignals
 * // result.packsExecuted lists which packs ran
 * // result.localeConfidence shows what confidence was used
 * ```
 */

// Export types
export * from './types';

// Export registry functions
export {
  resolveActivePacks,
  getActivePatterns,
  runDetection,
  inferLocaleConfidence,
  DEFAULT_PACK_CONFIG,
  DEFAULT_LOCALE_CONFIDENCE,
  GlobalPack,
  EnglishPack,
  RomancePack,
  NordicPack,
  LANGUAGE_PACKS,
  COUNTRY_PACKS,
} from './packRegistry';

// Re-export individual packs for direct access
export { GlobalPack as GlobalDetectionPack } from './packs/global';
export { EnglishPack as EnglishDetectionPack } from './packs/english';
export { RomancePack as RomanceDetectionPack } from './packs/romance';
export { NordicPack as NordicDetectionPack } from './packs/nordic';