/**
 * RomancePack - Romance Language Family Detection Patterns (STUB)
 *
 * Covers: Spain, Portugal, France, Italy, and Americas (MX, BR, AR, etc.)
 *
 * Status: STUB - Minimal implementation for architecture validation
 * TODO: Full implementation in Phase 2
 *
 * AG-PHASE-5E-060: DISABLED BY DEFAULT
 * This pack is a stub and is NOT active in production under default config.
 * To enable, explicitly set languagePacks.romance = true in PackConfig.
 *
 * Design Principles:
 * - Conservative phone patterns (EU vs Americas formats differ)
 * - Requires MEDIUM locale confidence to run
 * - Opt-in only until full implementation is complete
 */

import { DetectionPack, DetectionPattern } from '../types';

// ============================================================================
// ROMANCE LANGUAGE FAMILY PATTERNS (STUB)
// ============================================================================

const romancePatterns: DetectionPattern[] = [
  // === PHONE NUMBERS (PLACEHOLDER - CONSERVATIVE) ===
  {
    id: 'romance-phone-eu-intl',
    name: 'Phone Number (EU Romance)',
    // Only match with country code prefix
    pattern: /\+(?:33|34|39|351)[-.\s]?\d{1,3}[-.\s]?\d{2,3}[-.\s]?\d{2,3}[-.\s]?\d{2,3}\b/g,
    type: 'pii',
    defaultSeverity: 'low',
    description: 'Phone numbers',
    detail: 'File contains European phone numbers.',
    rationale: 'Country code prefix (+33 FR, +34 ES, +39 IT, +351 PT) indicates phone.',
    pack: 'romance',
    countMatches: true,
    minCount: 3,
    countDescription: '{count} phone numbers',
    maxSeverity: 'medium',
    tags: ['pii', 'contact', 'phone', 'eu'],
    minLocaleConfidence: 'medium',
  },
  
  // === LEGAL TERMINOLOGY (PLACEHOLDER) ===
  {
    id: 'romance-legal-contract',
    name: 'Legal Contract Language (Romance)',
    // AG-PROMPT-4: Unicode-safe boundary for Spanish (á in cláusula), French (é in responsabilité)
    pattern: /(?<!\p{L})(contrato|acuerdo|contrat|contratto|cláusula|clause|responsabilidad|responsabilité)(?!\p{L})/iu,
    type: 'legal',
    defaultSeverity: 'medium',
    description: 'Legal language detected',
    detail: 'File contains Romance language legal contract terms.',
    rationale: 'Contract terminology in Spanish, Portuguese, French, or Italian.',
    pack: 'romance',
    tags: ['legal', 'contract', 'romance'],
    minLocaleConfidence: 'medium',
  },
  {
    id: 'romance-confidential',
    name: 'Confidentiality Terms (Romance)',
    // AG-PROMPT-4: Unicode-safe boundary for French (é in réservé)
    pattern: /(?<!\p{L})(confidencial|confidentiel|confidenziale|riservato|réservé|secreto|segreto)(?!\p{L})/iu,
    type: 'confidential',
    defaultSeverity: 'high',
    description: 'Confidentiality marker',
    detail: 'File contains Romance language confidentiality markers.',
    rationale: 'Explicit confidentiality marking in Romance languages.',
    pack: 'romance',
    hardFloor: true,
    tags: ['classification', 'confidential', 'romance'],
    minLocaleConfidence: 'medium',
  },
  
  // TODO: Add more patterns for Phase 2:
  // - Spanish DNI format hints
  // - Portuguese NIF hints  
  // - French financial terminology
  // - Italian legal terminology
  // - Latin American phone formats
];

// ============================================================================
// ROMANCE PACK EXPORT
// ============================================================================

export const RomancePack: DetectionPack = {
  metadata: {
    id: 'romance',
    name: 'Romance Language Pack',
    layer: 'language',
    version: '0.2.0', // Stub version
    description: 'Detection patterns for Romance language regions (ES, PT, FR, IT + Americas). STUB - partial implementation. DISABLED BY DEFAULT.',
    languageFamily: 'romance',
    coverageCountries: ['ES', 'PT', 'FR', 'IT', 'MX', 'BR', 'AR', 'CO', 'PE', 'CL'],
    enabledByDefault: false, // AG-PHASE-5E-060: Stub pack disabled by default
    minLocaleConfidence: 'medium',
  },
  patterns: romancePatterns,
};

export default RomancePack;