/**
 * NordicPack - Nordic Language Family Detection Patterns
 * 
 * Covers: Denmark, Norway, Sweden, Finland, Iceland
 * 
 * Design Principles:
 * - VERY conservative phone patterns (the #1 source of false positives)
 * - Exclude patterns that match: order numbers, product codes, prices
 * - Phone numbers ONLY match with country code prefix or explicit phone indicator
 * - Requires MEDIUM locale confidence to run
 * 
 * Known False Positive Sources (Nordic documents):
 * - IKEA product codes: 003.098.91
 * - Order numbers: 1281610074
 * - Prices: 1.599,00 kr
 * - VAT numbers
 * - Reference numbers
 * 
 * These MUST NOT trigger phone detection.
 */

import { DetectionPack, DetectionPattern } from '../types';

// ============================================================================
// NORDIC LANGUAGE FAMILY PATTERNS
// ============================================================================

const nordicPatterns: DetectionPattern[] = [
  // === PHONE NUMBERS (EXTREMELY CONSERVATIVE) ===
  // Only match phones that are CLEARLY phones - with country code or indicator
  // Default severity is LOW, capped at MEDIUM
  {
    id: 'nordic-phone-dk-intl',
    name: 'Phone Number (Denmark +45)',
    // ONLY matches +45 with proper formatting
    // Pattern: +45 XX XX XX XX or +45 XXXX XXXX
    pattern: /\+45[-.\s]?\d{2}[-.\s]?\d{2}[-.\s]?\d{2}[-.\s]?\d{2}\b/g,
    type: 'pii',
    defaultSeverity: 'low',
    description: 'Phone numbers',
    detail: 'File contains Danish phone numbers.',
    rationale: '+45 country code indicates explicit Danish phone number.',
    pack: 'nordic',
    countMatches: true,
    minCount: 2,  // Only trigger if 2+ found
    countDescription: '{count} phone numbers',
    maxSeverity: 'medium',
    tags: ['pii', 'contact', 'phone', 'denmark'],
    minLocaleConfidence: 'medium',
  },
  {
    id: 'nordic-phone-se-intl',
    name: 'Phone Number (Sweden +46)',
    pattern: /\+46[-.\s]?\d{1,3}[-.\s]?\d{2,3}[-.\s]?\d{2}[-.\s]?\d{2}\b/g,
    type: 'pii',
    defaultSeverity: 'low',
    description: 'Phone numbers',
    detail: 'File contains Swedish phone numbers.',
    rationale: '+46 country code indicates explicit Swedish phone number.',
    pack: 'nordic',
    countMatches: true,
    minCount: 2,
    countDescription: '{count} phone numbers',
    maxSeverity: 'medium',
    tags: ['pii', 'contact', 'phone', 'sweden'],
    minLocaleConfidence: 'medium',
  },
  {
    id: 'nordic-phone-no-intl',
    name: 'Phone Number (Norway +47)',
    pattern: /\+47[-.\s]?\d{2}[-.\s]?\d{2}[-.\s]?\d{2}[-.\s]?\d{2}\b/g,
    type: 'pii',
    defaultSeverity: 'low',
    description: 'Phone numbers',
    detail: 'File contains Norwegian phone numbers.',
    rationale: '+47 country code indicates explicit Norwegian phone number.',
    pack: 'nordic',
    countMatches: true,
    minCount: 2,
    countDescription: '{count} phone numbers',
    maxSeverity: 'medium',
    tags: ['pii', 'contact', 'phone', 'norway'],
    minLocaleConfidence: 'medium',
  },
  {
    id: 'nordic-phone-fi-intl',
    name: 'Phone Number (Finland +358)',
    pattern: /\+358[-.\s]?\d{1,3}[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
    type: 'pii',
    defaultSeverity: 'low',
    description: 'Phone numbers',
    detail: 'File contains Finnish phone numbers.',
    rationale: '+358 country code indicates explicit Finnish phone number.',
    pack: 'nordic',
    countMatches: true,
    minCount: 2,
    countDescription: '{count} phone numbers',
    maxSeverity: 'medium',
    tags: ['pii', 'contact', 'phone', 'finland'],
    minLocaleConfidence: 'medium',
  },
  {
    id: 'nordic-phone-labeled',
    name: 'Phone Number (Labeled)',
    // ONLY matches when preceded by phone indicator word
    // tlf, tel, telefon, mobil, ring + separator + 8 digits
    pattern: /\b(?:tlf|tel|telefon|mobil|ring)[\s.:]+\d{2}[-.\s]?\d{2}[-.\s]?\d{2}[-.\s]?\d{2}\b/gi,
    type: 'pii',
    defaultSeverity: 'low',
    description: 'Phone numbers',
    detail: 'File contains labeled phone numbers.',
    rationale: 'Phone indicator word (tlf, mobil, etc.) confirms number is a phone.',
    pack: 'nordic',
    countMatches: true,
    minCount: 1,  // Even 1 labeled phone is valid
    countDescription: '{count} phone numbers',
    maxSeverity: 'medium',
    tags: ['pii', 'contact', 'phone', 'nordic', 'labeled'],
    minLocaleConfidence: 'medium',
  },
  
  // === LEGAL/FINANCIAL TERMINOLOGY ===
  {
    id: 'nordic-legal-contract',
    name: 'Legal Contract Language (Nordic)',
    // AG-PROMPT-4: Unicode-safe boundary for Nordic (å in vilkår)
    pattern: /(?<!\p{L})(kontrakt|aftale|avtale|avtal|ansvar|erstatning|forpligtelse|vilkår|betingelser)(?!\p{L})/iu,
    type: 'legal',
    defaultSeverity: 'medium',
    description: 'Legal language detected',
    detail: 'File contains Nordic legal contract language.',
    rationale: 'Nordic contract terminology indicates formal agreement.',
    pack: 'nordic',
    tags: ['legal', 'contract', 'nordic'],
    minLocaleConfidence: 'medium',
  },
  {
    id: 'nordic-confidential',
    name: 'Confidentiality Terms (Nordic)',
    // AG-PROMPT-4: Unicode-safe boundary for Nordic (ø in offentliggørelse)
    pattern: /(?<!\p{L})(fortrolig|hemmelig|intern\s+brug|strengt\s+fortroligt|ikke\s+til\s+offentliggørelse)(?!\p{L})/iu,
    type: 'confidential',
    defaultSeverity: 'high',
    description: 'Confidentiality marker',
    detail: 'File contains Nordic confidentiality markers.',
    rationale: 'Explicit confidentiality marking in Danish/Norwegian/Swedish.',
    pack: 'nordic',
    hardFloor: true,
    tags: ['classification', 'confidential', 'nordic'],
    minLocaleConfidence: 'medium',
  },
  
  // === HR TERMS ===
  {
    id: 'nordic-hr-terms',
    name: 'HR Terms (Nordic)',
    // AG-PROMPT-4: Unicode-safe boundary for Nordic (ø in løn, æ in ansættelse)
    pattern: /(?<!\p{L})(løn|ansættelse|opsigelse|ferie|medarbejder|personale|arbejdsgiver|ansat)(?!\p{L})/iu,
    type: 'pii',
    defaultSeverity: 'high',
    description: 'HR/Employee data',
    detail: 'File contains Nordic HR or employee information.',
    rationale: 'HR terminology indicates employee personal information.',
    pack: 'nordic',
    tags: ['hr', 'pii', 'nordic'],
    minLocaleConfidence: 'medium',
  },

  // === PAYROLL TERMS (AG-PHASE-5D-057) ===
  {
    id: 'nordic-payroll-terms',
    name: 'Payroll Terms (Nordic)',
    // Swedish: lönespecifikation, månadslön, bruttolön, nettolön, skatteavdrag, a-skatt
    // Norwegian: lønnslipp, månedslønn, bruttolønn, nettolønn, skattetrekk
    // Danish: lønseddel, månedsløn, bruttoløn, nettoløn, skat
    // AG-PROMPT-4: Unicode-safe boundary for Nordic (ö in lönespecifikation, ø in lønseddel, å in månadslön)
    pattern: /(?<!\p{L})(lönespecifikation|lönspec|månadslön|månlön|bruttolön|nettolön|skatteavdrag|a-skatt|ack\.?\s*skatt|lönnslipp|lønnslipp|månedslønn|bruttolønn|nettolønn|skattetrekk|lønseddel|månedsløn|bruttoløn|nettoløn|löneavdrag|skatteafsnit|arbetsgivaravgift|pensionsinbetalning)(?!\p{L})/iu,
    type: 'pii',
    defaultSeverity: 'critical',
    description: 'Payroll/Salary data',
    detail: 'File contains Nordic payroll or salary slip information.',
    rationale: 'Payroll terminology indicates personal compensation and tax data.',
    pack: 'nordic',
    hardFloor: true,
    tags: ['hr', 'pii', 'payroll', 'nordic'],
    minLocaleConfidence: 'medium',
  },
  
  // === FINANCIAL TERMS ===
  {
    id: 'nordic-financial-terms',
    name: 'Financial Terms (Nordic)',
    // AG-PROMPT-4: Unicode-safe boundary for Nordic (å in årsrapport, ø in resultatopgørelse, æ in omsætning)
    // AG-PROMPT-376: bare English "balance" REMOVED from this alternation. It has an
    // extremely common non-financial meaning (equilibrium/proportion — "visual balance",
    // "the right balance") that fired this Nordic-specific pack on English layout/design
    // prose containing no actual Nordic-language or financial content (root cause:
    // FINANCIAL_ANCHOR_TOO_WEAK — a bare ambiguous word used as a financial anchor).
    // Genuine "balance sheet" mentions remain covered by english.ts's
    // english-financial-statement pattern, which correctly requires the full phrase
    // "balance sheet" (not bare "balance"). Real Nordic financial documents are still
    // caught by the remaining genuinely Nordic-specific terms below (regnskab,
    // årsrapport, resultatopgørelse, omsætning, driftsresultat have no ambiguous
    // English meaning), confirmed via the existing nordic-financial-report-paste gold
    // fixture (fires via regnskab/omsætning/driftsresultat/resultatopgørelse alone).
    pattern: /(?<!\p{L})(regnskab|årsrapport|resultatopgørelse|omsætning|driftsresultat)(?!\p{L})/iu,
    type: 'financial',
    defaultSeverity: 'medium',
    description: 'Financial document',
    detail: 'File contains Nordic financial terminology.',
    rationale: 'Financial statement terminology indicates business-sensitive content.',
    pack: 'nordic',
    tags: ['financial', 'nordic'],
    minLocaleConfidence: 'medium',
  },

  // Note: Danish CPR numbers, Swedish personnummer, etc. are NOT included here
  // They belong in CountryPacks and require explicit enablement + high confidence
];

// ============================================================================
// NORDIC PACK EXPORT
// ============================================================================

export const NordicPack: DetectionPack = {
  metadata: {
    id: 'nordic',
    name: 'Nordic Language Pack',
    layer: 'language',
    version: '1.1.0',
    description: 'Detection patterns for Nordic regions (DK, NO, SE, FI, IS). Very conservative phone detection to avoid IKEA-style false positives.',
    languageFamily: 'nordic',
    coverageCountries: ['DK', 'NO', 'SE', 'FI', 'IS'],
    enabledByDefault: true,
    minLocaleConfidence: 'medium',  // Won't run at low confidence
  },
  patterns: nordicPatterns,
};

export default NordicPack;