/**
 * EnglishPack - English Language Family Detection Patterns
 * 
 * Covers: US, UK, Canada, Australia, New Zealand, Ireland
 * 
 * Design Principles:
 * - Conservative phone patterns (require clear formatting)
 * - Phone numbers default to LOW severity
 * - Requires MEDIUM locale confidence to run
 * 
 * Includes:
 * - Phone number formats (conservative, formatted only)
 * - Legal terminology
 * - HR/Employee data markers
 * - Financial terminology
 * - Health information (HIPAA)
 */

import { DetectionPack, DetectionPattern } from '../types';

// ============================================================================
// ENGLISH LANGUAGE FAMILY PATTERNS
// ============================================================================

const englishPatterns: DetectionPattern[] = [
  // === PHONE NUMBERS (CONSERVATIVE - LOW severity, MEDIUM cap) ===
  // Only match CLEARLY formatted phone numbers to avoid false positives
  // Order numbers, product codes, prices should NOT match
  {
    id: 'english-phone-us-formatted',
    name: 'Phone Number (US Formatted)',
    // ONLY matches: (XXX) XXX-XXXX or XXX-XXX-XXXX with separators
    // Does NOT match: bare 10-digit numbers, order IDs, prices
    pattern: /\b(?:\(\d{3}\)\s?[-.]?\d{3}[-.]?\d{4}|\d{3}[-.]?\d{3}[-.]?\d{4})\b/g,
    type: 'pii',
    defaultSeverity: 'low',
    description: 'Phone numbers',
    detail: 'File contains phone numbers.',
    rationale: 'US phone format. Low severity to avoid false positives from order numbers.',
    pack: 'english',
    countMatches: true,
    minCount: 5,  // Only trigger if 5+ found
    countDescription: '{count} phone numbers',
    maxSeverity: 'medium',  // Can NEVER go above medium
    tags: ['pii', 'contact', 'phone', 'us'],
    minLocaleConfidence: 'medium',
  },
  {
    id: 'english-phone-intl-prefix',
    name: 'Phone Number (International)',
    // ONLY matches with + country code prefix - high confidence it's a phone
    pattern: /\+1[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
    type: 'pii',
    defaultSeverity: 'low',
    description: 'Phone numbers',
    detail: 'File contains US/CA international phone numbers.',
    rationale: '+1 prefix indicates intentional phone number formatting.',
    pack: 'english',
    countMatches: true,
    minCount: 2,
    countDescription: '{count} phone numbers',
    maxSeverity: 'medium',
    tags: ['pii', 'contact', 'phone', 'international'],
    minLocaleConfidence: 'medium',
  },
  {
    id: 'english-phone-uk-format',
    name: 'Phone Number (UK Format)',
    // UK formats: +44 or 0XXXX XXXXXX with clear formatting
    pattern: /\b(?:\+44[-.\s]?\d{2,4}[-.\s]?\d{3}[-.\s]?\d{4}|0\d{2,4}[-.\s]\d{3}[-.\s]\d{4})\b/g,
    type: 'pii',
    defaultSeverity: 'low',
    description: 'Phone numbers',
    detail: 'File contains UK phone numbers.',
    rationale: 'UK phone formats with clear separators.',
    pack: 'english',
    countMatches: true,
    minCount: 3,
    countDescription: '{count} phone numbers',
    maxSeverity: 'medium',
    tags: ['pii', 'contact', 'phone', 'uk'],
    minLocaleConfidence: 'medium',
  },
  
  // === LEGAL TERMINOLOGY ===
  {
    id: 'english-legal-contract',
    name: 'Legal Contract Language',
    pattern: /\b(whereas|hereby|indemnify|liability|jurisdiction|arbitration|governing\s+law|force\s+majeure)\b/i,
    type: 'legal',
    defaultSeverity: 'medium',
    description: 'Legal language detected',
    detail: 'File contains legal contract language.',
    rationale: 'Contract boilerplate indicates formal legal document.',
    pack: 'english',
    tags: ['legal', 'contract'],
    minLocaleConfidence: 'medium',
  },
  {
    id: 'english-legal-nda',
    name: 'Non-Disclosure Agreement',
    pattern: /\b(non-?disclosure|confidentiality\s+agreement|nda|proprietary\s+information\s+agreement)\b/i,
    type: 'legal',
    defaultSeverity: 'high',
    description: 'NDA/Legal agreement',
    detail: 'File appears to be or reference a non-disclosure agreement.',
    rationale: 'NDAs contain confidential obligations. Sharing may breach contract.',
    pack: 'english',
    tags: ['legal', 'nda', 'confidential'],
    minLocaleConfidence: 'medium',
  },
  {
    id: 'english-legal-ip',
    name: 'Intellectual Property',
    pattern: /\b(intellectual\s+property|trade\s+secret|patent\s+pending|copyright\s+\d{4}|all\s+rights\s+reserved)\b/i,
    type: 'ip',
    defaultSeverity: 'high',
    description: 'IP content detected',
    detail: 'File contains intellectual property markers.',
    rationale: 'IP markers indicate proprietary content with legal protection.',
    pack: 'english',
    tags: ['legal', 'ip'],
    minLocaleConfidence: 'medium',
  },
  
  // === HR / EMPLOYEE DATA ===
  {
    id: 'english-hr-compensation',
    name: 'Compensation Data',
    pattern: /\b(salary|compensation|annual\s+pay|hourly\s+rate|bonus|commission|stock\s+options|equity\s+grant)\b/i,
    type: 'pii',
    defaultSeverity: 'high',
    description: 'HR/Employee data',
    detail: 'File contains compensation or HR information.',
    rationale: 'Compensation data is sensitive employee PII.',
    pack: 'english',
    tags: ['hr', 'pii', 'compensation'],
    minLocaleConfidence: 'medium',
  },
  {
    id: 'english-hr-performance',
    name: 'Performance Review',
    pattern: /\b(performance\s+review|annual\s+review|performance\s+rating|disciplinary|termination|severance)\b/i,
    type: 'pii',
    defaultSeverity: 'high',
    description: 'HR/Employee data',
    detail: 'File contains employee performance or HR information.',
    rationale: 'Performance data is sensitive HR information.',
    pack: 'english',
    tags: ['hr', 'pii', 'performance'],
    minLocaleConfidence: 'medium',
  },
  
  // === FINANCIAL TERMINOLOGY ===
  {
    id: 'english-financial-statement',
    name: 'Financial Statement',
    pattern: /\b(balance\s+sheet|income\s+statement|cash\s+flow|profit\s+and\s+loss|p&l|fiscal\s+year|quarterly\s+report)\b/i,
    type: 'financial',
    defaultSeverity: 'medium',
    description: 'Financial document',
    detail: 'File contains financial statement terminology.',
    rationale: 'Financial statements may contain non-public business information.',
    pack: 'english',
    tags: ['financial', 'statement'],
    minLocaleConfidence: 'medium',
  },
  {
    id: 'english-financial-banking',
    name: 'Banking Details',
    pattern: /\b(routing\s+number|account\s+number|wire\s+transfer|ach\s+transfer|direct\s+deposit)\b/i,
    type: 'financial',
    defaultSeverity: 'high',
    description: 'Banking information',
    detail: 'File contains banking or wire transfer details.',
    rationale: 'Banking details enable fraudulent transfers.',
    pack: 'english',
    tags: ['financial', 'banking'],
    minLocaleConfidence: 'medium',
  },
  
  // === MEDICAL / HEALTH (HIPAA) ===
  {
    id: 'english-health-phi',
    name: 'Protected Health Information',
    pattern: /\b(medical\s+record|patient\s+id|diagnosis|treatment\s+plan|prescription|health\s+insurance|hipaa)\b/i,
    type: 'pii',
    defaultSeverity: 'critical',
    description: 'Health information',
    detail: 'File contains protected health information (PHI).',
    rationale: 'PHI is HIPAA-protected. Unauthorized disclosure is illegal.',
    pack: 'english',
    hardFloor: true,
    tags: ['health', 'phi', 'hipaa'],
    minLocaleConfidence: 'medium',
  },
  
  // === GOVERNMENT / CLEARANCE ===
  {
    id: 'english-gov-clearance',
    name: 'Security Clearance',
    pattern: /\b(top\s+secret|secret\s+clearance|classified|for\s+official\s+use\s+only|fouo|sensitive\s+compartmented)\b/i,
    type: 'confidential',
    defaultSeverity: 'critical',
    description: 'Government classification',
    detail: 'File contains government security classification markers.',
    rationale: 'Government classified information has legal handling requirements.',
    pack: 'english',
    hardFloor: true,
    tags: ['government', 'classified', 'confidential'],
    minLocaleConfidence: 'medium',
  },
];

// ============================================================================
// ENGLISH PACK EXPORT
// ============================================================================

export const EnglishPack: DetectionPack = {
  metadata: {
    id: 'english',
    name: 'English Language Pack',
    layer: 'language',
    version: '1.1.0',
    description: 'Detection patterns for English-speaking regions (US, UK, CA, AU, NZ, IE). Requires medium locale confidence.',
    languageFamily: 'english',
    coverageCountries: ['US', 'UK', 'CA', 'AU', 'NZ', 'IE'],
    enabledByDefault: true,
    minLocaleConfidence: 'medium',  // Won't run at low confidence
  },
  patterns: englishPatterns,
};

export default EnglishPack;