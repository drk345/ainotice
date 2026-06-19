/**
 * AG-PHASE-5E-058: Degraded Document Fallback Classification
 *
 * Provides deterministic fallback classification for PDFs where text extraction
 * is degraded or blocked. Uses filename and metadata signals ONLY.
 *
 * Design principles:
 * - NO OCR, ML, or probabilistic inference
 * - Deterministic, explainable rules
 * - EU-wide language coverage
 * - Must not trigger on clean business documents
 *
 * Activation conditions:
 * - pdfExtractionStatus.quality is 'degraded' or 'blocked'
 * - At least one strong domain token in filename OR metadata
 */

import type { DocumentClass } from './documentClassAnchors';
import type { Severity } from '../types/riskSignal';

// ============================================================================
// TYPES
// ============================================================================

export interface FallbackClassificationResult {
  /** Whether fallback classification was applied */
  applied: boolean;
  /** Inferred document class (if any) */
  documentClass: DocumentClass | null;
  /** Recommended severity floor */
  severity: Severity;
  /** Source of classification (filename, metadata, or both) */
  source: 'filename' | 'metadata' | 'both' | null;
  /** Matched tokens for audit trail */
  matchedTokens: string[];
  /** Domain that was matched */
  domain: 'payroll' | 'hr_contract' | 'insurance' | null;
  /** Explicit disclaimer for UI */
  disclaimer: string;
}

// ============================================================================
// EU-WIDE DOMAIN VOCABULARIES
// ============================================================================

/**
 * Payroll domain tokens by language.
 * Classification: doc.payroll, Severity: critical
 */
const PAYROLL_TOKENS: Record<string, string[]> = {
  en: ['payslip', 'payroll', 'salary', 'compensation', 'wage', 'earnings'],
  // Swedish: include both proper and ASCII variants for robustness
  sv: ['lönespecifikation', 'lönspec', 'lön', 'månadslön', 'bruttolön', 'nettolön',
       'lonespecifikation', 'lonspec', 'lon', 'manadslon', 'bruttolon', 'nettolon'],
  // Danish: include both proper and ASCII variants
  da: ['lønseddel', 'løn', 'månedsløn', 'bruttoløn', 'nettoløn',
       'lonseddel', 'maanedslon', 'bruttolon', 'nettolon'],
  // Norwegian: include both proper and ASCII variants
  no: ['lønnslipp', 'lønn', 'månedslønn', 'bruttolønn', 'nettolønn',
       'lonnslipp', 'lonn', 'maanedslonn', 'bruttolonn', 'nettolonn'],
  fi: ['palkkalaskelma', 'palkka', 'kuukausipalkka'],
  de: ['gehaltsabrechnung', 'lohnabrechnung', 'gehalt', 'lohn', 'entgelt'],
  fr: ['bulletin', 'salaire', 'paie', 'fiche de paie'],
  // AG-PHASE-5E-061: Spanish/LatAm payroll tokens (Spain + Americas)
  es: ['nómina', 'nomina', 'salario', 'sueldo', 'recibo de nómina', 'recibo de nomina',
       'liquidación', 'liquidacion', 'remuneración', 'remuneracion', 'bruto', 'neto',
       'salario bruto', 'salario neto', 'sueldo bruto', 'sueldo neto'],
  it: ['busta paga', 'cedolino', 'stipendio', 'retribuzione'],
  nl: ['loonstrook', 'salaris', 'loon'],
  pt: ['recibo de vencimento', 'salário', 'contracheque', 'salario'],
  pl: ['pasek wynagrodzeń', 'wynagrodzenie', 'pensja', 'pasek wynagrodzen'],
};

/**
 * HR/Employment contract tokens by language.
 * Classification: doc.hr_record, Severity: critical
 */
const HR_CONTRACT_TOKENS: Record<string, string[]> = {
  en: ['employment', 'contract', 'agreement', 'employee', 'personnel', 'termination', 'resignation'],
  sv: ['anställningsavtal', 'anställning', 'arbetsavtal', 'personal', 'uppsägning'],
  da: ['ansættelseskontrakt', 'ansættelse', 'arbejdsaftale', 'medarbejder', 'opsigelse'],
  no: ['arbeidsavtale', 'ansettelse', 'arbeidstaker', 'oppsigelse'],
  fi: ['työsopimus', 'työntekijä', 'henkilöstö', 'irtisanominen'],
  de: ['arbeitsvertrag', 'anstellungsvertrag', 'mitarbeiter', 'kündigung', 'arbeitnehmer'],
  fr: ['contrat de travail', 'employé', 'salarié', 'licenciement', 'démission'],
  // AG-PHASE-5E-061: Spanish/LatAm HR/employment tokens (Spain + Americas)
  es: ['contrato de trabajo', 'empleador', 'empleado', 'trabajador', 'despido', 'renuncia',
       'relación laboral', 'relacion laboral', 'cláusulas', 'clausulas',
       'fecha de inicio', 'duración', 'duracion', 'puesto de trabajo', 'jornada laboral'],
  it: ['contratto di lavoro', 'dipendente', 'lavoratore', 'licenziamento', 'dimissioni'],
  nl: ['arbeidsovereenkomst', 'werknemer', 'medewerker', 'ontslag'],
  pt: ['contrato de trabalho', 'empregado', 'funcionário', 'demissão'],
  pl: ['umowa o pracę', 'pracownik', 'zatrudnienie', 'zwolnienie'],
};

/**
 * Insurance tokens by language.
 * Classification: doc.insurance_policy, Severity: high
 */
const INSURANCE_TOKENS: Record<string, string[]> = {
  en: ['insurance', 'policy', 'policyholder', 'premium', 'coverage', 'claim'],
  sv: ['försäkring', 'försäkringsbrev', 'premie', 'försäkringstagare'],
  da: ['forsikring', 'forsikringspolice', 'præmie', 'forsikringstager'],
  no: ['forsikring', 'forsikringspolise', 'premie', 'forsikringstaker'],
  fi: ['vakuutus', 'vakuutuskirja', 'vakuutusmaksu'],
  de: ['versicherung', 'versicherungspolice', 'prämie', 'versicherungsnehmer'],
  fr: ['assurance', 'police', 'prime', 'assuré'],
  // AG-PHASE-5E-061: Spanish/LatAm insurance tokens (Spain + Americas)
  es: ['seguro', 'póliza', 'poliza', 'prima', 'asegurado', 'aseguradora',
       'cobertura', 'siniestro', 'condiciones generales', 'seguro de vida',
       'seguro de auto', 'seguro de hogar', 'seguro de salud'],
  it: ['assicurazione', 'polizza', 'premio', 'assicurato'],
  nl: ['verzekering', 'polis', 'premie', 'verzekerde'],
  pt: ['seguro', 'apólice', 'prêmio', 'segurado'],
  pl: ['ubezpieczenie', 'polisa', 'składka', 'ubezpieczony'],
};

// ============================================================================
// TOKEN MATCHING
// ============================================================================

/**
 * Normalize text for token matching:
 * - Lowercase
 * - Replace underscores/hyphens with spaces
 * - Remove file extension
 */
function normalizeForMatching(text: string): string {
  return text
    .toLowerCase()
    .replace(/[-_]/g, ' ')
    .replace(/\.[a-z]{2,4}$/i, '')  // Remove file extension
    .trim();
}

/**
 * Find matching tokens in text from a vocabulary.
 * Returns matched tokens if any.
 */
function findMatchingTokens(text: string, vocabulary: Record<string, string[]>): string[] {
  const normalized = normalizeForMatching(text);
  const matches: string[] = [];

  for (const [_lang, tokens] of Object.entries(vocabulary)) {
    for (const token of tokens) {
      const tokenLower = token.toLowerCase();
      // Word boundary matching: token must be a complete word
      const pattern = new RegExp(`\\b${escapeRegex(tokenLower)}\\b`, 'i');
      if (pattern.test(normalized)) {
        matches.push(token);
      }
    }
  }

  return matches;
}

/**
 * Escape regex special characters in a string.
 */
function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ============================================================================
// FALLBACK CLASSIFICATION
// ============================================================================

/**
 * Check if quality level should trigger fallback classification.
 */
export function shouldUseFallbackClassification(
  quality: 'clean' | 'partial' | 'degraded' | 'blocked' | 'empty' | undefined
): boolean {
  // Only activate for degraded or blocked quality
  return quality === 'degraded' || quality === 'blocked';
}

/**
 * Classify a degraded document using filename and metadata.
 *
 * @param filename - The document filename
 * @param metadata - Document metadata (title, subject, keywords, etc.)
 * @param quality - Extraction quality level
 * @returns Classification result with document class and severity
 */
export function classifyDegradedDocument(
  filename: string,
  metadata: {
    title?: string;
    subject?: string;
    keywords?: string[];
    author?: string;
  } | undefined,
  quality: 'clean' | 'partial' | 'degraded' | 'blocked' | 'empty' | undefined
): FallbackClassificationResult {
  // Default: no classification
  const noMatch: FallbackClassificationResult = {
    applied: false,
    documentClass: null,
    severity: 'low',  // AG-AUDIT-FIX-005: 'none' is not a valid Severity; use 'low' (unused when applied=false)
    source: null,
    matchedTokens: [],
    domain: null,
    disclaimer: '',
  };

  // Only apply fallback if quality is degraded or blocked
  if (!shouldUseFallbackClassification(quality)) {
    return noMatch;
  }

  // Build searchable text from filename and metadata
  const filenameText = filename || '';
  const metadataText = [
    metadata?.title,
    metadata?.subject,
    ...(metadata?.keywords || []),
  ].filter(Boolean).join(' ');

  // Check each domain in priority order
  // Priority: Payroll > HR > Insurance

  // Check payroll
  const payrollFilenameMatches = findMatchingTokens(filenameText, PAYROLL_TOKENS);
  const payrollMetadataMatches = findMatchingTokens(metadataText, PAYROLL_TOKENS);
  if (payrollFilenameMatches.length > 0 || payrollMetadataMatches.length > 0) {
    const allMatches = [...new Set([...payrollFilenameMatches, ...payrollMetadataMatches])];
    return {
      applied: true,
      documentClass: 'doc.payroll',
      severity: 'critical',
      source: payrollFilenameMatches.length > 0 && payrollMetadataMatches.length > 0
        ? 'both'
        : payrollFilenameMatches.length > 0 ? 'filename' : 'metadata',
      matchedTokens: allMatches,
      domain: 'payroll',
      disclaimer: 'This PDF could not be fully analyzed due to text readability limitations.',
    };
  }

  // Check HR/employment
  const hrFilenameMatches = findMatchingTokens(filenameText, HR_CONTRACT_TOKENS);
  const hrMetadataMatches = findMatchingTokens(metadataText, HR_CONTRACT_TOKENS);
  if (hrFilenameMatches.length > 0 || hrMetadataMatches.length > 0) {
    const allMatches = [...new Set([...hrFilenameMatches, ...hrMetadataMatches])];
    return {
      applied: true,
      documentClass: 'doc.hr_record',
      severity: 'critical',
      source: hrFilenameMatches.length > 0 && hrMetadataMatches.length > 0
        ? 'both'
        : hrFilenameMatches.length > 0 ? 'filename' : 'metadata',
      matchedTokens: allMatches,
      domain: 'hr_contract',
      disclaimer: 'This PDF could not be fully analyzed due to text readability limitations.',
    };
  }

  // Check insurance
  const insuranceFilenameMatches = findMatchingTokens(filenameText, INSURANCE_TOKENS);
  const insuranceMetadataMatches = findMatchingTokens(metadataText, INSURANCE_TOKENS);
  if (insuranceFilenameMatches.length > 0 || insuranceMetadataMatches.length > 0) {
    const allMatches = [...new Set([...insuranceFilenameMatches, ...insuranceMetadataMatches])];
    return {
      applied: true,
      documentClass: 'doc.insurance_policy',
      severity: 'high',
      source: insuranceFilenameMatches.length > 0 && insuranceMetadataMatches.length > 0
        ? 'both'
        : insuranceFilenameMatches.length > 0 ? 'filename' : 'metadata',
      matchedTokens: allMatches,
      domain: 'insurance',
      disclaimer: 'This PDF could not be fully analyzed due to text readability limitations.',
    };
  }

  return noMatch;
}

// ============================================================================
// EXPORTS FOR TESTING
// ============================================================================

export const _testing = {
  PAYROLL_TOKENS,
  HR_CONTRACT_TOKENS,
  INSURANCE_TOKENS,
  normalizeForMatching,
  findMatchingTokens,
};
