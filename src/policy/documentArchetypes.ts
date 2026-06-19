/**
 * AG-ARCHETYPE-WORDLISTS-V1-SCHEMA-WIRING-TESTS-073
 *
 * Document Archetypes v1 - Deterministic Classification Evidence Layer
 *
 * Archetypes provide supplementary classification evidence for documents.
 * They are EVIDENCE ONLY and must NOT suppress identity/PII signals.
 *
 * Allowed effects per archetype:
 * - resume_cv: Veto M&A signals only (existing behavior)
 * - ticket_booking: Defer to existing ticket suppressor (no new suppressors)
 * - invoice_receipt: Classification + framing only
 * - medical_record: Classification + framing only
 * - legal_authority: Classification + framing only
 *
 * HARD GUARDRAILS:
 * - Archetypes NEVER suppress identity, national-id, email, phone, or payment signals
 * - Archetypes NEVER escalate severity (severity is signal-driven)
 * - All behavior is deterministic and testable
 */

import { FF } from '../config/featureFlags';

// ============================================================================
// TYPES
// ============================================================================

/**
 * Document archetype identifiers.
 * Each represents a distinct document category with specific handling rules.
 *
 * v2 additions: employment_hr, insurance, medical_health, education_school
 */
export type DocumentArchetypeId =
  | 'resume_cv'
  | 'ticket_booking'
  | 'invoice_receipt'
  | 'medical_record'      // v1 - clinical records
  | 'medical_health'      // v2 alias - same as medical_record
  | 'legal_authority'
  | 'employment_hr'       // v2 - internal HR documents
  | 'insurance'           // v2 - insurance documents
  | 'education_school'    // v2 - educational records
  | 'template_governance' // v3 - GDPR ROPA, privacy policies, questionnaires, inventories
  | 'policy_standard'     // v4 (AG-PROMPT-162) - policies, standards, procedures, guidelines
  | 'clinical_reference'  // v4 (AG-PROMPT-162) - clinical guidelines, formularies, reference material
  | 'aggregate_hr_finance'; // v4 (AG-PROMPT-162) - aggregate reports, dashboards, headcount summaries

/**
 * Confidence level for archetype detection.
 * - strong: Multiple strong markers or threshold exceeded
 * - weak: Some markers but below strong threshold
 */
export type ArchetypeConfidence = 'strong' | 'weak';

/**
 * Result of archetype detection for a single archetype.
 */
export interface ArchetypeMatch {
  /** Archetype identifier */
  archetypeId: DocumentArchetypeId;

  /** Confidence level */
  confidence: ArchetypeConfidence;

  /** Markers that matched (for audit trail) */
  matchedMarkers: string[];

  /** Total marker count */
  markerCount: number;

  /** Strong marker count */
  strongMarkerCount: number;
}

/**
 * Marker definition with strength classification.
 */
interface MarkerDefinition {
  /** Regex pattern for the marker */
  pattern: RegExp;

  /** Human-readable label for audit trail */
  label: string;

  /** Whether this is a strong marker */
  isStrong: boolean;

  /** Language tag (for future expansion) */
  lang?: 'en' | 'da' | 'sv' | 'no' | 'de' | 'es' | 'fr' | 'pt' | 'multi';
}

/**
 * Archetype definition with markers and thresholds.
 */
interface ArchetypeDefinition {
  /** Archetype identifier */
  id: DocumentArchetypeId;

  /** Human-readable name */
  name: string;

  /** Markers for this archetype */
  markers: MarkerDefinition[];

  /** Detection thresholds */
  thresholds: {
    /** Minimum strong markers for strong confidence */
    minStrong: number;
    /** Minimum total markers for weak confidence */
    minTotal: number;
    /** Minimum total markers for strong confidence (if minStrong not met) */
    minTotalForStrong: number;
  };
}

// ============================================================================
// ARCHETYPE DEFINITIONS (V1 - Minimal marker sets for schema wiring)
// ============================================================================

/**
 * Resume/CV archetype markers.
 * Note: Existing RESUME_CONTEXT_MARKERS in documentClassAnchors.ts handle M&A veto.
 * These markers complement that detection and provide archetype classification.
 */
const RESUME_CV_MARKERS: MarkerDefinition[] = [
  // Strong markers - highly specific to resumes
  { pattern: /\bcurriculum\s*vitae\b/i, label: 'curriculum vitae', isStrong: true, lang: 'en' },
  { pattern: /\bresume\b/i, label: 'resume', isStrong: true, lang: 'en' },
  { pattern: /\b(?:cv|c\.v\.)\b/i, label: 'CV', isStrong: true, lang: 'multi' },
  { pattern: /\blebenslauf\b/i, label: 'Lebenslauf', isStrong: true, lang: 'de' },
  // AG-PHASE-5E-064: Unicode-safe boundaries for non-ASCII
  { pattern: /(?<!\p{L})meritförteckning(?!\p{L})/iu, label: 'meritförteckning', isStrong: true, lang: 'sv' },
  // AG-PROMPT-154: Portuguese/Spanish/French resume markers
  { pattern: /(?<!\p{L})currículo(?!\p{L})/iu, label: 'currículo', isStrong: true, lang: 'pt' },
  { pattern: /\bhoja\s+de\s+vida\b/i, label: 'hoja de vida', isStrong: true, lang: 'es' },

  // Weak markers - common in resumes but not exclusive
  { pattern: /\bwork\s+experience\b/i, label: 'work experience', isStrong: false, lang: 'en' },
  { pattern: /\beducation\b/i, label: 'education', isStrong: false, lang: 'en' },
  { pattern: /\bskills?\b/i, label: 'skills', isStrong: false, lang: 'en' },
  { pattern: /\bprofessional\s+(?:summary|profile)\b/i, label: 'professional summary', isStrong: false, lang: 'en' },
  { pattern: /\bemployment\s+history\b/i, label: 'employment history', isStrong: false, lang: 'en' },
  { pattern: /\bberufserfahrung\b/i, label: 'Berufserfahrung', isStrong: false, lang: 'de' },
  { pattern: /\bausbildung\b/i, label: 'Ausbildung', isStrong: false, lang: 'de' },
  { pattern: /\barbejdserfaring\b/i, label: 'arbejdserfaring', isStrong: false, lang: 'da' },
  { pattern: /\buddannelse\b/i, label: 'uddannelse', isStrong: false, lang: 'da' },
  // AG-PROMPT-154: Portuguese/Spanish/French weak markers
  { pattern: /(?<!\p{L})experiência\s+profissional(?!\p{L})/iu, label: 'experiência profissional', isStrong: false, lang: 'pt' },
  { pattern: /(?<!\p{L})formação(?!\p{L})/iu, label: 'formação', isStrong: false, lang: 'pt' },
  { pattern: /(?<!\p{L})habilidades(?!\p{L})/iu, label: 'habilidades', isStrong: false, lang: 'pt' },
  { pattern: /(?<!\p{L})competências(?!\p{L})/iu, label: 'competências', isStrong: false, lang: 'pt' },
  { pattern: /\bexperiencia\s+laboral\b/i, label: 'experiencia laboral', isStrong: false, lang: 'es' },
  { pattern: /(?<!\p{L})formación(?!\p{L})/iu, label: 'formación', isStrong: false, lang: 'es' },
  { pattern: /(?<!\p{L})expérience\s+professionnelle(?!\p{L})/iu, label: 'expérience professionnelle', isStrong: false, lang: 'fr' },
];

/**
 * Ticket/Booking archetype markers.
 * Note: Existing TICKET_CONTEXT_MARKERS in documentClassAnchors.ts handle suppression.
 * These markers provide archetype classification evidence.
 */
const TICKET_BOOKING_MARKERS: MarkerDefinition[] = [
  // Strong markers - highly specific to tickets/bookings
  { pattern: /\bboarding\s*pass\b/i, label: 'boarding pass', isStrong: true, lang: 'en' },
  { pattern: /\be-?ticket\b/i, label: 'e-ticket', isStrong: true, lang: 'en' },
  { pattern: /\bbooking\s*(?:ref|reference|confirmation)\b/i, label: 'booking reference', isStrong: true, lang: 'en' },
  { pattern: /\btarjeta\s+de\s+embarque\b/i, label: 'tarjeta de embarque', isStrong: true, lang: 'es' },
  { pattern: /\bflugschein\b/i, label: 'Flugschein', isStrong: true, lang: 'de' },

  // Weak markers - common in tickets but could appear elsewhere
  { pattern: /\bflight\s*(?:number|no\.?|#)\b/i, label: 'flight number', isStrong: false, lang: 'en' },
  { pattern: /\bgate\s*[:#]?\s*[A-Z]?\d+\b/i, label: 'gate', isStrong: false, lang: 'en' },
  { pattern: /\bseat\s*[:#]?\s*\d+[A-Z]?\b/i, label: 'seat', isStrong: false, lang: 'en' },
  { pattern: /\bpassenger\b/i, label: 'passenger', isStrong: false, lang: 'en' },
  { pattern: /\bdeparture\b/i, label: 'departure', isStrong: false, lang: 'en' },
  { pattern: /\barrival\b/i, label: 'arrival', isStrong: false, lang: 'en' },
  { pattern: /\breservation\b/i, label: 'reservation', isStrong: false, lang: 'en' },
  { pattern: /\bbillet\b/i, label: 'billet', isStrong: false, lang: 'da' },
  { pattern: /\bbiljett\b/i, label: 'biljett', isStrong: false, lang: 'sv' },
];

/**
 * Invoice/Receipt archetype markers.
 */
const INVOICE_RECEIPT_MARKERS: MarkerDefinition[] = [
  // Strong markers
  { pattern: /\binvoice\s*(?:number|no\.?|#)\b/i, label: 'invoice number', isStrong: true, lang: 'en' },
  { pattern: /\breceipt\s*(?:number|no\.?|#)\b/i, label: 'receipt number', isStrong: true, lang: 'en' },
  { pattern: /\bfaktura(?:nummer)?\b/i, label: 'faktura', isStrong: true, lang: 'da' },
  { pattern: /\brechnung(?:snummer)?\b/i, label: 'Rechnung', isStrong: true, lang: 'de' },
  { pattern: /\bfactura\b/i, label: 'factura', isStrong: true, lang: 'es' },

  // Weak markers
  { pattern: /\btotal\s*(?:amount|due)\b/i, label: 'total amount', isStrong: false, lang: 'en' },
  { pattern: /\bsubtotal\b/i, label: 'subtotal', isStrong: false, lang: 'en' },
  { pattern: /\bvat\b/i, label: 'VAT', isStrong: false, lang: 'en' },
  { pattern: /\bmoms\b/i, label: 'moms', isStrong: false, lang: 'da' },
  { pattern: /\bpayment\s*(?:due|terms)\b/i, label: 'payment terms', isStrong: false, lang: 'en' },
  { pattern: /\bdue\s*date\b/i, label: 'due date', isStrong: false, lang: 'en' },
  { pattern: /\bitem\s*description\b/i, label: 'item description', isStrong: false, lang: 'en' },
  { pattern: /(?<!\p{L})beløb(?!\p{L})/iu, label: 'beløb', isStrong: false, lang: 'da' },
];

/**
 * Medical Record archetype markers.
 * Note: Complements existing MEDICAL_RECORD_INDICATORS in documentClassAnchors.ts.
 */
const MEDICAL_RECORD_MARKERS: MarkerDefinition[] = [
  // Strong markers - highly specific to medical records
  { pattern: /\bpatient\s*(?:record|journal|id)\b/i, label: 'patient record', isStrong: true, lang: 'en' },
  { pattern: /\bmedical\s*record\b/i, label: 'medical record', isStrong: true, lang: 'en' },
  { pattern: /\blab\s*result\b/i, label: 'lab result', isStrong: true, lang: 'en' },
  { pattern: /\bpatientjournal\b/i, label: 'patientjournal', isStrong: true, lang: 'da' },
  { pattern: /\blaboratoriesvar\b/i, label: 'laboratoriesvar', isStrong: true, lang: 'da' },
  { pattern: /\bepikrise\b/i, label: 'epikrise', isStrong: true, lang: 'da' },

  // Weak markers
  { pattern: /\bdiagnosis\b/i, label: 'diagnosis', isStrong: false, lang: 'en' },
  { pattern: /\bprescription\b/i, label: 'prescription', isStrong: false, lang: 'en' },
  { pattern: /\bmedication\b/i, label: 'medication', isStrong: false, lang: 'en' },
  { pattern: /\btreatment\b/i, label: 'treatment', isStrong: false, lang: 'en' },
  { pattern: /\bprognosis\b/i, label: 'prognosis', isStrong: false, lang: 'en' },
  { pattern: /(?<!\p{L})blodprøve(?!\p{L})/iu, label: 'blodprøve', isStrong: false, lang: 'da' },
  { pattern: /(?<!\p{L})undersøgelse(?!\p{L})/iu, label: 'undersøgelse', isStrong: false, lang: 'da' },
];

/**
 * Legal/Authority archetype markers.
 */
const LEGAL_AUTHORITY_MARKERS: MarkerDefinition[] = [
  // Strong markers
  { pattern: /\bpower\s+of\s+attorney\b/i, label: 'power of attorney', isStrong: true, lang: 'en' },
  { pattern: /\blegal\s+notice\b/i, label: 'legal notice', isStrong: true, lang: 'en' },
  { pattern: /\bnotarized\b/i, label: 'notarized', isStrong: true, lang: 'en' },
  { pattern: /\bfuldmagt\b/i, label: 'fuldmagt', isStrong: true, lang: 'da' },
  { pattern: /\bvollmacht\b/i, label: 'Vollmacht', isStrong: true, lang: 'de' },
  { pattern: /\bpoder\s+notarial\b/i, label: 'poder notarial', isStrong: true, lang: 'es' },

  // Weak markers
  { pattern: /\bhereby\s+(?:authorize|grant|certify)\b/i, label: 'hereby authorize', isStrong: false, lang: 'en' },
  { pattern: /\bwitness(?:ed)?\s+(?:by|signature)\b/i, label: 'witnessed', isStrong: false, lang: 'en' },
  { pattern: /\bauthorized\s+(?:representative|signatory)\b/i, label: 'authorized representative', isStrong: false, lang: 'en' },
  { pattern: /\blegally\s+binding\b/i, label: 'legally binding', isStrong: false, lang: 'en' },
  { pattern: /\baffidavit\b/i, label: 'affidavit', isStrong: false, lang: 'en' },
  { pattern: /\bdeclaration\b/i, label: 'declaration', isStrong: false, lang: 'en' },
  { pattern: /\bunderskrift\b/i, label: 'underskrift', isStrong: false, lang: 'da' },
];

// ============================================================================
// V2 ARCHETYPE MARKERS
// ============================================================================

/**
 * Employment/HR archetype markers (v2).
 * Internal HR documents not intended for public distribution.
 */
const EMPLOYMENT_HR_MARKERS: MarkerDefinition[] = [
  // Strong markers - highly specific to internal HR
  { pattern: /\bemployee\s+(?:record|file|handbook)\b/i, label: 'employee record', isStrong: true, lang: 'en' },
  { pattern: /\bhr\s+(?:record|file|document)\b/i, label: 'HR record', isStrong: true, lang: 'en' },
  { pattern: /\bperformance\s+(?:review|evaluation|appraisal)\b/i, label: 'performance review', isStrong: true, lang: 'en' },
  { pattern: /\bsalary\s+(?:slip|statement|details)\b/i, label: 'salary slip', isStrong: true, lang: 'en' },
  { pattern: /(?<!\p{L})lønbesked(?!\p{L})/iu, label: 'lønbesked', isStrong: true, lang: 'da' },
  { pattern: /\bgehaltsabrechnung\b/i, label: 'Gehaltsabrechnung', isStrong: true, lang: 'de' },

  // Weak markers
  { pattern: /\bcompensation\b/i, label: 'compensation', isStrong: false, lang: 'en' },
  { pattern: /\bbonus\b/i, label: 'bonus', isStrong: false, lang: 'en' },
  { pattern: /\btermination\b/i, label: 'termination', isStrong: false, lang: 'en' },
  { pattern: /\bprobation(?:ary)?\b/i, label: 'probation', isStrong: false, lang: 'en' },
  { pattern: /\bemployment\s+contract\b/i, label: 'employment contract', isStrong: false, lang: 'en' },
  { pattern: /(?<!\p{L})ansættelseskontrakt(?!\p{L})/iu, label: 'ansættelseskontrakt', isStrong: false, lang: 'da' },
  { pattern: /\barbeitsvertrag\b/i, label: 'Arbeitsvertrag', isStrong: false, lang: 'de' },
];

/**
 * Insurance archetype markers (v2).
 * Insurance documents with variable sensitivity.
 */
const INSURANCE_MARKERS: MarkerDefinition[] = [
  // Strong markers
  { pattern: /\binsurance\s+(?:policy|certificate|claim)\b/i, label: 'insurance policy', isStrong: true, lang: 'en' },
  { pattern: /\bpolicy\s+(?:number|holder)\b/i, label: 'policy number', isStrong: true, lang: 'en' },
  { pattern: /\bforsikringspolice\b/i, label: 'forsikringspolice', isStrong: true, lang: 'da' },
  { pattern: /\bversicherungspolice\b/i, label: 'Versicherungspolice', isStrong: true, lang: 'de' },
  { pattern: /(?<!\p{L})póliza\s+de\s+seguro(?!\p{L})/iu, label: 'póliza de seguro', isStrong: true, lang: 'es' },

  // Weak markers
  { pattern: /\bpremium\b/i, label: 'premium', isStrong: false, lang: 'en' },
  { pattern: /\bcoverage\b/i, label: 'coverage', isStrong: false, lang: 'en' },
  { pattern: /\bdeductible\b/i, label: 'deductible', isStrong: false, lang: 'en' },
  { pattern: /\bclaim\b/i, label: 'claim', isStrong: false, lang: 'en' },
  { pattern: /\bbeneficiary\b/i, label: 'beneficiary', isStrong: false, lang: 'en' },
  { pattern: /\bselvrisiko\b/i, label: 'selvrisiko', isStrong: false, lang: 'da' },
];

/**
 * Education/School archetype markers (v2).
 * Educational records, often involving minors.
 */
const EDUCATION_SCHOOL_MARKERS: MarkerDefinition[] = [
  // Strong markers
  { pattern: /\bstudent\s+(?:record|file|transcript)\b/i, label: 'student record', isStrong: true, lang: 'en' },
  { pattern: /\bacademic\s+(?:record|transcript)\b/i, label: 'academic record', isStrong: true, lang: 'en' },
  { pattern: /\breport\s+card\b/i, label: 'report card', isStrong: true, lang: 'en' },
  { pattern: /\bschool\s+(?:record|report)\b/i, label: 'school record', isStrong: true, lang: 'en' },
  { pattern: /\belevjournal\b/i, label: 'elevjournal', isStrong: true, lang: 'da' },
  { pattern: /\bzeugnis\b/i, label: 'Zeugnis', isStrong: true, lang: 'de' },

  // Weak markers
  { pattern: /\benrollment\b/i, label: 'enrollment', isStrong: false, lang: 'en' },
  { pattern: /\bgrade\s*(?:s|point)\b/i, label: 'grades', isStrong: false, lang: 'en' },
  { pattern: /\battendance\b/i, label: 'attendance', isStrong: false, lang: 'en' },
  { pattern: /\bparent(?:s)?(?:'s)?\s+(?:consent|signature)\b/i, label: 'parent consent', isStrong: false, lang: 'en' },
  { pattern: /\bguardian\b/i, label: 'guardian', isStrong: false, lang: 'en' },
  { pattern: /(?<!\p{L})skoleudtalelse(?!\p{L})/iu, label: 'skoleudtalelse', isStrong: false, lang: 'da' },
];

/**
 * Template/Governance archetype markers (v3, AG-PROMPT-155).
 * GDPR ROPA inventories, privacy policies, data processing agreements,
 * security questionnaires, and compliance templates. These documents
 * describe what data is processed but do not contain actual personal data.
 */
const TEMPLATE_GOVERNANCE_MARKERS: MarkerDefinition[] = [
  // Strong markers - highly specific to governance/template/form documents
  // GDPR/privacy governance
  { pattern: /\brecord\s+of\s+processing\s+activit(?:y|ies)\b/i, label: 'record of processing activities', isStrong: true, lang: 'en' },
  { pattern: /\bropa\b/i, label: 'ROPA', isStrong: true, lang: 'en' },
  { pattern: /\bdata\s+processing\s+(?:agreement|inventory|register)\b/i, label: 'data processing agreement/inventory', isStrong: true, lang: 'en' },
  { pattern: /\bprivacy\s+(?:impact\s+assessment|policy|notice)\b/i, label: 'privacy impact/policy/notice', isStrong: true, lang: 'en' },
  { pattern: /\bdata\s+protection\s+(?:impact\s+assessment|officer|policy)\b/i, label: 'data protection impact/officer/policy', isStrong: true, lang: 'en' },
  // Questionnaire/assessment forms
  { pattern: /\bsecurity\s+questionnaire\b/i, label: 'security questionnaire', isStrong: true, lang: 'en' },
  { pattern: /\bvendor\s+(?:assessment|questionnaire|evaluation)\b/i, label: 'vendor assessment', isStrong: true, lang: 'en' },
  { pattern: /\bcompliance\s+(?:questionnaire|checklist|template)\b/i, label: 'compliance questionnaire', isStrong: true, lang: 'en' },
  // HR template/form indicators (blank form structure, not filled-in data)
  { pattern: /\bperformance\s+evaluation\s+(?:overview|form|template)\b/i, label: 'performance evaluation form', isStrong: true, lang: 'en' },
  { pattern: /\btalent\s+development\s+(?:information|plan|template)\b/i, label: 'talent development template', isStrong: true, lang: 'en' },

  // Weak markers - common in governance/template docs but not exclusive
  { pattern: /\bdata\s+controller\b/i, label: 'data controller', isStrong: false, lang: 'en' },
  { pattern: /\bdata\s+processor\b/i, label: 'data processor', isStrong: false, lang: 'en' },
  { pattern: /\bdata\s+subject\b/i, label: 'data subject', isStrong: false, lang: 'en' },
  { pattern: /\bprocessing\s+activit(?:y|ies)\b/i, label: 'processing activity', isStrong: false, lang: 'en' },
  { pattern: /\blegal\s+basis\b/i, label: 'legal basis', isStrong: false, lang: 'en' },
  { pattern: /\bretention\s+period\b/i, label: 'retention period', isStrong: false, lang: 'en' },
  { pattern: /\bgdpr\b/i, label: 'GDPR', isStrong: false, lang: 'en' },
  { pattern: /\barticle\s+(?:6|9|13|14|15|30)\b/i, label: 'GDPR article reference', isStrong: false, lang: 'en' },
  { pattern: /\bpurpose\s+of\s+processing\b/i, label: 'purpose of processing', isStrong: false, lang: 'en' },
  { pattern: /\bcategories\s+of\s+(?:data|recipients)\b/i, label: 'categories of data/recipients', isStrong: false, lang: 'en' },
  // Form structure indicators
  { pattern: /\bmanager'?s?\s+signature\b/i, label: 'manager signature field', isStrong: false, lang: 'en' },
  { pattern: /\b(?:below|meet|exceed)\s+expectations\b/i, label: 'evaluation scale', isStrong: false, lang: 'en' },
  { pattern: /\bgoal\s+setting\b/i, label: 'goal setting', isStrong: false, lang: 'en' },
];

/**
 * AG-PROMPT-162 (3A): Contract carve-out markers.
 * Documents matching these are contracts/NDAs, NOT policies/standards.
 * If strong contract markers are present, policy_standard is suppressed.
 */
const CONTRACT_CARVEOUT_MARKERS = [
  /\bwhereas\b/i,
  /\bhereby\b/i,
  /\bindemnif(?:y|ies|ication)\b/i,
  /\bgoverning\s+law\b/i,
  /\bparty\s+[ab]\b/i,
  /\b(?:first|second)\s+party\b/i,
  /\b(?:executed|signed|witnessed)\s+(?:by|on|this)\b/i,
  /\bnon[\s-]*disclosure\s+agreement\b/i,
];

/**
 * AG-PROMPT-162 (3A): Policy/Standard document archetype markers.
 * Policies, standards, procedures, guidelines, and SOPs.
 * These documents describe rules and controls, not personal data.
 */
const POLICY_STANDARD_MARKERS: MarkerDefinition[] = [
  // Strong markers - highly specific to policy/standard documents
  // AG-PROMPT-165/WS-03: plural forms added where safe
  { pattern: /\b(?:information\s+)?security\s+polic(?:y|ies)\b/i, label: 'security policy', isStrong: true, lang: 'en' },
  { pattern: /\bdata\s+(?:classification|handling)\s+(?:polic(?:y|ies)|standards?|procedures?)\b/i, label: 'data classification policy', isStrong: true, lang: 'en' },
  { pattern: /\bacceptable\s+use\s+polic(?:y|ies)\b/i, label: 'acceptable use policy', isStrong: true, lang: 'en' },
  { pattern: /\bstandard\s+operating\s+procedures?\b/i, label: 'SOP', isStrong: true, lang: 'en' },
  { pattern: /\b(?:policy|procedure)\s+(?:number|no|ref|id)\s*[:.]?\s*\w/i, label: 'policy number', isStrong: true, lang: 'en' },
  { pattern: /\bdocument\s+(?:owner|approver|reviewer)\b/i, label: 'document control metadata', isStrong: true, lang: 'en' },
  { pattern: /\beffective\s+date\b.*\b(?:review|expir|revis)/i, label: 'policy lifecycle dates', isStrong: true, lang: 'en' },
  { pattern: /\bversion\s+(?:history|control)\b/i, label: 'version history', isStrong: true, lang: 'en' },
  { pattern: /\bcompliance\s+(?:polic(?:y|ies)|standards?|frameworks?|requirements?)\b/i, label: 'compliance framework', isStrong: true, lang: 'en' },
  { pattern: /\b(?:iso|nist|soc)\s*[\s-]*\d/i, label: 'standard reference', isStrong: true, lang: 'en' },

  // Weak markers - common in policy docs but not exclusive
  { pattern: /\bcontrol(?:s)?\b/i, label: 'control', isStrong: false, lang: 'en' },
  { pattern: /\b(?:safeguards?|countermeasures?|mitigations?)\b/i, label: 'safeguard/mitigation', isStrong: false, lang: 'en' },
  { pattern: /\brisk\s+(?:assessments?|analy(?:sis|ses)|registers?|treatments?)\b/i, label: 'risk assessment', isStrong: false, lang: 'en' },
  { pattern: /\bauthori[sz]ed\b/i, label: 'authorized', isStrong: false, lang: 'en' },
  { pattern: /\bunauthori[sz]ed\b/i, label: 'unauthorized', isStrong: false, lang: 'en' },
  { pattern: /\b(?:shall|must)\s+(?:not\s+)?(?:be|comply|ensure|maintain|report)\b/i, label: 'obligation language', isStrong: false, lang: 'en' },
  { pattern: /\bsection\s+\d+(?:\.\d+)*\b/i, label: 'section numbering', isStrong: false, lang: 'en' },
  { pattern: /\bscope\s+(?:of\s+)?(?:this|the)\s+(?:polic(?:y|ies)|standards?|procedures?|documents?)\b/i, label: 'scope statement', isStrong: false, lang: 'en' },
];

/**
 * AG-PROMPT-162 (Area 1): Clinical reference archetype markers.
 * Clinical guidelines, formularies, therapeutic references, and medical
 * reference material. These describe clinical knowledge, NOT patient data.
 */
const CLINICAL_REFERENCE_MARKERS: MarkerDefinition[] = [
  // Strong markers - highly specific to clinical reference material
  // AG-PROMPT-165/WS-03: plural forms added where safe (s? suffix)
  { pattern: /\bclinical\s+(?:guidelines?|pathways?|practice\s+guidelines?)\b/i, label: 'clinical guideline', isStrong: true, lang: 'en' },
  { pattern: /\bformular(?:y|ies)\b/i, label: 'formulary', isStrong: true, lang: 'en' },
  { pattern: /\btherapeutic\s+(?:class(?:es)?|categor(?:y|ies)|areas?|groups?)\b/i, label: 'therapeutic class', isStrong: true, lang: 'en' },
  { pattern: /\bevidence[\s-]+based\s+(?:medicine|practices?|recommendations?|guidelines?)\b/i, label: 'evidence-based', isStrong: true, lang: 'en' },
  { pattern: /\brecommendations?\s+(?:grades?|strengths?|levels?)\b/i, label: 'recommendation grade', isStrong: true, lang: 'en' },
  { pattern: /\bpharmacokinetics?\b/i, label: 'pharmacokinetics', isStrong: true, lang: 'en' },
  { pattern: /\bpharmacology\b/i, label: 'pharmacology', isStrong: true, lang: 'en' },

  // Weak markers - common in reference material
  { pattern: /\bsystematic\s+reviews?\b/i, label: 'systematic review', isStrong: false, lang: 'en' },
  { pattern: /\bmeta[\s-]*analy(?:sis|ses)\b/i, label: 'meta-analysis', isStrong: false, lang: 'en' },
  { pattern: /\bclinical\s+trials?\b/i, label: 'clinical trial', isStrong: false, lang: 'en' },
  { pattern: /\bdosages?\b/i, label: 'dosage', isStrong: false, lang: 'en' },
  { pattern: /\badministration\s+(?:routes?|forms?|methods?)\b/i, label: 'administration route', isStrong: false, lang: 'en' },
  { pattern: /\bdrug\s+interactions?\b/i, label: 'drug interaction', isStrong: false, lang: 'en' },
  { pattern: /\b(?:etiology|pathogenesis|epidemiology)\b/i, label: 'etiology/pathogenesis', isStrong: false, lang: 'en' },
  { pattern: /\bcontraindications?\b/i, label: 'contraindication', isStrong: false, lang: 'en' },
];

/**
 * AG-PROMPT-162-2A: Aggregate HR/finance markers.
 * Identifies documents with aggregate/summary data (headcounts, budget totals,
 * department summaries) rather than individual employee/payroll records.
 * Used to cap severity when no individual PII is present.
 */
const AGGREGATE_HR_FINANCE_MARKERS: MarkerDefinition[] = [
  // Strong markers - highly specific to aggregate/summary reports
  { pattern: /\bheadcount\b/i, label: 'headcount', isStrong: true, lang: 'en' },
  { pattern: /\b(?:total|aggregate)\s+(?:employees?|staff|fte|headcount)\b/i, label: 'aggregate employees', isStrong: true, lang: 'en' },
  { pattern: /\bdepartment\s+(?:summary|overview|breakdown|report)\b/i, label: 'department summary', isStrong: true, lang: 'en' },
  { pattern: /\bbudget\s+(?:summary|overview|allocation|forecast)\b/i, label: 'budget summary', isStrong: true, lang: 'en' },
  { pattern: /\b(?:annual|quarterly|monthly)\s+(?:report|review|summary)\b/i, label: 'periodic report', isStrong: true, lang: 'en' },
  { pattern: /\bworkforce\s+(?:planning|analytics?|metrics?|dashboard)\b/i, label: 'workforce planning', isStrong: true, lang: 'en' },
  { pattern: /\b(?:turnover|attrition|retention)\s+rate\b/i, label: 'turnover rate', isStrong: true, lang: 'en' },
  { pattern: /\borgani[sz]ational?\s+(?:chart|structure|overview)\b/i, label: 'org structure', isStrong: true, lang: 'en' },

  // Weak markers - common in aggregate/summary context
  { pattern: /\bkpi\b/i, label: 'KPI', isStrong: false, lang: 'en' },
  { pattern: /\b(?:total|average|median)\s+(?:salary|compensation|cost)\b/i, label: 'aggregate salary', isStrong: false, lang: 'en' },
  { pattern: /\byear[\s-]+over[\s-]+year\b/i, label: 'YoY', isStrong: false, lang: 'en' },
  { pattern: /\bfiscal\s+year\b/i, label: 'fiscal year', isStrong: false, lang: 'en' },
  { pattern: /\b(?:cost\s+per\s+hire|recruitment\s+cost)\b/i, label: 'cost per hire', isStrong: false, lang: 'en' },
  { pattern: /\boperating\s+(?:expenses?|budget|costs?)\b/i, label: 'operating expenses', isStrong: false, lang: 'en' },
  { pattern: /\bforecast\b/i, label: 'forecast', isStrong: false, lang: 'en' },
  { pattern: /\bboard\s+(?:report|presentation|deck|summary)\b/i, label: 'board report', isStrong: false, lang: 'en' },
];

/**
 * All archetype definitions.
 */
const ARCHETYPE_DEFINITIONS: ArchetypeDefinition[] = [
  // v1 archetypes
  {
    id: 'resume_cv',
    name: 'Resume/CV',
    markers: RESUME_CV_MARKERS,
    thresholds: { minStrong: 1, minTotal: 2, minTotalForStrong: 4 },
  },
  {
    id: 'ticket_booking',
    name: 'Ticket/Booking',
    markers: TICKET_BOOKING_MARKERS,
    thresholds: { minStrong: 1, minTotal: 2, minTotalForStrong: 4 },
  },
  {
    id: 'invoice_receipt',
    name: 'Invoice/Receipt',
    markers: INVOICE_RECEIPT_MARKERS,
    thresholds: { minStrong: 1, minTotal: 2, minTotalForStrong: 4 },
  },
  {
    id: 'medical_record',
    name: 'Medical Record',
    markers: MEDICAL_RECORD_MARKERS,
    thresholds: { minStrong: 1, minTotal: 2, minTotalForStrong: 4 },
  },
  {
    id: 'legal_authority',
    name: 'Legal/Authority',
    markers: LEGAL_AUTHORITY_MARKERS,
    thresholds: { minStrong: 1, minTotal: 2, minTotalForStrong: 4 },
  },
  // v2 archetypes
  {
    id: 'medical_health',
    name: 'Medical/Health',
    markers: MEDICAL_RECORD_MARKERS,  // Same markers as medical_record
    thresholds: { minStrong: 1, minTotal: 2, minTotalForStrong: 4 },
  },
  {
    id: 'employment_hr',
    name: 'Employment/HR',
    markers: EMPLOYMENT_HR_MARKERS,
    thresholds: { minStrong: 1, minTotal: 2, minTotalForStrong: 4 },
  },
  {
    id: 'insurance',
    name: 'Insurance',
    markers: INSURANCE_MARKERS,
    thresholds: { minStrong: 1, minTotal: 2, minTotalForStrong: 4 },
  },
  {
    id: 'education_school',
    name: 'Education/School',
    markers: EDUCATION_SCHOOL_MARKERS,
    thresholds: { minStrong: 1, minTotal: 2, minTotalForStrong: 4 },
  },
  // v3 archetypes (AG-PROMPT-155)
  {
    id: 'template_governance',
    name: 'Template/Governance',
    markers: TEMPLATE_GOVERNANCE_MARKERS,
    thresholds: { minStrong: 1, minTotal: 3, minTotalForStrong: 5 },
  },
  // v4 archetypes (AG-PROMPT-162)
  {
    id: 'policy_standard',
    name: 'Policy/Standard',
    markers: POLICY_STANDARD_MARKERS,
    thresholds: { minStrong: 1, minTotal: 3, minTotalForStrong: 5 },
  },
  {
    id: 'clinical_reference',
    name: 'Clinical Reference',
    markers: CLINICAL_REFERENCE_MARKERS,
    thresholds: { minStrong: 1, minTotal: 3, minTotalForStrong: 5 },
  },
  {
    id: 'aggregate_hr_finance',
    name: 'Aggregate HR/Finance',
    markers: AGGREGATE_HR_FINANCE_MARKERS,
    thresholds: { minStrong: 2, minTotal: 4, minTotalForStrong: 6 },
  },
];

// ============================================================================
// ALLOWED EFFECTS MATRIX
// ============================================================================

/**
 * Allowed effects for each archetype.
 * This is the authoritative matrix of what each archetype MAY affect.
 *
 * HARD RULE: No archetype may suppress identity, national-id, email, phone, or payment signals.
 */
export interface ArchetypeAllowedEffects {
  /** Can this archetype veto M&A signals? */
  mayVetoMA: boolean;

  /** Can this archetype suppress banking noise (via existing ticket suppressor)? */
  mayUseBankingSuppressor: boolean;

  /** Can this archetype suppress generic keyword signals (HR, M&A, financial)? AG-PROMPT-155 */
  mayVetoGenericKeywords: boolean;

  /**
   * AG-PROMPT-162-2A: Can this archetype cap severity?
   * When true and no protected PII signals are present, severity is capped
   * at severityCap to prevent over-alerting on aggregate/summary documents.
   */
  mayCapSeverity?: boolean;

  /** Maximum severity when mayCapSeverity is active (default: 'medium') */
  severityCap?: 'low' | 'medium' | 'high';

  /**
   * AG-PROMPT-187: Allowlist of document classes this archetype may suppress.
   * When a strong archetype match fires and the assigned document class is in
   * this list, the class is nulled out. This affects only class outcome and
   * downstream frame selection — protected signals and severity are untouched.
   */
  mayVetoClasses?: string[];

  /** Framing hint for this archetype */
  framingHint: string;

  /** Classification hint for this archetype */
  classificationHint: string;
}

/**
 * Effects matrix - defines what each archetype is allowed to do.
 */
export const ARCHETYPE_EFFECTS_MATRIX: Record<DocumentArchetypeId, ArchetypeAllowedEffects> = {
  // v1 archetypes
  resume_cv: {
    mayVetoMA: true,  // Existing behavior - veto M&A signals like "talent acquisition"
    mayUseBankingSuppressor: false,
    mayVetoGenericKeywords: false,
    framingHint: 'personal document',
    classificationHint: 'Personal career document',
  },
  ticket_booking: {
    mayVetoMA: false,
    mayUseBankingSuppressor: true,  // Defer to existing ticket suppressor with scam safety hatch
    mayVetoGenericKeywords: false,
    framingHint: 'transaction/booking document',
    classificationHint: 'Travel or event booking',
  },
  invoice_receipt: {
    mayVetoMA: false,
    mayUseBankingSuppressor: false,
    mayVetoGenericKeywords: false,
    mayVetoClasses: ['doc.legal_contract'],  // AG-PROMPT-187: Invoices are not legal contracts
    framingHint: 'financial transaction document',
    classificationHint: 'Invoice or receipt',
  },
  medical_record: {
    mayVetoMA: false,
    mayUseBankingSuppressor: false,
    mayVetoGenericKeywords: false,
    framingHint: 'medical document',
    classificationHint: 'Clinical or health record',
  },
  legal_authority: {
    mayVetoMA: false,
    mayUseBankingSuppressor: false,
    mayVetoGenericKeywords: false,
    framingHint: 'legal document',
    classificationHint: 'Legal or authority document',
  },
  // v2 archetypes
  medical_health: {
    mayVetoMA: false,
    mayUseBankingSuppressor: false,
    mayVetoGenericKeywords: false,
    framingHint: 'medical document',
    classificationHint: 'Health or medical record',
  },
  employment_hr: {
    mayVetoMA: false,
    mayUseBankingSuppressor: false,
    mayVetoGenericKeywords: false,
    framingHint: 'internal HR document',
    classificationHint: 'Internal employment record',
  },
  insurance: {
    mayVetoMA: false,
    mayUseBankingSuppressor: false,
    mayVetoGenericKeywords: false,
    framingHint: 'insurance document',
    classificationHint: 'Insurance policy or claim',
  },
  education_school: {
    mayVetoMA: false,
    mayUseBankingSuppressor: false,
    mayVetoGenericKeywords: false,
    mayVetoClasses: ['doc.hr_record'],  // AG-PROMPT-187: Educational content about employment is not HR
    framingHint: 'educational document',
    classificationHint: 'Educational or school record',
  },
  // v3 archetypes (AG-PROMPT-155)
  template_governance: {
    mayVetoMA: true,  // "due diligence" etc. are generic in governance context
    mayUseBankingSuppressor: false,
    mayVetoGenericKeywords: true,  // suppress HR/financial noise on template/inventory docs
    mayVetoClasses: ['doc.hr_record', 'doc.legal_contract'],  // AG-PROMPT-187: Governance templates are not HR/legal records
    framingHint: 'governance/compliance template',
    classificationHint: 'Data processing inventory, privacy policy, or compliance questionnaire',
  },
  // v4 archetypes (AG-PROMPT-162)
  policy_standard: {
    mayVetoMA: true,   // "due diligence", "acquisition" are generic in policy context
    mayUseBankingSuppressor: false,
    mayVetoGenericKeywords: true,  // suppress HR/financial/medical/M&A noise keywords
    mayVetoClasses: ['doc.hr_record', 'doc.legal_contract'],  // AG-PROMPT-187: Policies are not HR/legal records
    framingHint: 'policy/standard document',
    classificationHint: 'Policy, standard, procedure, or guideline',
  },
  clinical_reference: {
    mayVetoMA: false,
    mayUseBankingSuppressor: false,
    mayVetoGenericKeywords: false,
    mayVetoClasses: ['doc.medical_record'],  // AG-PROMPT-187: Clinical references are not patient records
    framingHint: 'clinical reference material',
    classificationHint: 'Clinical guideline, formulary, or medical reference',
  },
  aggregate_hr_finance: {
    mayVetoMA: false,
    mayUseBankingSuppressor: false,
    mayVetoGenericKeywords: true,   // suppress generic HR/financial noise in aggregate reports
    mayCapSeverity: true,
    severityCap: 'medium',
    framingHint: 'aggregate/summary report',
    classificationHint: 'Aggregate HR, finance, or workforce report',
  },
};

/**
 * Signal IDs that MUST NEVER be suppressed by any archetype.
 * This is a safety guard against accidental identity suppression.
 */
export const PROTECTED_SIGNAL_IDS = new Set([
  // National IDs
  'global-national-id',
  'global-dk-cpr',
  'global-se-personnummer',
  'global-no-fnr',
  'global-fi-hetu',             // AG-PROMPT-190: Finnish HETU (was missing)
  'registry-dk-cpr',
  'registry-se-personnummer',
  'registry-no-fnr',            // AG-PROMPT-190: Norwegian FNR legacy alias (was missing)
  'registry-fi-hetu',           // AG-PROMPT-190: Finnish HETU legacy alias (was missing)
  'registry-ssn-us',
  // Contact information
  'global-email',
  'registry-email',
  'global-phone',
  'registry-phone',
  // Payment/Financial identity
  'global-iban',
  'global-credit-card',
  'registry-credit-card',
  'global-bank-account',
  // Secrets
  'global-api-key-sk',
  'global-aws-access-key',
  'global-password-assignment',
]);

// ============================================================================
// DETECTION FUNCTION
// ============================================================================

/**
 * Detect document archetypes from normalized text.
 *
 * This function is deterministic: same input always produces same output.
 * It runs all archetype detectors and returns matches sorted by confidence (strong first).
 *
 * @param normalizedText - Text after normalization (same as used for detection)
 * @returns Array of archetype matches, sorted by confidence (strong first)
 */
export function detectDocumentArchetypes(normalizedText: string): ArchetypeMatch[] {
  if (!normalizedText || normalizedText.length < 50) {
    return [];
  }

  const matches: ArchetypeMatch[] = [];

  for (const definition of ARCHETYPE_DEFINITIONS) {
    const result = detectSingleArchetype(normalizedText, definition);
    if (result) {
      matches.push(result);
    }
  }

  // AG-PROMPT-162 (3A): Contract carve-out for policy_standard.
  // If contract-like markers are present, remove policy_standard to prevent
  // NDAs, employment contracts, and similar from being misclassified.
  if (FF.ff_archetype_policy_standard_v1) {
    const hasPolicyStandard = matches.some(m => m.archetypeId === 'policy_standard');
    if (hasPolicyStandard) {
      let contractMarkerCount = 0;
      for (const marker of CONTRACT_CARVEOUT_MARKERS) {
        marker.lastIndex = 0;
        if (marker.test(normalizedText)) {
          contractMarkerCount++;
        }
      }
      // 2+ contract markers = this is a contract, not a policy
      if (contractMarkerCount >= 2) {
        const idx = matches.findIndex(m => m.archetypeId === 'policy_standard');
        if (idx >= 0) matches.splice(idx, 1);
      }
    }
  }

  // AG-PROMPT-162: Feature-flag gating for new archetypes.
  // Remove disabled archetypes from results.
  const filtered = matches.filter(m => {
    if (m.archetypeId === 'policy_standard' && !FF.ff_archetype_policy_standard_v1) return false;
    if (m.archetypeId === 'clinical_reference' && !FF.ff_archetype_clinical_reference_v1) return false;
    if (m.archetypeId === 'aggregate_hr_finance' && !FF.ff_hr_aggregate_cap_v1) return false;
    return true;
  });

  // Sort by confidence (strong first), then by marker count
  filtered.sort((a, b) => {
    if (a.confidence !== b.confidence) {
      return a.confidence === 'strong' ? -1 : 1;
    }
    return b.markerCount - a.markerCount;
  });

  return filtered;
}

/**
 * Detect a single archetype.
 * Returns null if thresholds not met.
 */
function detectSingleArchetype(
  text: string,
  definition: ArchetypeDefinition
): ArchetypeMatch | null {
  const matchedMarkers: string[] = [];
  let strongCount = 0;
  let totalCount = 0;

  for (const marker of definition.markers) {
    // Reset lastIndex for stateful regexes
    marker.pattern.lastIndex = 0;
    if (marker.pattern.test(text)) {
      matchedMarkers.push(marker.label);
      totalCount++;
      if (marker.isStrong) {
        strongCount++;
      }
    }
  }

  // Check if thresholds are met
  if (totalCount < definition.thresholds.minTotal) {
    return null;
  }

  // Determine confidence
  let confidence: ArchetypeConfidence = 'weak';
  if (strongCount >= definition.thresholds.minStrong ||
      totalCount >= definition.thresholds.minTotalForStrong) {
    confidence = 'strong';
  }

  return {
    archetypeId: definition.id,
    confidence,
    matchedMarkers,
    markerCount: totalCount,
    strongMarkerCount: strongCount,
  };
}

/**
 * Get the primary archetype (highest confidence, most markers).
 * Returns null if no archetypes detected.
 */
export function getPrimaryArchetype(matches: ArchetypeMatch[]): ArchetypeMatch | null {
  if (matches.length === 0) return null;
  return matches[0]; // Already sorted by confidence and marker count
}

/**
 * Check if a signal ID is protected from archetype-based suppression.
 * This is a safety function to prevent accidental identity signal suppression.
 *
 * @param signalId - The signal ID to check
 * @returns true if the signal must never be suppressed by archetypes
 */
export function isProtectedSignal(signalId: string): boolean {
  return PROTECTED_SIGNAL_IDS.has(signalId);
}

/**
 * Get archetype effects for a given archetype ID.
 *
 * @param archetypeId - The archetype to get effects for
 * @returns Effects matrix entry for the archetype
 */
export function getArchetypeEffects(archetypeId: DocumentArchetypeId): ArchetypeAllowedEffects {
  return ARCHETYPE_EFFECTS_MATRIX[archetypeId];
}

// ============================================================================
// EXPORTS FOR TESTING
// ============================================================================

export const _testExports = {
  ARCHETYPE_DEFINITIONS,
  RESUME_CV_MARKERS,
  TICKET_BOOKING_MARKERS,
  INVOICE_RECEIPT_MARKERS,
  MEDICAL_RECORD_MARKERS,
  LEGAL_AUTHORITY_MARKERS,
  TEMPLATE_GOVERNANCE_MARKERS,
  POLICY_STANDARD_MARKERS,
  CLINICAL_REFERENCE_MARKERS,
  AGGREGATE_HR_FINANCE_MARKERS,
  CONTRACT_CARVEOUT_MARKERS,
  detectSingleArchetype,
};
