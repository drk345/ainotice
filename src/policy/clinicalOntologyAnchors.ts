/**
 * AgentGuard Clinical Ontology Anchors (AG-PROMPT-043)
 *
 * Deterministic, language-agnostic medical document classification based on
 * structural clinical invariants rather than natural language keywords.
 *
 * Why this exists:
 * - Identity-based detection (names, IDs) fails on anonymized health documents
 * - Keyword detection is language-dependent and unreliable across regions
 * - Medical content must NEVER resolve to LOW risk (seatbelt principle)
 *
 * Structural anchors used:
 * - ANCHOR A: ICD diagnostic codes (globally standardized)
 * - ANCHOR B: Clinical metrology units (bio-specific, rarely in non-medical)
 * - ANCHOR C: Result + reference range structure (lab report pattern)
 * - ANCHOR D: Vital sign telemetry (BP, BMI, pulse patterns)
 *
 * Classification is deterministic:
 * - ≥1 ICD code → doc.medical_record (unless low coherence)
 * - ≥2 distinct clinical units within 500 chars → doc.medical_record
 * - 1 clinical unit + 1 reference range within 100 chars → doc.medical_record
 *
 * ICD Coherence Heuristics (AG-PROMPT-098B):
 * Insurance/admin documents often contain ICD-like codes (e.g., A12.00, Z96.00)
 * that are reference numbers, not diagnoses. To avoid false positives:
 * - Real medical docs have ICD codes in 1-5 related chapters (e.g., M75, M79)
 * - False positives scatter across 8+ chapters with no clustering
 * - Rule: ≥10 codes AND ≥8 chapters AND no clustering → downgrade confidence
 * - Other medical structures (clinical units, ranges) override this downgrade
 *
 * @see ADR-023: Clinical Ontology Anchors
 * @see AG-PROMPT-043
 * @see AG-PROMPT-098B: ICD Coherence Heuristics
 */

// ============================================================================
// TYPES
// ============================================================================

/**
 * Result of clinical ontology analysis.
 */
export interface ClinicalOntologyResult {
  /** Whether document is classified as medical */
  isMedical: boolean;

  /** Confidence level based on anchor strength */
  confidence: 'high' | 'medium' | 'low' | 'none';

  /** Which anchor(s) triggered the classification */
  triggeringAnchors: ClinicalAnchor[];

  /** Detailed findings from each anchor */
  findings: ClinicalFindings;

  /** Rule that triggered classification (for audit) */
  classificationRule: string | null;

  /** Statistics */
  stats: ClinicalStats;
}

/**
 * Clinical anchor types.
 */
export type ClinicalAnchor =
  | 'icd_code'
  | 'clinical_unit'
  | 'reference_range'
  | 'vital_sign';

/**
 * Detailed findings from anchor analysis.
 */
export interface ClinicalFindings {
  /** ICD codes found */
  icdCodes: string[];

  /** Clinical units found with positions */
  clinicalUnits: Array<{ unit: string; position: number }>;

  /** Reference ranges found with positions */
  referenceRanges: Array<{ pattern: string; position: number }>;

  /** Vital signs found */
  vitalSigns: Array<{ pattern: string; type: string }>;
}

/**
 * Statistics for audit/logging.
 */
export interface ClinicalStats {
  icdCodeCount: number;
  clinicalUnitCount: number;
  distinctClinicalUnits: number;
  referenceRangeCount: number;
  vitalSignCount: number;
  unitRangeProximityFound: boolean;
  unitClusterFound: boolean;

  /** AG-PROMPT-098B: ICD coherence metrics */
  icdCoherence?: {
    /** Number of unique ICD chapter prefixes (e.g., A, B, C...) */
    uniqueChapters: number;
    /** Number of unique base codes (e.g., A00, E11, M75) */
    uniqueBaseCodes: number;
    /** Whether ICD codes appear in clusters (≥3 codes within 500 chars) */
    hasClusteredCodes: boolean;
    /** Whether coherence check triggered a downgrade */
    downgraded: boolean;
    /** Reason for downgrade (if any) */
    downgradeReason?: string;
  };
}

/**
 * Rule IDs for audit trail.
 */
export const CLINICAL_ONTOLOGY_RULE_IDS = {
  /** Single ICD code triggers classification */
  ICD_CODE_STANDALONE: 'COA-001-icd-standalone',
  /** Multiple clinical units in proximity */
  UNIT_CLUSTER: 'COA-002-unit-cluster',
  /** Clinical unit + reference range in proximity */
  UNIT_RANGE_PROXIMITY: 'COA-003-unit-range-proximity',
  /** Combined weak anchors */
  COMBINED_ANCHORS: 'COA-004-combined-anchors',
  /** No clinical anchors found */
  NO_ANCHORS: 'COA-000-no-anchors',
  /** AG-PROMPT-098B: ICD codes downgraded due to low coherence (scattered chapters) */
  ICD_LOW_COHERENCE: 'COA-005-icd-low-coherence',
} as const;

// ============================================================================
// ANCHOR A: ICD CODES
// ============================================================================

/**
 * ICD-10/ICD-11 diagnostic code pattern.
 *
 * Format: Letter + 2 digits + optional (dot + 1-2 digits)
 * Examples: I20.0, M75.1, E11.9, A00, Z99.89
 *
 * ICD codes are globally standardized and extremely high-signal for medical content.
 * A single valid ICD code is sufficient to classify as medical.
 */
const ICD_CODE_PATTERN = /\b([A-TV-Z]\d{2})(?:\.(\d{1,2}))?\b/g;

/**
 * ICD chapter prefixes for validation.
 * Excludes U (provisional) and X (external causes - too ambiguous).
 */
const VALID_ICD_PREFIXES = new Set([
  'A', 'B', // Infectious diseases
  'C', 'D', // Neoplasms, blood diseases
  'E',      // Endocrine, metabolic
  'F',      // Mental disorders
  'G',      // Nervous system
  'H',      // Eye and ear
  'I',      // Circulatory
  'J',      // Respiratory
  'K',      // Digestive
  'L',      // Skin
  'M',      // Musculoskeletal
  'N',      // Genitourinary
  'O',      // Pregnancy
  'P',      // Perinatal
  'Q',      // Congenital
  'R',      // Symptoms
  'S', 'T', // Injury
  'V',      // External causes (transport)
  'W',      // External causes (falls, etc.)
  'Y',      // External causes (other)
  'Z',      // Health status factors
]);

/**
 * Known false positive patterns that look like ICD codes but aren't.
 * These are excluded from ICD detection.
 */
const ICD_FALSE_POSITIVE_PATTERNS = [
  /\bA4\b/i,        // Paper size
  /\bB2B\b/i,       // Business term
  /\bC\+\+/i,       // Programming language
  /\bV[0-9]\b/i,    // Version numbers V0-V9 only (V10+ and V00+ are valid ICD transport codes)
  /\bT\d{1,2}C\b/i, // Temperature notation
];

/**
 * Detect valid ICD codes in text.
 *
 * @param text - Text to analyze
 * @returns Array of valid ICD codes found
 */
function detectICDCodes(text: string): string[] {
  const codes: string[] = [];
  ICD_CODE_PATTERN.lastIndex = 0;

  let match;
  while ((match = ICD_CODE_PATTERN.exec(text)) !== null) {
    const fullCode = match[0];
    const prefix = match[1].charAt(0).toUpperCase();

    // Validate prefix is a valid ICD chapter
    if (!VALID_ICD_PREFIXES.has(prefix)) {
      continue;
    }

    // Check for false positives
    const context = text.slice(
      Math.max(0, match.index - 10),
      Math.min(text.length, match.index + fullCode.length + 10)
    );

    let isFalsePositive = false;
    for (const fpPattern of ICD_FALSE_POSITIVE_PATTERNS) {
      if (fpPattern.test(context)) {
        isFalsePositive = true;
        break;
      }
    }

    if (!isFalsePositive) {
      codes.push(fullCode.toUpperCase());
    }
  }

  // Deduplicate
  return [...new Set(codes)];
}

// ============================================================================
// AG-PROMPT-098B: ICD COHERENCE ASSESSMENT
// ============================================================================

/**
 * AG-PROMPT-098B: ICD Coherence Assessment
 *
 * Detects whether ICD-like codes are likely real medical codes or false positives
 * from administrative/insurance documents.
 *
 * Real medical documents typically have:
 * - ICD codes clustered in 1-5 related chapters (e.g., M for musculoskeletal)
 * - Codes appearing in proximity (lists, tables)
 *
 * False positive documents (insurance, legal) typically have:
 * - Alphanumeric codes scattered across many chapters (8+)
 * - Codes appearing in isolation throughout the document
 *
 * Thresholds (conservative):
 * - HIGH_SCATTER_THRESHOLD: 8 unique chapters
 * - MANY_CODES_THRESHOLD: 10 total codes
 * - CLUSTER_PROXIMITY: 500 chars (same as unit cluster)
 * - CLUSTER_MIN_COUNT: 3 codes to form a cluster
 *
 * The heuristic ONLY downgrades confidence; it never blocks detection.
 * Other medical structures (units, ranges) override the downgrade.
 */
export interface IcdCoherenceResult {
  /** Number of unique ICD chapter letters (A, B, C...) */
  uniqueChapters: number;
  /** Number of unique base codes (A00, E11, M75...) */
  uniqueBaseCodes: number;
  /** Whether codes appear clustered (≥3 within 500 chars) */
  hasClusteredCodes: boolean;
  /** Whether this looks like scattered false positives */
  isLowCoherence: boolean;
  /** Reason for low coherence determination */
  lowCoherenceReason?: string;
}

/** Threshold: ≥8 unique chapter letters suggests scattered reference numbers */
const HIGH_SCATTER_THRESHOLD = 8;

/** Threshold: ≥10 codes total before scatter check applies */
const MANY_CODES_THRESHOLD = 10;

/** Proximity for cluster detection (chars) */
const ICD_CLUSTER_PROXIMITY = 500;

/** Minimum codes in proximity to count as a cluster */
const ICD_CLUSTER_MIN_COUNT = 3;

/**
 * Assess ICD code coherence to detect likely false positives.
 *
 * @param icdCodes - Array of detected ICD codes (e.g., ["A00", "E11.9", "M75.1"])
 * @param text - Original text for proximity analysis
 * @returns Coherence assessment result
 */
export function assessIcdCoherence(icdCodes: string[], text: string): IcdCoherenceResult {
  if (icdCodes.length === 0) {
    return {
      uniqueChapters: 0,
      uniqueBaseCodes: 0,
      hasClusteredCodes: false,
      isLowCoherence: false,
    };
  }

  // Extract chapter letters (first char) and base codes (first 3 chars)
  const chapters = new Set<string>();
  const baseCodes = new Set<string>();

  for (const code of icdCodes) {
    const chapter = code.charAt(0).toUpperCase();
    const baseCode = code.substring(0, 3).toUpperCase();
    chapters.add(chapter);
    baseCodes.add(baseCode);
  }

  const uniqueChapters = chapters.size;
  const uniqueBaseCodes = baseCodes.size;

  // Check for clustering: find positions of each code in text
  const codePositions: number[] = [];
  for (const code of icdCodes) {
    // Find all occurrences of this code
    const pattern = new RegExp(`\\b${code.replace('.', '\\.')}\\b`, 'gi');
    let match;
    while ((match = pattern.exec(text)) !== null) {
      codePositions.push(match.index);
    }
  }
  codePositions.sort((a, b) => a - b);

  // Check if any 3+ codes appear within CLUSTER_PROXIMITY chars
  let hasClusteredCodes = false;
  if (codePositions.length >= ICD_CLUSTER_MIN_COUNT) {
    for (let i = 0; i <= codePositions.length - ICD_CLUSTER_MIN_COUNT; i++) {
      const windowEnd = codePositions[i] + ICD_CLUSTER_PROXIMITY;
      let codesInWindow = 1;
      for (let j = i + 1; j < codePositions.length && codePositions[j] <= windowEnd; j++) {
        codesInWindow++;
      }
      if (codesInWindow >= ICD_CLUSTER_MIN_COUNT) {
        hasClusteredCodes = true;
        break;
      }
    }
  }

  // Determine if this is low coherence (likely false positives)
  // Rule: Many codes (≥10) AND high scatter (≥8 chapters) AND no clustering
  let isLowCoherence = false;
  let lowCoherenceReason: string | undefined;

  if (icdCodes.length >= MANY_CODES_THRESHOLD &&
      uniqueChapters >= HIGH_SCATTER_THRESHOLD &&
      !hasClusteredCodes) {
    isLowCoherence = true;
    lowCoherenceReason = `scattered_chapters:${uniqueChapters}_codes:${icdCodes.length}_no_clusters`;
  }

  return {
    uniqueChapters,
    uniqueBaseCodes,
    hasClusteredCodes,
    isLowCoherence,
    lowCoherenceReason,
  };
}

// ============================================================================
// ANCHOR B: CLINICAL METROLOGY UNITS
// ============================================================================

/**
 * Clinical/biological measurement units rarely used outside medicine.
 *
 * These are high-signal for medical content when combined with other anchors.
 * Single unit detection is NOT sufficient (chemistry homework could have mmol/L).
 */
const CLINICAL_UNITS: Array<{ pattern: RegExp; unit: string }> = [
  // Concentration units
  { pattern: /\bmmol\/L\b/gi, unit: 'mmol/L' },
  { pattern: /(?:^|[^a-zA-Z])[µμu]mol\/L\b/gi, unit: 'µmol/L' },  // micro sign, Greek mu, ASCII u
  { pattern: /\bng\/mL\b/gi, unit: 'ng/mL' },
  { pattern: /\bng\/L\b/gi, unit: 'ng/L' },
  { pattern: /\bmg\/dL\b/gi, unit: 'mg/dL' },
  { pattern: /\bmg\/L\b/gi, unit: 'mg/L' },
  { pattern: /\bg\/dL\b/gi, unit: 'g/dL' },          // Hemoglobin
  { pattern: /\bmEq\/L\b/gi, unit: 'mEq/L' },
  { pattern: /\bmIU\/L\b/gi, unit: 'mIU/L' },        // Milli-international units (TSH)
  { pattern: /\bIU\/L\b/gi, unit: 'IU/L' },          // International units
  { pattern: /\bU\/L\b/gi, unit: 'U/L' },            // Units per liter
  { pattern: /\bpg\/mL\b/gi, unit: 'pg/mL' },        // Picograms
  { pattern: /\bfmol\/L\b/gi, unit: 'fmol/L' },      // Femtomoles

  // Cell counts - multiple notation variants
  { pattern: /[×x]10[⁹9]\/?L\b/gi, unit: '×10⁹/L' },     // ×10⁹/L or x10⁹/L
  { pattern: /[×x]10[¹²12]{1,2}\/?L\b/gi, unit: '×10¹²/L' }, // ×10¹²/L
  { pattern: /\bcells?\/[µμu]L\b/gi, unit: 'cells/µL' },
  { pattern: /\b\/HPF\b/gi, unit: '/HPF' },          // Per high power field
  { pattern: /\bfL\b/g, unit: 'fL' },                // Femtoliters (MCV)
  { pattern: /\bpg\b/g, unit: 'pg' },                // Picograms (MCH)

  // Enzyme/protein specific
  { pattern: /\bkU\/L\b/gi, unit: 'kU/L' },
  { pattern: /\bnmol\/L\b/gi, unit: 'nmol/L' },
  { pattern: /\bpmol\/L\b/gi, unit: 'pmol/L' },

  // Blood gas units
  { pattern: /\bkPa\b/g, unit: 'kPa' },              // Partial pressure
  { pattern: /\bmmHg\b/g, unit: 'mmHg' },            // Blood pressure/gas
];

/**
 * Detect clinical metrology units in text with positions.
 *
 * @param text - Text to analyze
 * @returns Array of units found with their positions
 */
function detectClinicalUnits(text: string): Array<{ unit: string; position: number }> {
  const found: Array<{ unit: string; position: number }> = [];

  for (const { pattern, unit } of CLINICAL_UNITS) {
    pattern.lastIndex = 0;
    let match;
    while ((match = pattern.exec(text)) !== null) {
      found.push({ unit, position: match.index });
    }
  }

  // Sort by position
  found.sort((a, b) => a.position - b.position);

  return found;
}

/**
 * Check if there are ≥2 distinct clinical units within a given character distance.
 *
 * @param units - Detected units with positions
 * @param maxDistance - Maximum character distance between units
 * @returns Whether a cluster was found
 */
function hasClinicalUnitCluster(
  units: Array<{ unit: string; position: number }>,
  maxDistance: number = 500
): boolean {
  if (units.length < 2) return false;

  // Get distinct unit types
  const distinctUnits = new Set(units.map(u => u.unit.toLowerCase()));
  if (distinctUnits.size < 2) return false;

  // Check if any two distinct units are within distance
  for (let i = 0; i < units.length; i++) {
    for (let j = i + 1; j < units.length; j++) {
      const distance = units[j].position - units[i].position;
      if (distance <= maxDistance) {
        // Check if they're distinct
        if (units[i].unit.toLowerCase() !== units[j].unit.toLowerCase()) {
          return true;
        }
      }
    }
  }

  return false;
}

// ============================================================================
// ANCHOR C: REFERENCE RANGE STRUCTURE
// ============================================================================

/**
 * Reference range patterns commonly found in lab results.
 *
 * Examples:
 *   "5.2 mmol/L (3.5–6.0)"
 *   "Troponin T < 0.05 ng/L"
 *   "Result: 142 mEq/L [136-145]"
 *   "Normal: 4.0-11.0 ×10⁹/L"
 */
const REFERENCE_RANGE_PATTERNS: Array<{ pattern: RegExp; name: string }> = [
  // Parenthetical ranges: (3.5-6.0), (3.5–6.0), (< 5.0)
  {
    pattern: /\(\s*<?[\d.]+\s*[-–]\s*[\d.]+\s*\)/g,
    name: 'parenthetical_range',
  },
  {
    pattern: /\(\s*[<>≤≥]\s*[\d.]+\s*\)/g,
    name: 'parenthetical_limit',
  },

  // Bracketed ranges: [136-145], [< 0.5]
  {
    pattern: /\[\s*<?[\d.]+\s*[-–]\s*[\d.]+\s*\]/g,
    name: 'bracketed_range',
  },
  {
    pattern: /\[\s*[<>≤≥]\s*[\d.]+\s*\]/g,
    name: 'bracketed_limit',
  },

  // Labeled ranges: "Ref: 3.5-6.0", "Normal: 4.0-11.0"
  {
    pattern: /\b(?:ref(?:erence)?|normal|range)\s*[:=]\s*<?[\d.]+\s*[-–]\s*[\d.]+/gi,
    name: 'labeled_range',
  },

  // Comparison operators with values: "< 0.05", "> 3.0", "≤ 5.0"
  {
    pattern: /[<>≤≥]\s*[\d.]+\s*(?:mmol|µmol|umol|ng|mg|mEq|IU|U|pg|nmol|pmol)\/[mLdl]+/gi,
    name: 'comparison_with_unit',
  },
];

/**
 * Detect reference range patterns in text.
 *
 * @param text - Text to analyze
 * @returns Array of ranges found with positions
 */
function detectReferenceRanges(text: string): Array<{ pattern: string; position: number }> {
  const found: Array<{ pattern: string; position: number }> = [];

  for (const { pattern } of REFERENCE_RANGE_PATTERNS) {
    pattern.lastIndex = 0;
    let match;
    while ((match = pattern.exec(text)) !== null) {
      found.push({ pattern: match[0], position: match.index });
    }
  }

  return found;
}

/**
 * Check if a clinical unit and reference range are in proximity.
 *
 * @param units - Detected units with positions
 * @param ranges - Detected ranges with positions
 * @param maxDistance - Maximum character distance
 * @returns Whether unit-range proximity was found
 */
function hasUnitRangeProximity(
  units: Array<{ unit: string; position: number }>,
  ranges: Array<{ pattern: string; position: number }>,
  maxDistance: number = 100
): boolean {
  if (units.length === 0 || ranges.length === 0) return false;

  for (const unit of units) {
    for (const range of ranges) {
      const distance = Math.abs(unit.position - range.position);
      if (distance <= maxDistance) {
        return true;
      }
    }
  }

  return false;
}

// ============================================================================
// ANCHOR D: VITAL SIGN TELEMETRY
// ============================================================================

/**
 * Vital sign patterns.
 *
 * These are weak alone but strengthen classification when combined with other anchors.
 */
const VITAL_SIGN_PATTERNS: Array<{ pattern: RegExp; type: string }> = [
  // Blood pressure: 120/80, 120/80 mmHg
  {
    pattern: /\b\d{2,3}\/\d{2,3}\s*(?:mmHg)?\b/g,
    type: 'blood_pressure',
  },

  // BMI: BMI 24, BMI: 24.5
  {
    pattern: /\bBMI\s*[:=]?\s*\d{1,2}(?:\.\d)?\b/gi,
    type: 'bmi',
  },

  // Pulse/HR: Pulse 72, HR 80, Heart rate: 65
  {
    pattern: /\b(?:pulse|HR|heart\s*rate)\s*[:=]?\s*\d{2,3}\b/gi,
    type: 'pulse',
  },

  // Temperature: 37.5°C, 98.6°F, Temp 37.2
  {
    pattern: /\b(?:temp(?:erature)?)\s*[:=]?\s*\d{2,3}(?:\.\d)?(?:\s*°?[CF])?\b/gi,
    type: 'temperature',
  },

  // Oxygen saturation: SpO2 98%, O2 sat 97%
  {
    pattern: /\b(?:SpO2|O2\s*sat(?:uration)?)\s*[:=]?\s*\d{2,3}\s*%?\b/gi,
    type: 'oxygen_saturation',
  },

  // Respiratory rate: RR 16, Resp rate: 18
  {
    pattern: /\b(?:RR|resp(?:iratory)?\s*rate)\s*[:=]?\s*\d{1,2}\b/gi,
    type: 'respiratory_rate',
  },
];

/**
 * Detect vital sign patterns in text.
 *
 * @param text - Text to analyze
 * @returns Array of vital signs found
 */
function detectVitalSigns(text: string): Array<{ pattern: string; type: string }> {
  const found: Array<{ pattern: string; type: string }> = [];

  for (const { pattern, type } of VITAL_SIGN_PATTERNS) {
    pattern.lastIndex = 0;
    let match;
    while ((match = pattern.exec(text)) !== null) {
      found.push({ pattern: match[0], type });
    }
  }

  return found;
}

// ============================================================================
// CLASSIFICATION LOGIC
// ============================================================================

/**
 * Analyze text for clinical ontology anchors and classify as medical if appropriate.
 *
 * Classification rules (deterministic):
 * 1. ≥1 valid ICD code → doc.medical_record (HIGH confidence)
 *    - AG-PROMPT-098B: Downgrade to LOW if ICD codes have low coherence (scattered chapters)
 *      AND no other medical structures are present
 * 2. ≥2 distinct clinical units within 500 chars → doc.medical_record (MEDIUM confidence)
 * 3. 1 clinical unit + 1 reference range within 100 chars → doc.medical_record (MEDIUM confidence)
 *
 * @param text - Text content to analyze
 * @returns ClinicalOntologyResult with classification and findings
 */
export function analyzeClinicalOntology(text: string): ClinicalOntologyResult {
  // Run all anchor detections
  const icdCodes = detectICDCodes(text);
  const clinicalUnits = detectClinicalUnits(text);
  const referenceRanges = detectReferenceRanges(text);
  const vitalSigns = detectVitalSigns(text);

  // Compute derived metrics
  const distinctClinicalUnits = new Set(clinicalUnits.map(u => u.unit.toLowerCase())).size;
  const unitClusterFound = hasClinicalUnitCluster(clinicalUnits, 500);
  const unitRangeProximityFound = hasUnitRangeProximity(clinicalUnits, referenceRanges, 100);

  // AG-PROMPT-098B: Assess ICD coherence to detect likely false positives
  const icdCoherence = assessIcdCoherence(icdCodes, text);

  // Check if other medical structures are present (overrides coherence downgrade)
  const hasOtherMedicalStructures = unitClusterFound ||
    unitRangeProximityFound ||
    vitalSigns.length >= 2 ||
    referenceRanges.length >= 2;

  // Determine if ICD coherence should trigger a downgrade
  // Only downgrade if: low coherence AND no other medical structures
  const shouldDowngradeIcd = icdCoherence.isLowCoherence && !hasOtherMedicalStructures;

  // Build findings
  const findings: ClinicalFindings = {
    icdCodes,
    clinicalUnits,
    referenceRanges,
    vitalSigns,
  };

  // Build stats with coherence metrics
  const stats: ClinicalStats = {
    icdCodeCount: icdCodes.length,
    clinicalUnitCount: clinicalUnits.length,
    distinctClinicalUnits,
    referenceRangeCount: referenceRanges.length,
    vitalSignCount: vitalSigns.length,
    unitRangeProximityFound,
    unitClusterFound,
    // AG-PROMPT-098B: Include coherence metrics
    icdCoherence: {
      uniqueChapters: icdCoherence.uniqueChapters,
      uniqueBaseCodes: icdCoherence.uniqueBaseCodes,
      hasClusteredCodes: icdCoherence.hasClusteredCodes,
      downgraded: shouldDowngradeIcd,
      downgradeReason: shouldDowngradeIcd ? icdCoherence.lowCoherenceReason : undefined,
    },
  };

  // Apply classification rules (deterministic, in order of confidence)
  const triggeringAnchors: ClinicalAnchor[] = [];
  let isMedical = false;
  let confidence: ClinicalOntologyResult['confidence'] = 'none';
  let classificationRule: string | null = null;

  // RULE 1: ICD codes present
  if (icdCodes.length >= 1) {
    // AG-PROMPT-098B: Check if ICD should be downgraded due to low coherence
    // AG-PHASE-5C-056: Also downgrade single isolated ICD codes.
    // A single ICD-like pattern (e.g., "A04" in an admin section code) is
    // insufficient evidence for medical classification. Real medical documents
    // have multiple ICD codes. Single codes commonly appear as section references,
    // department codes, or UUID fragments (e.g., DocuSign envelope IDs).
    const isSingleIsolatedCode = icdCodes.length === 1 && !hasOtherMedicalStructures;

    if (shouldDowngradeIcd || isSingleIsolatedCode) {
      // Downgrade: ICD codes detected but low coherence or isolated code
      // Set isMedical=false so other rules can take over, or stay unclassified
      // This does NOT block detection - just reduces confidence
      isMedical = false;
      confidence = 'low';
      triggeringAnchors.push('icd_code');
      classificationRule = CLINICAL_ONTOLOGY_RULE_IDS.ICD_LOW_COHERENCE;
      // Note: We still set triggeringAnchors so the ICD detection is recorded,
      // but isMedical=false means this alone won't classify as medical
    } else {
      // Normal case: ICD codes with good coherence = HIGH confidence medical
      isMedical = true;
      confidence = 'high';
      triggeringAnchors.push('icd_code');
      classificationRule = CLINICAL_ONTOLOGY_RULE_IDS.ICD_CODE_STANDALONE;
    }
  }

  // RULE 2: Multiple distinct clinical units in proximity (MEDIUM confidence)
  if (!isMedical && unitClusterFound) {
    isMedical = true;
    confidence = 'medium';
    triggeringAnchors.push('clinical_unit');
    classificationRule = CLINICAL_ONTOLOGY_RULE_IDS.UNIT_CLUSTER;
  }

  // RULE 3: Clinical unit + reference range in proximity (MEDIUM confidence)
  if (!isMedical && unitRangeProximityFound) {
    isMedical = true;
    confidence = 'medium';
    triggeringAnchors.push('clinical_unit');
    triggeringAnchors.push('reference_range');
    classificationRule = CLINICAL_ONTOLOGY_RULE_IDS.UNIT_RANGE_PROXIMITY;
  }

  // If not classified, set rule to NO_ANCHORS (unless already set to LOW_COHERENCE)
  if (!isMedical && classificationRule !== CLINICAL_ONTOLOGY_RULE_IDS.ICD_LOW_COHERENCE) {
    classificationRule = CLINICAL_ONTOLOGY_RULE_IDS.NO_ANCHORS;
  }

  return {
    isMedical,
    confidence,
    triggeringAnchors,
    findings,
    classificationRule,
    stats,
  };
}

// ============================================================================
// INTEGRATION HELPER
// ============================================================================

/**
 * Check if clinical ontology anchors indicate medical content.
 *
 * This is the main entry point for integration with the document classification pipeline.
 *
 * @param textContent - Text content to analyze (can be undefined/empty)
 * @returns Result indicating if medical classification should be applied
 */
export function hasClinicalOntologyAnchors(textContent?: string): {
  isMedical: boolean;
  confidence: ClinicalOntologyResult['confidence'];
  rule: string;
  stats: ClinicalStats;
} {
  if (!textContent || textContent.length === 0) {
    return {
      isMedical: false,
      confidence: 'none',
      rule: CLINICAL_ONTOLOGY_RULE_IDS.NO_ANCHORS,
      stats: {
        icdCodeCount: 0,
        clinicalUnitCount: 0,
        distinctClinicalUnits: 0,
        referenceRangeCount: 0,
        vitalSignCount: 0,
        unitRangeProximityFound: false,
        unitClusterFound: false,
      },
    };
  }

  const result = analyzeClinicalOntology(textContent);

  return {
    isMedical: result.isMedical,
    confidence: result.confidence,
    rule: result.classificationRule || CLINICAL_ONTOLOGY_RULE_IDS.NO_ANCHORS,
    stats: result.stats,
  };
}

// ============================================================================
// EXPORTS
// ============================================================================

export {
  detectICDCodes,
  detectClinicalUnits,
  detectReferenceRanges,
  detectVitalSigns,
  hasClinicalUnitCluster,
  hasUnitRangeProximity,
  // Note: assessIcdCoherence is already exported via 'export function' declaration
  ICD_CODE_PATTERN,
  CLINICAL_UNITS,
  REFERENCE_RANGE_PATTERNS,
  VITAL_SIGN_PATTERNS,
  VALID_ICD_PREFIXES,
};
