/**
 * AG-PROMPT-NATIONAL-ID-ARCHITECTURE-035: National ID Validation Framework
 * AG-XLSX-HARDENING-PLAN-001: Checksum gates + Gate & Boost confidence
 *
 * Generic validator interface with country-specific implementations.
 * Emits a single unified signal `global-national-id` with subtype metadata.
 *
 * Supported subtypes:
 * - dk_cpr:          Danish CPR number (DDMMYY-?XXXX) — Mod11 soft gate
 * - se_personnummer: Swedish personnummer (YYMMDD[-+]XXXX) — Luhn10 hard gate
 * - no_fnr:          Norwegian fødselsnummer (DDMMYYXXXXX) — Mod11 hard gate
 * - fi_hetu:         Finnish henkilötunnus (DDMMYYXXXC) — Mod31 hard gate
 *
 * Each validator uses the same gate architecture:
 * - Gate 1 (HARD): Date plausibility
 * - Gate 2 (HARD): Digit boundary — not embedded in longer digit sequence
 * - Gate 3 (SOFT): Context proximity — informational only
 * - Gate 4 (varies): Checksum validation (see per-subtype policy above)
 *
 * Confidence (Gate & Boost, AG-XLSX-HARDENING-PLAN-001):
 * - checksum valid + anchor in window → 0.99
 * - checksum valid, no anchor         → 0.60
 * - DK CPR checksum fail + anchor     → 0.40  (mod11 downgrade exception)
 * - DK CPR checksum fail, no anchor   → 0.20
 *
 * Privacy: No raw content is ever logged or returned in results.
 */

import { validateCpr } from './cprValidation';
import { checkDigitBoundary } from './cprValidation';
import { luhn10, mod11No, mod31Fi, mod1110Steuer, bsn11Test, mod97Nir, mod11Nif, mod97BeNn, mod11Cpf, mod11Cnpj, mod23IePps, mod10AtSvNr, mod11RoCnp, mod11CzRc, mod11ArCuil, mod11ClRut, mod11AuTfn, mod89AuAbn, mod10HuTaj } from './checksums';
import { scoreProximity, SE_PERSONNUMMER_ANCHORS, NO_FNR_ANCHORS, FI_HETU_ANCHORS, DE_STEUER_ID_ANCHORS, ES_DNI_NIE_ANCHORS, IT_CODICE_FISCALE_ANCHORS, PL_PESEL_ANCHORS, NL_BSN_ANCHORS, FR_NIR_ANCHORS, PT_NIF_ANCHORS, BE_NN_ANCHORS, BR_CPF_ANCHORS, BR_CNPJ_ANCHORS, MX_CURP_ANCHORS, MX_RFC_ANCHORS, IE_PPS_ANCHORS, AT_SV_NR_ANCHORS, RO_CNP_ANCHORS, CZ_RC_ANCHORS, AR_CUIL_ANCHORS, CL_RUT_ANCHORS, HU_TAJ_ANCHORS, UK_NIN_ANCHORS, AU_TFN_ANCHORS, AU_ABN_ANCHORS, CA_SIN_ANCHORS } from './proximityScorer';

// ============================================================================
// TYPES
// ============================================================================

export type NationalIdSubtype = 'dk_cpr' | 'se_personnummer' | 'no_fnr' | 'fi_hetu' | 'de_steuer_id' | 'es_dni_nie' | 'it_codice_fiscale' | 'pl_pesel' | 'nl_bsn' | 'fr_nir' | 'pt_nif' | 'be_nn' | 'br_cpf' | 'br_cnpj' | 'mx_curp' | 'mx_rfc' | 'ie_pps' | 'at_sv_nr' | 'ro_cnp' | 'cz_rc' | 'ar_cuil' | 'cl_rut' | 'cl_rut_bare' | 'hu_taj' | 'uk_nin' | 'au_tfn' | 'au_abn' | 'ca_sin';

/**
 * Result of national ID validation.
 * Privacy-safe: contains only metrics, never raw content.
 */
export interface NationalIdValidationResult {
  /** Whether this is a valid national ID match */
  is_valid: boolean;
  /** Country-specific subtype */
  subtype: NationalIdSubtype;
  /** Gates that passed */
  gatesPassed: Record<string, boolean>;
  /** Reason for rejection (privacy-safe) */
  reason: string | null;
  /** Metrics for audit (privacy-safe) */
  metrics: Record<string, unknown>;
  /**
   * AG-XLSX-HARDENING-PLAN-001: Gate & Boost confidence score (0.20 – 0.99).
   * Only set when is_valid is true.
   */
  confidence?: number;
}

/** Validator function signature */
type ValidatorFn = (matchString: string, fullText: string, matchIndex: number) => NationalIdValidationResult;

// ============================================================================
// UNIFIED SIGNAL ID
// ============================================================================

/** The single signal ID emitted by all national ID validators */
export const NATIONAL_ID_SIGNAL_ID = 'global-national-id';

// ============================================================================
// DK CPR VALIDATOR
// ============================================================================

/**
 * Danish CPR validation — delegates to existing validateCpr().
 */
function validateNationalId_dk_cpr(
  matchString: string,
  fullText: string,
  matchIndex: number
): NationalIdValidationResult {
  const result = validateCpr(matchString, fullText, matchIndex);
  return {
    is_valid: result.isValidCpr,
    subtype: 'dk_cpr',
    gatesPassed: {
      datePlausible: result.gatesPassed.datePlausible,
      digitBoundaryClean: result.gatesPassed.digitBoundaryClean,
      contextProximity: result.gatesPassed.contextProximity,
      mod11Valid: result.gatesPassed.mod11Valid,
    },
    reason: result.rejectionReason,
    metrics: {
      matchLength: result.metrics.matchLength,
      day: result.metrics.day,
      month: result.metrics.month,
      hasHyphen: result.metrics.hasHyphen,
      hasContext: result.metrics.hasCprContext,
      mod11Valid: result.metrics.mod11Valid,
    },
    confidence: result.confidence,
  };
}

// ============================================================================
// SE PERSONNUMMER VALIDATOR
// ============================================================================

/**
 * Swedish personnummer context keywords for proximity check (Gate 3).
 */
const SE_CONTEXT_KEYWORDS = [
  'personnummer', 'personnr', 'samordningsnummer',
  'folkbokföring', 'skatteverket', 'patient',
  'person', 'id-nummer',
];

/** Context window for SE keyword proximity check */
const SE_CONTEXT_WINDOW_CHARS = 80;

/**
 * Swedish personnummer validation.
 * Format: YYMMDD[-+]XXXX or YYYYMMDD[-+]XXXX
 * - MM 01-12, DD 01-31 (or 61-91 for samordningsnummer: day + 60)
 * - Separator: '-' for same century, '+' for previous century
 * - AG-PHASE-4-052: Extended to handle 12-digit YYYYMMDD format and space-tolerant separator
 * - AG-XLSX-HARDENING-PLAN-001: Luhn10 hard gate on the 10-digit form
 */
function validateNationalId_se_personnummer(
  matchString: string,
  fullText: string,
  matchIndex: number
): NationalIdValidationResult {
  // Extract components: strip separator and spaces
  const digits = matchString.replace(/[-+\s]/g, '');
  if (digits.length < 6) {
    return {
      is_valid: false,
      subtype: 'se_personnummer',
      gatesPassed: { datePlausible: false, digitBoundaryClean: false, contextProximity: false, luhnValid: false },
      reason: 'Too few digits',
      metrics: { matchLength: matchString.length },
    };
  }

  // AG-PHASE-4-052: Detect 12-digit YYYYMMDD format (century prefix present)
  // 10 digits = YYMMDDXXXX (short), 12 digits = YYYYMMDDXXXX (long)
  const isLongFormat = digits.length >= 12;
  const dateStart = isLongFormat ? 4 : 2;
  const month = parseInt(digits.substring(dateStart, dateStart + 2), 10);
  const rawDay = parseInt(digits.substring(dateStart + 2, dateStart + 4), 10);

  // Samordningsnummer: day field is real day + 60
  const isSamordning = rawDay >= 61 && rawDay <= 91;
  const effectiveDay = isSamordning ? rawDay - 60 : rawDay;

  // Gate 1 (HARD): Date plausibility
  const datePlausible = month >= 1 && month <= 12 && effectiveDay >= 1 && effectiveDay <= 31;

  // Gate 2 (HARD): Digit boundary
  const digitBoundaryClean = checkDigitBoundary(fullText, matchIndex, matchString.length);

  // Gate 3 (SOFT): Context proximity
  const windowStart = Math.max(0, matchIndex - SE_CONTEXT_WINDOW_CHARS);
  const windowEnd = Math.min(fullText.length, matchIndex + matchString.length + SE_CONTEXT_WINDOW_CHARS);
  const contextWindow = fullText.slice(windowStart, windowEnd).toLowerCase();
  let hasContext = false;
  for (const keyword of SE_CONTEXT_KEYWORDS) {
    if (contextWindow.includes(keyword)) {
      hasContext = true;
      break;
    }
  }

  // Gate 4 (HARD, AG-XLSX-HARDENING-PLAN-001): Luhn10 on 10-digit form
  // For 12-digit form, take last 10 digits (drop century YYYY prefix → 2 leading digits)
  const luhnDigits = isLongFormat ? digits.slice(2) : digits;
  // Luhn applies to exactly 10 digits (6 date + 4 individual/check)
  const luhnValid = luhnDigits.length === 10 ? luhn10(luhnDigits) : false;

  // Samordningsnummer: Luhn is computed with the raw (pre-subtraction) day value
  // This is correct since we validate the digits as-is
  const is_valid = datePlausible && digitBoundaryClean && luhnValid;

  let reason: string | null = null;
  if (!datePlausible) {
    reason = `Implausible date: month=${month}, day=${rawDay}${isSamordning ? ' (samordning)' : ''}`;
  } else if (!digitBoundaryClean) {
    reason = 'Match is embedded in a longer digit sequence';
  } else if (!luhnValid) {
    reason = 'Luhn10 checksum failed';
  }

  let confidence: number | undefined;
  if (is_valid) {
    const score = scoreProximity(fullText, matchIndex, matchString.length, SE_PERSONNUMMER_ANCHORS, true);
    confidence = score.confidence;
  }

  return {
    is_valid,
    subtype: 'se_personnummer',
    gatesPassed: { datePlausible, digitBoundaryClean, contextProximity: hasContext, luhnValid },
    reason,
    metrics: {
      matchLength: matchString.length,
      month,
      rawDay,
      effectiveDay,
      isSamordning,
      hasContext,
      hasSeparator: matchString.includes('-') || matchString.includes('+'),
      luhnValid,
    },
    confidence,
  };
}

// ============================================================================
// NO FØDSELSNUMMER VALIDATOR
// ============================================================================

/**
 * Norwegian fødselsnummer context keywords for proximity check (Gate 3).
 */
const NO_CONTEXT_KEYWORDS = [
  'fødselsnummer', 'fodselsnummer', 'personnummer',
  'fnr', 'folkeregister', 'patient',
  'person', 'id-nummer',
];

/** Context window for NO keyword proximity check */
const NO_CONTEXT_WINDOW_CHARS = 80;

/**
 * Norwegian fødselsnummer validation.
 * Format: DDMMYYXXXXX (11 digits total)
 * - DD 01-31, MM 01-12
 * - AG-XLSX-HARDENING-PLAN-001: Mod11 double check-digit hard gate
 */
function validateNationalId_no_fnr(
  matchString: string,
  fullText: string,
  matchIndex: number
): NationalIdValidationResult {
  const digits = matchString.replace(/\D/g, '');
  if (digits.length < 6) {
    return {
      is_valid: false,
      subtype: 'no_fnr',
      gatesPassed: { datePlausible: false, digitBoundaryClean: false, contextProximity: false, mod11Valid: false },
      reason: 'Too few digits',
      metrics: { matchLength: matchString.length },
    };
  }

  const day = parseInt(digits.substring(0, 2), 10);
  const month = parseInt(digits.substring(2, 4), 10);

  // Gate 1 (HARD): Date plausibility
  const datePlausible = day >= 1 && day <= 31 && month >= 1 && month <= 12;

  // Gate 2 (HARD): Digit boundary
  const digitBoundaryClean = checkDigitBoundary(fullText, matchIndex, matchString.length);

  // Gate 3 (SOFT): Context proximity
  const windowStart = Math.max(0, matchIndex - NO_CONTEXT_WINDOW_CHARS);
  const windowEnd = Math.min(fullText.length, matchIndex + matchString.length + NO_CONTEXT_WINDOW_CHARS);
  const contextWindow = fullText.slice(windowStart, windowEnd).toLowerCase();
  let hasContext = false;
  for (const keyword of NO_CONTEXT_KEYWORDS) {
    if (contextWindow.includes(keyword)) {
      hasContext = true;
      break;
    }
  }

  // Gate 4 (HARD, AG-XLSX-HARDENING-PLAN-001): Mod11 double check-digit
  const mod11Valid = digits.length === 11 ? mod11No(digits) : false;

  const is_valid = datePlausible && digitBoundaryClean && mod11Valid;

  let reason: string | null = null;
  if (!datePlausible) {
    reason = `Implausible date: day=${day}, month=${month}`;
  } else if (!digitBoundaryClean) {
    reason = 'Match is embedded in a longer digit sequence';
  } else if (!mod11Valid) {
    reason = 'Mod11 double check-digit failed';
  }

  let confidence: number | undefined;
  if (is_valid) {
    const score = scoreProximity(fullText, matchIndex, matchString.length, NO_FNR_ANCHORS, true);
    confidence = score.confidence;
  }

  return {
    is_valid,
    subtype: 'no_fnr',
    gatesPassed: { datePlausible, digitBoundaryClean, contextProximity: hasContext, mod11Valid },
    reason,
    metrics: {
      matchLength: matchString.length,
      day,
      month,
      hasContext,
      mod11Valid,
    },
    confidence,
  };
}

// ============================================================================
// FI HETU VALIDATOR
// ============================================================================

/**
 * Finnish HETU context keywords for proximity check (Gate 3).
 */
const FI_CONTEXT_KEYWORDS = [
  'hetu', 'henkilötunnus', 'sosiaaliturvatunnus', 'sotu',
  'potilasnumero', 'patient', 'henkilö', 'tunniste',
];

/** Context window for FI keyword proximity check */
const FI_CONTEXT_WINDOW_CHARS = 80;

/**
 * Finnish henkilötunnus (HETU) validation.
 * Format: DDMMYYXXXC or DDMMYY±XXXC (with separator at position 6)
 * - Separator: '+' (1800s), '-' (1900s), 'A'-'Y' (2000s+)
 * - XXX: individual number 002-899 for natural persons
 * - C: control character validated via Mod31
 * - AG-XLSX-HARDENING-PLAN-001: Mod31 hard gate
 */
function validateNationalId_fi_hetu(
  matchString: string,
  fullText: string,
  matchIndex: number
): NationalIdValidationResult {
  const digits = matchString.replace(/[+\-A-Za-z]/g, '');
  if (digits.length < 6) {
    return {
      is_valid: false,
      subtype: 'fi_hetu',
      gatesPassed: { datePlausible: false, digitBoundaryClean: false, contextProximity: false, mod31Valid: false },
      reason: 'Too few digits',
      metrics: { matchLength: matchString.length },
    };
  }

  const day = parseInt(digits.substring(0, 2), 10);
  const month = parseInt(digits.substring(2, 4), 10);

  // Gate 1 (HARD): Date plausibility
  const datePlausible = day >= 1 && day <= 31 && month >= 1 && month <= 12;

  // Gate 2 (HARD): Digit boundary
  const digitBoundaryClean = checkDigitBoundary(fullText, matchIndex, matchString.length);

  // Gate 3 (SOFT): Context proximity
  const windowStart = Math.max(0, matchIndex - FI_CONTEXT_WINDOW_CHARS);
  const windowEnd = Math.min(fullText.length, matchIndex + matchString.length + FI_CONTEXT_WINDOW_CHARS);
  const contextWindow = fullText.slice(windowStart, windowEnd).toLowerCase();
  let hasContext = false;
  for (const keyword of FI_CONTEXT_KEYWORDS) {
    if (contextWindow.includes(keyword)) {
      hasContext = true;
      break;
    }
  }

  // Gate 4 (HARD, AG-XLSX-HARDENING-PLAN-001): Mod31 control character
  const mod31Valid = mod31Fi(matchString);

  const is_valid = datePlausible && digitBoundaryClean && mod31Valid;

  let reason: string | null = null;
  if (!datePlausible) {
    reason = `Implausible date: day=${day}, month=${month}`;
  } else if (!digitBoundaryClean) {
    reason = 'Match is embedded in a longer digit sequence';
  } else if (!mod31Valid) {
    reason = 'Mod31 control character check failed';
  }

  let confidence: number | undefined;
  if (is_valid) {
    const score = scoreProximity(fullText, matchIndex, matchString.length, FI_HETU_ANCHORS, true);
    confidence = score.confidence;
  }

  return {
    is_valid,
    subtype: 'fi_hetu',
    gatesPassed: { datePlausible, digitBoundaryClean, contextProximity: hasContext, mod31Valid },
    reason,
    metrics: {
      matchLength: matchString.length,
      day,
      month,
      hasContext,
      mod31Valid,
    },
    confidence,
  };
}

// ============================================================================
// DE STEUER-ID VALIDATOR (AG-MONSTER-HARDENING-TIERA-ENGINE-001)
// ============================================================================

/**
 * German Steuer-ID context keywords for proximity check (Gate 3).
 */
const DE_CONTEXT_KEYWORDS = [
  'steuer-id', 'steuerid', 'steueridentifikationsnummer',
  'identifikationsnummer', 'idnr', 'finanzamt',
  'steuernummer', 'steuerpflichtig', 'einkommensteuer',
  'elster', 'bundeszentralamt',
];

/** Context window for DE keyword proximity check */
const DE_CONTEXT_WINDOW_CHARS = 100;

/**
 * German Steuerliche Identifikationsnummer (Steuer-ID / IdNr) validation.
 * Format: 11 digits, first digit 1-9, ISO 7064 Mod 11,10 check digit.
 *
 * Digit constraint: among the first 10 digits, exactly one digit appears
 * twice (or three times) and at most one digit from 0-9 is missing entirely.
 */
function validateNationalId_de_steuer_id(
  matchString: string,
  fullText: string,
  matchIndex: number
): NationalIdValidationResult {
  const digits = matchString.replace(/\D/g, '');
  if (digits.length !== 11) {
    return {
      is_valid: false,
      subtype: 'de_steuer_id',
      gatesPassed: { digitBoundaryClean: false, contextProximity: false, checksumValid: false, digitStructure: false },
      reason: 'Not 11 digits',
      metrics: { matchLength: matchString.length },
    };
  }

  // Gate 1 (HARD): Digit boundary
  const digitBoundaryClean = checkDigitBoundary(fullText, matchIndex, matchString.length);

  // Gate 2 (HARD): Digit structure — among first 10 digits, exactly one
  // digit appears 2 or 3 times.
  //
  // Correct constraint: multiCount === 1 && tripleCount <= 1.
  // When a digit appears twice:  2+8×1=10 → 1 digit missing (zeroCount=1).
  // When a digit appears thrice: 3+7×1=10 → 2 digits missing (zeroCount=2).
  // The previous `&& zeroCount <= 1` incorrectly rejected valid triple-occurrence
  // Steuer-IDs (e.g., 65929970489 has digit 9 three times → zeroCount=2).
  // P0-FIX-GOLD-DE-STEUER-ID-DOCX: Removed zeroCount guard (AG-MONSTER-UNIFIED-GOVERNANCE-SPEC-001).
  const freq = new Array(10).fill(0);
  for (let i = 0; i < 10; i++) {
    freq[parseInt(digits[i], 10)]++;
  }
  const multiCount = freq.filter(f => f >= 2).length;
  const tripleCount = freq.filter(f => f >= 3).length;
  const digitStructure = multiCount === 1 && tripleCount <= 1;

  // Gate 3 (SOFT): Context proximity
  const windowStart = Math.max(0, matchIndex - DE_CONTEXT_WINDOW_CHARS);
  const windowEnd = Math.min(fullText.length, matchIndex + matchString.length + DE_CONTEXT_WINDOW_CHARS);
  const contextWindow = fullText.slice(windowStart, windowEnd).toLowerCase();
  let hasContext = false;
  for (const keyword of DE_CONTEXT_KEYWORDS) {
    if (contextWindow.includes(keyword)) {
      hasContext = true;
      break;
    }
  }

  // Gate 4 (HARD): ISO 7064 Mod 11,10 checksum
  const checksumValid = mod1110Steuer(digits);

  const is_valid = digitBoundaryClean && digitStructure && checksumValid;

  let reason: string | null = null;
  if (!digitBoundaryClean) {
    reason = 'Match is embedded in a longer digit sequence';
  } else if (!digitStructure) {
    reason = 'Digit frequency structure invalid for Steuer-ID';
  } else if (!checksumValid) {
    reason = 'ISO 7064 Mod 11,10 checksum failed';
  }

  let confidence: number | undefined;
  if (is_valid) {
    const score = scoreProximity(fullText, matchIndex, matchString.length, DE_STEUER_ID_ANCHORS, true);
    confidence = score.confidence;
  }

  return {
    is_valid,
    subtype: 'de_steuer_id',
    gatesPassed: { digitBoundaryClean, contextProximity: hasContext, checksumValid, digitStructure },
    reason,
    metrics: {
      matchLength: matchString.length,
      hasContext,
      checksumValid,
      digitStructure,
    },
    confidence,
  };
}

// ============================================================================
// ES DNI/NIE VALIDATOR (P2-ADD-ES-DNI-NIE)
// ============================================================================

/**
 * Spanish DNI/NIE context keywords for proximity check (Gate 3).
 */
const ES_CONTEXT_KEYWORDS = [
  'dni', 'nie', 'nif', 'cif', 'documento nacional',
  'número de identidad', 'identidad', 'identidad personal',
];

/** Context window for ES keyword proximity check */
const ES_CONTEXT_WINDOW_CHARS = 100;

/**
 * Spanish DNI / NIE (Número de Identidad de Extranjero) validation.
 *
 * DNI format:  8 digits + check letter  (e.g. 12345678Z)
 * NIE format:  X/Y/Z prefix + 7 digits + check letter  (e.g. X1234567L)
 *
 * Check letter algorithm (Mod-23):
 *   - NIE: normalize prefix (X→0, Y→1, Z→2), concatenate with the 7 digits
 *     to form an 8-digit number.
 *   - DNI: the 8-digit number directly.
 *   - index = number mod 23
 *   - letter = TRWAGMYFPDXBNJZSQVHLCKE[index]
 */
const ES_LETTER_TABLE = 'TRWAGMYFPDXBNJZSQVHLCKE';

function validateNationalId_es_dni_nie(
  matchString: string,
  fullText: string,
  matchIndex: number
): NationalIdValidationResult {
  const upper = matchString.toUpperCase();

  // Determine if NIE or DNI
  const firstChar = upper[0];
  let numberStr: string;
  if (firstChar === 'X' || firstChar === 'Y' || firstChar === 'Z') {
    // NIE: normalize prefix
    const prefixMap: Record<string, string> = { X: '0', Y: '1', Z: '2' };
    numberStr = prefixMap[firstChar] + upper.slice(1, 8);
  } else {
    // DNI: 8 digits
    numberStr = upper.slice(0, 8);
  }

  const checkLetter = upper[upper.length - 1];

  // Gate 1 (HARD): Parse and validate number
  const number = parseInt(numberStr, 10);
  const numberValid = !isNaN(number) && numberStr.length === 8;

  // Gate 2 (HARD): Compute expected check letter
  const expectedLetter = numberValid ? ES_LETTER_TABLE[number % 23] : '';
  const checksumValid = numberValid && checkLetter === expectedLetter;

  // Gate 3 (HARD): Digit boundary
  const digitBoundaryClean = checkDigitBoundary(fullText, matchIndex, matchString.length);

  // Gate 4 (SOFT): Context proximity
  const windowStart = Math.max(0, matchIndex - ES_CONTEXT_WINDOW_CHARS);
  const windowEnd = Math.min(fullText.length, matchIndex + matchString.length + ES_CONTEXT_WINDOW_CHARS);
  const contextWindow = fullText.slice(windowStart, windowEnd).toLowerCase();
  let hasContext = false;
  for (const keyword of ES_CONTEXT_KEYWORDS) {
    if (contextWindow.includes(keyword)) {
      hasContext = true;
      break;
    }
  }

  const is_valid = numberValid && checksumValid && digitBoundaryClean;

  let reason: string | null = null;
  if (!numberValid) {
    reason = 'Could not parse 8-digit number from match';
  } else if (!checksumValid) {
    reason = `Mod-23 check letter failed (expected ${expectedLetter}, got ${checkLetter})`;
  } else if (!digitBoundaryClean) {
    reason = 'Match is embedded in a longer digit sequence';
  }

  let confidence: number | undefined;
  if (is_valid) {
    const score = scoreProximity(fullText, matchIndex, matchString.length, ES_DNI_NIE_ANCHORS, true);
    confidence = score.confidence;
  }

  return {
    is_valid,
    subtype: 'es_dni_nie',
    gatesPassed: { numberValid, checksumValid, digitBoundaryClean, contextProximity: hasContext },
    reason,
    metrics: {
      matchLength: matchString.length,
      hasContext,
      checksumValid,
    },
    confidence,
  };
}

// ============================================================================
// IT CODICE FISCALE VALIDATOR (P2-ADD-IT-CODICE-FISCALE)
// ============================================================================

/**
 * Italian Codice Fiscale context keywords for proximity check (Gate 3).
 */
const IT_CONTEXT_KEYWORDS = [
  'codice fiscale', 'c.f.', 'cf.', 'codice tributario',
  'agenzia delle entrate', 'contribuente', 'partita iva',
];

/** Context window for IT keyword proximity check */
const IT_CONTEXT_WINDOW_CHARS = 100;

/**
 * Odd-position (1-indexed) character values for Italian Codice Fiscale check digit.
 * Source: Italian Ministry of Economy and Finance algorithm.
 */
const IT_ODD_VALUES: Record<string, number> = {
  '0': 1,  '1': 0,  '2': 5,  '3': 7,  '4': 9,
  '5': 13, '6': 15, '7': 17, '8': 19, '9': 21,
  A: 1,  B: 0,  C: 5,  D: 7,  E: 9,  F: 13, G: 15, H: 17, I: 19, J: 21,
  K: 2,  L: 4,  M: 18, N: 20, O: 11, P: 3,  Q: 6,  R: 8,  S: 12, T: 14,
  U: 16, V: 10, W: 22, X: 25, Y: 24, Z: 23,
};

/**
 * Italian Codice Fiscale validation.
 * Format: AAABBBYYXZZZZC (16 alphanumeric characters)
 * - Positions 1,3,5,...,15 (odd, 1-indexed): use ODD_VALUES table
 * - Positions 2,4,6,...,14 (even, 1-indexed): A=0, B=1, ..., Z=25, 0=0, ..., 9=9
 * - Check digit: chr(65 + sum % 26)
 */
function validateNationalId_it_codice_fiscale(
  matchString: string,
  fullText: string,
  matchIndex: number
): NationalIdValidationResult {
  const upper = matchString.toUpperCase();

  // Gate 1 (HARD): Exact 16 characters
  if (upper.length !== 16) {
    return {
      is_valid: false,
      subtype: 'it_codice_fiscale',
      gatesPassed: { lengthValid: false, digitBoundaryClean: false, contextProximity: false, checksumValid: false },
      reason: `Expected 16 characters, got ${upper.length}`,
      metrics: { matchLength: matchString.length },
    };
  }

  // Gate 2 (HARD): Digit boundary
  const digitBoundaryClean = checkDigitBoundary(fullText, matchIndex, matchString.length);

  // Gate 3 (HARD): Check digit computation
  let sum = 0;
  let checksumValid = false;
  try {
    for (let i = 0; i < 15; i++) {
      const ch = upper[i];
      if ((i + 1) % 2 === 1) {
        // Odd position (1-indexed)
        const val = IT_ODD_VALUES[ch];
        if (val === undefined) {
          throw new Error(`Invalid char at odd position: ${ch}`);
        }
        sum += val;
      } else {
        // Even position (1-indexed): A=0, ..., Z=25, 0=0, ..., 9=9
        if (ch >= 'A' && ch <= 'Z') {
          sum += ch.charCodeAt(0) - 65;
        } else if (ch >= '0' && ch <= '9') {
          sum += parseInt(ch, 10);
        } else {
          throw new Error(`Invalid char at even position: ${ch}`);
        }
      }
    }
    const expectedCheck = String.fromCharCode(65 + (sum % 26));
    checksumValid = upper[15] === expectedCheck;
  } catch {
    checksumValid = false;
  }

  // Gate 4 (SOFT): Context proximity
  const windowStart = Math.max(0, matchIndex - IT_CONTEXT_WINDOW_CHARS);
  const windowEnd = Math.min(fullText.length, matchIndex + matchString.length + IT_CONTEXT_WINDOW_CHARS);
  const contextWindow = fullText.slice(windowStart, windowEnd).toLowerCase();
  let hasContext = false;
  for (const keyword of IT_CONTEXT_KEYWORDS) {
    if (contextWindow.includes(keyword)) {
      hasContext = true;
      break;
    }
  }

  const is_valid = digitBoundaryClean && checksumValid;

  let reason: string | null = null;
  if (!digitBoundaryClean) {
    reason = 'Match is embedded in a longer digit sequence';
  } else if (!checksumValid) {
    reason = 'Italian Codice Fiscale check digit validation failed';
  }

  let confidence: number | undefined;
  if (is_valid) {
    const score = scoreProximity(fullText, matchIndex, matchString.length, IT_CODICE_FISCALE_ANCHORS, true);
    confidence = score.confidence;
  }

  return {
    is_valid,
    subtype: 'it_codice_fiscale',
    gatesPassed: { lengthValid: true, digitBoundaryClean, contextProximity: hasContext, checksumValid },
    reason,
    metrics: {
      matchLength: matchString.length,
      hasContext,
      checksumValid,
    },
    confidence,
  };
}

// ============================================================================
// PL PESEL VALIDATOR (P2-ADD-PL-PESEL)
// ============================================================================

/**
 * Polish PESEL context keywords for proximity check (Gate 3).
 */
const PL_CONTEXT_KEYWORDS = [
  'pesel', 'numer ewidencyjny', 'identyfikator',
  'numer pesel', 'ewidencja ludności',
];

/** Context window for PL keyword proximity check */
const PL_CONTEXT_WINDOW_CHARS = 100;

/**
 * Polish PESEL validation.
 * Format: 11 digits. Weights: [1,3,7,9,1,3,7,9,1,3].
 * Check digit = (10 - (weighted sum mod 10)) mod 10.
 *
 * Month century encoding:
 *   01-12 = 1900s, 21-32 = 2000s, 41-52 = 2100s, 61-72 = 1800s, 81-92 = 1700s
 */
const PL_PESEL_WEIGHTS = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3];

function validateNationalId_pl_pesel(
  matchString: string,
  fullText: string,
  matchIndex: number
): NationalIdValidationResult {
  const digits = matchString.replace(/\D/g, '');

  // Gate 1 (HARD): Must be exactly 11 digits
  if (digits.length !== 11) {
    return {
      is_valid: false,
      subtype: 'pl_pesel',
      gatesPassed: { digitBoundaryClean: false, contextProximity: false, checksumValid: false, monthValid: false },
      reason: `Expected 11 digits, got ${digits.length}`,
      metrics: { matchLength: matchString.length },
    };
  }

  // Gate 2 (HARD): Digit boundary
  const digitBoundaryClean = checkDigitBoundary(fullText, matchIndex, matchString.length);

  // Gate 3 (HARD): Weighted checksum
  let weightedSum = 0;
  for (let i = 0; i < 10; i++) {
    weightedSum += parseInt(digits[i], 10) * PL_PESEL_WEIGHTS[i];
  }
  const expectedCheck = (10 - (weightedSum % 10)) % 10;
  const checksumValid = parseInt(digits[10], 10) === expectedCheck;

  // Gate 4 (HARD): Month plausibility (century-encoded month field, digits 3-4, 1-indexed)
  const monthField = parseInt(digits.substring(2, 4), 10);
  // Valid century-encoded months: 01-12, 21-32, 41-52, 61-72, 81-92
  const monthValid = (monthField >= 1 && monthField <= 12)
    || (monthField >= 21 && monthField <= 32)
    || (monthField >= 41 && monthField <= 52)
    || (monthField >= 61 && monthField <= 72)
    || (monthField >= 81 && monthField <= 92);

  // Gate 5 (SOFT): Context proximity
  const windowStart = Math.max(0, matchIndex - PL_CONTEXT_WINDOW_CHARS);
  const windowEnd = Math.min(fullText.length, matchIndex + matchString.length + PL_CONTEXT_WINDOW_CHARS);
  const contextWindow = fullText.slice(windowStart, windowEnd).toLowerCase();
  let hasContext = false;
  for (const keyword of PL_CONTEXT_KEYWORDS) {
    if (contextWindow.includes(keyword)) {
      hasContext = true;
      break;
    }
  }

  const is_valid = digitBoundaryClean && checksumValid && monthValid;

  let reason: string | null = null;
  if (!digitBoundaryClean) {
    reason = 'Match is embedded in a longer digit sequence';
  } else if (!monthValid) {
    reason = `Invalid century-encoded month field: ${monthField}`;
  } else if (!checksumValid) {
    reason = 'PESEL weighted checksum failed';
  }

  let confidence: number | undefined;
  if (is_valid) {
    const score = scoreProximity(fullText, matchIndex, matchString.length, PL_PESEL_ANCHORS, true);
    confidence = score.confidence;
  }

  return {
    is_valid,
    subtype: 'pl_pesel',
    gatesPassed: { digitBoundaryClean, contextProximity: hasContext, checksumValid, monthValid },
    reason,
    metrics: {
      matchLength: matchString.length,
      monthField,
      hasContext,
      checksumValid,
      monthValid,
    },
    confidence,
  };
}

// ============================================================================
// NL BSN VALIDATOR (AG-PROMPT-105)
// ============================================================================

/**
 * Dutch BSN context keywords for proximity check (Gate 3).
 */
const NL_CONTEXT_KEYWORDS = [
  'bsn', 'burgerservicenummer', 'burger service nummer',
  'sofinummer', 'sofi-nummer', 'digid',
  'belastingdienst', 'gemeente', 'persoonsgegevens',
];

/** Context window for NL keyword proximity check */
const NL_CONTEXT_WINDOW_CHARS = 100;

/**
 * Dutch BSN (Burgerservicenummer) validation.
 * Format: 9 digits. Weights: [9, 8, 7, 6, 5, 4, 3, 2, -1].
 * Weighted sum must be divisible by 11 and must NOT be 0.
 */
function validateNationalId_nl_bsn(
  matchString: string,
  fullText: string,
  matchIndex: number
): NationalIdValidationResult {
  const digits = matchString.replace(/\D/g, '');

  // Gate 1 (HARD): Must be exactly 9 digits
  if (digits.length !== 9) {
    return {
      is_valid: false,
      subtype: 'nl_bsn',
      gatesPassed: { digitBoundaryClean: false, contextProximity: false, checksumValid: false },
      reason: `Expected 9 digits, got ${digits.length}`,
      metrics: { matchLength: matchString.length },
    };
  }

  // Gate 2 (HARD): Digit boundary
  const digitBoundaryClean = checkDigitBoundary(fullText, matchIndex, matchString.length);

  // Gate 3 (HARD): BSN 11-test checksum
  const checksumValid = bsn11Test(digits);

  // Gate 4 (SOFT): Context proximity
  const windowStart = Math.max(0, matchIndex - NL_CONTEXT_WINDOW_CHARS);
  const windowEnd = Math.min(fullText.length, matchIndex + matchString.length + NL_CONTEXT_WINDOW_CHARS);
  const contextWindow = fullText.slice(windowStart, windowEnd).toLowerCase();
  let hasContext = false;
  for (const keyword of NL_CONTEXT_KEYWORDS) {
    if (contextWindow.includes(keyword)) {
      hasContext = true;
      break;
    }
  }

  const is_valid = digitBoundaryClean && checksumValid;

  let reason: string | null = null;
  if (!digitBoundaryClean) {
    reason = 'Match is embedded in a longer digit sequence';
  } else if (!checksumValid) {
    reason = 'BSN 11-test checksum failed';
  }

  let confidence: number | undefined;
  if (is_valid) {
    const score = scoreProximity(fullText, matchIndex, matchString.length, NL_BSN_ANCHORS, true);
    confidence = score.confidence;
  }

  return {
    is_valid,
    subtype: 'nl_bsn',
    gatesPassed: { digitBoundaryClean, contextProximity: hasContext, checksumValid },
    reason,
    metrics: {
      matchLength: matchString.length,
      hasContext,
      checksumValid,
    },
    confidence,
  };
}

// ============================================================================
// AG-PROMPT-106: FRENCH NIR / INSEE
// ============================================================================

/**
 * French NIR context keywords for proximity check.
 */
const FR_NIR_CONTEXT_KEYWORDS = [
  'nir', 'insee', 'sécurité sociale', 'securite sociale',
  'carte vitale', 'vitale', 'cpam', 'assuré',
];

/** Context window for FR keyword proximity check */
const FR_NIR_CONTEXT_WINDOW_CHARS = 100;

/**
 * French NIR / INSEE (numéro de sécurité sociale) validation.
 *
 * Format: S SS MM DDD CCC CC (15 chars, may contain spaces/dashes)
 *   S   = sex (1 or 2)
 *   SS  = year of birth
 *   MM  = month of birth (01-12, or 20+ for overseas)
 *   DDD = department (00-99, 2A, 2B for Corsica, 97x for overseas)
 *   CCC = commune code
 *   CC  = key (97 - (first 13 mod 97))
 *
 * Gates:
 *   1 (HARD): Digit extraction — must yield 15 chars after normalization
 *   2 (HARD): Digit boundary — not embedded in longer digit sequence
 *   3 (HARD): Mod-97 checksum
 *   4 (SOFT): Context proximity
 */
function validateNationalId_fr_nir(
  matchString: string,
  fullText: string,
  matchIndex: number
): NationalIdValidationResult {
  // Normalize: strip spaces/dashes
  const cleaned = matchString.replace(/[\s-]/g, '').toUpperCase();

  // Gate 1 (HARD): Must be 15 characters after normalization
  if (cleaned.length !== 15) {
    return {
      is_valid: false,
      subtype: 'fr_nir',
      gatesPassed: { digitBoundaryClean: false, contextProximity: false, checksumValid: false },
      reason: `Expected 15 characters after normalization, got ${cleaned.length}`,
      metrics: { matchLength: matchString.length },
    };
  }

  // Gate 2 (HARD): Digit boundary
  const digitBoundaryClean = checkDigitBoundary(fullText, matchIndex, matchString.length);

  // Gate 3 (HARD): Mod-97 checksum (handles Corsica 2A/2B internally)
  const checksumValid = mod97Nir(cleaned);

  // Gate 4 (SOFT): Context proximity
  const windowStart = Math.max(0, matchIndex - FR_NIR_CONTEXT_WINDOW_CHARS);
  const windowEnd = Math.min(fullText.length, matchIndex + matchString.length + FR_NIR_CONTEXT_WINDOW_CHARS);
  const contextWindow = fullText.slice(windowStart, windowEnd).toLowerCase();
  let hasContext = false;
  for (const keyword of FR_NIR_CONTEXT_KEYWORDS) {
    if (contextWindow.includes(keyword)) {
      hasContext = true;
      break;
    }
  }

  const is_valid = digitBoundaryClean && checksumValid;

  let reason: string | null = null;
  if (!digitBoundaryClean) {
    reason = 'Match is embedded in a longer digit sequence';
  } else if (!checksumValid) {
    reason = 'NIR mod-97 checksum failed';
  }

  let confidence: number | undefined;
  if (is_valid) {
    const score = scoreProximity(fullText, matchIndex, matchString.length, FR_NIR_ANCHORS as unknown as string[], true);
    confidence = score.confidence;
  }

  return {
    is_valid,
    subtype: 'fr_nir',
    gatesPassed: { digitBoundaryClean, contextProximity: hasContext, checksumValid },
    reason,
    metrics: {
      matchLength: matchString.length,
      hasContext,
      checksumValid,
    },
    confidence,
  };
}

// ============================================================================
// AG-PROMPT-110: PORTUGUESE NIF (Número de Identificação Fiscal)
// ============================================================================

/**
 * Portuguese NIF context keywords for proximity check.
 */
const PT_NIF_CONTEXT_KEYWORDS = [
  'nif', 'contribuinte', 'número de contribuinte', 'identificação fiscal',
  'finanças', 'financas', 'autoridade tributária',
];

/** Context window for PT keyword proximity check */
const PT_NIF_CONTEXT_WINDOW_CHARS = 100;

/**
 * Portuguese NIF (Número de Identificação Fiscal) validation.
 *
 * Format: 9 digits, first digit 1-3/5-9 (never 0 or 4)
 * Checksum: mod-11, weights [9,8,7,6,5,4,3,2]
 *
 * Gates:
 *   1 (HARD): Must be exactly 9 digits
 *   2 (HARD): Digit boundary — not embedded in longer digit sequence
 *   3 (HARD): Mod-11 checksum + first digit validation
 *   4 (SOFT): Context proximity
 */
function validateNationalId_pt_nif(
  matchString: string,
  fullText: string,
  matchIndex: number
): NationalIdValidationResult {
  const digits = matchString.replace(/\D/g, '');

  // Gate 1 (HARD): Must be exactly 9 digits
  if (digits.length !== 9) {
    return {
      is_valid: false,
      subtype: 'pt_nif',
      gatesPassed: { digitBoundaryClean: false, contextProximity: false, checksumValid: false },
      reason: `Expected 9 digits, got ${digits.length}`,
      metrics: { matchLength: matchString.length },
    };
  }

  // Gate 2 (HARD): Digit boundary
  const digitBoundaryClean = checkDigitBoundary(fullText, matchIndex, matchString.length);

  // Gate 3 (HARD): Mod-11 checksum (includes first-digit validation)
  const checksumValid = mod11Nif(digits);

  // Gate 4 (SOFT): Context proximity
  const windowStart = Math.max(0, matchIndex - PT_NIF_CONTEXT_WINDOW_CHARS);
  const windowEnd = Math.min(fullText.length, matchIndex + matchString.length + PT_NIF_CONTEXT_WINDOW_CHARS);
  const contextWindow = fullText.slice(windowStart, windowEnd).toLowerCase();
  let hasContext = false;
  for (const keyword of PT_NIF_CONTEXT_KEYWORDS) {
    if (contextWindow.includes(keyword)) {
      hasContext = true;
      break;
    }
  }

  const is_valid = digitBoundaryClean && checksumValid;

  let reason: string | null = null;
  if (!digitBoundaryClean) {
    reason = 'Match is embedded in a longer digit sequence';
  } else if (!checksumValid) {
    reason = 'PT NIF mod-11 checksum failed or invalid first digit';
  }

  let confidence: number | undefined;
  if (is_valid) {
    const score = scoreProximity(fullText, matchIndex, matchString.length, PT_NIF_ANCHORS, true);
    confidence = score.confidence;
  }

  return {
    is_valid,
    subtype: 'pt_nif',
    gatesPassed: { digitBoundaryClean, contextProximity: hasContext, checksumValid },
    reason,
    metrics: {
      matchLength: matchString.length,
      hasContext,
      checksumValid,
    },
    confidence,
  };
}

// ============================================================================
// AG-PROMPT-115: BELGIAN NN (Rijksregisternummer / Numéro national)
// ============================================================================

/**
 * Belgian NN context keywords for proximity check (Gate 3).
 * Bilingual FR/NL keywords — Belgium uses both languages officially.
 */
const BE_NN_CONTEXT_KEYWORDS = [
  'rijksregisternummer', 'rijksregister', 'nationaal nummer',
  'numéro national', 'numero national', 'registre national',
  'identiteitskaart', 'carte d\'identité', 'carte d\'identite',
  'eid', 'belgisch', 'belge',
];

/** Context window for BE keyword proximity check */
const BE_NN_CONTEXT_WINDOW_CHARS = 100;

/**
 * Belgian National Number (Rijksregisternummer) validation.
 *
 * Format: YY.MM.DD-SSS.CC (11 digits with separators)
 * Checksum: mod-97 (both pre-2000 and post-2000 variants tried)
 *
 * Gates:
 *   1 (HARD): Must yield exactly 11 digits after separator stripping
 *   2 (HARD): Date plausibility (YYMMDD)
 *   3 (HARD): Mod-97 checksum
 *   4 (SOFT): Context proximity
 */
function validateNationalId_be_nn(
  matchString: string,
  fullText: string,
  matchIndex: number
): NationalIdValidationResult {
  const digits = matchString.replace(/\D/g, '');

  // Gate 1 (HARD): Must be exactly 11 digits
  if (digits.length !== 11) {
    return {
      is_valid: false,
      subtype: 'be_nn',
      gatesPassed: { datePlausible: false, checksumValid: false, contextProximity: false },
      reason: `Expected 11 digits, got ${digits.length}`,
      metrics: { matchLength: matchString.length },
    };
  }

  // Gate 2 (HARD): Date plausibility (YYMMDD)
  const mm = parseInt(digits.substring(2, 4), 10);
  const dd = parseInt(digits.substring(4, 6), 10);
  const datePlausible = mm >= 1 && mm <= 12 && dd >= 1 && dd <= 31;
  if (!datePlausible) {
    return {
      is_valid: false,
      subtype: 'be_nn',
      gatesPassed: { datePlausible: false, checksumValid: false, contextProximity: false },
      reason: 'Date portion not plausible',
      metrics: { matchLength: matchString.length },
    };
  }

  // Gate 3 (HARD): Mod-97 checksum
  const checksumValid = mod97BeNn(digits);

  // Gate 4 (SOFT): Context proximity
  const windowStart = Math.max(0, matchIndex - BE_NN_CONTEXT_WINDOW_CHARS);
  const windowEnd = Math.min(fullText.length, matchIndex + matchString.length + BE_NN_CONTEXT_WINDOW_CHARS);
  const contextWindow = fullText.slice(windowStart, windowEnd).toLowerCase();
  let hasContext = false;
  for (const keyword of BE_NN_CONTEXT_KEYWORDS) {
    if (contextWindow.includes(keyword)) {
      hasContext = true;
      break;
    }
  }

  const is_valid = checksumValid;

  let reason: string | null = null;
  if (!checksumValid) {
    reason = 'Belgian NN mod-97 checksum failed';
  }

  let confidence: number | undefined;
  if (is_valid) {
    const score = scoreProximity(fullText, matchIndex, matchString.length, BE_NN_ANCHORS, true);
    confidence = score.confidence;
  }

  return {
    is_valid,
    subtype: 'be_nn',
    gatesPassed: { datePlausible, checksumValid, contextProximity: hasContext },
    reason,
    metrics: {
      matchLength: matchString.length,
      hasContext,
      checksumValid,
    },
    confidence,
  };
}

// ============================================================================
// AG-PROMPT-115: BRAZILIAN CPF (Cadastro de Pessoas Físicas)
// ============================================================================

/**
 * Brazilian CPF context keywords for proximity check.
 */
const BR_CPF_CONTEXT_KEYWORDS = [
  'cpf', 'cadastro de pessoas', 'receita federal',
  'contribuinte', 'pessoa física', 'pessoa fisica',
];

/** Context window for BR keyword proximity check */
const BR_CPF_CONTEXT_WINDOW_CHARS = 100;

/**
 * Brazilian CPF validation.
 *
 * Format: XXX.XXX.XXX-XX (11 digits with dots + dash)
 * Checksum: double mod-11
 *
 * Gates:
 *   1 (HARD): Must yield exactly 11 digits after separator stripping
 *   2 (HARD): Double mod-11 checksum (rejects all-same-digit)
 *   3 (SOFT): Context proximity
 */
function validateNationalId_br_cpf(
  matchString: string,
  fullText: string,
  matchIndex: number
): NationalIdValidationResult {
  const digits = matchString.replace(/\D/g, '');

  // Gate 1 (HARD): Must be exactly 11 digits
  if (digits.length !== 11) {
    return {
      is_valid: false,
      subtype: 'br_cpf',
      gatesPassed: { checksumValid: false, contextProximity: false },
      reason: `Expected 11 digits, got ${digits.length}`,
      metrics: { matchLength: matchString.length },
    };
  }

  // Gate 2 (HARD): Double mod-11 checksum
  const checksumValid = mod11Cpf(digits);

  // Gate 3 (SOFT): Context proximity
  const windowStart = Math.max(0, matchIndex - BR_CPF_CONTEXT_WINDOW_CHARS);
  const windowEnd = Math.min(fullText.length, matchIndex + matchString.length + BR_CPF_CONTEXT_WINDOW_CHARS);
  const contextWindow = fullText.slice(windowStart, windowEnd).toLowerCase();
  let hasContext = false;
  for (const keyword of BR_CPF_CONTEXT_KEYWORDS) {
    if (contextWindow.includes(keyword)) {
      hasContext = true;
      break;
    }
  }

  const is_valid = checksumValid;

  let reason: string | null = null;
  if (!checksumValid) {
    reason = 'Brazilian CPF double mod-11 checksum failed';
  }

  let confidence: number | undefined;
  if (is_valid) {
    const score = scoreProximity(fullText, matchIndex, matchString.length, BR_CPF_ANCHORS, true);
    confidence = score.confidence;
  }

  return {
    is_valid,
    subtype: 'br_cpf',
    gatesPassed: { checksumValid, contextProximity: hasContext },
    reason,
    metrics: {
      matchLength: matchString.length,
      hasContext,
      checksumValid,
    },
    confidence,
  };
}

// ============================================================================
// AG-PROMPT-119: BRAZILIAN CNPJ (Cadastro Nacional da Pessoa Jurídica)
// ============================================================================

/**
 * Brazilian CNPJ context keywords for proximity check.
 */
const BR_CNPJ_CONTEXT_KEYWORDS = [
  'cnpj', 'cadastro nacional', 'pessoa jurídica', 'pessoa juridica',
  'razão social', 'razao social', 'empresa', 'cnpj no', 'inscrição federal',
];

/** Context window for CNPJ keyword proximity check */
const BR_CNPJ_CONTEXT_WINDOW_CHARS = 100;

/**
 * Brazilian CNPJ validation.
 *
 * Format: XX.XXX.XXX/XXXX-YY (14 digits with dots/slash/dash separators)
 * The /XXXX-YY suffix makes this format uniquely distinctive.
 *
 * Gates:
 *   1 (HARD): Must yield exactly 14 digits after stripping
 *   2 (HARD): Double mod-11 checksum (rejects all-same-digit)
 *   3 (SOFT): Context proximity
 */
function validateNationalId_br_cnpj(
  matchString: string,
  fullText: string,
  matchIndex: number
): NationalIdValidationResult {
  const digits = matchString.replace(/\D/g, '');

  // Gate 1 (HARD): Must be exactly 14 digits
  if (digits.length !== 14) {
    return {
      is_valid: false,
      subtype: 'br_cnpj',
      gatesPassed: { checksumValid: false, contextProximity: false },
      reason: `Expected 14 digits, got ${digits.length}`,
      metrics: { matchLength: matchString.length },
    };
  }

  // Gate 2 (HARD): Double mod-11 checksum
  const checksumValid = mod11Cnpj(digits);

  // Gate 3 (SOFT): Context proximity
  const windowStart = Math.max(0, matchIndex - BR_CNPJ_CONTEXT_WINDOW_CHARS);
  const windowEnd = Math.min(fullText.length, matchIndex + matchString.length + BR_CNPJ_CONTEXT_WINDOW_CHARS);
  const contextWindow = fullText.slice(windowStart, windowEnd).toLowerCase();
  let hasContext = false;
  for (const keyword of BR_CNPJ_CONTEXT_KEYWORDS) {
    if (contextWindow.includes(keyword)) {
      hasContext = true;
      break;
    }
  }

  const is_valid = checksumValid;

  let reason: string | null = null;
  if (!checksumValid) {
    reason = 'Brazilian CNPJ double mod-11 checksum failed';
  }

  let confidence: number | undefined;
  if (is_valid) {
    const score = scoreProximity(fullText, matchIndex, matchString.length, BR_CNPJ_ANCHORS, true);
    confidence = score.confidence;
  }

  return {
    is_valid,
    subtype: 'br_cnpj',
    gatesPassed: { checksumValid, contextProximity: hasContext },
    reason,
    metrics: {
      matchLength: matchString.length,
      hasContext,
      checksumValid,
    },
    confidence,
  };
}

// ============================================================================
// AG-PROMPT-115: MEXICAN CURP (Clave Única de Registro de Población)
// ============================================================================

/**
 * Mexican CURP context keywords for proximity check.
 */
const MX_CURP_CONTEXT_KEYWORDS = [
  'curp', 'clave única', 'clave unica', 'registro de población',
  'registro de poblacion', 'acta de nacimiento',
  'ine', 'credencial de elector',
];

/** Context window for MX keyword proximity check */
const MX_CURP_CONTEXT_WINDOW_CHARS = 100;

/**
 * Mexican CURP validation.
 *
 * Format: AAAA######HSSCCCD# (18 alphanumeric characters)
 * No full checksum implemented yet — format validation + date plausibility + context.
 *
 * Gates:
 *   1 (HARD): Must be exactly 18 characters matching CURP pattern
 *   2 (HARD): Date plausibility (YYMMDD at positions 4-9)
 *   3 (HARD): Valid sex indicator (H or M at position 10)
 *   4 (SOFT): Context proximity
 */
function validateNationalId_mx_curp(
  matchString: string,
  fullText: string,
  matchIndex: number
): NationalIdValidationResult {
  const upper = matchString.toUpperCase();

  // Gate 1 (HARD): Format check
  if (!/^[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d$/.test(upper)) {
    return {
      is_valid: false,
      subtype: 'mx_curp',
      gatesPassed: { formatValid: false, datePlausible: false, contextProximity: false },
      reason: 'Does not match CURP format',
      metrics: { matchLength: matchString.length },
    };
  }

  // Gate 2 (HARD): Date plausibility (positions 4-9: YYMMDD)
  const mm = parseInt(upper.substring(6, 8), 10);
  const dd = parseInt(upper.substring(8, 10), 10);
  const datePlausible = mm >= 1 && mm <= 12 && dd >= 1 && dd <= 31;

  if (!datePlausible) {
    return {
      is_valid: false,
      subtype: 'mx_curp',
      gatesPassed: { formatValid: true, datePlausible: false, contextProximity: false },
      reason: 'Date portion not plausible',
      metrics: { matchLength: matchString.length },
    };
  }

  // Gate 3 (SOFT): Context proximity
  const windowStart = Math.max(0, matchIndex - MX_CURP_CONTEXT_WINDOW_CHARS);
  const windowEnd = Math.min(fullText.length, matchIndex + matchString.length + MX_CURP_CONTEXT_WINDOW_CHARS);
  const contextWindow = fullText.slice(windowStart, windowEnd).toLowerCase();
  let hasContext = false;
  for (const keyword of MX_CURP_CONTEXT_KEYWORDS) {
    if (contextWindow.includes(keyword)) {
      hasContext = true;
      break;
    }
  }

  const is_valid = true; // Format + date validated; CURP format is very distinctive

  let confidence: number | undefined;
  if (is_valid) {
    const score = scoreProximity(fullText, matchIndex, matchString.length, MX_CURP_ANCHORS, true);
    confidence = score.confidence;
  }

  return {
    is_valid,
    subtype: 'mx_curp',
    gatesPassed: { formatValid: true, datePlausible, contextProximity: hasContext },
    reason: null,
    metrics: {
      matchLength: matchString.length,
      hasContext,
    },
    confidence,
  };
}

// ============================================================================
// AG-PROMPT-119: MEXICAN RFC (Registro Federal de Contribuyentes)
// ============================================================================

/**
 * Mexican RFC context keywords for proximity check.
 * Context is MANDATORY for RFC due to high FP risk (no public checksum;
 * 12-13 char alphanumeric pattern overlaps with product codes, model numbers).
 */
const MX_RFC_CONTEXT_KEYWORDS = [
  'rfc', 'registro federal de contribuyentes', 'contribuyente',
  'sat', 'servicio de administración tributaria', 'servicio de administracion tributaria',
  'cédula fiscal', 'cedula fiscal', 'constancia fiscal', 'constancia de situación',
];

/** Context window for RFC keyword proximity check */
const MX_RFC_CONTEXT_WINDOW_CHARS = 150;

/**
 * Mexican RFC (Registro Federal de Contribuyentes) validation.
 *
 * Format: [A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3} (12-13 characters)
 *   - Individuals (personas físicas): 4 letters + YYMMDD + 3 alphanumeric
 *   - Legal entities (personas morales): 3 letters + YYMMDD + 3 alphanumeric
 * No public checksum algorithm exists for RFC.
 *
 * Gates:
 *   1 (HARD): Must match RFC format pattern
 *   2 (HARD): Date plausibility (YYMMDD — month 01-12, day 00-31)
 *   3 (MANDATORY context gate): RFC-specific keyword required in proximity window
 *                                (elevated FP risk without checksum)
 */
function validateNationalId_mx_rfc(
  matchString: string,
  fullText: string,
  matchIndex: number
): NationalIdValidationResult {
  const upper = matchString.toUpperCase().replace(/[\s-]/g, '');

  // Gate 1 (HARD): Format check — 3-4 letters, 6 digits, 3 alphanumeric
  if (!/^[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3}$/.test(upper)) {
    return {
      is_valid: false,
      subtype: 'mx_rfc',
      gatesPassed: { formatValid: false, datePlausible: false, contextProximity: false },
      reason: 'Does not match RFC format ([A-ZÑ&]{3,4}\\d{6}[A-Z0-9]{3})',
      metrics: { matchLength: matchString.length },
    };
  }

  // Determine prefix length (3 or 4 letters)
  const prefixMatch = upper.match(/^[A-ZÑ&]+/);
  const prefixLen = prefixMatch ? prefixMatch[0].length : 0;
  const dateStr = upper.substring(prefixLen, prefixLen + 6);

  // Gate 2 (HARD): Date plausibility — month 01-12, day 00-31
  const mm = parseInt(dateStr.substring(2, 4), 10);
  const dd = parseInt(dateStr.substring(4, 6), 10);
  const datePlausible = mm >= 1 && mm <= 12 && dd >= 0 && dd <= 31;

  if (!datePlausible) {
    return {
      is_valid: false,
      subtype: 'mx_rfc',
      gatesPassed: { formatValid: true, datePlausible: false, contextProximity: false },
      reason: 'RFC date portion not plausible (month must be 01-12, day 00-31)',
      metrics: { matchLength: matchString.length, month: mm, day: dd },
    };
  }

  // Gate 3 (MANDATORY): Context keyword required — no checksum available
  const windowStart = Math.max(0, matchIndex - MX_RFC_CONTEXT_WINDOW_CHARS);
  const windowEnd = Math.min(fullText.length, matchIndex + matchString.length + MX_RFC_CONTEXT_WINDOW_CHARS);
  const contextWindow = fullText.slice(windowStart, windowEnd).toLowerCase();
  let hasContext = false;
  for (const keyword of MX_RFC_CONTEXT_KEYWORDS) {
    if (contextWindow.includes(keyword)) { hasContext = true; break; }
  }

  // For RFC: context is MANDATORY (no checksum; pattern overlaps with product codes)
  const is_valid = hasContext;
  let reason: string | null = null;
  if (!hasContext) {
    reason = 'RFC match requires context keyword (rfc, contribuyente, sat, cédula fiscal) within window';
  }

  let confidence: number | undefined;
  if (is_valid) {
    const score = scoreProximity(fullText, matchIndex, matchString.length, MX_RFC_ANCHORS, true);
    confidence = score.confidence;
  }

  return {
    is_valid,
    subtype: 'mx_rfc',
    gatesPassed: { formatValid: true, datePlausible, contextProximity: hasContext },
    reason,
    metrics: { matchLength: matchString.length, prefixLength: prefixLen, hasContext, month: mm, day: dd },
    confidence,
  };
}

// ============================================================================
// AG-PROMPT-116: IRISH PPS NUMBER (Personal Public Service Number)
// ============================================================================

/**
 * Irish PPS Number context keywords for proximity check.
 */
const IE_PPS_CONTEXT_KEYWORDS = [
  'pps', 'ppsn', 'pps number', 'personal public service',
  'revenue', 'department of social protection', 'deasp',
  'hse', 'public services card',
];

const IE_PPS_CONTEXT_WINDOW_CHARS = 100;

/**
 * Irish PPS Number validation.
 *
 * Format: 7 digits + 1-2 uppercase letters (1 check letter [A-W] + optional type letter)
 * Checksum: mod-23 check letter (weights [8,7,6,5,4,3,2], 0→W, 1→A, ..., 22→V)
 *
 * Gates:
 *   1 (HARD): Format check (7 digits + 1-2 letters A-W)
 *   2 (HARD): Mod-23 check letter
 *   3 (SOFT): Context proximity
 */
function validateNationalId_ie_pps(
  matchString: string,
  fullText: string,
  matchIndex: number
): NationalIdValidationResult {
  const upper = matchString.replace(/\s/g, '').toUpperCase();

  // Gate 1 (HARD): Format check
  if (!/^\d{7}[A-W]{1,2}$/.test(upper)) {
    return {
      is_valid: false,
      subtype: 'ie_pps',
      gatesPassed: { formatValid: false, checksumValid: false, contextProximity: false },
      reason: 'Does not match PPS format (7 digits + 1-2 letters A-W)',
      metrics: { matchLength: matchString.length },
    };
  }

  // Gate 2 (HARD): Mod-23 check letter
  const checksumValid = mod23IePps(upper);

  // Gate 3 (SOFT): Context proximity
  const windowStart = Math.max(0, matchIndex - IE_PPS_CONTEXT_WINDOW_CHARS);
  const windowEnd = Math.min(fullText.length, matchIndex + matchString.length + IE_PPS_CONTEXT_WINDOW_CHARS);
  const contextWindow = fullText.slice(windowStart, windowEnd).toLowerCase();
  let hasContext = false;
  for (const keyword of IE_PPS_CONTEXT_KEYWORDS) {
    if (contextWindow.includes(keyword)) { hasContext = true; break; }
  }

  const is_valid = checksumValid;
  let reason: string | null = null;
  if (!checksumValid) reason = 'Irish PPS mod-23 check letter failed';

  let confidence: number | undefined;
  if (is_valid) {
    const score = scoreProximity(fullText, matchIndex, matchString.length, IE_PPS_ANCHORS, true);
    confidence = score.confidence;
  }

  return {
    is_valid,
    subtype: 'ie_pps',
    gatesPassed: { formatValid: true, checksumValid, contextProximity: hasContext },
    reason,
    metrics: { matchLength: matchString.length, hasContext, checksumValid },
    confidence,
  };
}

// ============================================================================
// AG-PROMPT-116: AUSTRIAN SV-NR (Sozialversicherungsnummer)
// ============================================================================

/**
 * Austrian SV-Nr context keywords for proximity check.
 */
const AT_SV_NR_CONTEXT_KEYWORDS = [
  'sozialversicherungsnummer', 'sozialversicherung', 'sv-nr', 'svnr',
  'versicherungsnummer', 'österreich', 'osterreich',
  'pensionsversicherung', 'geburtsdatum',
];

const AT_SV_NR_CONTEXT_WINDOW_CHARS = 100;

/**
 * Austrian SV-Nr (Sozialversicherungsnummer) validation.
 *
 * Format: XXX C DDMMYY — 10 digits (4-digit prefix + 6-digit DOB)
 * Checksum: mod-10 at position 3 (weights [3,7,9,5,8,4,2,1,6])
 *
 * Gates:
 *   1 (HARD): Must yield exactly 10 digits
 *   2 (HARD): Date plausibility (DDMMYY at positions 4-9)
 *   3 (HARD): Mod-10 check digit
 *   4 (SOFT): Context proximity (required due to medium FP risk)
 */
function validateNationalId_at_sv_nr(
  matchString: string,
  fullText: string,
  matchIndex: number
): NationalIdValidationResult {
  const digits = matchString.replace(/\D/g, '');

  // Gate 1 (HARD): Must be exactly 10 digits
  if (digits.length !== 10) {
    return {
      is_valid: false,
      subtype: 'at_sv_nr',
      gatesPassed: { datePlausible: false, checksumValid: false, contextProximity: false },
      reason: `Expected 10 digits, got ${digits.length}`,
      metrics: { matchLength: matchString.length },
    };
  }

  // Gate 2 (HARD): Date plausibility (DDMMYY at positions 4-9)
  const dd = parseInt(digits.substring(4, 6), 10);
  const mm = parseInt(digits.substring(6, 8), 10);
  const datePlausible = dd >= 1 && dd <= 31 && mm >= 1 && mm <= 12;
  if (!datePlausible) {
    return {
      is_valid: false,
      subtype: 'at_sv_nr',
      gatesPassed: { datePlausible: false, checksumValid: false, contextProximity: false },
      reason: 'Date portion not plausible',
      metrics: { matchLength: matchString.length },
    };
  }

  // Gate 3 (HARD): Mod-10 check digit
  const checksumValid = mod10AtSvNr(digits);

  // Gate 4 (SOFT): Context proximity — enforced as is_valid gate due to medium FP risk
  const windowStart = Math.max(0, matchIndex - AT_SV_NR_CONTEXT_WINDOW_CHARS);
  const windowEnd = Math.min(fullText.length, matchIndex + matchString.length + AT_SV_NR_CONTEXT_WINDOW_CHARS);
  const contextWindow = fullText.slice(windowStart, windowEnd).toLowerCase();
  let hasContext = false;
  for (const keyword of AT_SV_NR_CONTEXT_KEYWORDS) {
    if (contextWindow.includes(keyword)) { hasContext = true; break; }
  }

  // For SV-Nr: require checksum AND context (medium FP risk)
  const is_valid = checksumValid && hasContext;
  let reason: string | null = null;
  if (!checksumValid) reason = 'Austrian SV-Nr mod-10 check digit failed';
  else if (!hasContext) reason = 'Austrian SV-Nr requires context keyword in proximity';

  let confidence: number | undefined;
  if (is_valid) {
    const score = scoreProximity(fullText, matchIndex, matchString.length, AT_SV_NR_ANCHORS, true);
    confidence = score.confidence;
  }

  return {
    is_valid,
    subtype: 'at_sv_nr',
    gatesPassed: { datePlausible, checksumValid, contextProximity: hasContext },
    reason,
    metrics: { matchLength: matchString.length, hasContext, checksumValid },
    confidence,
  };
}

// ============================================================================
// AG-PROMPT-116: ROMANIAN CNP (Cod Numeric Personal)
// ============================================================================

/**
 * Romanian CNP context keywords for proximity check.
 */
const RO_CNP_CONTEXT_KEYWORDS = [
  'cnp', 'cod numeric personal', 'carte de identitate',
  'buletin de identitate', 'codul numeric', 'anaf',
  'România', 'romania', 'românesc', 'romanesc',
];

const RO_CNP_CONTEXT_WINDOW_CHARS = 100;

/**
 * Romanian CNP (Cod Numeric Personal) validation.
 *
 * Format: 13 digits — S YY MM DD CC XXX K
 * Checksum: mod-11 with constant vector [2,7,9,1,4,6,3,5,8,2,7,9]
 *
 * Gates:
 *   1 (HARD): Must be exactly 13 digits
 *   2 (HARD): First digit 1-8 (sex/century indicator)
 *   3 (HARD): Date plausibility (YYMMDD)
 *   4 (HARD): Mod-11 check digit
 *   5 (SOFT): Context proximity
 */
function validateNationalId_ro_cnp(
  matchString: string,
  fullText: string,
  matchIndex: number
): NationalIdValidationResult {
  const digits = matchString.replace(/\D/g, '');

  // Gate 1 (HARD): Must be exactly 13 digits
  if (digits.length !== 13) {
    return {
      is_valid: false,
      subtype: 'ro_cnp',
      gatesPassed: { sexDigitValid: false, datePlausible: false, checksumValid: false, contextProximity: false },
      reason: `Expected 13 digits, got ${digits.length}`,
      metrics: { matchLength: matchString.length },
    };
  }

  // Gate 2 (HARD): First digit 1-8
  const s = parseInt(digits[0], 10);
  const sexDigitValid = s >= 1 && s <= 8;
  if (!sexDigitValid) {
    return {
      is_valid: false,
      subtype: 'ro_cnp',
      gatesPassed: { sexDigitValid: false, datePlausible: false, checksumValid: false, contextProximity: false },
      reason: 'Sex/century digit not in range 1-8',
      metrics: { matchLength: matchString.length },
    };
  }

  // Gate 3 (HARD): Date plausibility (YYMMDD at positions 1-6)
  const mm = parseInt(digits.substring(3, 5), 10);
  const dd = parseInt(digits.substring(5, 7), 10);
  const datePlausible = mm >= 1 && mm <= 12 && dd >= 1 && dd <= 31;
  if (!datePlausible) {
    return {
      is_valid: false,
      subtype: 'ro_cnp',
      gatesPassed: { sexDigitValid: true, datePlausible: false, checksumValid: false, contextProximity: false },
      reason: 'Date portion not plausible',
      metrics: { matchLength: matchString.length },
    };
  }

  // Gate 4 (HARD): Mod-11 check digit
  const checksumValid = mod11RoCnp(digits);

  // Gate 5 (SOFT): Context proximity
  const windowStart = Math.max(0, matchIndex - RO_CNP_CONTEXT_WINDOW_CHARS);
  const windowEnd = Math.min(fullText.length, matchIndex + matchString.length + RO_CNP_CONTEXT_WINDOW_CHARS);
  const contextWindow = fullText.slice(windowStart, windowEnd).toLowerCase();
  let hasContext = false;
  for (const keyword of RO_CNP_CONTEXT_KEYWORDS) {
    if (contextWindow.includes(keyword)) { hasContext = true; break; }
  }

  const is_valid = checksumValid;
  let reason: string | null = null;
  if (!checksumValid) reason = 'Romanian CNP mod-11 check digit failed';

  let confidence: number | undefined;
  if (is_valid) {
    const score = scoreProximity(fullText, matchIndex, matchString.length, RO_CNP_ANCHORS, true);
    confidence = score.confidence;
  }

  return {
    is_valid,
    subtype: 'ro_cnp',
    gatesPassed: { sexDigitValid, datePlausible, checksumValid, contextProximity: hasContext },
    reason,
    metrics: { matchLength: matchString.length, hasContext, checksumValid },
    confidence,
  };
}

// ============================================================================
// AG-PROMPT-116: CZECH / SLOVAK RODNÉ ČÍSLO (Birth Number)
// ============================================================================

/**
 * Czech/Slovak Rodné číslo context keywords for proximity check.
 */
const CZ_RC_CONTEXT_KEYWORDS = [
  'rodné číslo', 'rodne cislo', 'rodné', 'r.č.',
  'česká republika', 'ceska republika', 'slovenská republika',
  'slovensko', 'občanský průkaz', 'občiansky preukaz',
];

const CZ_RC_CONTEXT_WINDOW_CHARS = 100;

/**
 * Czech / Slovak Rodné číslo (Birth Number) validation.
 *
 * Format: YYMMDD/XXXX or YYMMDDXXXX (10 digits, slash is separator)
 * Checksum: The 10-digit number must be divisible by 11 (mod-11 = 0)
 * Women: month is incremented by 50 (01-12 → 51-62)
 *
 * Gates:
 *   1 (HARD): Must yield exactly 10 digits
 *   2 (HARD): Date plausibility (YYMMDD, accepting female month offset 51-62)
 *   3 (HARD): Mod-11 (10-digit number divisible by 11)
 *   4 (SOFT): Context proximity
 */
function validateNationalId_cz_rc(
  matchString: string,
  fullText: string,
  matchIndex: number
): NationalIdValidationResult {
  const digits = matchString.replace(/[\/\s]/g, '');

  // Gate 1 (HARD): Must be exactly 10 digits
  if (digits.length !== 10 || !/^\d{10}$/.test(digits)) {
    return {
      is_valid: false,
      subtype: 'cz_rc',
      gatesPassed: { datePlausible: false, checksumValid: false, contextProximity: false },
      reason: `Expected 10 digits, got ${digits.length}`,
      metrics: { matchLength: matchString.length },
    };
  }

  // Gate 2 (HARD): Date plausibility
  const mm = parseInt(digits.substring(2, 4), 10);
  const dd = parseInt(digits.substring(4, 6), 10);
  // Accept male months 1-12 and female months 51-62
  const monthNormalized = mm > 50 ? mm - 50 : mm;
  const datePlausible = monthNormalized >= 1 && monthNormalized <= 12 && dd >= 1 && dd <= 31;
  if (!datePlausible) {
    return {
      is_valid: false,
      subtype: 'cz_rc',
      gatesPassed: { datePlausible: false, checksumValid: false, contextProximity: false },
      reason: 'Date portion not plausible',
      metrics: { matchLength: matchString.length },
    };
  }

  // Gate 3 (HARD): Mod-11 (10-digit number divisible by 11)
  const checksumValid = mod11CzRc(digits);

  // Gate 4 (SOFT): Context proximity
  const windowStart = Math.max(0, matchIndex - CZ_RC_CONTEXT_WINDOW_CHARS);
  const windowEnd = Math.min(fullText.length, matchIndex + matchString.length + CZ_RC_CONTEXT_WINDOW_CHARS);
  const contextWindow = fullText.slice(windowStart, windowEnd).toLowerCase();
  let hasContext = false;
  for (const keyword of CZ_RC_CONTEXT_KEYWORDS) {
    if (contextWindow.includes(keyword)) { hasContext = true; break; }
  }

  const is_valid = checksumValid;
  let reason: string | null = null;
  if (!checksumValid) reason = 'Czech/Slovak Rodné číslo mod-11 check failed';

  let confidence: number | undefined;
  if (is_valid) {
    const score = scoreProximity(fullText, matchIndex, matchString.length, CZ_RC_ANCHORS, true);
    confidence = score.confidence;
  }

  return {
    is_valid,
    subtype: 'cz_rc',
    gatesPassed: { datePlausible, checksumValid, contextProximity: hasContext },
    reason,
    metrics: { matchLength: matchString.length, hasContext, checksumValid },
    confidence,
  };
}

// ============================================================================
// AG-PROMPT-117: ARGENTINE CUIL / CUIT
// ============================================================================

const AR_CUIL_CONTEXT_KEYWORDS = [
  'cuil', 'cuit', 'afip', 'contribuyente', 'argentina',
  'número de cuil', 'número de cuit', 'nro. cuil', 'nro. cuit',
  'identificación tributaria', 'identificacion tributaria',
];

const AR_CUIL_CONTEXT_WINDOW_CHARS = 100;

/**
 * Argentine CUIL / CUIT validation.
 *
 * Format: XX-XXXXXXXX-C (11 digits, dashes stripped for validation)
 * Checksum: mod-11 (weights [5,4,3,2,7,6,5,4,3,2]; check=0/9/11-rem)
 *
 * Gates:
 *   1 (HARD): Must yield exactly 11 digits
 *   2 (HARD): First 2 digits (type prefix) in valid range [20,23,24,27,30,33,34]
 *   3 (HARD): Mod-11 check digit
 *   4 (SOFT): Context proximity
 */
function validateNationalId_ar_cuil(
  matchString: string,
  fullText: string,
  matchIndex: number
): NationalIdValidationResult {
  const digits = matchString.replace(/\D/g, '');

  // Gate 1 (HARD): Must be exactly 11 digits
  if (digits.length !== 11) {
    return {
      is_valid: false,
      subtype: 'ar_cuil',
      gatesPassed: { prefixValid: false, checksumValid: false, contextProximity: false },
      reason: `Expected 11 digits, got ${digits.length}`,
      metrics: { matchLength: matchString.length },
    };
  }

  // Gate 2 (HARD): Type prefix in valid range
  const prefix = parseInt(digits.substring(0, 2), 10);
  const validPrefixes = [20, 23, 24, 27, 30, 33, 34];
  const prefixValid = validPrefixes.includes(prefix);
  if (!prefixValid) {
    return {
      is_valid: false,
      subtype: 'ar_cuil',
      gatesPassed: { prefixValid: false, checksumValid: false, contextProximity: false },
      reason: `CUIL/CUIT type prefix ${prefix} not in valid range`,
      metrics: { matchLength: matchString.length },
    };
  }

  // Gate 3 (HARD): Mod-11 check digit
  const checksumValid = mod11ArCuil(digits);

  // Gate 4 (SOFT): Context proximity
  const windowStart = Math.max(0, matchIndex - AR_CUIL_CONTEXT_WINDOW_CHARS);
  const windowEnd = Math.min(fullText.length, matchIndex + matchString.length + AR_CUIL_CONTEXT_WINDOW_CHARS);
  const contextWindow = fullText.slice(windowStart, windowEnd).toLowerCase();
  let hasContext = false;
  for (const keyword of AR_CUIL_CONTEXT_KEYWORDS) {
    if (contextWindow.includes(keyword)) { hasContext = true; break; }
  }

  const is_valid = checksumValid;
  let reason: string | null = null;
  if (!checksumValid) reason = 'Argentine CUIL/CUIT mod-11 check digit failed';

  let confidence: number | undefined;
  if (is_valid) {
    const score = scoreProximity(fullText, matchIndex, matchString.length, AR_CUIL_ANCHORS, true);
    confidence = score.confidence;
  }

  return {
    is_valid,
    subtype: 'ar_cuil',
    gatesPassed: { prefixValid, checksumValid, contextProximity: hasContext },
    reason,
    metrics: { matchLength: matchString.length, hasContext, checksumValid, prefix },
    confidence,
  };
}

// ============================================================================
// AG-PROMPT-117: CHILEAN RUT (Rol Único Tributario) / RUN
// ============================================================================

const CL_RUT_CONTEXT_KEYWORDS = [
  'rut', 'run', 'sii', 'servicio de impuestos',
  'registro civil', 'cédula de identidad', 'cedula de identidad',
  'chile', 'chileno', 'chilena',
];

const CL_RUT_CONTEXT_WINDOW_CHARS = 100;

/**
 * Chilean RUT / RUN validation.
 *
 * Format: XX.XXX.XXX-K (formatted) or XXXXXXXX-K (bare with dash)
 * Checksum: mod-11 cycling weights [2,3,4,5,6,7] right-to-left; 11→'0', 10→'K'
 *
 * Gates:
 *   1 (HARD): Format check — numeric part + dash + check character
 *   2 (HARD): Mod-11 check character
 *   3 (SOFT): Context proximity
 */
function validateNationalId_cl_rut(
  matchString: string,
  fullText: string,
  matchIndex: number
): NationalIdValidationResult {
  // Strip formatting (dots, commas, spaces) but keep the dash before check character
  // AG-PROMPT-133: also strip commas to handle separator_shuffle mutations
  const normalized = matchString.replace(/[.,]/g, '').replace(/\s/g, '').toUpperCase();

  // Gate 1 (HARD): Format check — expect digits + dash + check char
  if (!/^\d{7,8}-[0-9K]$/.test(normalized)) {
    return {
      is_valid: false,
      subtype: 'cl_rut',
      gatesPassed: { formatValid: false, checksumValid: false, contextProximity: false },
      reason: 'Does not match RUT format (7-8 digits + dash + check [0-9K])',
      metrics: { matchLength: matchString.length },
    };
  }

  // Gate 2 (HARD): Mod-11 check character
  // Pass numericPart + checkChar to mod11ClRut (which expects last char as check)
  const rutForValidation = normalized.replace('-', '');
  const checksumValid = mod11ClRut(rutForValidation);

  // Gate 3 (SOFT): Context proximity
  const windowStart = Math.max(0, matchIndex - CL_RUT_CONTEXT_WINDOW_CHARS);
  const windowEnd = Math.min(fullText.length, matchIndex + matchString.length + CL_RUT_CONTEXT_WINDOW_CHARS);
  const contextWindow = fullText.slice(windowStart, windowEnd).toLowerCase();
  let hasContext = false;
  for (const keyword of CL_RUT_CONTEXT_KEYWORDS) {
    if (contextWindow.includes(keyword)) { hasContext = true; break; }
  }

  const is_valid = checksumValid;
  let reason: string | null = null;
  if (!checksumValid) reason = 'Chilean RUT mod-11 check character failed';

  let confidence: number | undefined;
  if (is_valid) {
    const score = scoreProximity(fullText, matchIndex, matchString.length, CL_RUT_ANCHORS, true);
    confidence = score.confidence;
  }

  return {
    is_valid,
    subtype: 'cl_rut',
    gatesPassed: { formatValid: true, checksumValid, contextProximity: hasContext },
    reason,
    metrics: { matchLength: matchString.length, hasContext, checksumValid },
    confidence,
  };
}

// ============================================================================
// AG-PROMPT-124: CHILEAN RUT BARE-DASH FORMAT (MANDATORY CONTEXT GATE)
// ============================================================================

const CL_RUT_BARE_CONTEXT_WINDOW_CHARS = 100;

/**
 * Chilean RUT / RUN bare-dash format validation.
 *
 * Format: XXXXXXXX-K (7-8 digits + dash + check character, no dots)
 * Checksum: same mod-11 cycling weights [2,3,4,5,6,7] as dotted format
 *
 * Gates:
 *   1 (HARD): Format check — 7-8 digits + dash + check character
 *   2 (HARD): Mod-11 check character
 *   3 (HARD): Context proximity MANDATORY (bare format is FP-prone)
 */
function validateNationalId_cl_rut_bare(
  matchString: string,
  fullText: string,
  matchIndex: number
): NationalIdValidationResult {
  const normalized = matchString.replace(/\s/g, '').toUpperCase();

  // Gate 1 (HARD): Format check
  if (!/^\d{7,8}-[0-9K]$/.test(normalized)) {
    return {
      is_valid: false,
      subtype: 'cl_rut_bare',
      gatesPassed: { formatValid: false, checksumValid: false, contextProximity: false },
      reason: 'Does not match bare RUT format (7-8 digits + dash + check [0-9K])',
      metrics: { matchLength: matchString.length },
    };
  }

  // Gate 2 (HARD): Mod-11 check character
  const rutForValidation = normalized.replace('-', '');
  const checksumValid = mod11ClRut(rutForValidation);

  if (!checksumValid) {
    return {
      is_valid: false,
      subtype: 'cl_rut_bare',
      gatesPassed: { formatValid: true, checksumValid: false, contextProximity: false },
      reason: 'Chilean RUT mod-11 check character failed',
      metrics: { matchLength: matchString.length, checksumValid: false },
    };
  }

  // Gate 3 (HARD — MANDATORY): Context proximity required for bare format
  const windowStart = Math.max(0, matchIndex - CL_RUT_BARE_CONTEXT_WINDOW_CHARS);
  const windowEnd = Math.min(fullText.length, matchIndex + matchString.length + CL_RUT_BARE_CONTEXT_WINDOW_CHARS);
  const contextWindow = fullText.slice(windowStart, windowEnd).toLowerCase();
  let hasContext = false;
  for (const keyword of CL_RUT_CONTEXT_KEYWORDS) {
    if (contextWindow.includes(keyword)) { hasContext = true; break; }
  }

  if (!hasContext) {
    return {
      is_valid: false,
      subtype: 'cl_rut_bare',
      gatesPassed: { formatValid: true, checksumValid: true, contextProximity: false },
      reason: 'Chilean RUT bare format requires context keyword in proximity (mandatory gate)',
      metrics: { matchLength: matchString.length, hasContext: false, checksumValid: true },
    };
  }

  const score = scoreProximity(fullText, matchIndex, matchString.length, CL_RUT_ANCHORS, true);

  return {
    is_valid: true,
    subtype: 'cl_rut_bare',
    gatesPassed: { formatValid: true, checksumValid: true, contextProximity: true },
    reason: null,
    metrics: { matchLength: matchString.length, hasContext: true, checksumValid: true },
    confidence: score.confidence,
  };
}

// ============================================================================
// AG-PROMPT-121: HUNGARIAN TAJ (Társadalombiztosítási Azonosító Jel)
// ============================================================================

const HU_TAJ_CONTEXT_KEYWORDS = [
  'taj', 'taj szám', 'taj-szám', 'társadalombiztosítási', 'tarsadalombiztositasi',
  'egészségbiztosítás', 'egeszsegbiztositas', 'oep', 'tb azonosító', 'magyarország',
];

const HU_TAJ_CONTEXT_WINDOW_CHARS = 100;

/**
 * Hungarian TAJ (Társadalombiztosítási Azonosító Jel) validation.
 *
 * Format: XXX XXX XXX — 9 digits displayed in three groups.
 * Checksum: mod-10 weighted (weights [3,7,3,7,3,7,3,7]; check = (10 - sum%10) % 10).
 *
 * Gates:
 *   1 (HARD): Must yield exactly 9 digits
 *   2 (HARD): Mod-10 check digit
 *   3 (HARD): Context proximity required (format overlaps with AU TFN)
 */
function validateNationalId_hu_taj(
  matchString: string,
  fullText: string,
  matchIndex: number
): NationalIdValidationResult {
  const digits = matchString.replace(/\D/g, '');

  // Gate 1 (HARD): Must be exactly 9 digits
  if (digits.length !== 9 || !/^\d{9}$/.test(digits)) {
    return {
      is_valid: false,
      subtype: 'hu_taj',
      gatesPassed: { checksumValid: false, contextProximity: false },
      reason: `Expected 9 digits, got ${digits.length}`,
      metrics: { matchLength: matchString.length },
    };
  }

  // Gate 2 (HARD): Mod-10 check digit
  const checksumValid = mod10HuTaj(digits);

  // Gate 3 (HARD): Context required (format shared with AU TFN)
  const windowStart = Math.max(0, matchIndex - HU_TAJ_CONTEXT_WINDOW_CHARS);
  const windowEnd = Math.min(fullText.length, matchIndex + matchString.length + HU_TAJ_CONTEXT_WINDOW_CHARS);
  const contextWindow = fullText.slice(windowStart, windowEnd).toLowerCase();
  let hasContext = false;
  for (const keyword of HU_TAJ_CONTEXT_KEYWORDS) {
    if (contextWindow.includes(keyword)) { hasContext = true; break; }
  }

  const is_valid = checksumValid && hasContext;
  let reason: string | null = null;
  if (!checksumValid) reason = 'Hungarian TAJ mod-10 check digit failed';
  else if (!hasContext) reason = 'Hungarian TAJ requires context keyword in proximity';

  let confidence: number | undefined;
  if (is_valid) {
    const score = scoreProximity(fullText, matchIndex, matchString.length, HU_TAJ_ANCHORS, true);
    confidence = score.confidence;
  }

  return {
    is_valid,
    subtype: 'hu_taj',
    gatesPassed: { checksumValid, contextProximity: hasContext },
    reason,
    metrics: { matchLength: matchString.length, hasContext, checksumValid },
    confidence,
  };
}

// ============================================================================
// AG-PROMPT-121: UK NATIONAL INSURANCE NUMBER (NIN / NINO)
// ============================================================================

const UK_NIN_CONTEXT_KEYWORDS = [
  'national insurance', 'ni number', 'nino', 'ni no',
  'hmrc', 'national insurance number', 'national insurance no',
  'paye', 'p45', 'p60',
];

const UK_NIN_CONTEXT_WINDOW_CHARS = 120;

/**
 * UK National Insurance Number (NIN / NINO) validation.
 *
 * Format: [A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] \d{6} [A-D]
 * No public checksum algorithm. Format validation + mandatory context gate.
 *
 * Gates:
 *   1 (HARD): Format — correct letter classes + digit count + suffix A-D
 *   2 (HARD): Context proximity required (no checksum available)
 */
function validateNationalId_uk_nin(
  matchString: string,
  fullText: string,
  matchIndex: number
): NationalIdValidationResult {
  const stripped = matchString.replace(/\s/g, '').toUpperCase();

  // Gate 1 (HARD): Must be 9 chars: 2 letters + 6 digits + 1 letter
  const formatValid = /^[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\d{6}[A-D]$/.test(stripped);
  if (!formatValid) {
    return {
      is_valid: false,
      subtype: 'uk_nin',
      gatesPassed: { formatValid: false, contextProximity: false },
      reason: 'UK NIN format invalid',
      metrics: { matchLength: matchString.length },
    };
  }

  // Gate 2 (HARD): Context proximity required (no checksum)
  const windowStart = Math.max(0, matchIndex - UK_NIN_CONTEXT_WINDOW_CHARS);
  const windowEnd = Math.min(fullText.length, matchIndex + matchString.length + UK_NIN_CONTEXT_WINDOW_CHARS);
  const contextWindow = fullText.slice(windowStart, windowEnd).toLowerCase();
  let hasContext = false;
  for (const keyword of UK_NIN_CONTEXT_KEYWORDS) {
    if (contextWindow.includes(keyword)) { hasContext = true; break; }
  }

  const is_valid = hasContext;
  const reason = hasContext ? null : 'UK NIN requires context keyword in proximity (no public checksum)';

  let confidence: number | undefined;
  if (is_valid) {
    const score = scoreProximity(fullText, matchIndex, matchString.length, UK_NIN_ANCHORS, true);
    confidence = score.confidence;
  }

  return {
    is_valid,
    subtype: 'uk_nin',
    gatesPassed: { formatValid, contextProximity: hasContext },
    reason,
    metrics: { matchLength: matchString.length, hasContext, formatValid },
    confidence,
  };
}

// ============================================================================
// AG-PROMPT-121: AUSTRALIAN TAX FILE NUMBER (TFN)
// ============================================================================

const AU_TFN_CONTEXT_KEYWORDS = [
  'tax file number', 'tfn', 'ato', 'australian taxation office',
  'tax file', 'mytax', 'mygov', 'australia',
];

const AU_TFN_CONTEXT_WINDOW_CHARS = 100;

/**
 * Australian Tax File Number (TFN) validation.
 *
 * Format: XXX XXX XXX — 9 digits displayed in three groups.
 * Checksum: mod-11 weighted (weights [1,4,3,7,5,8,6,9,10]; sum mod 11 = 0).
 *
 * Gates:
 *   1 (HARD): Must yield exactly 9 digits
 *   2 (HARD): Mod-11 weighted checksum
 *   3 (HARD): Context proximity required (format overlaps with HU TAJ)
 */
function validateNationalId_au_tfn(
  matchString: string,
  fullText: string,
  matchIndex: number
): NationalIdValidationResult {
  const digits = matchString.replace(/\D/g, '');

  // Gate 1 (HARD): Must be exactly 9 digits
  if (digits.length !== 9 || !/^\d{9}$/.test(digits)) {
    return {
      is_valid: false,
      subtype: 'au_tfn',
      gatesPassed: { checksumValid: false, contextProximity: false },
      reason: `Expected 9 digits, got ${digits.length}`,
      metrics: { matchLength: matchString.length },
    };
  }

  // Gate 2 (HARD): Mod-11 checksum
  const checksumValid = mod11AuTfn(digits);

  // Gate 3 (HARD): Context required (format shared with HU TAJ)
  const windowStart = Math.max(0, matchIndex - AU_TFN_CONTEXT_WINDOW_CHARS);
  const windowEnd = Math.min(fullText.length, matchIndex + matchString.length + AU_TFN_CONTEXT_WINDOW_CHARS);
  const contextWindow = fullText.slice(windowStart, windowEnd).toLowerCase();
  let hasContext = false;
  for (const keyword of AU_TFN_CONTEXT_KEYWORDS) {
    if (contextWindow.includes(keyword)) { hasContext = true; break; }
  }

  const is_valid = checksumValid && hasContext;
  let reason: string | null = null;
  if (!checksumValid) reason = 'Australian TFN mod-11 checksum failed';
  else if (!hasContext) reason = 'Australian TFN requires context keyword in proximity';

  let confidence: number | undefined;
  if (is_valid) {
    const score = scoreProximity(fullText, matchIndex, matchString.length, AU_TFN_ANCHORS, true);
    confidence = score.confidence;
  }

  return {
    is_valid,
    subtype: 'au_tfn',
    gatesPassed: { checksumValid, contextProximity: hasContext },
    reason,
    metrics: { matchLength: matchString.length, hasContext, checksumValid },
    confidence,
  };
}

// ============================================================================
// AG-PROMPT-121: AUSTRALIAN BUSINESS NUMBER (ABN)
// ============================================================================

const AU_ABN_CONTEXT_KEYWORDS = [
  'abn', 'australian business number', 'ato', 'asic', 'gst', 'australia', 'acn',
];

const AU_ABN_CONTEXT_WINDOW_CHARS = 100;

/**
 * Australian Business Number (ABN) validation.
 *
 * Format: XX XXX XXX XXX — 11 digits displayed as 2+3+3+3.
 * Checksum: mod-89 (subtract 1 from first digit, multiply by weights
 *   [10,1,3,5,7,9,11,13,15,17,19], sum mod 89 = 0).
 *
 * Gates:
 *   1 (HARD): Must yield exactly 11 digits
 *   2 (HARD): Mod-89 checksum
 *   3 (HARD): Context proximity required
 */
function validateNationalId_au_abn(
  matchString: string,
  fullText: string,
  matchIndex: number
): NationalIdValidationResult {
  const digits = matchString.replace(/\D/g, '');

  // Gate 1 (HARD): Must be exactly 11 digits
  if (digits.length !== 11 || !/^\d{11}$/.test(digits)) {
    return {
      is_valid: false,
      subtype: 'au_abn',
      gatesPassed: { checksumValid: false, contextProximity: false },
      reason: `Expected 11 digits, got ${digits.length}`,
      metrics: { matchLength: matchString.length },
    };
  }

  // Gate 2 (HARD): Mod-89 checksum
  const checksumValid = mod89AuAbn(digits);

  // Gate 3 (HARD): Context required
  const windowStart = Math.max(0, matchIndex - AU_ABN_CONTEXT_WINDOW_CHARS);
  const windowEnd = Math.min(fullText.length, matchIndex + matchString.length + AU_ABN_CONTEXT_WINDOW_CHARS);
  const contextWindow = fullText.slice(windowStart, windowEnd).toLowerCase();
  let hasContext = false;
  for (const keyword of AU_ABN_CONTEXT_KEYWORDS) {
    if (contextWindow.includes(keyword)) { hasContext = true; break; }
  }

  const is_valid = checksumValid && hasContext;
  let reason: string | null = null;
  if (!checksumValid) reason = 'Australian ABN mod-89 checksum failed';
  else if (!hasContext) reason = 'Australian ABN requires context keyword in proximity';

  let confidence: number | undefined;
  if (is_valid) {
    const score = scoreProximity(fullText, matchIndex, matchString.length, AU_ABN_ANCHORS, true);
    confidence = score.confidence;
  }

  return {
    is_valid,
    subtype: 'au_abn',
    gatesPassed: { checksumValid, contextProximity: hasContext },
    reason,
    metrics: { matchLength: matchString.length, hasContext, checksumValid },
    confidence,
  };
}

// ============================================================================
// AG-PROMPT-121: CANADIAN SOCIAL INSURANCE NUMBER (SIN / NAS)
// ============================================================================

const CA_SIN_CONTEXT_KEYWORDS = [
  'social insurance', 'sin', 'social insurance number', 'numéro d\'assurance sociale',
  'nas', 'cra', 'canada revenue', 't4', 'canada', 'employment insurance',
];

const CA_SIN_CONTEXT_WINDOW_CHARS = 100;

/**
 * Canadian Social Insurance Number (SIN / NAS) validation.
 *
 * Format: XXX-XXX-XXX — 9 digits displayed with dashes.
 * Checksum: Luhn-10 (standard Luhn algorithm on all 9 digits).
 * SINs starting with 9 are temporary (issued to non-citizens); included.
 *
 * Gates:
 *   1 (HARD): Must yield exactly 9 digits; must not start with 0 or 8
 *   2 (HARD): Luhn-10 checksum
 *   3 (HARD): Context proximity required
 */
function validateNationalId_ca_sin(
  matchString: string,
  fullText: string,
  matchIndex: number
): NationalIdValidationResult {
  const digits = matchString.replace(/\D/g, '');

  // Gate 1 (HARD): Must be exactly 9 digits; first digit not 0 or 8 (unassigned)
  if (digits.length !== 9 || !/^\d{9}$/.test(digits)) {
    return {
      is_valid: false,
      subtype: 'ca_sin',
      gatesPassed: { prefixValid: false, checksumValid: false, contextProximity: false },
      reason: `Expected 9 digits, got ${digits.length}`,
      metrics: { matchLength: matchString.length },
    };
  }
  const firstDigit = parseInt(digits[0], 10);
  const prefixValid = firstDigit !== 0 && firstDigit !== 8;
  if (!prefixValid) {
    return {
      is_valid: false,
      subtype: 'ca_sin',
      gatesPassed: { prefixValid: false, checksumValid: false, contextProximity: false },
      reason: `SIN first digit ${firstDigit} is in unassigned range (0, 8)`,
      metrics: { matchLength: matchString.length },
    };
  }

  // Gate 2 (HARD): Luhn-10 checksum
  const checksumValid = luhn10(digits);

  // Gate 3 (HARD): Context required
  const windowStart = Math.max(0, matchIndex - CA_SIN_CONTEXT_WINDOW_CHARS);
  const windowEnd = Math.min(fullText.length, matchIndex + matchString.length + CA_SIN_CONTEXT_WINDOW_CHARS);
  const contextWindow = fullText.slice(windowStart, windowEnd).toLowerCase();
  let hasContext = false;
  for (const keyword of CA_SIN_CONTEXT_KEYWORDS) {
    if (contextWindow.includes(keyword)) { hasContext = true; break; }
  }

  const is_valid = checksumValid && hasContext;
  let reason: string | null = null;
  if (!checksumValid) reason = 'Canadian SIN Luhn-10 checksum failed';
  else if (!hasContext) reason = 'Canadian SIN requires context keyword in proximity';

  let confidence: number | undefined;
  if (is_valid) {
    const score = scoreProximity(fullText, matchIndex, matchString.length, CA_SIN_ANCHORS, true);
    confidence = score.confidence;
  }

  return {
    is_valid,
    subtype: 'ca_sin',
    gatesPassed: { prefixValid, checksumValid, contextProximity: hasContext },
    reason,
    metrics: { matchLength: matchString.length, hasContext, checksumValid },
    confidence,
  };
}

// ============================================================================
// AG-PROMPT-041: INSURANCE CONTEXT GATE
// ============================================================================

/**
 * National-ID labels that confirm a digit sequence is intended as an identifier.
 * Used for label proximity gating in ambiguous contexts (e.g., insurance).
 */
const NATIONAL_ID_LABELS = [
  'cpr', 'cpr-nr', 'cpr nr', 'cprnr', 'cpr-nummer',
  'personnummer', 'personnr',
  'fødselsnummer', 'fodselsnummer',
  'personal identification', 'national id', 'national identification',
  'id-nummer',
  'bsn', 'burgerservicenummer',
  'nir', 'insee', 'sécurité sociale', 'securite sociale', 'carte vitale',
  'nif', 'contribuinte', 'número de contribuinte', 'identificação fiscal',
  'rijksregisternummer', 'numéro national', 'numero national', 'registre national',
  'cpf', 'cadastro de pessoas',
  'curp', 'clave única', 'clave unica',
];

/**
 * Insurance context markers — when present, national-ID emission requires
 * explicit label proximity to avoid numeric collisions (policy numbers, etc.).
 */
const INSURANCE_CONTEXT_MARKERS = [
  'forsikringspolice', 'forsikring', // Must check compound forms first
  'police nr', 'police',
  'præmie', 'selvrisiko',
];

/** Window for label proximity check (chars before and after match) */
const LABEL_PROXIMITY_WINDOW = 160;

/**
 * Check if a national-ID label exists near the matched digits.
 * Returns true if any label keyword is found within the proximity window.
 */
export function hasNationalIdLabelProximity(
  fullText: string,
  matchIndex: number,
  matchLength: number,
): boolean {
  const windowStart = Math.max(0, matchIndex - LABEL_PROXIMITY_WINDOW);
  const windowEnd = Math.min(fullText.length, matchIndex + matchLength + LABEL_PROXIMITY_WINDOW);
  const window = fullText.slice(windowStart, windowEnd).toLowerCase();
  return NATIONAL_ID_LABELS.some(label => window.includes(label));
}

/**
 * Check if the document text contains insurance context markers.
 * When true, national-ID emission requires explicit label proximity.
 */
export function hasInsuranceContext(fullText: string): boolean {
  const lower = fullText.toLowerCase();
  return INSURANCE_CONTEXT_MARKERS.some(marker => lower.includes(marker));
}

/**
 * AG-PROMPT-185/WS-01: Invoice/financial context patterns.
 * When present, national-ID emission requires explicit label proximity
 * to avoid numeric collisions (customer numbers, bank accounts matching CPR format).
 *
 * Uses regex word boundaries to avoid matching inside compound words
 * (e.g., "Gehaltsabrechnung" should NOT trigger — only standalone "Rechnung").
 */
const INVOICE_FINANCIAL_CONTEXT_PATTERNS: RegExp[] = [
  /\bfaktura\b/i,
  /\binvoice\b/i,
  /\brechnung\b/i,         // standalone "Rechnung" only, not "Gehaltsabrechnung"
  /\bfactura\b/i,
  /\bkundenr\b/i,
  /\bkundenummer\b/i,
  /\bcustomer\s*no\b/i,
  /\bbankkonto\b/i,
  /\bkontonr\b/i,
  /\bbank\s*account\b/i,
  /\bordrenr\b/i,
  /\bordrenummer\b/i,
  /\border\s*no\b/i,
];

/**
 * AG-PROMPT-185/WS-01: Check if the document text contains invoice/financial context markers.
 * When true, national-ID emission requires explicit label proximity to avoid
 * false positives on customer numbers, bank accounts, and order numbers.
 */
export function hasInvoiceFinancialContext(fullText: string): boolean {
  return INVOICE_FINANCIAL_CONTEXT_PATTERNS.some(pattern => pattern.test(fullText));
}

// ============================================================================
// DISPATCHER REGISTRY
// ============================================================================

/**
 * Map from pattern ID → validator function.
 * Used by packRegistry to dispatch validation for national ID patterns.
 */
export const NATIONAL_ID_PATTERN_IDS = new Map<string, ValidatorFn>([
  ['global-dk-cpr', validateNationalId_dk_cpr],
  ['global-se-personnummer', validateNationalId_se_personnummer],
  ['global-no-fnr', validateNationalId_no_fnr],
  // AG-XLSX-HARDENING-PLAN-001: FI HETU with Mod31 gate
  ['global-fi-hetu', validateNationalId_fi_hetu],
  ['registry-fi-hetu', validateNationalId_fi_hetu],
  // AG-MONSTER-HARDENING-TIERA-ENGINE-001: German Steuer-ID with Mod 11,10 gate
  ['global-de-steuer-id', validateNationalId_de_steuer_id],
  // P2-ADD-ES-DNI-NIE: Spanish DNI/NIE with Mod-23 letter table gate
  ['global-es-dni-nie', validateNationalId_es_dni_nie],
  // P2-ADD-IT-CODICE-FISCALE: Italian Codice Fiscale with bipartite check digit gate
  ['global-it-codice-fiscale', validateNationalId_it_codice_fiscale],
  // P2-ADD-PL-PESEL: Polish PESEL with weighted checksum + month validity gate
  ['global-pl-pesel', validateNationalId_pl_pesel],
  // AG-PROMPT-105: Dutch BSN with 11-test checksum gate
  ['global-nl-bsn', validateNationalId_nl_bsn],
  // AG-PROMPT-106: French NIR with mod-97 checksum gate
  ['global-fr-nir', validateNationalId_fr_nir],
  // AG-PROMPT-110: Portuguese NIF with mod-11 checksum gate
  ['global-pt-nif', validateNationalId_pt_nif],
  // AG-PROMPT-115: Belgian NN with mod-97 checksum gate
  ['global-be-nn', validateNationalId_be_nn],
  // AG-PROMPT-115: Brazilian CPF with double mod-11 checksum gate
  ['global-br-cpf', validateNationalId_br_cpf],
  // AG-PROMPT-119: Brazilian CNPJ with double mod-11 checksum gate
  ['global-br-cnpj', validateNationalId_br_cnpj],
  // AG-PROMPT-115: Mexican CURP with format + date validation
  ['global-mx-curp', validateNationalId_mx_curp],
  // AG-PROMPT-119: Mexican RFC with format + date + mandatory context gate
  ['global-mx-rfc', validateNationalId_mx_rfc],
  // AG-PROMPT-116: Irish PPS Number with mod-23 check letter gate
  ['global-ie-pps', validateNationalId_ie_pps],
  // AG-PROMPT-116: Austrian SV-Nr with mod-10 check digit gate
  ['global-at-sv-nr', validateNationalId_at_sv_nr],
  // AG-PROMPT-116: Romanian CNP with mod-11 check digit gate
  ['global-ro-cnp', validateNationalId_ro_cnp],
  // AG-PROMPT-116: Czech/Slovak Rodné číslo with mod-11 gate
  ['global-cz-rc', validateNationalId_cz_rc],
  // AG-PROMPT-117: Argentine CUIL/CUIT with mod-11 check digit gate
  ['global-ar-cuil', validateNationalId_ar_cuil],
  // AG-PROMPT-117: Chilean RUT with mod-11 check character gate
  ['global-cl-rut', validateNationalId_cl_rut],
  // AG-PROMPT-124: Chilean RUT bare-dash format with mod-11 + mandatory context gate
  ['global-cl-rut-bare', validateNationalId_cl_rut_bare],
  // AG-PROMPT-121: Hungarian TAJ with mod-10 check digit + mandatory context gate
  ['global-hu-taj', validateNationalId_hu_taj],
  // AG-PROMPT-121: UK NIN with format validation + mandatory context gate
  ['global-uk-nin', validateNationalId_uk_nin],
  // AG-PROMPT-121: Australian TFN with mod-11 checksum + mandatory context gate
  ['global-au-tfn', validateNationalId_au_tfn],
  // AG-PROMPT-121: Australian ABN with mod-89 checksum + mandatory context gate
  ['global-au-abn', validateNationalId_au_abn],
  // AG-PROMPT-121: Canadian SIN with Luhn-10 checksum + mandatory context gate
  ['global-ca-sin', validateNationalId_ca_sin],
]);
