/**
 * AG-XLSX-HARDENING-PLAN-001: Nordic/EU PII Checksum Validators
 *
 * Pure TypeScript, no external dependencies, deterministic.
 *
 * Algorithms:
 *  - luhn10()    : Luhn mod-10 (SE personnummer check digit, payment cards)
 *  - mod11Dk()   : Danish CPR mod-11 (weights [4,3,2,7,6,5,4,3,2,1])
 *  - mod11No()   : Norwegian fødselsnummer double mod-11 (two check digits)
 *  - mod31Fi()   : Finnish HETU mod-31 with control character table
 *  - mod97Iban() : IBAN mod-97 (BigInt to handle full IBAN length)
 *
 * Usage policy (from plan):
 *  - DK CPR: Mod11 failure → downgrade confidence, NOT hard rejection
 *    (CPR authority stopped issuing mod-11-valid numbers post-2007)
 *  - SE personnummer: Luhn failure → hard reject (all numbers follow Luhn)
 *  - NO fødselsnummer: Mod11 failure → hard reject
 *  - FI HETU: Mod31 failure → hard reject
 *  - IBAN: Mod97 failure → hard reject
 */

// ============================================================================
// LUHN MOD-10 (SE personnummer, payment cards)
// ============================================================================

/**
 * Luhn mod-10 check (ISO/IEC 7812).
 * Accepts the complete digit string including the check digit.
 * Returns true if checksum is valid.
 */
export function luhn10(digits: string): boolean {
  if (!digits || !/^\d+$/.test(digits)) return false;
  let sum = 0;
  let alternate = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10);
    if (alternate) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

// ============================================================================
// MOD-11 — DANISH CPR
// ============================================================================

/**
 * Danish CPR mod-11 validation.
 * Weights: [4, 3, 2, 7, 6, 5, 4, 3, 2, 1] applied to the 10 digits.
 * Sum must be divisible by 11.
 *
 * IMPORTANT: The Danish CPR authority stopped issuing mod-11-valid CPR numbers
 * in 2007 because they ran out of valid numbers. A mod-11 failure does NOT
 * mean the number is fake — use this for confidence scoring only, not rejection.
 *
 * @param digits Exactly 10 digit string (DDMMYYXXXX, no separators)
 */
export function mod11Dk(digits: string): boolean {
  if (!digits || digits.length !== 10 || !/^\d{10}$/.test(digits)) return false;
  const weights = [4, 3, 2, 7, 6, 5, 4, 3, 2, 1];
  let sum = 0;
  for (let i = 0; i < 10; i++) {
    sum += parseInt(digits[i], 10) * weights[i];
  }
  return sum % 11 === 0;
}

// ============================================================================
// MOD-11 — NORWEGIAN FØDSELSNUMMER (double check digit)
// ============================================================================

/**
 * Norwegian fødselsnummer mod-11 double check-digit validation.
 *
 * Weight set 1 (for digit at position 9):  [3, 7, 6, 1, 8, 9, 4, 5, 2]
 * Weight set 2 (for digit at position 10): [5, 4, 3, 2, 7, 6, 5, 4, 3, 2]
 *
 * If a remainder yields check-digit 10 the number is officially invalid.
 *
 * @param digits Exactly 11 digit string (DDMMYYXXXXX, no separators)
 */
export function mod11No(digits: string): boolean {
  if (!digits || digits.length !== 11 || !/^\d{11}$/.test(digits)) return false;

  const w1 = [3, 7, 6, 1, 8, 9, 4, 5, 2];
  let sum1 = 0;
  for (let i = 0; i < 9; i++) {
    sum1 += parseInt(digits[i], 10) * w1[i];
  }
  const k1 = 11 - (sum1 % 11);
  const check1 = k1 === 11 ? 0 : k1;
  if (check1 === 10 || check1 !== parseInt(digits[9], 10)) return false;

  const w2 = [5, 4, 3, 2, 7, 6, 5, 4, 3, 2];
  let sum2 = 0;
  for (let i = 0; i < 10; i++) {
    sum2 += parseInt(digits[i], 10) * w2[i];
  }
  const k2 = 11 - (sum2 % 11);
  const check2 = k2 === 11 ? 0 : k2;
  if (check2 === 10) return false;
  return check2 === parseInt(digits[10], 10);
}

// ============================================================================
// MOD-31 — FINNISH HETU (henkilötunnus)
// ============================================================================

/** Control character alphabet for Finnish HETU mod-31 */
const HETU_ALPHABET = '0123456789ABCDEFHJKLMNPRSTUVWXY';

/**
 * Finnish HETU (henkilötunnus) mod-31 control character validation.
 *
 * Format: DDMMYYXXXC
 *   - DDMMYY = birth date
 *   - Separator: '+' (1800s), '-' or 'A' or 'B'-'Y' (2000s) at position 6
 *   - XXX = individual number (001-899 for actual persons)
 *   - C   = control character from HETU_ALPHABET
 *
 * The 9-digit concatenation DDMMYYXXX interpreted as an integer, mod 31,
 * gives the index into HETU_ALPHABET for the expected control character.
 *
 * @param hetu Full HETU string including control character (10 or 11 chars with separator)
 */
export function mod31Fi(hetu: string): boolean {
  if (!hetu) return false;
  // Remove separator at position 6 ('+', '-', or a letter like 'A'–'Y')
  // Expected: 6 digit chars + optional separator + 3 digit chars + 1 control char
  const cleaned = hetu.replace(/[+\-A-Y]/g, (ch, idx) => (idx === 6 ? '' : ch));
  if (cleaned.length !== 10 || !/^\d{9}[0-9A-Z]$/.test(cleaned)) return false;
  const numStr = cleaned.substring(0, 9);
  const controlChar = cleaned[9].toUpperCase();
  const num = parseInt(numStr, 10);
  if (isNaN(num)) return false;
  return HETU_ALPHABET[num % 31] === controlChar;
}

// ============================================================================
// ISO 7064 MOD 11,10 — GERMAN STEUER-ID (Steuerliche Identifikationsnummer)
// ============================================================================

/**
 * ISO 7064 Mod 11,10 check digit validation.
 * Used for German Steuerliche Identifikationsnummer (Steuer-ID / IdNr).
 *
 * The Steuer-ID is 11 digits: 10 payload digits + 1 check digit.
 * First digit must be 1-9 (never 0).
 *
 * Algorithm:
 *  p = 0
 *  for each digit d[i] (i = 0..9):
 *    p = (p + d[i]) mod 10
 *    if p == 0: p = 10
 *    p = (p * 2) mod 11
 *  check_digit = (11 - p) mod 10
 *
 * @param digits Exactly 11-digit string
 */
export function mod1110Steuer(digits: string): boolean {
  if (!digits || digits.length !== 11 || !/^\d{11}$/.test(digits)) return false;
  // First digit must not be 0
  if (digits[0] === '0') return false;

  let p = 0;
  for (let i = 0; i < 10; i++) {
    p = (p + parseInt(digits[i], 10)) % 10;
    if (p === 0) p = 10;
    p = (p * 2) % 11;
  }
  const checkDigit = (11 - p) % 10;
  return checkDigit === parseInt(digits[10], 10);
}

// ============================================================================
// MOD-97 — FRENCH NIR / INSEE (Numéro d'Inscription au Répertoire)
// ============================================================================

/**
 * French NIR (numéro de sécurité sociale) mod-97 key validation.
 *
 * The NIR is 13 characters (usually digits, but Corsica uses 2A/2B for department)
 * followed by a 2-digit key.
 *
 * Key = 97 - (first_13_as_number mod 97)
 *
 * Corsica handling: department 2A is replaced by 19, 2B by 18 for computation.
 *
 * @param nirRaw 15-character string (may contain A/B for Corsica departments)
 */
export function mod97Nir(nirRaw: string): boolean {
  if (!nirRaw) return false;
  // Normalize: strip spaces/dashes, uppercase
  const cleaned = nirRaw.replace(/[\s-]/g, '').toUpperCase();
  if (cleaned.length !== 15) return false;

  // Corsica substitution: 2A→19, 2B→18 at positions 5-6 (0-indexed)
  let numericStr = cleaned;
  if (cleaned[5] === '2' && cleaned[6] === 'A') {
    numericStr = cleaned.substring(0, 5) + '19' + cleaned.substring(7);
  } else if (cleaned[5] === '2' && cleaned[6] === 'B') {
    numericStr = cleaned.substring(0, 5) + '18' + cleaned.substring(7);
  }

  // After substitution, must be all digits
  if (!/^\d{15}$/.test(numericStr)) return false;

  const payload = numericStr.substring(0, 13);
  const key = parseInt(numericStr.substring(13, 15), 10);

  try {
    const expectedKey = 97 - Number(BigInt(payload) % 97n);
    return key === expectedKey;
  } catch {
    return false;
  }
}

// ============================================================================
// BSN 11-TEST — DUTCH BSN (Burgerservicenummer)
// ============================================================================

/**
 * Dutch BSN (Burgerservicenummer) 11-test validation.
 *
 * The BSN is a 9-digit number. Weights: [9, 8, 7, 6, 5, 4, 3, 2, -1].
 * The weighted sum must be divisible by 11 and must NOT be 0.
 *
 * Example: 123456782
 *   9*1 + 8*2 + 7*3 + 6*4 + 5*5 + 4*6 + 3*7 + 2*8 + (-1)*2
 *   = 9 + 16 + 21 + 24 + 25 + 24 + 21 + 16 - 2 = 154
 *   154 mod 11 = 0 → valid
 *
 * @param digits Exactly 9-digit string
 */
export function bsn11Test(digits: string): boolean {
  if (!digits || digits.length !== 9 || !/^\d{9}$/.test(digits)) return false;
  const weights = [9, 8, 7, 6, 5, 4, 3, 2, -1];
  let sum = 0;
  for (let i = 0; i < 9; i++) {
    sum += parseInt(digits[i], 10) * weights[i];
  }
  return sum !== 0 && sum % 11 === 0;
}

// ============================================================================
// MOD-11 — PORTUGUESE NIF (Número de Identificação Fiscal)
// ============================================================================

/**
 * Portuguese NIF (Número de Identificação Fiscal) mod-11 check digit validation.
 *
 * The NIF is 9 digits. First digit indicates entity type:
 *   1, 2, 3 = individual (pessoa singular)
 *   5 = corporate (pessoa coletiva)
 *   6 = public administration (administração pública)
 *   7 = international entity (entidade internacional)
 *   8 = sole trader / empresa em nome individual
 *   9 = irregular / temporary (irregular ou provisório)
 *   0, 4 = NEVER valid as first digit
 *
 * Weights: [9, 8, 7, 6, 5, 4, 3, 2] applied to first 8 digits.
 * Check digit (9th) = 11 - (weighted_sum mod 11).
 * If result is 10 or 11, check digit is 0.
 *
 * @param digits Exactly 9-digit string
 */
export function mod11Nif(digits: string): boolean {
  if (!digits || digits.length !== 9 || !/^\d{9}$/.test(digits)) return false;
  // First digit must not be 0 or 4
  const first = digits[0];
  if (first === '0' || first === '4') return false;
  const weights = [9, 8, 7, 6, 5, 4, 3, 2];
  let sum = 0;
  for (let i = 0; i < 8; i++) {
    sum += parseInt(digits[i], 10) * weights[i];
  }
  const remainder = sum % 11;
  const checkDigit = remainder < 2 ? 0 : 11 - remainder;
  return checkDigit === parseInt(digits[8], 10);
}

// ============================================================================
// MOD-97 — BELGIAN NN (Rijksregisternummer / Numéro national)
// ============================================================================

/**
 * Belgian National Number (Rijksregisternummer) mod-97 check digit validation.
 *
 * The NN is 11 digits: YYMMDD-SSS-CC
 *   - YYMMDD = birth date (last 2 digits of year)
 *   - SSS = sequential number (odd for males, even for females)
 *   - CC = check digits
 *
 * For people born before 2000:
 *   CC = 97 - (YYMMDDSSS mod 97)
 *
 * For people born from 2000 onward:
 *   CC = 97 - ((2_000_000_000 + YYMMDDSSS) mod 97)
 *
 * Both variants are tried — valid if either matches.
 *
 * @param digits Exactly 11-digit string (no separators)
 */
export function mod97BeNn(digits: string): boolean {
  if (!digits || digits.length !== 11 || !/^\d{11}$/.test(digits)) return false;

  const payload = parseInt(digits.substring(0, 9), 10);
  const checkDigits = parseInt(digits.substring(9, 11), 10);

  // Try pre-2000 interpretation
  const expectedPre2000 = 97 - (payload % 97);
  if (checkDigits === expectedPre2000) return true;

  // Try 2000+ interpretation (prefix 2 to 9-digit payload)
  const payload2000 = 2000000000 + payload;
  const expectedPost2000 = 97 - (payload2000 % 97);
  return checkDigits === expectedPost2000;
}

// ============================================================================
// MOD-11 — BRAZILIAN CPF (Cadastro de Pessoas Físicas)
// ============================================================================

/**
 * Brazilian CPF double mod-11 check digit validation.
 *
 * The CPF is 11 digits: XXX.XXX.XXX-YY
 *   - First 9 digits: registration number
 *   - Y1: first check digit (weights 10..2 on first 9 digits)
 *   - Y2: second check digit (weights 11..2 on first 10 digits)
 *
 * Rule: remainder = sum mod 11; if < 2 → 0, else → 11 - remainder.
 * All-same-digit CPFs (e.g., 111.111.111-11) are invalid despite passing checksum.
 *
 * @param digits Exactly 11-digit string (no separators)
 */
export function mod11Cpf(digits: string): boolean {
  if (!digits || digits.length !== 11 || !/^\d{11}$/.test(digits)) return false;

  // Reject all-same-digit CPFs
  if (/^(\d)\1{10}$/.test(digits)) return false;

  // First check digit
  let sum1 = 0;
  for (let i = 0; i < 9; i++) {
    sum1 += parseInt(digits[i], 10) * (10 - i);
  }
  const rem1 = sum1 % 11;
  const y1 = rem1 < 2 ? 0 : 11 - rem1;
  if (y1 !== parseInt(digits[9], 10)) return false;

  // Second check digit
  let sum2 = 0;
  for (let i = 0; i < 10; i++) {
    sum2 += parseInt(digits[i], 10) * (11 - i);
  }
  const rem2 = sum2 % 11;
  const y2 = rem2 < 2 ? 0 : 11 - rem2;
  return y2 === parseInt(digits[10], 10);
}

// ============================================================================
// MOD-97 — IBAN (ISO 13616)
// ============================================================================

/**
 * IBAN mod-97 validation (ISO 13616-1).
 *
 * Algorithm:
 *  1. Remove spaces and uppercase.
 *  2. Move first 4 characters to the end.
 *  3. Replace each letter A-Z with its numeric equivalent (A=10, Z=35).
 *  4. Parse as integer; valid if result mod 97 === 1.
 *
 * Uses BigInt to handle IBANs up to 34 characters (98-digit numeric string).
 */
export function mod97Iban(iban: string): boolean {
  if (!iban) return false;
  const normalized = iban.replace(/\s+/g, '').toUpperCase();
  if (normalized.length < 5 || normalized.length > 34) return false;
  // Basic format: 2 letters + 2 digits + up to 30 alphanumeric
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{4,30}$/.test(normalized)) return false;
  // Rearrange: move first 4 chars to end
  const rearranged = normalized.substring(4) + normalized.substring(0, 4);
  // Replace letters with numbers
  const numeric = rearranged.replace(/[A-Z]/g, c => String(c.charCodeAt(0) - 55));
  try {
    return BigInt(numeric) % 97n === 1n;
  } catch {
    return false;
  }
}

// ============================================================================
// MOD-23 — IRISH PPS NUMBER (Personal Public Service Number)
// ============================================================================

/**
 * Irish PPS Number check-letter validation (mod-23).
 *
 * Format: 7 digits + 1 check letter [A-W] (old), or 7 digits + check + type letter (new).
 * Only the check letter at position 7 is validated here.
 *
 * Weights: [8, 7, 6, 5, 4, 3, 2] applied to first 7 digits.
 * remainder = sum mod 23
 * Map: 0→W, 1→A, 2→B, ..., 22→V
 *
 * @param pps Full PPS string — first 8 chars used (7 digits + 1 check letter)
 */
export function mod23IePps(pps: string): boolean {
  if (!pps) return false;
  const upper = pps.replace(/\s/g, '').toUpperCase();
  // Must start with 7 digits followed by at least 1 letter A-W
  if (!/^\d{7}[A-W]/.test(upper)) return false;
  const weights = [8, 7, 6, 5, 4, 3, 2];
  let sum = 0;
  for (let i = 0; i < 7; i++) {
    sum += parseInt(upper[i], 10) * weights[i];
  }
  const remainder = sum % 23;
  const expectedLetter = remainder === 0 ? 'W' : String.fromCharCode(64 + remainder); // A=65, so 1→A
  return upper[7] === expectedLetter;
}

// ============================================================================
// MOD-10 — AUSTRIAN SV-NR (Sozialversicherungsnummer)
// ============================================================================

/**
 * Austrian Sozialversicherungsnummer (SV-Nr) check digit validation.
 *
 * The SV-Nr is 10 digits: XXX C DDMMYY where C at position 3 is the check digit.
 * Weights [3,7,9,5,8,4,2,1,6] applied to the 9 non-check positions.
 * check_digit = weighted_sum mod 10
 *
 * @param digits Exactly 10-digit string (no separators)
 */
export function mod10AtSvNr(digits: string): boolean {
  if (!digits || digits.length !== 10 || !/^\d{10}$/.test(digits)) return false;
  const weights = [3, 7, 9, /* skip pos 3 */ 5, 8, 4, 2, 1, 6];
  // Positions: 0,1,2 → weights[0,1,2]; skip pos 3 (check digit); positions 4-9 → weights[3-8]
  let sum = 0;
  for (let i = 0; i < 3; i++) {
    sum += parseInt(digits[i], 10) * weights[i];
  }
  for (let i = 4; i < 10; i++) {
    sum += parseInt(digits[i], 10) * weights[i - 1];
  }
  const checkDigit = sum % 10;
  return checkDigit === parseInt(digits[3], 10);
}

// ============================================================================
// MOD-11 — ROMANIAN CNP (Cod Numeric Personal)
// ============================================================================

/**
 * Romanian CNP (Cod Numeric Personal) check digit validation.
 *
 * The CNP is 13 digits: S YY MM DD CC XXX K
 *   - S: sex/century indicator (1-8)
 *   - YY: birth year (last 2 digits)
 *   - MM: birth month (01-12)
 *   - DD: birth day (01-31)
 *   - CC: county code (01-52, excluding 51-52 or with special values)
 *   - XXX: sequential (001-999)
 *   - K: check digit
 *
 * Weights: [2,7,9,1,4,6,3,5,8,2,7,9] on first 12 digits.
 * remainder = weighted_sum mod 11
 * if remainder < 10 → K = remainder; if remainder = 10 → K = 1
 *
 * @param digits Exactly 13-digit string
 */
export function mod11RoCnp(digits: string): boolean {
  if (!digits || digits.length !== 13 || !/^\d{13}$/.test(digits)) return false;
  // First digit must be 1-8
  const s = parseInt(digits[0], 10);
  if (s < 1 || s > 8) return false;
  const weights = [2, 7, 9, 1, 4, 6, 3, 5, 8, 2, 7, 9];
  let sum = 0;
  for (let i = 0; i < 12; i++) {
    sum += parseInt(digits[i], 10) * weights[i];
  }
  const remainder = sum % 11;
  const expectedK = remainder === 10 ? 1 : remainder;
  return expectedK === parseInt(digits[12], 10);
}

// ============================================================================
// MOD-11 — CZECH / SLOVAK RODNÉ ČÍSLO (Birth Number)
// ============================================================================

/**
 * Czech / Slovak Rodné číslo (Birth Number) mod-11 validation.
 *
 * The 10-digit number (YYMMDDXXXX, slash removed if present) must be
 * divisible by 11 for numbers issued after January 1, 1954.
 *
 * Notes:
 *  - For women, the month portion (MM) is increased by 50 (e.g., July=07 → 57).
 *  - Pre-1954 numbers have only 9 digits and are not validated here.
 *  - Some organizations add +20 to month for disambiguation; not handled here.
 *
 * @param digits Exactly 10-digit string (no separator)
 */
export function mod11CzRc(digits: string): boolean {
  if (!digits || digits.length !== 10 || !/^\d{10}$/.test(digits)) return false;
  try {
    return BigInt(digits) % 11n === 0n;
  } catch {
    return false;
  }
}

// ============================================================================
// MOD-11 — ARGENTINE CUIL / CUIT
// ============================================================================

/**
 * Argentine CUIL (Clave Única de Identificación Laboral) /
 * CUIT (Clave Única de Identificación Tributaria) check digit validation.
 *
 * Format: XX-XXXXXXXX-C (11 digits; 2-digit type + 8-digit base + check)
 * Type prefixes: 20/23/24=male, 27=female, 30/33/34=company
 *
 * Weights: [5, 4, 3, 2, 7, 6, 5, 4, 3, 2] applied to first 10 digits.
 * remainder = sum mod 11
 *   remainder == 0  →  check = 0
 *   remainder == 1  →  check = 9 (used for special entity types)
 *   else            →  check = 11 - remainder
 *
 * @param digits Exactly 11-digit string (no separators)
 */
export function mod11ArCuil(digits: string): boolean {
  if (!digits || digits.length !== 11 || !/^\d{11}$/.test(digits)) return false;
  const weights = [5, 4, 3, 2, 7, 6, 5, 4, 3, 2];
  let sum = 0;
  for (let i = 0; i < 10; i++) {
    sum += parseInt(digits[i], 10) * weights[i];
  }
  const remainder = sum % 11;
  let expectedCheck: number;
  if (remainder === 0) {
    expectedCheck = 0;
  } else if (remainder === 1) {
    expectedCheck = 9;
  } else {
    expectedCheck = 11 - remainder;
  }
  return expectedCheck === parseInt(digits[10], 10);
}

// ============================================================================
// MOD-11 — BRAZILIAN CNPJ (Cadastro Nacional da Pessoa Jurídica)
// ============================================================================

/**
 * Brazilian CNPJ double mod-11 check digit validation.
 *
 * The CNPJ is 14 digits: XX.XXX.XXX/XXXX-YY
 *   - First 12 digits: registration number
 *   - Y1: first check digit (weights [5,4,3,2,9,8,7,6,5,4,3,2] on first 12)
 *   - Y2: second check digit (weights [6,5,4,3,2,9,8,7,6,5,4,3,2] on first 13)
 *
 * Rule: remainder = sum mod 11; if < 2 → 0, else → 11 - remainder.
 * All-same-digit CNPJs (e.g., 11.111.111/1111-11) are invalid despite passing checksum.
 *
 * @param digits Exactly 14-digit string (no separators)
 */
export function mod11Cnpj(digits: string): boolean {
  if (!digits || digits.length !== 14 || !/^\d{14}$/.test(digits)) return false;

  // Reject all-same-digit CNPJs
  if (/^(\d)\1{13}$/.test(digits)) return false;

  // First check digit (position 12)
  const w1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
  let sum1 = 0;
  for (let i = 0; i < 12; i++) {
    sum1 += parseInt(digits[i], 10) * w1[i];
  }
  const rem1 = sum1 % 11;
  const y1 = rem1 < 2 ? 0 : 11 - rem1;
  if (y1 !== parseInt(digits[12], 10)) return false;

  // Second check digit (position 13)
  const w2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
  let sum2 = 0;
  for (let i = 0; i < 13; i++) {
    sum2 += parseInt(digits[i], 10) * w2[i];
  }
  const rem2 = sum2 % 11;
  const y2 = rem2 < 2 ? 0 : 11 - rem2;
  return y2 === parseInt(digits[13], 10);
}

// ============================================================================
// WEIGHTED-SUM MOD-11 — AUSTRALIAN TFN (Tax File Number)
// ============================================================================

/**
 * Australian Tax File Number (TFN) mod-11 checksum validation.
 *
 * Format: 8 or 9 digits (displayed with spaces, e.g. XXX XXX XXX).
 * This validator handles only the 9-digit form (all modern TFNs).
 *
 * Weights (9-digit): [1, 4, 3, 7, 5, 8, 6, 9, 10]
 * The weighted sum of all 9 digits must be divisible by 11.
 *
 * Example (valid 9-digit TFN): 123456782
 *   1×1 + 2×4 + 3×3 + 4×7 + 5×5 + 6×8 + 7×6 + 8×9 + 2×10
 *   = 1+8+9+28+25+48+42+72+20 = 253; 253 mod 11 = 0 ✓
 *
 * @param digits Exactly 9-digit string (no separators)
 */
export function mod11AuTfn(digits: string): boolean {
  if (!digits || digits.length !== 9 || !/^\d{9}$/.test(digits)) return false;
  const weights = [1, 4, 3, 7, 5, 8, 6, 9, 10];
  let sum = 0;
  for (let i = 0; i < 9; i++) {
    sum += parseInt(digits[i], 10) * weights[i];
  }
  return sum % 11 === 0;
}

// ============================================================================
// MOD-89 — AUSTRALIAN ABN (Australian Business Number)
// ============================================================================

/**
 * Australian Business Number (ABN) mod-89 checksum validation.
 *
 * The ABN is 11 digits. Algorithm:
 *   1. Subtract 1 from the first (leftmost) digit.
 *   2. Multiply each digit by the corresponding weight.
 *      Weights: [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19]
 *   3. Sum all products. Valid if sum mod 89 = 0.
 *
 * Example (valid ABN): 51 824 753 556
 *   First digit 5→4; digits [4,1,8,2,4,7,5,3,5,5,6]
 *   40+1+24+10+28+63+55+39+75+85+114 = 534; 534 mod 89 = 0 ✓
 *
 * @param digits Exactly 11-digit string (no separators)
 */
export function mod89AuAbn(digits: string): boolean {
  if (!digits || digits.length !== 11 || !/^\d{11}$/.test(digits)) return false;
  const weights = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19];
  // Subtract 1 from first digit
  const d = digits.split('').map(Number);
  d[0] = d[0] - 1;
  let sum = 0;
  for (let i = 0; i < 11; i++) {
    sum += d[i] * weights[i];
  }
  return sum % 89 === 0;
}

// ============================================================================
// MOD-10 VARIANT — HUNGARIAN TAJ (Társadalombiztosítási Azonosító Jel)
// ============================================================================

/**
 * Hungarian TAJ (Társadalombiztosítási Azonosító Jel — social insurance number)
 * check digit validation.
 *
 * Format: 9 digits (displayed as XXX XXX XXX or bare).
 * Weights: [3, 7, 3, 7, 3, 7, 3, 7] applied to first 8 digits.
 * Check digit (9th) = (10 - (sum mod 10)) mod 10.
 *
 * Example: 123 456 782 → digits [1,2,3,4,5,6,7,8,2]
 *   3+14+9+28+15+42+21+56 = 188; (10 - 8) mod 10 = 2 ✓
 *
 * @param digits Exactly 9-digit string (no separators)
 */
export function mod10HuTaj(digits: string): boolean {
  if (!digits || digits.length !== 9 || !/^\d{9}$/.test(digits)) return false;
  const weights = [3, 7, 3, 7, 3, 7, 3, 7];
  let sum = 0;
  for (let i = 0; i < 8; i++) {
    sum += parseInt(digits[i], 10) * weights[i];
  }
  const expectedCheck = (10 - (sum % 10)) % 10;
  return expectedCheck === parseInt(digits[8], 10);
}

// ============================================================================
// MOD-11 — CHILEAN RUT (Rol Único Tributario) / RUN
// ============================================================================

/**
 * Chilean RUT (Rol Único Tributario) check character validation.
 *
 * Format: XXXXXXXX-V where V is a digit 0-9 or 'K'.
 * Weights cycle [2, 3, 4, 5, 6, 7] applied right-to-left on the numeric part.
 * result = 11 - (sum mod 11)
 *   result == 11  →  check = '0'
 *   result == 10  →  check = 'K'
 *   else          →  check = String(result)
 *
 * @param rut Numeric part (digits only, no dots) + check character (last char is V)
 *            e.g. "123456785" where last char '5' is the check
 */
export function mod11ClRut(rut: string): boolean {
  if (!rut || rut.length < 2) return false;
  const upper = rut.toUpperCase();
  const numericPart = upper.slice(0, -1);
  const checkChar = upper[upper.length - 1];
  if (!/^\d+$/.test(numericPart)) return false;
  if (!/^[0-9K]$/.test(checkChar)) return false;

  const weights = [2, 3, 4, 5, 6, 7];
  let sum = 0;
  for (let i = 0; i < numericPart.length; i++) {
    const weightIndex = i % weights.length;
    // Apply weights right-to-left: rightmost digit gets weight[0]=2
    const digit = parseInt(numericPart[numericPart.length - 1 - i], 10);
    sum += digit * weights[weightIndex];
  }
  const result = 11 - (sum % 11);
  let expectedCheck: string;
  if (result === 11) {
    expectedCheck = '0';
  } else if (result === 10) {
    expectedCheck = 'K';
  } else {
    expectedCheck = String(result);
  }
  return checkChar === expectedCheck;
}
