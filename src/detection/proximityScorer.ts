/**
 * AG-XLSX-HARDENING-PLAN-001: Gate & Boost Proximity Scorer
 *
 * Scores detection confidence for checksum-validated national ID matches
 * based on anchor keyword proximity in the surrounding text.
 *
 * Model: "Gate & Boost"
 *  - Gate phase:  checksum validates the candidate (per checksums.ts)
 *  - Boost phase: anchor proximity lifts confidence from 0.6 → 0.99
 *
 * Scoring table (from plan):
 *  ┌─────────────────────────────────────┬────────────┐
 *  │ Condition                           │ Confidence │
 *  ├─────────────────────────────────────┼────────────┤
 *  │ Checksum valid, no anchor           │ 0.60       │
 *  │ Checksum valid + anchor in window   │ 0.99       │
 *  │ DK CPR: checksum fails, anchor      │ 0.40       │
 *  │ DK CPR: checksum fails, no anchor   │ 0.20       │
 *  └─────────────────────────────────────┴────────────┘
 *
 * Note: This file does NOT perform checksum validation itself.
 * Callers (nationalIdValidation.ts, ibanValidation, etc.) must gate
 * on the checksum first, then call scoreProximity().
 */

/** Result of a Gate & Boost proximity scoring pass */
export interface ProximityScore {
  /** Confidence value: 0.20, 0.40, 0.60, or 0.99 */
  confidence: number;
  /** Whether an anchor keyword was found in the proximity window */
  anchorFound: boolean;
  /** The anchor keyword that triggered the boost, if any */
  anchorKeyword?: string;
}

/** Default proximity window: chars before + after the match */
const DEFAULT_WINDOW_CHARS = 100;

/**
 * Score a checksum-validated match using the Gate & Boost model.
 *
 * Call this AFTER the checksum gate has passed. The caller decides
 * whether to use `checksumPassed` for the DK CPR downgrade path
 * (where mod-11 can fail legitimately for post-2007 CPR numbers).
 *
 * @param text          Full document text
 * @param matchIndex    Start character offset of the match in text
 * @param matchLength   Length of the matched string
 * @param anchors       Anchor keywords to search for near the match
 * @param checksumPassed Whether the checksum validated (for downgrade logic)
 * @param windowChars   Search window in chars before+after (default 100)
 */
export function scoreProximity(
  text: string,
  matchIndex: number,
  matchLength: number,
  anchors: string[],
  checksumPassed: boolean,
  windowChars: number = DEFAULT_WINDOW_CHARS,
): ProximityScore {
  const windowStart = Math.max(0, matchIndex - windowChars);
  const windowEnd = Math.min(text.length, matchIndex + matchLength + windowChars);
  const window = text.slice(windowStart, windowEnd).toLowerCase();

  let anchorFound = false;
  let anchorKeyword: string | undefined;
  for (const anchor of anchors) {
    if (window.includes(anchor.toLowerCase())) {
      anchorFound = true;
      anchorKeyword = anchor;
      break;
    }
  }

  // Scoring matrix
  let confidence: number;
  if (checksumPassed) {
    confidence = anchorFound ? 0.99 : 0.60;
  } else {
    // Checksum failed (DK CPR downgrade path)
    confidence = anchorFound ? 0.40 : 0.20;
  }

  return { confidence, anchorFound, anchorKeyword };
}

// ============================================================================
// ANCHOR LISTS — plan-defined, per ID type
// ============================================================================

/** Plan-defined anchors for each national ID type (proximity window: 100 chars) */
export const NORDIC_ANCHORS = [
  'CPR',
  'Personnummer',
  'Samordningsnummer',
  'HETU',
  'IBAN',
  'Steuer-ID',
  'kontonummer',
  'fødselsnummer',
  'fodselsnummer',
  'Account',
  // Additional Nordic context words
  'personnr',
  'cpr-nr',
  'cprnr',
  'fnr',
] as const;

/** DK CPR-specific anchors */
export const DK_CPR_ANCHORS: string[] = [
  'CPR', 'cpr-nr', 'cprnr', 'personnummer', 'personnr',
  'borger', 'patient', 'identifikation', 'fødselsdato', 'national id',
];

/** SE personnummer-specific anchors */
export const SE_PERSONNUMMER_ANCHORS: string[] = [
  'Personnummer', 'personnr', 'Samordningsnummer', 'samordning',
  'folkbokföring', 'skatteverket', 'patient', 'id-nummer',
];

/** NO fødselsnummer-specific anchors */
export const NO_FNR_ANCHORS: string[] = [
  'fødselsnummer', 'fodselsnummer', 'Personnummer', 'fnr',
  'folkeregister', 'patient', 'id-nummer',
];

/** FI HETU-specific anchors */
export const FI_HETU_ANCHORS: string[] = [
  'HETU', 'henkilötunnus', 'hetu', 'sosiaaliturvatunnus', 'sotu',
  'potilasnumero', 'patient',
];

/** IBAN-specific anchors */
export const IBAN_ANCHORS: string[] = [
  'IBAN', 'Account', 'kontonummer', 'kontonr', 'tilinumero',
  'bank account', 'banking', 'wire transfer',
];

/** AG-MONSTER-HARDENING-TIERA-ENGINE-001: German Steuer-ID anchors */
export const DE_STEUER_ID_ANCHORS: string[] = [
  'Steuer-ID', 'Steuerid', 'Steueridentifikationsnummer',
  'Identifikationsnummer', 'IdNr', 'Finanzamt',
  'Steuernummer', 'Steuerpflichtig', 'Einkommensteuer',
  'ELSTER', 'Bundeszentralamt',
];

/** P2-ADD-ES-DNI-NIE: Spanish DNI/NIE anchors */
export const ES_DNI_NIE_ANCHORS: string[] = [
  'dni', 'nie', 'nif', 'cif',
  'documento nacional', 'número de identidad', 'identidad',
  'identidad personal', 'documento de identidad',
];

/** P2-ADD-IT-CODICE-FISCALE: Italian Codice Fiscale anchors */
export const IT_CODICE_FISCALE_ANCHORS: string[] = [
  'codice fiscale', 'codice fiscale:', 'c.f.', 'cf.',
  'codice tributario', 'agenzia delle entrate',
  'contribuente', 'partita iva',
];

/** P2-ADD-PL-PESEL: Polish PESEL anchors */
export const PL_PESEL_ANCHORS: string[] = [
  'pesel', 'numer ewidencyjny', 'identyfikator',
  'numer pesel', 'ewidencja ludności',
];

/** AG-PROMPT-105: Dutch BSN (Burgerservicenummer) anchors */
export const NL_BSN_ANCHORS: string[] = [
  'bsn', 'burgerservicenummer', 'burger service nummer',
  'sofinummer', 'sofi-nummer', 'digid',
  'belastingdienst', 'gemeente', 'persoonsgegevens',
];

/** AG-PROMPT-106: French NIR / INSEE anchors */
export const FR_NIR_ANCHORS: string[] = [
  'nir', 'insee', 'numéro de sécurité sociale', 'sécurité sociale',
  'numero de securite sociale', 'carte vitale', 'vitale',
  'cpam', 'caisse d\'assurance maladie', 'numéro d\'inscription',
];

/** AG-PROMPT-110: Portuguese NIF (Número de Identificação Fiscal) anchors */
export const PT_NIF_ANCHORS: string[] = [
  'nif', 'número de identificação fiscal', 'numero de identificacao fiscal',
  'contribuinte', 'número de contribuinte', 'numero de contribuinte',
  'finanças', 'financas', 'autoridade tributária', 'autoridade tributaria',
];

/** AG-PROMPT-115: Belgian NN (Rijksregisternummer / Numéro national) anchors */
export const BE_NN_ANCHORS: string[] = [
  'rijksregisternummer', 'rijksregister', 'nationaal nummer',
  'numéro national', 'numero national', 'registre national',
  'identiteitskaart', 'carte d\'identité', 'carte d\'identite',
  'eid', 'belgisch', 'belge',
];

/** AG-PROMPT-115: Brazilian CPF (Cadastro de Pessoas Físicas) anchors */
export const BR_CPF_ANCHORS: string[] = [
  'cpf', 'cadastro de pessoas', 'cadastro de pessoas físicas',
  'receita federal', 'contribuinte', 'pessoa física', 'pessoa fisica',
];

/** AG-PROMPT-115: Mexican CURP (Clave Única de Registro de Población) anchors */
export const MX_CURP_ANCHORS: string[] = [
  'curp', 'clave única', 'clave unica', 'registro de población',
  'registro de poblacion', 'acta de nacimiento',
  'ine', 'credencial de elector',
];

/** AG-PROMPT-116: Irish PPS Number (Personal Public Service Number) anchors */
export const IE_PPS_ANCHORS: string[] = [
  'pps', 'ppsn', 'pps number', 'personal public service',
  'revenue', 'department of social protection', 'deasp',
  'hse', 'public services card',
];

/** AG-PROMPT-116: Austrian Sozialversicherungsnummer (SV-Nr) anchors */
export const AT_SV_NR_ANCHORS: string[] = [
  'sozialversicherungsnummer', 'sozialversicherung', 'sv-nr', 'svnr',
  'versicherungsnummer', 'österreich', 'osterreich',
  'österreichisch', 'pensionsversicherung',
];

/** AG-PROMPT-116: Romanian CNP (Cod Numeric Personal) anchors */
export const RO_CNP_ANCHORS: string[] = [
  'cnp', 'cod numeric personal', 'carte de identitate',
  'buletin de identitate', 'codul numeric', 'anaf',
  'romania', 'românesc', 'romanesc',
];

/** AG-PROMPT-119: Brazilian CNPJ anchors */
export const BR_CNPJ_ANCHORS: string[] = [
  'cnpj', 'cadastro nacional', 'pessoa jurídica', 'pessoa juridica',
  'razão social', 'razao social', 'empresa', 'cnpj n°', 'cnpj no',
  'inscrição federal', 'inscricao federal',
];

/** AG-PROMPT-119: Mexican RFC anchors */
export const MX_RFC_ANCHORS: string[] = [
  'rfc', 'registro federal de contribuyentes', 'contribuyente',
  'sat', 'servicio de administración tributaria', 'servicio de administracion tributaria',
  'cédula fiscal', 'cedula fiscal', 'constancia fiscal',
];

/** AG-PROMPT-117: Argentine CUIL / CUIT anchors */
export const AR_CUIL_ANCHORS: string[] = [
  'cuil', 'cuit', 'afip', 'contribuyente', 'argentina',
  'número de cuil', 'número de cuit', 'nro. cuil', 'nro. cuit',
  'identificación tributaria', 'identificacion tributaria',
  // AG-PROMPT-127: AR semantic depth — business/finance/employment terms
  'anses', 'monotributo', 'afp', 'obra social', 'recibo de sueldo',
  'liquidación de sueldo', 'liquidacion de sueldo', 'empleador',
];

/** AG-PROMPT-117: Chilean RUT / RUN anchors */
export const CL_RUT_ANCHORS: string[] = [
  'rut', 'run', 'sii', 'servicio de impuestos',
  'registro civil', 'cédula de identidad', 'cedula de identidad',
  'chile', 'chileno', 'chilena',
  // AG-PROMPT-127: CL semantic depth — business/finance/employment terms
  'afp', 'isapre', 'fonasa', 'previred', 'liquidación de sueldo',
  'liquidacion de sueldo', 'empleador', 'contrato de trabajo',
];

/** AG-PROMPT-116: Czech / Slovak Rodné číslo anchors */
export const CZ_RC_ANCHORS: string[] = [
  'rodné číslo', 'rodne cislo', 'rodné', 'r.č.',
  'česká republika', 'ceska republika', 'slovenská republika',
  'slovensko', 'občanský průkaz', 'občiansky preukaz',
];

/** AG-PROMPT-121: Hungarian TAJ (Társadalombiztosítási Azonosító Jel) anchors */
export const HU_TAJ_ANCHORS: string[] = [
  'taj', 'taj szám', 'taj-szám', 'társadalombiztosítási',
  'tarsadalombiztositasi', 'taj azonosító', 'egészségbiztosítás',
  'egeszsegbiztositas', 'oep', 'tb azonosító',
];

/** AG-PROMPT-121: Hungarian Adóazonosító jel anchors */
export const HU_ADO_ANCHORS: string[] = [
  'adóazonosító', 'adoazonositó', 'adóazonosító jel', 'adó-azonosító',
  'adószám', 'adoszam', 'nav', 'apeh',
  'adóhivatal', 'adohivatal',
];

/** AG-PROMPT-121: UK National Insurance Number (NIN) anchors */
export const UK_NIN_ANCHORS: string[] = [
  'national insurance', 'ni number', 'nino', 'ni no',
  'hmrc', 'national insurance number', 'national insurance no',
  'paye', 'p45', 'p60', 'self-assessment',
];

/** AG-PROMPT-121: Australian TFN (Tax File Number) anchors */
export const AU_TFN_ANCHORS: string[] = [
  'tax file number', 'tfn', 'ato', 'australian taxation office',
  'tax file', 'myTax', 'myGov',
];

/** AG-PROMPT-121: Australian ABN (Australian Business Number) anchors */
export const AU_ABN_ANCHORS: string[] = [
  'abn', 'australian business number', 'ato', 'asic',
  'acn', 'gst', 'business number',
];

/** AG-PROMPT-121: Canadian SIN (Social Insurance Number) anchors */
export const CA_SIN_ANCHORS: string[] = [
  'social insurance', 'sin', 'social insurance number', 'numéro d\'assurance sociale',
  'nas', 'cra', 'canada revenue', 't4', 'rrsp', 'tfsa',
  'employment insurance', 'ei premium', 'cpp',
];

// ============================================================================
// DOMAIN ANCHOR CONFIDENCE ADJUSTMENT
// AG-MONSTER-HARDENING-TIERA-ENGINE-001-CONSOLIDATE-AND-GAPS Phase 4
// ============================================================================

/**
 * Risky domain anchors — indicate the numeric match is likely PII.
 * Presence of these near a national-ID-like number increases confidence
 * that the match is a real national ID.
 */
export const RISKY_DOMAIN_ANCHORS: string[] = [
  'IBAN', 'Payroll', 'Gehalt', 'Løn', 'Beneficiary',
  'Lønmodtager', 'Medarbejder', 'Personnummer', 'CPR',
];

/**
 * Safe domain anchors — indicate the numeric match is a business reference,
 * not a national ID. Presence of these near a national-ID-like number
 * decreases confidence that the match is a real national ID.
 */
export const SAFE_DOMAIN_ANCHORS: string[] = [
  'SKU', 'AWB', 'Ref', 'Sequence', 'Batch',
  'Order', 'Invoice No', 'PO', 'Tracking',
  'Shipment', 'Part No', 'Item No', 'Catalog',
];

/**
 * Adjust confidence for a numeric national-ID-like match based on
 * domain context anchors in the surrounding text.
 *
 * - Safe anchor found → confidence *= 0.50 (downgrade by 50%)
 * - Risky anchor found → confidence *= 1.10 (boost by 10%, capped at 0.99)
 * - Neither found → no change
 *
 * This does NOT change severity — only the confidence field on the signal.
 */
export function adjustConfidenceByDomainAnchors(
  text: string,
  matchIndex: number,
  matchLength: number,
  currentConfidence: number,
  windowChars: number = DEFAULT_WINDOW_CHARS,
): { confidence: number; adjustment: 'safe_downgrade' | 'risky_boost' | 'none'; anchorFound?: string } {
  const windowStart = Math.max(0, matchIndex - windowChars);
  const windowEnd = Math.min(text.length, matchIndex + matchLength + windowChars);
  const window = text.slice(windowStart, windowEnd).toLowerCase();

  // Check safe anchors first (safe anchor wins over risky in same window)
  for (const anchor of SAFE_DOMAIN_ANCHORS) {
    if (window.includes(anchor.toLowerCase())) {
      return {
        confidence: Math.max(0.10, currentConfidence * 0.50),
        adjustment: 'safe_downgrade',
        anchorFound: anchor,
      };
    }
  }

  // Check risky anchors
  for (const anchor of RISKY_DOMAIN_ANCHORS) {
    if (window.includes(anchor.toLowerCase())) {
      return {
        confidence: Math.min(0.99, currentConfidence * 1.10),
        adjustment: 'risky_boost',
        anchorFound: anchor,
      };
    }
  }

  return { confidence: currentConfidence, adjustment: 'none' };
}
