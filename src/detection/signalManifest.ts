/**
 * AG-PHASE-2-EXECUTION-PLAN-046: Canonical Signal Manifest
 *
 * Single source of truth for all signal IDs emitted by the detection layer.
 * Policy files, tests, and detection modules should import IDs from here
 * rather than using scattered string literals.
 *
 * Naming convention:
 *   - `global-*`   : Patterns in the global pack (always-on, no locale gating)
 *   - `english-*`  : Patterns in the english language pack
 *   - `nordic-*`   : Patterns in the nordic language pack
 *   - `romance-*`  : Patterns in the romance language pack
 *   - `registry-*` : Legacy IDs from patterns originally in registry.ts
 *                     (migrated to global pack in Phase 2, IDs preserved for stability)
 *   - `us-*`       : Patterns in the US country pack
 *
 * IMPORTANT: Changing a signal ID is a breaking change for policy, tests, and
 * any admin-configured overrides. Add new IDs; deprecate old ones with aliases.
 */

// ============================================================================
// SECRETS & CREDENTIALS (critical, hardFloor)
// ============================================================================

export const SIG_API_KEY_SK = 'global-api-key-sk' as const;
export const SIG_API_KEY_PK = 'global-api-key-pk' as const;
export const SIG_API_KEY_GENERIC = 'global-api-key-generic' as const;
export const SIG_BEARER_TOKEN = 'global-bearer-token' as const;
export const SIG_AWS_ACCESS_KEY = 'global-aws-access-key' as const;
export const SIG_PASSWORD_ASSIGNMENT = 'global-password-assignment' as const;
export const SIG_PRIVATE_KEY = 'global-private-key' as const;
export const SIG_CONNECTION_STRING = 'global-connection-string' as const;
export const SIG_URL_CREDENTIALS = 'global-url-credentials' as const;
export const SIG_URL_QUERY_CREDENTIALS = 'global-url-query-credentials' as const;
export const SIG_DB_CONNECTION_STRING = 'global-db-connection-string' as const;

// ============================================================================
// PII — NATIONAL IDs
// ============================================================================

/** Unified national ID signal (emitted for DK CPR, SE personnummer, NO fnr) */
export const SIG_NATIONAL_ID = 'global-national-id' as const;
export const SIG_DK_CPR = 'global-dk-cpr' as const;
export const SIG_SE_PERSONNUMMER = 'global-se-personnummer' as const;
export const SIG_NO_FNR = 'global-no-fnr' as const;
/** US Social Security Number (migrated from registry) */
export const SIG_SSN_US = 'registry-ssn-us' as const;
/** AG-MONSTER-HARDENING-TIERA-ENGINE-001-CONSOLIDATE-AND-GAPS: Finnish HETU (henkilötunnus) */
export const SIG_FI_HETU = 'global-fi-hetu' as const;
/** AG-MONSTER-HARDENING-TIERA-ENGINE-001: German Steuer-ID (Steuerliche Identifikationsnummer) */
export const SIG_DE_STEUER_ID = 'global-de-steuer-id' as const;
/** P2-ADD-ES-DNI-NIE: Spanish DNI (Documento Nacional de Identidad) / NIE (Número de Identidad de Extranjero) */
export const SIG_ES_DNI_NIE = 'global-es-dni-nie' as const;
/** P2-ADD-IT-CODICE-FISCALE: Italian Codice Fiscale (tax identification code) */
export const SIG_IT_CODICE_FISCALE = 'global-it-codice-fiscale' as const;
/** P2-ADD-PL-PESEL: Polish PESEL (Powszechny Elektroniczny System Ewidencji Ludności) */
export const SIG_PL_PESEL = 'global-pl-pesel' as const;
/** AG-PROMPT-105: Dutch BSN (Burgerservicenummer) */
export const SIG_NL_BSN = 'global-nl-bsn' as const;
/** AG-PROMPT-106: French NIR / INSEE (numéro de sécurité sociale) */
export const SIG_FR_NIR = 'global-fr-nir' as const;
/** AG-PROMPT-110: Portuguese NIF (Número de Identificação Fiscal) */
export const SIG_PT_NIF = 'global-pt-nif' as const;
/** AG-PROMPT-115: Belgian NN (Rijksregisternummer / Numéro national) */
export const SIG_BE_NN = 'global-be-nn' as const;
/** AG-PROMPT-115: Brazilian CPF (Cadastro de Pessoas Físicas) */
export const SIG_BR_CPF = 'global-br-cpf' as const;
/** AG-PROMPT-119: Brazilian CNPJ (Cadastro Nacional da Pessoa Jurídica) */
export const SIG_BR_CNPJ = 'global-br-cnpj' as const;
/** AG-PROMPT-115: Mexican CURP (Clave Única de Registro de Población) */
export const SIG_MX_CURP = 'global-mx-curp' as const;
/** AG-PROMPT-119: Mexican RFC (Registro Federal de Contribuyentes) */
export const SIG_MX_RFC = 'global-mx-rfc' as const;
/** AG-PROMPT-117: Argentine CUIL / CUIT (Clave Única de Identificación Laboral/Tributaria) */
export const SIG_AR_CUIL = 'global-ar-cuil' as const;
/** AG-PROMPT-117: Chilean RUT (Rol Único Tributario) / RUN */
export const SIG_CL_RUT = 'global-cl-rut' as const;
/** AG-PROMPT-124: Chilean RUT bare-dash format with mandatory context gate */
export const SIG_CL_RUT_BARE = 'global-cl-rut-bare' as const;
/** AG-PROMPT-116: Irish PPS Number (Personal Public Service Number) */
export const SIG_IE_PPS = 'global-ie-pps' as const;
/** AG-PROMPT-116: Austrian Sozialversicherungsnummer */
export const SIG_AT_SV_NR = 'global-at-sv-nr' as const;
/** AG-PROMPT-116: Romanian CNP (Cod Numeric Personal) */
export const SIG_RO_CNP = 'global-ro-cnp' as const;
/** AG-PROMPT-116: Czech / Slovak Rodné číslo (Birth Number) */
export const SIG_CZ_RC = 'global-cz-rc' as const;
/** AG-PROMPT-121: Hungarian TAJ (Társadalombiztosítási Azonosító Jel) */
export const SIG_HU_TAJ = 'global-hu-taj' as const;
/** AG-PROMPT-121: UK National Insurance Number (NIN) */
export const SIG_UK_NIN = 'global-uk-nin' as const;
/** AG-PROMPT-121: Australian Tax File Number (TFN) */
export const SIG_AU_TFN = 'global-au-tfn' as const;
/** AG-PROMPT-121: Australian Business Number (ABN) */
export const SIG_AU_ABN = 'global-au-abn' as const;
/** AG-PROMPT-121: Canadian Social Insurance Number (SIN) */
export const SIG_CA_SIN = 'global-ca-sin' as const;

// Legacy aliases (these IDs no longer emit but policy may reference them)
export const SIG_LEGACY_DK_CPR = 'registry-dk-cpr' as const;
export const SIG_LEGACY_SE_PERSONNUMMER = 'registry-se-personnummer' as const;
export const SIG_LEGACY_NO_FNR = 'registry-no-fnr' as const;
export const SIG_LEGACY_FI_HETU = 'registry-fi-hetu' as const;

// ============================================================================
// PII — CONTACT & GENERAL
// ============================================================================

export const SIG_EMAIL = 'global-email' as const;

// ============================================================================
// FINANCIAL
// ============================================================================

export const SIG_CREDIT_CARD = 'global-credit-card' as const;
/** Spaced/dashed credit card format (migrated from registry) */
export const SIG_CREDIT_CARD_SPACED = 'registry-credit-card-spaced' as const;
/** Corroborated financial report terminology: balance sheet, margins, EBITDA, P&L, etc. (AG-PROMPT-386) */
export const SIG_GLOBAL_FINANCIAL_REPORT = 'global-financial-report' as const;
export const SIG_IBAN = 'global-iban' as const;
export const SIG_SWIFT = 'global-swift' as const;
/** Banking keyword terms (migrated from registry) */
export const SIG_BANKING_TERMS = 'registry-banking-terms' as const;
/** Insurance domain keywords (AG-PHASE-5-053A) */
export const SIG_INSURANCE_TERMS = 'global-insurance-terms' as const;
/** Insurance policy number, context-gated (AG-PHASE-5-053A) */
export const SIG_INSURANCE_POLICY_NUMBER = 'global-insurance-policy-number' as const;
/** Date of birth, context-gated (AG-PHASE-5-053A) */
export const SIG_DOB = 'global-dob' as const;

// Legacy aliases
export const SIG_LEGACY_CREDIT_CARD = 'registry-credit-card' as const;

// ============================================================================
// LEGAL
// ============================================================================

/** Legal contract language keywords (migrated from registry) */
export const SIG_LEGAL_LANGUAGE = 'registry-legal-language' as const;

// ============================================================================
// MEDICAL
// ============================================================================

/** ICD-10 medical diagnosis codes (migrated from registry) */
export const SIG_ICD10_CODE = 'registry-icd10-code' as const;
/** Medical/health content keywords (migrated from registry) */
export const SIG_MEDICAL_CONTENT = 'registry-medical-content' as const;

// ============================================================================
// HR / EMPLOYEE
// ============================================================================

/** HR/Employee data keywords (migrated from registry) */
export const SIG_HR_EMPLOYEE = 'registry-hr-employee' as const;
/** Organizational roster / people list (AG-PROMPT-185/WS-04) */
export const SIG_ORG_ROSTER = 'global-org-roster' as const;

// ============================================================================
// CONFIDENTIALITY MARKERS
// ============================================================================

export const SIG_CONFIDENTIAL_EN = 'global-confidential-en' as const;
export const SIG_CONFIDENTIAL_DE = 'global-confidential-de' as const;
export const SIG_CONFIDENTIAL_FR = 'global-confidential-fr' as const;
export const SIG_CONFIDENTIAL_ES = 'global-confidential-es' as const;
export const SIG_CONFIDENTIAL_NORDIC = 'global-confidential-nordic' as const;
export const SIG_CONFIDENTIAL_NL = 'global-confidential-nl' as const;
export const SIG_CONFIDENTIAL_IT = 'global-confidential-it' as const;
/** AG-PROMPT-109: Portuguese confidentiality marker */
export const SIG_CONFIDENTIAL_PT = 'global-confidential-pt' as const;
/** AG-PROMPT-114: Polish confidentiality marker */
export const SIG_CONFIDENTIAL_PL = 'global-confidential-pl' as const;
/** AG-PROMPT-121: Romanian confidentiality marker */
export const SIG_CONFIDENTIAL_RO = 'global-confidential-ro' as const;
/** AG-PROMPT-121: Czech/Slovak confidentiality marker */
export const SIG_CONFIDENTIAL_CZ = 'global-confidential-cz' as const;
/** AG-PROMPT-121: Hungarian confidentiality marker */
export const SIG_CONFIDENTIAL_HU = 'global-confidential-hu' as const;
/** AG-PROMPT-121: US privacy law keyword signal */
export const SIG_US_PRIVACY_LAW = 'global-us-privacy-law' as const;

// ============================================================================
// M&A / SENSITIVE BUSINESS
// ============================================================================

export const SIG_MA_TERMS = 'global-ma-terms' as const;
export const SIG_MA_VALUATION_CONTEXT = 'global-ma-valuation-context' as const;

// ============================================================================
// LANGUAGE PACK SIGNALS (english)
// ============================================================================

export const SIG_ENGLISH_PHONE_US = 'english-phone-us-formatted' as const;
export const SIG_ENGLISH_PHONE_INTL = 'english-phone-intl-prefix' as const;
export const SIG_ENGLISH_PHONE_UK = 'english-phone-uk-format' as const;
export const SIG_ENGLISH_LEGAL_CONTRACT = 'english-legal-contract' as const;
export const SIG_ENGLISH_LEGAL_NDA = 'english-legal-nda' as const;
export const SIG_ENGLISH_LEGAL_IP = 'english-legal-ip' as const;
export const SIG_ENGLISH_HR_COMPENSATION = 'english-hr-compensation' as const;
export const SIG_ENGLISH_HR_PERFORMANCE = 'english-hr-performance' as const;
export const SIG_ENGLISH_FINANCIAL_STATEMENT = 'english-financial-statement' as const;
export const SIG_ENGLISH_FINANCIAL_BANKING = 'english-financial-banking' as const;
export const SIG_ENGLISH_HEALTH_PHI = 'english-health-phi' as const;
export const SIG_ENGLISH_GOV_CLEARANCE = 'english-gov-clearance' as const;

// ============================================================================
// LANGUAGE PACK SIGNALS (nordic)
// ============================================================================

export const SIG_NORDIC_PHONE_DK = 'nordic-phone-dk-intl' as const;
export const SIG_NORDIC_PHONE_SE = 'nordic-phone-se-intl' as const;
export const SIG_NORDIC_PHONE_NO = 'nordic-phone-no-intl' as const;
export const SIG_NORDIC_PHONE_FI = 'nordic-phone-fi-intl' as const;
export const SIG_NORDIC_PHONE_LABELED = 'nordic-phone-labeled' as const;
export const SIG_NORDIC_LEGAL_CONTRACT = 'nordic-legal-contract' as const;
export const SIG_NORDIC_CONFIDENTIAL = 'nordic-confidential' as const;
export const SIG_NORDIC_HR_TERMS = 'nordic-hr-terms' as const;
export const SIG_NORDIC_FINANCIAL_TERMS = 'nordic-financial-terms' as const;
export const SIG_NORDIC_PAYROLL = 'nordic-payroll-terms' as const;  // AG-PHASE-5D-057: Nordic payroll

// ============================================================================
// LANGUAGE PACK SIGNALS (romance)
// ============================================================================

export const SIG_ROMANCE_PHONE_EU = 'romance-phone-eu-intl' as const;
export const SIG_ROMANCE_LEGAL_CONTRACT = 'romance-legal-contract' as const;
export const SIG_ROMANCE_CONFIDENTIAL = 'romance-confidential' as const;

// ============================================================================
// COUNTRY PACK SIGNALS
// ============================================================================

export const SIG_US_SSN = 'us-ssn' as const;

// ============================================================================
// SEMANTIC GROUPS (for policy layer use)
// ============================================================================

/** All signal IDs that represent national identity documents */
export const NATIONAL_ID_SIGNALS = [
  SIG_NATIONAL_ID,
  SIG_DK_CPR,
  SIG_SE_PERSONNUMMER,
  SIG_NO_FNR,
  SIG_SSN_US,
  SIG_FI_HETU,
  SIG_DE_STEUER_ID,
  SIG_ES_DNI_NIE,
  SIG_IT_CODICE_FISCALE,
  SIG_PL_PESEL,
  SIG_NL_BSN,
  SIG_FR_NIR,
  SIG_PT_NIF,
  SIG_BE_NN,
  SIG_BR_CPF,
  SIG_BR_CNPJ,
  SIG_MX_CURP,
  SIG_MX_RFC,
  SIG_AR_CUIL,
  SIG_CL_RUT,
  SIG_CL_RUT_BARE,
  SIG_IE_PPS,
  SIG_AT_SV_NR,
  SIG_RO_CNP,
  SIG_CZ_RC,
  SIG_HU_TAJ,
  SIG_UK_NIN,
  SIG_AU_TFN,
  SIG_AU_ABN,
  SIG_CA_SIN,
  // Legacy aliases (policy may still reference these)
  SIG_LEGACY_DK_CPR,
  SIG_LEGACY_SE_PERSONNUMMER,
  SIG_LEGACY_NO_FNR,
  SIG_LEGACY_FI_HETU,
] as const;

/** All signal IDs that represent payment cards */
export const PAYMENT_CARD_SIGNALS = [
  SIG_CREDIT_CARD,
  SIG_CREDIT_CARD_SPACED,
  SIG_LEGACY_CREDIT_CARD,
] as const;

/** All signal IDs that represent medical content */
export const MEDICAL_SIGNALS = [
  SIG_ICD10_CODE,
  SIG_MEDICAL_CONTENT,
] as const;

/** Signal IDs for Nordic national IDs (pack + legacy) */
export const NORDIC_NATIONAL_ID_SIGNALS = [
  SIG_NATIONAL_ID,
  SIG_LEGACY_DK_CPR,
  SIG_LEGACY_SE_PERSONNUMMER,
  SIG_LEGACY_NO_FNR,
  SIG_LEGACY_FI_HETU,
] as const;

/** All secret/credential signal IDs (always critical, hardFloor) */
export const SECRET_SIGNALS = [
  SIG_API_KEY_SK,
  SIG_API_KEY_PK,
  SIG_API_KEY_GENERIC,
  SIG_BEARER_TOKEN,
  SIG_AWS_ACCESS_KEY,
  SIG_PASSWORD_ASSIGNMENT,
  SIG_PRIVATE_KEY,
  SIG_CONNECTION_STRING,
  SIG_URL_CREDENTIALS,
  SIG_URL_QUERY_CREDENTIALS,
] as const;

/** PII signals (for signalDominance, identityConfidence) */
export const PII_SIGNAL_IDS = [
  SIG_NATIONAL_ID,
  SIG_DK_CPR,
  SIG_SE_PERSONNUMMER,
  SIG_NO_FNR,
  SIG_SSN_US,
  SIG_FI_HETU,
  SIG_DE_STEUER_ID,
  SIG_ES_DNI_NIE,
  SIG_IT_CODICE_FISCALE,
  SIG_PL_PESEL,
  SIG_NL_BSN,
  SIG_FR_NIR,
  SIG_PT_NIF,
  SIG_BE_NN,
  SIG_BR_CPF,
  SIG_BR_CNPJ,
  SIG_MX_CURP,
  SIG_MX_RFC,
  SIG_AR_CUIL,
  SIG_CL_RUT,
  SIG_CL_RUT_BARE,
  SIG_IE_PPS,
  SIG_AT_SV_NR,
  SIG_RO_CNP,
  SIG_CZ_RC,
  SIG_HU_TAJ,
  SIG_UK_NIN,
  SIG_AU_TFN,
  SIG_AU_ABN,
  SIG_CA_SIN,
  SIG_EMAIL,
  SIG_HR_EMPLOYEE,
  SIG_ICD10_CODE,
  SIG_MEDICAL_CONTENT,
  SIG_LEGACY_DK_CPR,
  SIG_LEGACY_SE_PERSONNUMMER,
  SIG_LEGACY_NO_FNR,
  SIG_LEGACY_FI_HETU,
] as const;

/** Strong regulated signal IDs (for interpretationCalibration) */
export const STRONG_REGULATED_SIGNAL_IDS = [
  SIG_NATIONAL_ID,
  SIG_LEGACY_DK_CPR,
  SIG_LEGACY_SE_PERSONNUMMER,
  SIG_LEGACY_NO_FNR,
  SIG_LEGACY_FI_HETU,
] as const;

// ============================================================================
// TYPE HELPERS
// ============================================================================

/** Union type of all known signal IDs */
export type KnownSignalId =
  | typeof SIG_API_KEY_SK | typeof SIG_API_KEY_PK | typeof SIG_API_KEY_GENERIC
  | typeof SIG_BEARER_TOKEN | typeof SIG_AWS_ACCESS_KEY | typeof SIG_PASSWORD_ASSIGNMENT
  | typeof SIG_PRIVATE_KEY | typeof SIG_CONNECTION_STRING | typeof SIG_URL_CREDENTIALS
  | typeof SIG_URL_QUERY_CREDENTIALS | typeof SIG_DB_CONNECTION_STRING
  | typeof SIG_NATIONAL_ID | typeof SIG_DK_CPR | typeof SIG_SE_PERSONNUMMER | typeof SIG_NO_FNR
  | typeof SIG_FI_HETU | typeof SIG_SSN_US | typeof SIG_DE_STEUER_ID
  | typeof SIG_ES_DNI_NIE | typeof SIG_IT_CODICE_FISCALE | typeof SIG_PL_PESEL
  | typeof SIG_NL_BSN | typeof SIG_FR_NIR | typeof SIG_PT_NIF
  | typeof SIG_BE_NN | typeof SIG_BR_CPF | typeof SIG_BR_CNPJ | typeof SIG_MX_CURP | typeof SIG_MX_RFC
  | typeof SIG_AR_CUIL | typeof SIG_CL_RUT | typeof SIG_CL_RUT_BARE
  | typeof SIG_IE_PPS | typeof SIG_AT_SV_NR | typeof SIG_RO_CNP | typeof SIG_CZ_RC
  | typeof SIG_HU_TAJ | typeof SIG_UK_NIN | typeof SIG_AU_TFN | typeof SIG_AU_ABN | typeof SIG_CA_SIN
  | typeof SIG_EMAIL
  | typeof SIG_CREDIT_CARD | typeof SIG_CREDIT_CARD_SPACED | typeof SIG_IBAN | typeof SIG_SWIFT
  | typeof SIG_BANKING_TERMS | typeof SIG_LEGAL_LANGUAGE
  | typeof SIG_ICD10_CODE | typeof SIG_MEDICAL_CONTENT | typeof SIG_HR_EMPLOYEE
  | typeof SIG_CONFIDENTIAL_EN | typeof SIG_CONFIDENTIAL_DE | typeof SIG_CONFIDENTIAL_FR
  | typeof SIG_CONFIDENTIAL_ES | typeof SIG_CONFIDENTIAL_NORDIC
  | typeof SIG_CONFIDENTIAL_NL | typeof SIG_CONFIDENTIAL_IT | typeof SIG_CONFIDENTIAL_PT | typeof SIG_CONFIDENTIAL_PL
  | typeof SIG_CONFIDENTIAL_RO | typeof SIG_CONFIDENTIAL_CZ | typeof SIG_CONFIDENTIAL_HU | typeof SIG_US_PRIVACY_LAW
  | typeof SIG_MA_TERMS | typeof SIG_MA_VALUATION_CONTEXT
  | typeof SIG_LEGACY_DK_CPR | typeof SIG_LEGACY_SE_PERSONNUMMER
  | typeof SIG_LEGACY_NO_FNR | typeof SIG_LEGACY_FI_HETU | typeof SIG_LEGACY_CREDIT_CARD
  | string; // Allow unknown IDs from future packs/admin config
