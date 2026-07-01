/**
 * GlobalPack - Universal Detection Patterns
 * 
 * Patterns that work reliably across ALL locales with minimal false positives.
 * This pack is ALWAYS enabled and cannot be disabled.
 * 
 * Design Principles:
 * - HIGH precision, low false positive rate
 * - Works globally without locale context
 * - No phone numbers (too locale-specific)
 * - No national IDs (country-specific)
 * 
 * Includes:
 * - API keys and secrets (sk-, pk_, AKIA, etc.)
 * - Passwords
 * - Email addresses (high threshold)
 * - Credit cards
 * - Multi-language confidentiality markers
 * - IBAN/SWIFT (universal format)
 */

import { DetectionPack, DetectionPattern } from '../types';

// ============================================================================
// GLOBAL PATTERNS
// ============================================================================

const globalPatterns: DetectionPattern[] = [
  // === SECRETS & CREDENTIALS (CRITICAL - HARD FLOOR) ===
  {
    id: 'global-api-key-sk',
    name: 'API Key (sk-)',
    pattern: /\b(sk-[a-zA-Z0-9]{20,})\b/,
    type: 'confidential',
    defaultSeverity: 'critical',
    description: 'API key pattern',
    detail: 'File appears to contain API keys or access tokens.',
    rationale: 'OpenAI-style API keys. Exposure allows unauthorized API usage and billing.',
    pack: 'global',
    hardFloor: true,
    tags: ['secret', 'credential', 'api'],
  },
  {
    id: 'global-api-key-pk',
    name: 'API Key (pk_)',
    pattern: /\b(pk_[a-zA-Z0-9_]{20,})\b/,
    type: 'confidential',
    defaultSeverity: 'critical',
    description: 'API key pattern',
    detail: 'File appears to contain publishable API keys.',
    rationale: 'Stripe-style publishable keys. May expose payment integration.',
    pack: 'global',
    hardFloor: true,
    tags: ['secret', 'credential', 'stripe'],
  },
  {
    id: 'global-api-key-generic',
    name: 'API Key (generic)',
    pattern: /\b(api[_-]?key|apikey)\s*[:=]\s*['"]?([a-zA-Z0-9_-]{20,})['"]?/i,
    type: 'confidential',
    defaultSeverity: 'critical',
    description: 'API key pattern',
    detail: 'File appears to contain API keys or access tokens.',
    rationale: 'Generic API key assignment pattern. High confidence when key= format found.',
    pack: 'global',
    hardFloor: true,
    tags: ['secret', 'credential'],
  },
  {
    id: 'global-bearer-token',
    name: 'Bearer Token',
    pattern: /\bbearer\s+[a-zA-Z0-9_-]{20,}/i,
    type: 'confidential',
    defaultSeverity: 'critical',
    description: 'Bearer token detected',
    detail: 'File contains a bearer authentication token.',
    rationale: 'OAuth bearer tokens enable authenticated access. Must not be shared.',
    pack: 'global',
    hardFloor: true,
    tags: ['secret', 'credential', 'auth', 'oauth'],
  },
  {
    id: 'global-aws-access-key',
    name: 'AWS Access Key',
    pattern: /\bAKIA[0-9A-Z]{16}\b/,
    type: 'confidential',
    defaultSeverity: 'critical',
    description: 'AWS access key',
    detail: 'File contains an AWS access key ID pattern.',
    rationale: 'AWS access keys enable cloud resource access. Extremely high risk if exposed.',
    pack: 'global',
    hardFloor: true,
    tags: ['secret', 'credential', 'aws', 'cloud'],
  },
  {
    id: 'global-password-assignment',
    name: 'Password Assignment',
    pattern: /\b(password|passwd|pwd)\s*[:=]\s*['"]?[^\s'"]{4,}['"]?/i,
    type: 'confidential',
    defaultSeverity: 'critical',
    description: 'Password detected',
    detail: 'File appears to contain a password.',
    rationale: 'Plaintext passwords in files are a critical security risk.',
    pack: 'global',
    hardFloor: true,
    tags: ['secret', 'credential', 'password'],
  },
  {
    id: 'global-private-key',
    name: 'Private Key',
    pattern: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/,
    type: 'confidential',
    defaultSeverity: 'critical',
    description: 'Private key detected',
    detail: 'File contains a cryptographic private key.',
    rationale: 'Private keys enable authentication and decryption. Never share.',
    pack: 'global',
    hardFloor: true,
    tags: ['secret', 'credential', 'crypto', 'key'],
  },
  {
    id: 'global-connection-string',
    name: 'Database Connection String',
    pattern: /\b(mongodb|postgres|mysql|redis):\/\/[^\s]+:[^\s]+@[^\s]+/i,
    type: 'confidential',
    defaultSeverity: 'critical',
    description: 'Database credentials',
    detail: 'File contains database connection string with credentials.',
    rationale: 'Connection strings with embedded credentials expose database access.',
    pack: 'global',
    hardFloor: true,
    tags: ['secret', 'credential', 'database'],
  },
  {
    id: 'global-url-credentials',
    name: 'URL with Credentials',
    pattern: /https?:\/\/[^:]+:[^@]+@[^\s]+/i,
    type: 'confidential',
    defaultSeverity: 'critical',
    description: 'URL with embedded credentials',
    detail: 'File contains a URL with username/password embedded.',
    rationale: 'URLs with embedded auth expose credentials in logs and history.',
    pack: 'global',
    hardFloor: true,
    tags: ['secret', 'credential', 'url'],
  },
  // AG-PROMPT-034: URL query parameter credentials (pass=, password=, etc.)
  {
    id: 'global-url-query-credentials',
    name: 'URL with Credential Parameters',
    pattern: /https?:\/\/[^\s]+[?&](password|passwd|pwd|pass|secret|token|api_key|apikey)=[^\s&]{4,}/i,
    type: 'confidential',
    defaultSeverity: 'critical',
    description: 'URL with credential query parameters',
    detail: 'File contains a URL with credential-like query parameters.',
    rationale: 'Credentials in URL query strings are logged in server access logs and browser history.',
    pack: 'global',
    hardFloor: true,
    tags: ['secret', 'credential', 'url'],
  },

  // === EMAIL ADDRESSES (LOW default, MEDIUM cap) ===
  // AG-PROMPT-6 A1: Fixed character class bug - [A-Z|a-z] had literal pipe, now [A-Za-z]
  {
    id: 'global-email',
    name: 'Email Addresses',
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    type: 'pii',
    defaultSeverity: 'low',
    description: 'Email addresses',
    detail: 'File contains email addresses which may be personal data.',
    rationale: 'Email addresses are PII under GDPR. Low severity unless high density.',
    pack: 'global',
    countMatches: true,
    minCount: 5,  // Only trigger if 5+ emails found
    countDescription: '{count} email addresses',
    maxSeverity: 'medium',
    tags: ['pii', 'contact', 'email'],
  },
  
  // === CREDIT CARDS (CRITICAL - HARD FLOOR) ===
  {
    id: 'global-credit-card',
    name: 'Credit Card Number',
    // Luhn-valid patterns for major card types
    pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/,
    type: 'financial',
    defaultSeverity: 'critical',
    description: 'Payment card pattern',
    detail: 'File contains text matching credit/debit card number format.',
    rationale: 'Payment card data is PCI-DSS regulated. Exposure is a compliance violation.',
    pack: 'global',
    hardFloor: true,
    tags: ['pii', 'financial', 'pci', 'card'],
  },

  // === DANISH CPR NUMBER (CRITICAL - HARD FLOOR) ===
  // AG-PROMPT-034: Danish national ID (CPR) with optional hyphen.
  // Validation gates in packRegistry.ts filter false positives.
  {
    id: 'global-dk-cpr',
    name: 'Danish CPR Number',
    pattern: /\b(0[1-9]|[12][0-9]|3[01])(0[1-9]|1[0-2])(\d{2})-?(\d{4})\b/g,
    type: 'pii',
    defaultSeverity: 'critical',
    description: 'Danish national ID (CPR number)',
    detail: 'File contains a Danish CPR number (national identification).',
    rationale: 'CPR numbers are highly sensitive national identifiers under GDPR. Format: DDMMYY-XXXX.',
    pack: 'global',
    hardFloor: true,
    tags: ['pii', 'national-id', 'denmark', 'cpr'],
  },
  // AG-PROMPT-035: Swedish personnummer with validation gates in packRegistry
  // AG-PHASE-4-052: Extended to handle 12-digit YYYYMMDD format and space-tolerant separator
  {
    id: 'global-se-personnummer',
    name: 'Swedish Personnummer',
    pattern: /\b(?:(?:19|20)\d{2}|\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01]|6[1-9]|[78]\d|9[01])\s*[-+]\s*(\d{4})\b/g,
    type: 'pii',
    defaultSeverity: 'critical',
    description: 'Swedish national ID (personnummer)',
    detail: 'File contains a Swedish personnummer (national identification).',
    rationale: 'Swedish personnummer are highly sensitive national identifiers under GDPR. Format: YYMMDD[-+]XXXX or YYYYMMDD[-+]XXXX.',
    pack: 'global',
    hardFloor: true,
    tags: ['pii', 'national-id', 'sweden', 'personnummer'],
  },
  // AG-PROMPT-035: Norwegian fødselsnummer with validation gates in packRegistry
  {
    id: 'global-no-fnr',
    name: 'Norwegian Fødselsnummer',
    pattern: /\b(0[1-9]|[12][0-9]|3[01])(0[1-9]|1[0-2])(\d{2})(\d{5})\b/g,
    type: 'pii',
    defaultSeverity: 'critical',
    description: 'Norwegian national ID (fødselsnummer)',
    detail: 'File contains a Norwegian fødselsnummer (national identification).',
    rationale: 'Norwegian fødselsnummer are highly sensitive national identifiers under GDPR. Format: DDMMYYXXXXX.',
    pack: 'global',
    hardFloor: true,
    tags: ['pii', 'national-id', 'norway', 'fnr'],
  },

  // === FINNISH HETU (AG-MONSTER-HARDENING-TIERA-ENGINE-001-CONSOLIDATE-AND-GAPS) ===
  // Format: DDMMYY[-+A-Y]XXXC where C is mod-31 control character.
  // Separator: '+' (1800s), '-' (1900s), 'A'-'Y' (2000s+).
  // Validation gates in nationalIdValidation.ts filter FPs.
  {
    id: 'global-fi-hetu',
    name: 'Finnish HETU',
    pattern: /\b(0[1-9]|[12]\d|3[01])(0[1-9]|1[0-2])(\d{2})[-+A-Ya-y](\d{3})([0-9A-Ya-y])\b/g,
    type: 'pii',
    defaultSeverity: 'critical',
    description: 'Finnish national ID (henkilötunnus / HETU)',
    detail: 'File contains a Finnish henkilötunnus (national identification).',
    rationale: 'Finnish henkilötunnus are highly sensitive national identifiers under GDPR. Format: DDMMYY±XXXC.',
    pack: 'global',
    hardFloor: true,
    tags: ['pii', 'national-id', 'finland', 'hetu'],
  },

  // === GERMAN STEUER-ID (AG-MONSTER-HARDENING-TIERA-ENGINE-001) ===
  // 11-digit tax identification number, ISO 7064 Mod 11,10 checksum gate.
  // First digit 1-9; validation gates in nationalIdValidation.ts filter FPs.
  {
    id: 'global-de-steuer-id',
    name: 'German Steuer-ID',
    pattern: /\b([1-9]\d{10})\b/g,
    type: 'pii',
    defaultSeverity: 'critical',
    description: 'German tax identification number (Steuer-ID)',
    detail: 'File contains a German Steuerliche Identifikationsnummer.',
    rationale: 'German Steuer-ID is a permanent, unique tax identifier under GDPR. Format: 11 digits, ISO 7064 checksum.',
    pack: 'global',
    hardFloor: true,
    tags: ['pii', 'national-id', 'germany', 'steuer-id', 'tax'],
  },

  // === SPANISH DNI / NIE (P2-ADD-ES-DNI-NIE) ===
  // DNI format: 8 digits + letter (e.g. 12345678Z)
  // NIE format: X/Y/Z prefix + 7 digits + letter (e.g. X1234567L)
  // Mod-23 check letter gate in nationalIdValidation.ts.
  // Context-gated: requires identity/document keyword proximity to suppress FP.
  {
    id: 'global-es-dni-nie',
    name: 'Spanish DNI / NIE',
    pattern: /\b(?:[XYZxyz]\d{7}|[1-9]\d{7})[A-Za-z]\b/g,
    type: 'pii',
    defaultSeverity: 'critical',
    description: 'Spanish national ID (DNI / NIE)',
    detail: 'File contains a Spanish DNI or NIE (national identification).',
    rationale: 'Spanish DNI/NIE are highly sensitive national identifiers under GDPR. Mod-23 check digit validated.',
    pack: 'global',
    hardFloor: true,
    tags: ['pii', 'national-id', 'spain', 'dni', 'nie'],
  },

  // === ITALIAN CODICE FISCALE (P2-ADD-IT-CODICE-FISCALE) ===
  // 16-character alphanumeric: AAABBBYYXZZZZC
  // - AAA = surname consonants, BBB = first name consonants
  // - YY = birth year, X = birth month letter, ZZZZ = municipality + day, C = check digit
  // Bipartite odd/even check digit gate in nationalIdValidation.ts.
  {
    id: 'global-it-codice-fiscale',
    name: 'Italian Codice Fiscale',
    pattern: /\b[A-Z]{6}[0-9]{2}[A-Z][0-9]{2}[A-Z][0-9]{3}[A-Z]\b/gi,
    type: 'pii',
    defaultSeverity: 'critical',
    description: 'Italian tax code (Codice Fiscale)',
    detail: 'File contains an Italian Codice Fiscale (national tax identification).',
    rationale: 'Italian Codice Fiscale is a permanent national tax identifier under GDPR. Check digit validated.',
    pack: 'global',
    hardFloor: true,
    tags: ['pii', 'national-id', 'italy', 'codice-fiscale'],
  },

  // === POLISH PESEL (P2-ADD-PL-PESEL) ===
  // 11-digit number with century-encoded birth date and weighted checksum.
  // Weights [1,3,7,9,1,3,7,9,1,3]; check = (10 - (sum mod 10)) mod 10.
  // Context-gated: requires 'pesel' or related keyword proximity to suppress FP
  // for arbitrary 11-digit sequences.
  {
    id: 'global-pl-pesel',
    name: 'Polish PESEL',
    pattern: /\b\d{11}\b/g,
    type: 'pii',
    defaultSeverity: 'critical',
    description: 'Polish national ID (PESEL)',
    detail: 'File contains a Polish PESEL number (national identification).',
    rationale: 'Polish PESEL is a unique national identifier under GDPR. Weighted checksum + month validity gate applied.',
    pack: 'global',
    hardFloor: true,
    tags: ['pii', 'national-id', 'poland', 'pesel'],
  },

  // === DUTCH BSN (AG-PROMPT-105) ===
  // 9-digit Burgerservicenummer with 11-test checksum gate.
  // Weights [9,8,7,6,5,4,3,2,-1]; sum mod 11 == 0 and sum != 0.
  // Context-gated: requires 'bsn' or related keyword proximity to suppress FP
  // for arbitrary 9-digit sequences.
  {
    id: 'global-nl-bsn',
    name: 'Dutch BSN',
    pattern: /\b\d{9}\b/g,
    type: 'pii',
    defaultSeverity: 'critical',
    description: 'Dutch national ID (BSN / Burgerservicenummer)',
    detail: 'File contains a Dutch BSN number (Burgerservicenummer).',
    rationale: 'Dutch BSN is a permanent national identifier under GDPR. 11-test checksum validated.',
    pack: 'global',
    hardFloor: true,
    tags: ['pii', 'national-id', 'netherlands', 'bsn'],
  },

  // === FRENCH NIR / INSEE (AG-PROMPT-106) ===
  // 15-character national ID: sex(1) + year(2) + month(2) + dept(2-3, incl. 2A/2B) + commune(3) + order(3) + key(2)
  // Mod-97 checksum validated. Corsica departments 2A/2B handled by checksum function.
  {
    id: 'global-fr-nir',
    name: 'French NIR / INSEE',
    pattern: /\b[12]\s?\d{2}\s?(?:0[1-9]|1[0-2]|[2-9]\d)\s?(?:\d{2}|2[ABab])\s?\d{3}\s?\d{3}\s?\d{2}\b/gi,
    type: 'pii',
    defaultSeverity: 'critical',
    description: 'French national ID (NIR / numéro de sécurité sociale)',
    detail: 'File contains a French NIR number (numéro de sécurité sociale / INSEE).',
    rationale: 'French NIR is a permanent national identifier under GDPR. Mod-97 checksum validated.',
    pack: 'global',
    hardFloor: true,
    tags: ['pii', 'national-id', 'france', 'nir'],
  },

  // === PORTUGUESE NIF (AG-PROMPT-110) ===
  // 9-digit Número de Identificação Fiscal with mod-11 checksum gate.
  // First digit: 1-3 (individual), 5 (corporate), 6 (public), 7 (intl), 8 (sole trader), 9 (irregular).
  // Never 0 or 4. Context-gated: requires 'nif' or related keyword proximity.
  {
    id: 'global-pt-nif',
    name: 'Portuguese NIF',
    pattern: /\b\d{9}\b/g,
    type: 'pii',
    defaultSeverity: 'critical',
    description: 'Portuguese national tax ID (NIF / Número de Identificação Fiscal)',
    detail: 'File contains a Portuguese NIF number (Número de Identificação Fiscal).',
    rationale: 'Portuguese NIF is a permanent tax identifier under GDPR. Mod-11 checksum validated.',
    pack: 'global',
    hardFloor: true,
    tags: ['pii', 'national-id', 'portugal', 'nif'],
  },

  // === BELGIAN RIJKSREGISTERNUMMER / NUMÉRO NATIONAL (AG-PROMPT-115) ===
  // 11-digit national register number: YY.MM.DD-SSS.CC
  // Formatted pattern (dots + dash) avoids overlap with PESEL's bare 11-digit regex.
  // Mod-97 checksum validated (both pre-2000 and post-2000 variants).
  // Context-gated: bilingual FR/NL keywords already available.
  {
    id: 'global-be-nn',
    name: 'Belgian National Number',
    pattern: /\b\d{2}[.,\s]\d{2}[.,\s]\d{2}[-–\s]\d{3}[.,\s]\d{2}\b/g,
    type: 'pii',
    defaultSeverity: 'critical',
    description: 'Belgian national register number (Rijksregisternummer / Numéro national)',
    detail: 'File contains a Belgian national register number (Rijksregisternummer / Numéro national).',
    rationale: 'Belgian NN is a permanent national identifier under GDPR. Mod-97 checksum validated.',
    pack: 'global',
    hardFloor: true,
    tags: ['pii', 'national-id', 'belgium', 'nn', 'rijksregisternummer'],
  },

  // === BRAZILIAN CPF (AG-PROMPT-115) ===
  // 11-digit taxpayer ID: XXX.XXX.XXX-XX
  // Formatted pattern (dots + dash) avoids FP with bare digit sequences.
  // Double mod-11 checksum validated. All-same-digit CPFs rejected.
  {
    id: 'global-br-cpf',
    name: 'Brazilian CPF',
    pattern: /\b\d{3}[.,]\d{3}[.,]\d{3}-\d{2}\b/g,
    type: 'pii',
    defaultSeverity: 'critical',
    description: 'Brazilian taxpayer ID (CPF / Cadastro de Pessoas Físicas)',
    detail: 'File contains a Brazilian CPF number (Cadastro de Pessoas Físicas).',
    rationale: 'Brazilian CPF is a permanent taxpayer identifier under LGPD. Double mod-11 checksum validated.',
    pack: 'global',
    hardFloor: true,
    tags: ['pii', 'national-id', 'brazil', 'cpf'],
  },

  // === BRAZILIAN CNPJ (AG-PROMPT-119) ===
  // 14-digit company tax ID: XX.XXX.XXX/XXXX-YY
  // The /XXXX-YY suffix (forward slash) is uniquely Brazilian — very low FP risk.
  // Double mod-11 checksum validated. All-same-digit CNPJs rejected.
  {
    id: 'global-br-cnpj',
    name: 'Brazilian CNPJ',
    pattern: /\b\d{2}[.,]\d{3}[.,]\d{3}\/\d{4}-\d{2}\b/g,
    type: 'pii',
    defaultSeverity: 'critical',
    description: 'Brazilian company tax ID (CNPJ / Cadastro Nacional da Pessoa Jurídica)',
    detail: 'File contains a Brazilian CNPJ number (Cadastro Nacional da Pessoa Jurídica).',
    rationale: 'Brazilian CNPJ identifies legal entities under LGPD. The XX.XXX.XXX/XXXX-YY format with forward slash is uniquely distinctive. Double mod-11 checksum validated.',
    pack: 'global',
    hardFloor: true,
    tags: ['pii', 'national-id', 'brazil', 'cnpj'],
  },

  // === MEXICAN CURP (AG-PROMPT-115) ===
  // 18-character alphanumeric: AAAA######HSSCCCD#
  // Highly distinctive format. Context-gated: requires CURP/clave keyword proximity.
  // H=sex (H/M), SS=state code, CCC=consonants, D=century, #=check digit.
  {
    id: 'global-mx-curp',
    name: 'Mexican CURP',
    pattern: /\b[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d\b/gi,
    type: 'pii',
    defaultSeverity: 'critical',
    description: 'Mexican population registry key (CURP / Clave Única de Registro de Población)',
    detail: 'File contains a Mexican CURP (Clave Única de Registro de Población).',
    rationale: 'Mexican CURP is a unique national identifier. 18-character alphanumeric format is highly distinctive.',
    pack: 'global',
    hardFloor: true,
    tags: ['pii', 'national-id', 'mexico', 'curp'],
  },

  // === MEXICAN RFC (AG-PROMPT-119) ===
  // 12-13 char alphanumeric: [A-ZÑ&]{3,4} + YYMMDD + [A-Z0-9]{3}
  // Format gate + date plausibility gate + MANDATORY context gate (no public checksum).
  // Covers both personas físicas (4-letter prefix) and personas morales (3-letter prefix).
  {
    id: 'global-mx-rfc',
    name: 'Mexican RFC',
    pattern: /\b[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3}\b/gi,
    type: 'pii',
    defaultSeverity: 'critical',
    description: 'Mexican taxpayer ID (RFC / Registro Federal de Contribuyentes)',
    detail: 'File contains a Mexican RFC (Registro Federal de Contribuyentes).',
    rationale: 'Mexican RFC identifies taxpayers under SAT regulations. Format: 3-4 letter prefix + YYMMDD + 3-char homoclave. Mandatory context gate applied (no public checksum).',
    pack: 'global',
    hardFloor: true,
    tags: ['pii', 'national-id', 'mexico', 'rfc'],
  },

  // === ARGENTINE CUIL / CUIT (AG-PROMPT-117) ===
  // 11-digit tax/labor identifier: XX-XXXXXXXX-C (dashed format).
  // Type prefix: 20/23/24=male, 27=female, 30/33/34=company.
  // Mod-11 check digit (weights [5,4,3,2,7,6,5,4,3,2]).
  // Dashed format avoids FP with bare digit sequences.
  {
    id: 'global-ar-cuil',
    name: 'Argentine CUIL/CUIT',
    pattern: /\b\d{2}-\d{8}-\d\b/g,
    type: 'pii',
    defaultSeverity: 'critical',
    description: 'Argentine tax/labor identifier (CUIL / CUIT)',
    detail: 'File contains an Argentine CUIL (Clave Única de Identificación Laboral) or CUIT (Clave Única de Identificación Tributaria).',
    rationale: 'Argentine CUIL/CUIT is a permanent national tax identifier. Dashed format is distinctive. Mod-11 check digit + type prefix validated.',
    pack: 'global',
    hardFloor: true,
    tags: ['pii', 'national-id', 'ar', 'argentina', 'cuil', 'cuit'],
  },

  // === CHILEAN RUT / RUN (AG-PROMPT-117) ===
  // Tax and civil identifier: XX.XXX.XXX-K (formatted) or XXXXXXXX-K (bare).
  // Mod-11 cycling weights [2,3,4,5,6,7] right-to-left; check may be digit or 'K'.
  // Only the formatted (dotted) pattern is detected here to minimize FP risk.
  {
    id: 'global-cl-rut',
    name: 'Chilean RUT/RUN',
    pattern: /\b\d{1,2}[.,]\d{3}[.,]\d{3}-[0-9Kk]\b/g,
    type: 'pii',
    defaultSeverity: 'critical',
    description: 'Chilean tax/civil identifier (RUT / RUN)',
    detail: 'File contains a Chilean RUT (Rol Único Tributario) or RUN (Rol Único Nacional).',
    rationale: 'Chilean RUT/RUN is a permanent national tax/civil identifier. Dotted format (X.XXX.XXX-K) is distinctive. Mod-11 check character validated.',
    pack: 'global',
    hardFloor: true,
    tags: ['pii', 'national-id', 'cl', 'chile', 'rut', 'run'],
  },

  // === CHILEAN RUT / RUN BARE-DASH FORMAT (AG-PROMPT-124) ===
  // Bare format: XXXXXXXX-K (7-8 digits + dash + check character).
  // High FP risk without context, so MANDATORY context gate via validator.
  // Checksum: same mod-11 cycling weights as dotted format.
  {
    id: 'global-cl-rut-bare',
    name: 'Chilean RUT/RUN (bare format)',
    pattern: /\b\d{7,8}-[0-9Kk]\b/g,
    type: 'pii',
    defaultSeverity: 'critical',
    description: 'Chilean tax/civil identifier (RUT/RUN) — bare dash format',
    detail: 'File contains a Chilean RUT in bare format (XXXXXXXX-K). Requires context keywords for validation.',
    rationale: 'Bare-dash RUT format is common in Chilean business documents but FP-prone without context. Mandatory context gate + mod-11 checksum provide quality control.',
    pack: 'global',
    hardFloor: true,
    tags: ['pii', 'national-id', 'cl', 'chile', 'rut', 'run'],
  },

  // === IRISH PPS NUMBER (AG-PROMPT-116) ===
  // 7 digits + 1-2 uppercase letters [A-W]. Old format: 7+1; new format: 7+2.
  // Mod-23 check letter validated. Context-gated: requires PPS/PPSN keyword proximity.
  // English semantics already active for IE.
  {
    id: 'global-ie-pps',
    name: 'Irish PPS Number',
    pattern: /\b\d{7}[A-W]{1,2}\b/g,
    type: 'pii',
    defaultSeverity: 'critical',
    description: 'Irish Personal Public Service (PPS) Number',
    detail: 'File contains an Irish PPS Number (Personal Public Service Number).',
    rationale: 'Irish PPS Number is a unique identifier used for tax, social welfare and public services. Mod-23 check letter validated.',
    pack: 'global',
    hardFloor: true,
    tags: ['pii', 'national-id', 'ie', 'ireland', 'pps'],
  },

  // === AUSTRIAN SV-NR (AG-PROMPT-116) ===
  // 10-digit sequence: XXXCDDMMYY — 3-digit seq + 1 check digit + 6-digit DOB.
  // Written with space: "XXXC DDMMYY". Mod-10 check digit + date plausibility.
  // Context keyword required due to medium FP risk.
  // DE semantics already active for AT.
  {
    id: 'global-at-sv-nr',
    name: 'Austrian SV-Nr',
    pattern: /\b\d{4}[\s]\d{6}\b/g,
    type: 'pii',
    defaultSeverity: 'critical',
    description: 'Austrian Sozialversicherungsnummer (SV-Nr)',
    detail: 'File contains an Austrian social insurance number (Sozialversicherungsnummer).',
    rationale: 'Austrian SV-Nr is a permanent social security identifier. Mod-10 check digit + date plausibility validated. Context keyword required.',
    pack: 'global',
    hardFloor: true,
    tags: ['pii', 'national-id', 'at', 'austria', 'sv-nr'],
  },

  // === ROMANIAN CNP (AG-PROMPT-116) ===
  // 13-digit national ID: SYYMMDDCCXXXK where S=sex/century (1-8).
  // Mod-11 check digit with constant vector [2,7,9,1,4,6,3,5,8,2,7,9].
  // Distinctive 13-digit format with sex-prefixed century indicator.
  {
    id: 'global-ro-cnp',
    name: 'Romanian CNP',
    pattern: /\b[1-8]\d{12}\b/g,
    type: 'pii',
    defaultSeverity: 'critical',
    description: 'Romanian personal numeric code (CNP / Cod Numeric Personal)',
    detail: 'File contains a Romanian CNP (Cod Numeric Personal).',
    rationale: 'Romanian CNP is a lifetime national identifier. 13-digit format starting with sex/century digit (1-8) is distinctive. Mod-11 checksum validated.',
    pack: 'global',
    hardFloor: true,
    tags: ['pii', 'national-id', 'ro', 'romania', 'cnp'],
  },

  // === CZECH / SLOVAK RODNÉ ČÍSLO (AG-PROMPT-116) ===
  // 10-digit birth number: YYMMDD/XXXX (slash format) or YYMMDDXXXX (bare).
  // For women, month is incremented by 50 (57 = July for women).
  // Mod-11: the 10-digit number must be divisible by 11.
  // CZ and SK share identical format; one validator covers both.
  {
    id: 'global-cz-rc',
    name: 'Czech/Slovak Rodné číslo',
    pattern: /\b\d{6}\/\d{4}\b/g,
    type: 'pii',
    defaultSeverity: 'critical',
    description: 'Czech / Slovak birth number (Rodné číslo)',
    detail: 'File contains a Czech or Slovak Rodné číslo (birth number).',
    rationale: 'Rodné číslo is a lifelong national identifier used in CZ and SK. Slash-separated format is distinctive. Mod-11 checksum validated.',
    pack: 'global',
    hardFloor: true,
    tags: ['pii', 'national-id', 'cz', 'sk', 'czechia', 'slovakia', 'rc'],
  },

  // === HUNGARIAN TAJ (Társadalombiztosítási Azonosító Jel) — AG-PROMPT-121 ===
  // 9-digit format displayed as XXX XXX XXX (three groups of 3 with spaces).
  // Mandatory context + mod-10 checksum required (format overlaps with AU TFN).
  {
    id: 'global-hu-taj',
    name: 'Hungarian TAJ',
    pattern: /\b\d{3} \d{3} \d{3}\b/g,
    type: 'pii',
    defaultSeverity: 'critical',
    description: 'Hungarian social insurance number (TAJ — Társadalombiztosítási Azonosító Jel)',
    detail: 'File contains a Hungarian TAJ social insurance number.',
    rationale: 'Hungarian TAJ is a permanent social insurance identifier. 9-digit format displayed as XXX XXX XXX. Mod-10 weighted checksum and mandatory context gate applied (format shared with AU TFN; context + checksum distinguish them).',
    pack: 'global',
    hardFloor: true,
    tags: ['pii', 'national-id', 'hu', 'hungary', 'taj'],
  },

  // === UK NATIONAL INSURANCE NUMBER (NIN / NINO) — AG-PROMPT-121 ===
  // Format: [A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] \d{6} [A-D]
  // Forbidden prefixes: BG GB NK KN TN NT ZZ
  {
    id: 'global-uk-nin',
    name: 'UK National Insurance Number',
    pattern: /\b(?!(?:BG|GB|NK|KN|TN|NT|ZZ))[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b/gi,
    type: 'pii',
    defaultSeverity: 'critical',
    description: 'UK National Insurance Number (NIN / NINO)',
    detail: 'File contains a UK National Insurance Number.',
    rationale: 'UK NIN is a lifelong personal identifier used for tax, employment, and benefits. Format: 2-letter prefix (with specific excluded letters) + 6 digits + suffix A–D. Mandatory context gate applied.',
    pack: 'global',
    hardFloor: true,
    tags: ['pii', 'national-id', 'uk', 'gb', 'nino', 'nin', 'national-insurance'],
  },

  // === AUSTRALIAN TAX FILE NUMBER (TFN) — AG-PROMPT-121 ===
  // 9-digit format displayed as XXX XXX XXX (three groups of 3 with spaces).
  // Same display format as HU TAJ; checksum + context distinguish them.
  {
    id: 'global-au-tfn',
    name: 'Australian Tax File Number',
    pattern: /\b\d{3} \d{3} \d{3}\b/g,
    type: 'pii',
    defaultSeverity: 'critical',
    description: 'Australian Tax File Number (TFN)',
    detail: 'File contains an Australian Tax File Number.',
    rationale: 'Australian TFN is a permanent tax identifier issued by the ATO. 9-digit format displayed as XXX XXX XXX. Mod-11 weighted checksum validated. Mandatory context gate applied (format shared with HU TAJ; checksum + context distinguish them).',
    pack: 'global',
    hardFloor: true,
    tags: ['pii', 'national-id', 'au', 'australia', 'tfn'],
  },

  // === AUSTRALIAN BUSINESS NUMBER (ABN) — AG-PROMPT-121 ===
  // 11-digit format displayed as XX XXX XXX XXX (2+3+3+3 groups with spaces).
  {
    id: 'global-au-abn',
    name: 'Australian Business Number',
    pattern: /\b\d{2} \d{3} \d{3} \d{3}\b/g,
    type: 'pii',
    defaultSeverity: 'critical',
    description: 'Australian Business Number (ABN)',
    detail: 'File contains an Australian Business Number.',
    rationale: 'Australian ABN is a public business identifier under ASIC/ATO. 11-digit format displayed as XX XXX XXX XXX (2+3+3+3). Mod-89 checksum validated. Mandatory context gate applied.',
    pack: 'global',
    hardFloor: true,
    tags: ['pii', 'national-id', 'au', 'australia', 'abn', 'business'],
  },

  // === CANADIAN SOCIAL INSURANCE NUMBER (SIN / NAS) — AG-PROMPT-121 ===
  // 9-digit format displayed as XXX-XXX-XXX (three groups of 3 with dashes).
  {
    id: 'global-ca-sin',
    name: 'Canadian Social Insurance Number',
    pattern: /\b\d{3}-\d{3}-\d{3}\b/g,
    type: 'pii',
    defaultSeverity: 'critical',
    description: 'Canadian Social Insurance Number (SIN / NAS)',
    detail: 'File contains a Canadian Social Insurance Number.',
    rationale: 'Canadian SIN is a 9-digit identifier used for tax, employment, and government benefits. Dash-separated format XXX-XXX-XXX. Luhn-10 checksum validated. Mandatory context gate applied.',
    pack: 'global',
    hardFloor: true,
    tags: ['pii', 'national-id', 'ca', 'canada', 'sin', 'nas'],
  },

  // === MULTI-LANGUAGE CONFIDENTIALITY MARKERS (HIGH - HARD FLOOR) ===
  // AG-PROMPT-FP-CONFIDENTIAL-IDIOM-006: "secret" uses negative lookahead to
  // exclude idiomatic phrases like "secret sauce" (business idiom meaning
  // "competitive differentiator"). The lookahead (?![\s\-'"]*sauce) rejects
  // "secret" when immediately followed by optional whitespace/punctuation and "sauce".
  // This does NOT affect: "SECRET", "TOP SECRET", "secret document", "confidential", etc.
  {
    id: 'global-confidential-en',
    name: 'Confidentiality Marker (English)',
    pattern: /\b(confidential|secret(?![\s\-'"]*sauce)|classified|internal\s+only|restricted|proprietary|do\s+not\s+distribute)\b/i,
    type: 'confidential',
    defaultSeverity: 'high',
    description: 'Confidentiality marker in text',
    detail: 'Document text contains confidentiality markers.',
    rationale: 'Explicit confidentiality classification indicates sensitive content.',
    pack: 'global',
    hardFloor: true,
    tags: ['classification', 'confidential', 'english'],
  },
  {
    id: 'global-confidential-de',
    name: 'Confidentiality Marker (German)',
    // AG-PROMPT-6 A3: Unicode-safe boundary using \p{L} for complete EU letter coverage
    // Covers German umlauts (ü in "für") and ß
    pattern: /(?<!\p{L})(vertraulich|geheim|streng\s+vertraulich|nur\s+für\s+den\s+internen\s+gebrauch)(?!\p{L})/iu,
    type: 'confidential',
    defaultSeverity: 'high',
    description: 'Confidentiality marker in text',
    detail: 'Document text contains German confidentiality markers.',
    rationale: 'German confidentiality classification.',
    pack: 'global',
    hardFloor: true,
    tags: ['classification', 'confidential', 'german'],
  },
  // AG-PROMPT-FP-CONFIDENTIAL-IDIOM-006: French also has "secret" - apply same
  // idiom exclusion for "secret sauce" (English business idiom used globally)
  {
    id: 'global-confidential-fr',
    name: 'Confidentiality Marker (French)',
    pattern: /\b(confidentiel|secret(?![\s\-'"]*sauce)|usage\s+interne|ne\s+pas\s+diffuser)\b/i,
    type: 'confidential',
    defaultSeverity: 'high',
    description: 'Confidentiality marker in text',
    detail: 'Document text contains French confidentiality markers.',
    rationale: 'French confidentiality classification.',
    pack: 'global',
    hardFloor: true,
    tags: ['classification', 'confidential', 'french'],
  },
  {
    id: 'global-confidential-es',
    name: 'Confidentiality Marker (Spanish)',
    pattern: /\b(confidencial|secreto|uso\s+interno|no\s+distribuir)\b/i,
    type: 'confidential',
    defaultSeverity: 'high',
    description: 'Confidentiality marker in text',
    detail: 'Document text contains Spanish confidentiality markers.',
    rationale: 'Spanish confidentiality classification.',
    pack: 'global',
    hardFloor: true,
    tags: ['classification', 'confidential', 'spanish'],
  },
  {
    id: 'global-confidential-nordic',
    name: 'Confidentiality Marker (Nordic)',
    // AG-PROMPT-4: Unicode-safe boundary for Nordic languages
    // AG-PROMPT-105: Added Finnish keywords (luottamuksellinen, salainen, sisäinen käyttö)
    pattern: /(?<!\p{L})(fortrolig|hemmelig|intern\s+brug|konfidentiell|hemlig|luottamuksellinen|salainen|sis[aä]inen\s+k[aä]ytt[oö])(?!\p{L})/iu,
    type: 'confidential',
    defaultSeverity: 'high',
    description: 'Confidentiality marker in text',
    detail: 'Document text contains Nordic confidentiality markers.',
    rationale: 'Danish/Norwegian/Swedish/Finnish confidentiality classification.',
    pack: 'global',
    hardFloor: true,
    tags: ['classification', 'confidential', 'nordic'],
  },
  // AG-PROMPT-100: Dutch confidentiality marker
  {
    id: 'global-confidential-nl',
    name: 'Confidentiality Marker (Dutch)',
    pattern: /(?<!\p{L})(vertrouwelijk|geheim|strikt\s+vertrouwelijk|intern\s+gebruik|niet\s+verspreiden)(?!\p{L})/iu,
    type: 'confidential',
    defaultSeverity: 'high',
    description: 'Confidentiality marker in text',
    detail: 'Document text contains Dutch confidentiality markers.',
    rationale: 'Dutch confidentiality classification under GDPR.',
    pack: 'global',
    hardFloor: true,
    tags: ['classification', 'confidential', 'dutch'],
  },
  // AG-PROMPT-100: Italian confidentiality marker
  {
    id: 'global-confidential-it',
    name: 'Confidentiality Marker (Italian)',
    pattern: /(?<!\p{L})(confidenziale|riservato|strettamente\s+riservato|uso\s+interno|non\s+divulgare)(?!\p{L})/iu,
    type: 'confidential',
    defaultSeverity: 'high',
    description: 'Confidentiality marker in text',
    detail: 'Document text contains Italian confidentiality markers.',
    rationale: 'Italian confidentiality classification under GDPR.',
    pack: 'global',
    hardFloor: true,
    tags: ['classification', 'confidential', 'italian'],
  },

  // AG-PROMPT-109: Portuguese confidentiality marker
  // Note: "confidencial" already fires via global-confidential-es (identical in PT/ES)
  // This signal adds PT-specific terms that don't overlap with ES.
  {
    id: 'global-confidential-pt',
    name: 'Confidentiality Marker (Portuguese)',
    pattern: /(?<!\p{L})(reservado|restrito|estritamente\s+confidencial|n[aã]o\s+distribuir)(?!\p{L})/iu,
    type: 'confidential',
    defaultSeverity: 'high',
    description: 'Confidentiality marker in text',
    detail: 'Document text contains Portuguese confidentiality markers.',
    rationale: 'Portuguese confidentiality classification under GDPR.',
    pack: 'global',
    hardFloor: true,
    tags: ['classification', 'confidential', 'portuguese'],
  },

  // AG-PROMPT-114: Polish confidentiality marker
  // Polish uses distinct Slavic vocabulary — no overlap with existing Romance/Germanic patterns.
  {
    id: 'global-confidential-pl',
    name: 'Confidentiality Marker (Polish)',
    pattern: /(?<!\p{L})(poufne|tajne|zastrze[zż]one|do\s+u[zż]ytku\s+wewn[eę]trznego|nie\s+rozpowszechnia[cć])(?!\p{L})/iu,
    type: 'confidential',
    defaultSeverity: 'high',
    description: 'Confidentiality marker in text',
    detail: 'Document text contains Polish confidentiality markers.',
    rationale: 'Polish confidentiality classification under GDPR.',
    pack: 'global',
    hardFloor: true,
    tags: ['classification', 'confidential', 'polish'],
  },

  // AG-PROMPT-121: Romanian confidentiality marker
  // Note: "confidential" and "secret" are already covered by global-confidential-en.
  // This signal adds RO-specific terms: uz intern, clasificat, restricționat.
  {
    id: 'global-confidential-ro',
    name: 'Confidentiality Marker (Romanian)',
    pattern: /(?<!\p{L})(uz\s+intern|pentru\s+uz\s+intern|clasificat|restric[tț]ionat|nu\s+distribui[tț]i)(?!\p{L})/iu,
    type: 'confidential',
    defaultSeverity: 'high',
    description: 'Confidentiality marker in text',
    detail: 'Document text contains Romanian confidentiality markers.',
    rationale: 'Romanian confidentiality classification under GDPR. Covers terms distinct from English/French/Spanish cognates.',
    pack: 'global',
    hardFloor: true,
    tags: ['classification', 'confidential', 'romanian'],
  },

  // AG-PROMPT-121: Czech/Slovak confidentiality marker
  // Czech and Slovak share similar vocabulary; combined into one signal.
  {
    id: 'global-confidential-cz',
    name: 'Confidentiality Marker (Czech/Slovak)',
    pattern: /(?<!\p{L})(d[uů]věrn[eé]|tajn[eé]|p[rř][ií]sně\s+d[uů]věrn[eé]|interní\s+dokument|nerozšiřovat|dôvern[eé]|prísne\s+dôvern[eé]|nešíri[tť])(?!\p{L})/iu,
    type: 'confidential',
    defaultSeverity: 'high',
    description: 'Confidentiality marker in text',
    detail: 'Document text contains Czech or Slovak confidentiality markers.',
    rationale: 'Czech/Slovak confidentiality classification under GDPR. Distinct Slavic vocabulary with diacritics minimises overlap with other languages.',
    pack: 'global',
    hardFloor: true,
    tags: ['classification', 'confidential', 'czech', 'slovak'],
  },

  // AG-PROMPT-121: Hungarian confidentiality marker
  {
    id: 'global-confidential-hu',
    name: 'Confidentiality Marker (Hungarian)',
    pattern: /(?<!\p{L})(bizalmas|titkos|szigor[uú]an\s+bizalmas|bels[oő]\s+haszn[aá]latra|nem\s+terjesztend[oő]|nem\s+sokszoros[ií]that[oó])(?!\p{L})/iu,
    type: 'confidential',
    defaultSeverity: 'high',
    description: 'Confidentiality marker in text',
    detail: 'Document text contains Hungarian confidentiality markers.',
    rationale: 'Hungarian confidentiality classification under GDPR. Hungarian vocabulary is linguistically isolated (Finno-Ugric) — zero overlap with Indo-European language patterns.',
    pack: 'global',
    hardFloor: true,
    tags: ['classification', 'confidential', 'hungarian'],
  },

  // AG-PROMPT-121: US privacy law and regulated data category keywords
  // References to HIPAA, CCPA, FERPA, COPPA, GLBA, and regulated data categories
  // indicate documents subject to US privacy law obligations.
  {
    id: 'global-us-privacy-law',
    name: 'US Privacy Law Reference',
    pattern: /\b(HIPAA|CCPA|FERPA|COPPA|GLBA|protected\s+health\s+information|personally\s+identifiable\s+information)\b/i,
    type: 'confidential',
    defaultSeverity: 'high',
    description: 'US privacy law or regulated data category reference',
    detail: 'Document references US privacy regulations or regulated data categories.',
    rationale: 'References to HIPAA, CCPA, FERPA, COPPA, or GLBA indicate documents subject to US data privacy law. "Protected health information" and "personally identifiable information" indicate regulated data categories.',
    pack: 'global',
    hardFloor: true,
    tags: ['classification', 'privacy', 'us', 'hipaa', 'ccpa', 'ferpa', 'coppa', 'glba'],
  },

  // === M&A / SENSITIVE BUSINESS (CRITICAL - HARD FLOOR) ===
  // AG-PROMPT-6 B2: Removed "valuation" from hardFloor pattern - standalone "valuation"
  // can appear in benign contexts (property valuation, self-valuation, etc.)
  {
    id: 'global-ma-terms',
    name: 'M&A Terminology',
    // AG-PROMPT-350: precision fix. The ambiguous single words "acquisition",
    // "merger", and "due diligence" appear constantly in resumes/CVs and general
    // business text (customer/talent acquisition, KYC/vendor due diligence, "led
    // post-merger integration"), so they previously produced a critical
    // "M&A content detected" FALSE POSITIVE on a lone occurrence. They now escalate
    // only WITH corroborating M&A context (deal/transaction/target company/buyer/
    // seller/shareholders/term sheet/LOI/purchase agreement/share purchase/equity
    // stake/divestiture) within a bounded window — mirroring global-ma-valuation-context.
    // Strongly-specific M&A phrases (term sheet / target company / letter of intent)
    // still fire standalone.
    pattern: /\b(?:term\s+sheet|target\s+company|letter\s+of\s+intent|(?:acquisition|merger|due\s+diligence)\s+(?:\w+\s+){0,8}?(?:deal|transaction|buyer|seller|shareholders?|purchase\s+agreement|share\s+purchase|equity\s+stake|divestiture|target\s+company|term\s+sheet|letter\s+of\s+intent)|(?:deal|transaction|buyer|seller|shareholders?|purchase\s+agreement|share\s+purchase|equity\s+stake|divestiture|target\s+company|term\s+sheet|letter\s+of\s+intent)\s+(?:\w+\s+){0,8}?(?:acquisition|merger|due\s+diligence))\b/i,
    type: 'confidential',
    defaultSeverity: 'critical',
    description: 'M&A content detected',
    detail: 'File contains merger/acquisition-related content.',
    rationale: 'M&A content is highly confidential. Premature disclosure can be illegal.',
    pack: 'global',
    hardFloor: true,
    tags: ['business', 'ma', 'confidential', 'material'],
  },
  // AG-PROMPT-6 B2: Context-gated "valuation" - only escalates when near M&A terms
  // Standalone "valuation" (property, self-valuation, etc.) does NOT force critical
  {
    id: 'global-ma-valuation-context',
    name: 'M&A Valuation (Context-Gated)',
    // Match "valuation" only when preceded/followed by M&A context within bounded window
    // Uses lookbehind/lookahead to check for M&A terms within ~50 chars
    pattern: /\b(?:(?:acquisition|merger|deal|transaction|target|company)\s+(?:\w+\s+){0,5}valuation|valuation\s+(?:\w+\s+){0,5}(?:of\s+)?(?:acquisition|merger|deal|transaction|target|company))\b/gi,
    type: 'confidential',
    defaultSeverity: 'high',
    description: 'M&A valuation context detected',
    detail: 'File contains valuation in M&A context.',
    rationale: 'Valuation in M&A context is confidential. Standalone valuation is lower risk.',
    pack: 'global',
    maxSeverity: 'critical',
    tags: ['business', 'ma', 'confidential', 'valuation'],
  },
  
  // === US SOCIAL SECURITY NUMBER (migrated from registry — AG-PHASE-2-046) ===
  {
    id: 'registry-ssn-us',
    name: 'US Social Security Number',
    pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
    type: 'pii',
    defaultSeverity: 'critical',
    description: 'SSN pattern detected',
    detail: 'File contains text matching Social Security Number format (XXX-XX-XXXX).',
    rationale: 'US SSN is a critical national identifier. Format is globally distinctive.',
    pack: 'global',
    hardFloor: true,
    countMatches: true,
    minCount: 1,
    tags: ['pii', 'ssn', 'us', 'national-id'],
  },

  // === CREDIT CARD SPACED FORMAT (migrated from registry — AG-PHASE-2-046) ===
  // Complements global-credit-card (continuous issuer-prefix format) by catching
  // spaced/dashed 4×4 format. Uses PAYMENT_CARD_PATTERN_IDS gate in packRegistry.
  {
    id: 'registry-credit-card-spaced',
    name: 'Payment Card (Spaced Format)',
    pattern: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
    type: 'financial',
    defaultSeverity: 'critical',
    description: 'Payment card pattern',
    detail: 'File contains text matching credit/debit card number format.',
    rationale: 'Spaced card format (XXXX XXXX XXXX XXXX). Validated via Luhn + issuer prefix gate.',
    pack: 'global',
    hardFloor: true,
    tags: ['pii', 'financial', 'pci', 'card'],
  },

  // === BANKING KEYWORDS (migrated from registry — AG-PHASE-2-046) ===
  // AG-PROMPT-104: Added DE/FR/IT/NL/ES financial keywords for EU SME parity
  {
    id: 'registry-banking-terms',
    name: 'Banking Terminology',
    // EN: bank account, routing number, swift code/bic, iban, wire transfer, account number
    // DE: Kontonummer, Bankverbindung, Überweisung, Kontoauszug, Bankleitzahl
    // FR: compte bancaire, virement, relevé de compte, numéro de compte, titulaire du compte, solde bancaire, prélèvement automatique, domiciliation bancaire, encaissement, facturation
    // IT: conto corrente, bonifico, estratto conto, numero di conto, fatturazione, partita IVA, ricevuta bancaria, addebito diretto, titolare del conto, saldo contabile
    // NL: bankrekening, rekeningnummer, overschrijving, rekeningoverzicht
    // ES: cuenta bancaria, transferencia bancaria, número de cuenta, extracto bancario, domiciliación bancaria, titular de cuenta, saldo bancario/disponible/pendiente, facturación, recibo bancario
    // PT: conta bancária, transferência bancária, número de conta, extracto bancário, titular da conta, saldo bancário
    // PL: konto bankowe, przelew bankowy, numer konta, wyciąg bankowy, posiadacz konta, saldo konta
    // BR: boleto bancário, boleto (payment slip), comprovante de pagamento | MX: CFDI, comprobante fiscal
    // RO: cont bancar, transfer bancar, extras de cont, număr de cont, titular de cont, sold bancar
    // CZ: bankovní účet, bankovní převod, výpis z účtu, číslo účtu, zůstatek | SK: bankový účet, bankový prevod, zostatok
    // HU: bankszámla, átutalás, számlakivonat, számlaszám, egyenleg
    pattern: /(?<!\p{L})(routing\s+number|swift\s*(?:code|bic)|iban|wire\s+transfer|account\s+number|kontonummer|bankverbindung|[uü]berweisung|kontoauszug|bankleitzahl|compte\s+bancaire|virement|relev[eé]\s+de\s+compte|num[eé]ro\s+de\s+compte|titulaire\s+du\s+compte|solde\s+bancaire|pr[eé]l[eè]vement\s+automatique|domiciliation\s+bancaire|encaissement|facturation|conto\s+corrente|bonifico|estratto\s+conto|numero\s+di\s+conto|fatturazione|partita\s+iva|ricevuta\s+bancaria|addebito\s+diretto|titolare\s+del\s+conto|saldo\s+contabile|bankrekening|rekeningnummer|overschrijving|rekeningoverzicht|cuenta\s+bancaria|transferencia\s+bancaria|n[uú]mero\s+de\s+cuenta|extracto\s+bancario|domiciliaci[oó]n\s+bancaria|titular\s+de\s+cuenta|saldo\s+(?:bancario|disponible|pendiente)|facturaci[oó]n|recibo\s+bancario|conta\s+banc[aá]ria|transfer[eê]ncia\s+banc[aá]ria|n[uú]mero\s+de\s+conta|extracto\s+banc[aá]rio|titular\s+da\s+conta|saldo\s+banc[aá]rio|konto\s+bankowe|przelew\s+bankowy|numer\s+konta|wyci[aą]g\s+bankowy|posiadacz\s+konta|saldo\s+konta|boleto\s+banc[aá]rio|boleto|comprovante\s+de\s+pagamento|CFDI|comprobante\s+fiscal|cont\s+bancar|transfer\s+bancar|extras\s+de\s+cont|num[aă]r\s+de\s+cont|titular\s+de\s+cont|sold\s+bancar|bankovn[ií]\s+[uú][cč]et|bankovn[ií]\s+p[rř]evod|v[yý]pis\s+z\s+[uú][cč]tu|[cč][ií]slo\s+[uú][cč]tu|z[uů]statek|bankov[yý]\s+[uú][cč]et|bankov[yý]\s+prevod|zostatok|banksz[aá]mla|[aá]tutal[aá]s|sz[aá]mlakivonat|sz[aá]mlasz[aá]m|egyenleg)(?!\p{L})/giu,
    type: 'financial',
    defaultSeverity: 'high',
    description: 'Banking information',
    detail: 'File contains banking or wire transfer details.',
    rationale: 'Banking keywords (EN/DE/FR/IT/NL/ES/PT/PL/BR/MX/RO/CZ/SK/HU) indicate financial document context.',
    pack: 'global',
    countMatches: true,
    // AG-PROMPT-350: the generic English phrase "bank account" was REMOVED from
    // the alternation above — on its own it is ambiguous and previously produced a
    // High-Risk warning by itself. Strong account identifiers (IBAN, SWIFT/BIC,
    // routing number, account number, …) and real IBAN VALUES (global-iban) still
    // warn on a single match. A doc that names an actual account/identifier or
    // multiple banking terms is unaffected.
    minCount: 1,
    tags: ['financial', 'banking', 'keywords'],
  },

  // === LEGAL KEYWORDS (migrated from registry — AG-PHASE-2-046) ===
  // AG-PROMPT-104: Added DE/FR/IT/NL/ES legal keywords for EU SME parity
  {
    id: 'registry-legal-language',
    name: 'Legal Contract Language',
    // EN: whereas, hereby, indemnify, liability, jurisdiction, arbitration, governing law, force majeure
    // DE: Haftung, Gerichtsstand, Schiedsverfahren, Schadensersatz, höhere Gewalt
    // FR: juridiction, arbitrage, mise en demeure, dommages et intérêts, clause, responsabilité civile, accord de confidentialité, contrat commercial, pénalité contractuelle, résiliation de contrat
    // IT: giurisdizione, arbitrato, risarcimento, forza maggiore, clausola, responsabilità civile, accordo di riservatezza, contratto commerciale, penale contrattuale, risoluzione del contratto
    // NL: aansprakelijkheid, geschillenbeslechting, schadevergoeding, jurisdictie, arbitrage, overmacht, vertrouwelijkheidsovereenkomst, handelsovereenkomst
    // ES: jurisdicción, arbitraje, indemnización, fuerza mayor, cláusula, responsabilidad civil, acuerdo de confidencialidad, contrato mercantil, penalización, resolución de contrato
    // PT: jurisdição, arbitragem, indemnização, força maior, responsabilidade civil, contrato comercial, penalização, rescisão de contrato
    // PL: jurysdykcja, arbitraż, odszkodowanie, siła wyższa, odpowiedzialność cywilna, umowa handlowa, klauzula, rozwiązanie umowy
    // MX: Ley Federal del Trabajo, contrato colectivo de trabajo
    // RO: jurisdicție, arbitraj, despăgubire, forță majoră, responsabilitate civilă, contract comercial, reziliere
    // CZ: jurisdikce, arbitráž, odškodnění, vyšší moc, odpovědnost | SK: jurisdikcia, odškodnenie, vyššia moc
    // HU: joghatóság, választottbíróság, kártérítés, vis major, felelősség
    pattern: /(?<!\p{L})(whereas|hereby|indemnify|liability|jurisdiction|arbitration|governing\s+law|force\s+majeure|haftung|gerichtsstand|schiedsverfahren|schadensersatz|h[oö]here\s+gewalt|juridiction|arbitrage|mise\s+en\s+demeure|dommages\s+et\s+int[eé]r[eê]ts|clause|responsabilit[eé]\s+civile|accord\s+de\s+confidentialit[eé]|contrat\s+commercial|p[eé]nalit[eé]\s+contractuelle|r[eé]siliation\s+de\s+contrat|giurisdizione|arbitrato|risarcimento|forza\s+maggiore|clausola|responsabilit[aà]\s+civile|accordo\s+di\s+riservatezza|contratto\s+commerciale|penale\s+contrattuale|risoluzione\s+del\s+contratto|aansprakelijkheid|geschillenbeslechting|schadevergoeding|jurisdictie|overmacht|vertrouwelijkheidsovereenkomst|handelsovereenkomst|jurisdicci[oó]n|arbitraje|indemnizaci[oó]n|fuerza\s+mayor|cl[aá]usula|responsabilidad\s+civil|acuerdo\s+de\s+confidencialidad|contrato\s+mercantil|penalizaci[oó]n|resoluci[oó]n\s+de\s+contrato|jurisdi[cç][aã]o|arbitragem|indemniza[cç][aã]o|for[cç]a\s+maior|responsabilidade\s+civil|contrato\s+comercial|penaliza[cç][aã]o|rescis[aã]o\s+de\s+contrato|jurysdykcja|arbitra[zż]|odszkodowanie|si[lł]a\s+wy[zż]sza|odpowiedzialno[sś][cć]\s+cywilna|umowa\s+handlowa|klauzula|rozwi[aą]zanie\s+umowy|Ley\s+Federal\s+del\s+Trabajo|contrato\s+colectivo\s+de\s+trabajo|jurisdic[tț]ie|arbitraj|desp[aă]gubire|for[tț][aă]\s+major[aă]|responsabilitate\s+civil[aă]|contract\s+comercial|reziliere|jurisdikce|arbitr[aá][zž]|od[sš]kodn[eě]n[ií]|vy[sš][sš][ií]\s+moc|odpov[eě]dnost|jurisdikcia|od[sš]kodnenie|vy[sš][sš]ia\s+moc|joghat[oó]s[aá]g|v[aá]lasztottb[ií]r[oó]s[aá]g|k[aá]rt[eé]r[ií]t[eé]s|felel[oő]ss[eé]g)(?!\p{L})/giu,
    type: 'legal',
    defaultSeverity: 'medium',
    description: 'Legal language detected',
    detail: 'File contains legal contract language.',
    rationale: 'Legal boilerplate (EN/DE/FR/IT/NL/ES/PT/PL/MX/RO/CZ/SK/HU) indicates formal contract document.',
    pack: 'global',
    maxSeverity: 'high',
    countMatches: true,
    minCount: 2,
    tags: ['legal', 'contract', 'keywords'],
  },

  // === HR / EMPLOYEE DATA KEYWORDS (migrated from registry — AG-PHASE-2-046) ===
  // AG-PHASE-5E-061: Added Spanish/LatAm HR keywords for non-RomancePack coverage
  // AG-PROMPT-102: Added DE/FR/IT/NL HR keywords for EU SME parity
  {
    id: 'registry-hr-employee',
    name: 'HR/Employee Data',
    // EN: salary, compensation, performance review, termination, disciplinary, employee id
    // ES: contrato de trabajo, empleador, empleado, trabajador, relación laboral, despido, renuncia, nómina, sueldo, salario, remuneración, liquidación
    // DE: Gehalt, Arbeitsvertrag, Arbeitgeber, Arbeitnehmer, Kündigung, Abfindung, Lohnabrechnung, Personalakte, Bruttolohn, Nettolohn, Gehaltsabrechnung, Steuerklasse, Sozialversicherungsnummer, Lohnzettel
    // FR: contrat de travail, employeur, employé, salarié, licenciement, indemnité, rémunération, fiche de paie
    // IT: contratto di lavoro, datore di lavoro, dipendente, stipendio, retribuzione, licenziamento, busta paga
    // NL: arbeidsovereenkomst, werkgever, werknemer, salaris, ontslagvergoeding, loonstrook
    // PT: contrato de trabalho, empregador, empregado, trabalhador, despedimento, salário, remuneração, recibo de vencimento, vencimento
    // PL: umowa o pracę, pracodawca, pracownik, wynagrodzenie, zwolnienie, wypowiedzenie, lista płac, odprawa
    // BR: FGTS, INSS, holerite, CLT, décimo terceiro | MX: IMSS, INFONAVIT, finiquito
    // RO: contract de muncă, angajator, angajat, salariu, concediere, demisie, stat de plată
    // CZ: pracovní smlouva, zaměstnavatel, zaměstnanec, mzda, výpověď | SK: pracovná zmluva, zamestnávateľ
    // HU: munkaszerződés, munkáltató, munkavállaló, fizetés, felmondás
    pattern: /(?<!\p{L})(salary|compensation|performance\s+review|termination|disciplinary|employee\s+id|contrato\s+de\s+trabajo|empleador|empleado|trabajador|relaci[oó]n\s+laboral|despido|renuncia|n[oó]mina|sueldo|salario|remuneraci[oó]n|liquidaci[oó]n|gehalt|arbeitsvertrag|arbeitgeber|arbeitnehmer|k[uü]ndigung|abfindung|lohnabrechnung|personalakte|bruttolohn|nettolohn|gehaltsabrechnung|steuerklasse|sozialversicherungsnummer|lohnzettel|contrat\s+de\s+travail|employeur|employ[eé]|salari[eé]|licenciement|indemnit[eé]|r[eé]mun[eé]ration|fiche\s+de\s+paie|contratto\s+di\s+lavoro|datore\s+di\s+lavoro|dipendente|stipendio|retribuzione|licenziamento|busta\s+paga|arbeidsovereenkomst|werkgever|werknemer|salaris|ontslagvergoeding|loonstrook|contrato\s+de\s+trabalho|empregador|empregado|trabalhador|despedimento|sal[aá]rio|remunera[cç][aã]o|recibo\s+de\s+vencimento|vencimento|umowa\s+o\s+prac[eę]|pracodawca|pracownik|wynagrodzenie|zwolnienie|wypowiedzenie|lista\s+p[lł]ac|odprawa|FGTS|INSS|holerite|CLT|d[eé]cimo\s+terceiro|IMSS|INFONAVIT|finiquito|contract\s+de\s+munc[aă]|angajator|angajat|salariu|concediere|demisie|stat\s+de\s+plat[aă]|pracovn[ií]\s+smlouva|zam[eě]stnavatel|zam[eě]stnanec|mzda|v[yý]pov[eě][dď]|odstupn[eé]|pracovn[aá]\s+zmluva|zamestn[aá]vate[lľ]|munkaszerződ[eé]s|munk[aá]ltat[oó]|munkav[aá]llal[oó]|fizet[eé]s|felmond[aá]s)(?!\p{L})/giu,
    type: 'pii',
    defaultSeverity: 'high',
    description: 'HR/Employee data',
    detail: 'File contains HR or employee-related information.',
    rationale: 'HR keywords (EN/ES/DE/FR/IT/NL/PT/PL/BR/MX/RO/CZ/SK/HU) indicate employee personal data.',
    pack: 'global',
    countMatches: true,
    // AG-PROMPT-350: require 2+ corroborating HR keywords so a lone generic term
    // (e.g. "salary") no longer produces a High-Risk warning by itself. Payroll/HR
    // documents contain multiple such terms; standalone mentions do not escalate.
    minCount: 2,
    tags: ['hr', 'pii', 'keywords'],
  },

  // === ICD-10 MEDICAL CODES (migrated from registry — AG-PHASE-2-046) ===
  {
    id: 'registry-icd10-code',
    name: 'ICD-10 Diagnosis Code',
    pattern: /\b[A-Z]\d{2}\.\d{1,2}\b/g,
    type: 'pii',
    defaultSeverity: 'high',
    description: 'ICD-10 diagnosis code',
    detail: 'File contains medical diagnosis codes (ICD-10).',
    rationale: 'ICD-10 codes are universal medical classification. High confidence clinical signal.',
    pack: 'global',
    countMatches: true,
    minCount: 1,
    countDescription: '{count} ICD-10 codes',
    tags: ['pii', 'medical', 'icd10'],
  },

  // === ORGANIZATIONAL ROSTER / PEOPLE LIST (AG-PROMPT-185/WS-04) ===
  // Detects people-list / org-roster documents: spreadsheets and flat lists
  // containing organizational keywords that co-occur with person names.
  // Uses compound terms to avoid single-word FP.
  {
    id: 'global-org-roster',
    name: 'Organizational Roster',
    pattern: /\b((?:job|future)\s+title|department|team\s+(?:lead|member|name)|(?:site|location)\s+name|line\s+manager|reporting\s+to|headcount|\bfte\b|employee\s+(?:list|roster|directory)|staff\s+list|org(?:anization(?:al)?|anisation)?\s+(?:chart|structure|unit)|befattning|avdelning|arbetsplats|afdeling|medarbejder(?:liste|oversigt)|personaleoversigt)\b/gi,
    type: 'pii',
    defaultSeverity: 'medium',
    description: 'Organizational roster or people list detected',
    detail: 'File contains organizational people data such as employee names, titles, or team assignments.',
    rationale: 'People rosters contain identifiable individual data in organizational context.',
    pack: 'global',
    countMatches: true,
    minCount: 2,
    countDescription: '{count} organizational roster indicators',
    tags: ['pii', 'hr', 'roster', 'people-list'],
  },

  // === MEDICAL CONTENT KEYWORDS (migrated from registry — AG-PHASE-2-046) ===
  // AG-PROMPT-102: Added DE/FR/IT/NL medical keywords for EU SME parity
  {
    id: 'registry-medical-content',
    name: 'Medical Content',
    // EN: diagnosis, patient journal, medical record, health record, clinical note, lab result, blood test, prescription, medication, prognosis
    // Nordic: anamnese, epikrise, journalnummer, labsvar, blodprøve, sundhedsdata, patientdata, undersøgelse, behandling
    // DE: Patientenakte, Krankenakte, Befund, Arztbrief, Laborergebnis, Blutbild, Rezept, Medikament
    // FR: dossier médical, ordonnance, résultat de laboratoire, antécédents médicaux
    // IT: cartella clinica, referto, ricetta medica, risultato di laboratorio
    // NL: patiëntendossier, medisch dossier, laboratoriumresultaat, recept, bloedonderzoek
    pattern: /(?<!\p{L})(diagnosis|diagnose|patient\s*journal|patientjournal|medical\s*record|health\s*record|clinical\s*note|lab\s*result|blood\s*test|prescription|medication|prognosis|anamnese|epikrise|journal\s*nr|journalnummer|labsvar|laboratoriesvar|laboratorieresultat|blodprøve|laboratorium|sundhedsdata|helbredsoplysninger|patientdata|undersøgelse|prøvesvar|behandling|patientenakte|krankenakte|befund|arztbrief|laborergebnis|blutbild|rezept|medikament|dossier\s+m[eé]dical|ordonnance|r[eé]sultat\s+de\s+laboratoire|ant[eé]c[eé]dents\s+m[eé]dicaux|cartella\s+clinica|referto|ricetta\s+medica|risultato\s+di\s+laboratorio|pati[eë]ntendossier|medisch\s+dossier|laboratoriumresultaat|bloedonderzoek)(?!\p{L})/giu,
    type: 'pii',
    defaultSeverity: 'high',
    description: 'Medical content detected',
    detail: 'File contains medical or health-related information.',
    rationale: 'Medical keywords (EN/Nordic/DE/FR/IT/NL) indicate clinical document.',
    pack: 'global',
    countMatches: true,
    minCount: 2,
    tags: ['pii', 'medical', 'keywords'],
  },

  // === INSURANCE DOMAIN (AG-PHASE-5-053A) ===
  // AG-PHASE-5E-061: Added Spanish/LatAm insurance keywords for non-RomancePack coverage
  {
    id: 'global-insurance-terms',
    name: 'Insurance Document',
    // English + Nordic + Spanish insurance keywords. Compound terms to avoid single-word FP.
    pattern: /\b(insurance\s+(?:certificate|policy|company|coverage|claim|premium)|(?:travel|health|life|car|home|motor)\s+insurance|policyholder|insured\s+(?:person|party)|underwriter|forsikring(?:spolice|stager|sselskab)?|bilforsikring|rejseforsikring|livsforsikring|indboforsikring|ulykkesforsikring|ansvarsforsikring|selvrisiko|dæknings?oversigt|forsikringsdækning|policenummer|p[oó]liza(?:\s+de\s+seguro)?|asegurado|aseguradora|cobertura|prima\s+de\s+seguro|siniestro|condiciones\s+generales|seguro\s+(?:de\s+)?(?:vida|auto|hogar|salud|viaje))\b/gi,
    type: 'financial',
    defaultSeverity: 'medium',
    description: 'Insurance document detected',
    detail: 'File contains insurance-related terminology.',
    rationale: 'Insurance keywords (English + Nordic + Spanish) indicate insurance document with policy details.',
    pack: 'global',
    countMatches: true,
    minCount: 2,
    countDescription: '{count} insurance terms',
    tags: ['financial', 'insurance', 'keywords'],
  },

  // === DATE OF BIRTH (AG-PHASE-5-053A) ===
  {
    id: 'global-dob',
    name: 'Date of Birth',
    // Context-gated: only matches date formats preceded by DOB keywords.
    // Handles: DD-MM-YYYY, DD/MM/YYYY, DD.MM.YYYY, YYYY-MM-DD, and spaced variants like "01 - 12 - 2007"
    // AG-PROMPT-4: Unicode-safe boundary for Nordic DOB labels (ø in fødselsdato, ö in födelsedatum)
    pattern: /(?<!\p{L})(?:date\s+of\s+birth|dob|birth\s*date|fødselsdato|födelsedatum|geboortedatum|geburtsdatum)\s*[:\-]?\s*\d{1,2}\s*[\-\/\.,]\s*\d{1,2}\s*[\-\/\.,]\s*\d{2,4}(?!\p{N})/giu,
    type: 'pii',
    defaultSeverity: 'high',
    description: 'Date of birth',
    detail: 'File contains a labeled date of birth.',
    rationale: 'DOB is PII. Context keyword ensures only labeled dates are flagged, not arbitrary dates.',
    pack: 'global',
    tags: ['pii', 'dob', 'personal'],
  },

  // === INSURANCE POLICY NUMBER (AG-PHASE-5-053A) ===
  {
    id: 'global-insurance-policy-number',
    name: 'Insurance Policy Number',
    // Context-gated: only matches number sequences labeled as policy numbers.
    pattern: /\b(?:policy\s*(?:number|no\.?|nr\.?)|policenr\.?|policenummer|police\s*nr\.?)\s*[:\s]\s*\d{5,12}\b/gi,
    type: 'financial',
    defaultSeverity: 'medium',
    description: 'Insurance policy number',
    detail: 'File contains a labeled insurance policy number.',
    rationale: 'Policy numbers are semi-PII identifiers, not direct personal data. Medium aligns with insurance archetype baseline (car/property insurance = medium). Escalation to high occurs via archetype anchors when identity_strong signals are present.',
    pack: 'global',
    tags: ['financial', 'insurance', 'policy-number'],
  },

  // === BANKING (UNIVERSAL FORMATS) ===
  {
    id: 'global-iban',
    name: 'IBAN',
    pattern: /\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b/,
    type: 'financial',
    defaultSeverity: 'high',
    description: 'Banking information',
    detail: 'File contains IBAN (International Bank Account Number).',
    rationale: 'IBAN enables international transfers. High risk if paired with account holder.',
    pack: 'global',
    tags: ['financial', 'banking', 'iban'],
  },
  {
    id: 'global-swift',
    name: 'SWIFT/BIC Code',
    pattern: /\b[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\b/,
    type: 'financial',
    defaultSeverity: 'medium',
    description: 'SWIFT/BIC code',
    detail: 'File contains a SWIFT/BIC bank identifier code.',
    rationale: 'SWIFT codes identify banks. Lower risk without account numbers.',
    pack: 'global',
    tags: ['financial', 'banking', 'swift'],
  },
];

// ============================================================================
// GLOBAL PACK EXPORT
// ============================================================================

export const GlobalPack: DetectionPack = {
  metadata: {
    id: 'global',
    name: 'Global Pack',
    layer: 'global',
    version: '1.1.0',
    description: 'Universal detection patterns that work across all locales. Always enabled.',
    enabledByDefault: true,
    minLocaleConfidence: 'low', // Always runs
  },
  patterns: globalPatterns,
};

export default GlobalPack;