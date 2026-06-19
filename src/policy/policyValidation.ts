/**
 * AgentGuard Policy Validation (AG-PROMPT-034)
 *
 * Provides strict, local-only validation for policy JSON to prevent
 * silent failures from IT misconfigurations via MDM/GPO.
 *
 * Features:
 * - Shape validation (required keys, types)
 * - Taxonomy guardrails (validates against canonical signal types, explanation IDs)
 * - Safe fallbacks (use bundled defaults on failure)
 * - Admin diagnostics (console logging, no UI changes)
 *
 * Privacy: No network calls, no telemetry. Local-only validation.
 *
 * @see ADR-018: Policy Validation
 */

import { getMappedSignalTypes } from './policyMapper';
import { getAvailableCopyIds } from './explainabilityCopy';
import type { PolicySchema, SignalConfig, LocaleOverride, DepartmentOverride, CooccurrenceRule } from './schema';
import { DEFAULT_POLICY_SCHEMA } from './schema';

// ============================================================================
// CONFIGURATION
// ============================================================================

/** Log prefix for admin diagnostics */
const LOG_PREFIX = '[AgentGuard][PolicyValidation]';

/** Enable debug logging (counts only, no content) */
const DEBUG_VALIDATION = false;

// ============================================================================
// TYPES
// ============================================================================

/**
 * Validation result returned by validatePolicyConfig
 */
export interface PolicyValidationResult {
  /** Whether validation passed (no errors) */
  ok: boolean;

  /** Critical errors that require fallback to defaults */
  errors: string[];

  /** Non-critical warnings (logged but policy still usable) */
  warnings: string[];

  /** Validated policy (original if ok, defaults if errors in strict mode) */
  policy: PolicySchema;

  /** Summary stats for admin diagnostics */
  stats: {
    signalCount: number;
    localeOverrideCount: number;
    departmentOverrideCount: number;
    cooccurrenceRuleCount: number;
  };
}

/**
 * Validation options
 */
export interface PolicyValidationOptions {
  /**
   * Strict mode (default: true)
   * - true: unknown keys/references are errors, fallback to defaults
   * - false: unknown keys/references are warnings, keep policy
   */
  strictMode?: boolean;

  /**
   * Log results to console (default: true)
   */
  logResults?: boolean;
}

// ============================================================================
// CANONICAL SOURCES (cached for performance)
// ============================================================================

/** Cached canonical signal types from policy-mapper */
let _canonicalSignalTypes: Set<string> | null = null;

/** Cached canonical explanation IDs from copy-library */
let _canonicalExplanationIds: Set<string> | null = null;

/**
 * Get canonical signal types from policy-mapper-v1.1.json
 */
function getCanonicalSignalTypes(): Set<string> {
  if (!_canonicalSignalTypes) {
    _canonicalSignalTypes = new Set(getMappedSignalTypes());
  }
  return _canonicalSignalTypes;
}

/**
 * Get canonical explanation IDs from copy-library-v0.json
 */
function getCanonicalExplanationIds(): Set<string> {
  if (!_canonicalExplanationIds) {
    _canonicalExplanationIds = new Set(getAvailableCopyIds());
  }
  return _canonicalExplanationIds;
}

// ============================================================================
// KNOWN VALUES (hardcoded for validation)
// ============================================================================

/** Known severity values */
const VALID_SEVERITIES = new Set(['low', 'medium', 'high', 'critical']);

/** Known locale keys (from locale.ts) */
const VALID_LOCALES = new Set([
  'US', 'UK', 'EU-NORDICS', 'EU-DACH', 'EU-SOUTHERN', 'EU-WESTERN', 'EU-EASTERN',
  'EN-COMMONWEALTH', 'LATAM', 'unknown'
]);

/** Known department IDs (from policy.ts) */
const VALID_DEPARTMENTS = new Set([
  'engineering', 'legal', 'finance', 'hr', 'marketing', 'sales', 'operations',
  'executive', 'security', 'compliance', 'default'
]);

/** Known UI escalation values */
const VALID_UI_ESCALATIONS = new Set(['none', 'inline', 'modal']);

// ============================================================================
// TYPE GUARDS
// ============================================================================

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isString(value: unknown): value is string {
  return typeof value === 'string';
}

function isBoolean(value: unknown): value is boolean {
  return typeof value === 'boolean';
}

function isNumber(value: unknown): value is number {
  return typeof value === 'number' && !isNaN(value);
}

function isArray(value: unknown): value is unknown[] {
  return Array.isArray(value);
}

// ============================================================================
// SHAPE VALIDATORS
// ============================================================================

/**
 * Validate SignalConfig shape
 */
function validateSignalConfig(
  config: unknown,
  signalId: string,
  errors: string[],
  warnings: string[],
  strictMode: boolean
): void {
  if (!isObject(config)) {
    errors.push(`Signal '${signalId}': expected object, got ${typeof config}`);
    return;
  }

  // Required: enabled (boolean)
  if (!isBoolean(config.enabled)) {
    errors.push(`Signal '${signalId}': 'enabled' must be boolean`);
  }

  // Required: baseSeverity (string from set)
  if (!isString(config.baseSeverity)) {
    errors.push(`Signal '${signalId}': 'baseSeverity' must be string`);
  } else if (!VALID_SEVERITIES.has(config.baseSeverity)) {
    errors.push(`Signal '${signalId}': invalid baseSeverity '${config.baseSeverity}'`);
  }

  // Optional: maxSeverity
  if (config.maxSeverity !== undefined) {
    if (!isString(config.maxSeverity) || !VALID_SEVERITIES.has(config.maxSeverity)) {
      (strictMode ? errors : warnings).push(`Signal '${signalId}': invalid maxSeverity '${config.maxSeverity}'`);
    }
  }

  // Optional: escalatedSeverity
  if (config.escalatedSeverity !== undefined) {
    if (!isString(config.escalatedSeverity) || !VALID_SEVERITIES.has(config.escalatedSeverity)) {
      (strictMode ? errors : warnings).push(`Signal '${signalId}': invalid escalatedSeverity '${config.escalatedSeverity}'`);
    }
  }

  // Optional: minCount (number)
  if (config.minCount !== undefined && !isNumber(config.minCount)) {
    (strictMode ? errors : warnings).push(`Signal '${signalId}': 'minCount' must be number`);
  }

  // Optional: escalationThreshold (number)
  if (config.escalationThreshold !== undefined && !isNumber(config.escalationThreshold)) {
    (strictMode ? errors : warnings).push(`Signal '${signalId}': 'escalationThreshold' must be number`);
  }

  // Optional: mandatory (boolean)
  if (config.mandatory !== undefined && !isBoolean(config.mandatory)) {
    (strictMode ? errors : warnings).push(`Signal '${signalId}': 'mandatory' must be boolean`);
  }
}

/**
 * Validate LocaleOverride shape
 */
function validateLocaleOverride(
  override: unknown,
  index: number,
  errors: string[],
  warnings: string[],
  strictMode: boolean
): void {
  if (!isObject(override)) {
    errors.push(`localeOverrides[${index}]: expected object`);
    return;
  }

  // Required: locale
  if (!isString(override.locale)) {
    errors.push(`localeOverrides[${index}]: 'locale' must be string`);
  } else if (!VALID_LOCALES.has(override.locale)) {
    (strictMode ? errors : warnings).push(`localeOverrides[${index}]: unknown locale '${override.locale}'`);
  }

  // Optional: signals (object)
  if (override.signals !== undefined && !isObject(override.signals)) {
    errors.push(`localeOverrides[${index}]: 'signals' must be object`);
  }

  // Optional: phone (object)
  if (override.phone !== undefined && !isObject(override.phone)) {
    (strictMode ? errors : warnings).push(`localeOverrides[${index}]: 'phone' must be object`);
  }

  // Optional: nationalId (object)
  if (override.nationalId !== undefined && !isObject(override.nationalId)) {
    (strictMode ? errors : warnings).push(`localeOverrides[${index}]: 'nationalId' must be object`);
  }
}

/**
 * Validate DepartmentOverride shape
 */
function validateDepartmentOverride(
  override: unknown,
  index: number,
  errors: string[],
  warnings: string[],
  strictMode: boolean
): void {
  if (!isObject(override)) {
    errors.push(`departmentOverrides[${index}]: expected object`);
    return;
  }

  // Required: department
  if (!isString(override.department)) {
    errors.push(`departmentOverrides[${index}]: 'department' must be string`);
  } else if (!VALID_DEPARTMENTS.has(override.department)) {
    (strictMode ? errors : warnings).push(`departmentOverrides[${index}]: unknown department '${override.department}'`);
  }

  // Optional: signals (object)
  if (override.signals !== undefined && !isObject(override.signals)) {
    errors.push(`departmentOverrides[${index}]: 'signals' must be object`);
  }

  // Optional: dictionaries (object)
  if (override.dictionaries !== undefined && !isObject(override.dictionaries)) {
    (strictMode ? errors : warnings).push(`departmentOverrides[${index}]: 'dictionaries' must be object`);
  }
}

/**
 * Validate CooccurrenceRule shape
 */
function validateCooccurrenceRule(
  rule: unknown,
  index: number,
  errors: string[],
  warnings: string[],
  strictMode: boolean
): void {
  if (!isObject(rule)) {
    errors.push(`cooccurrenceRules[${index}]: expected object`);
    return;
  }

  // Required: id (string)
  if (!isString(rule.id)) {
    errors.push(`cooccurrenceRules[${index}]: 'id' must be string`);
  }

  // Required: description (string)
  if (!isString(rule.description)) {
    errors.push(`cooccurrenceRules[${index}]: 'description' must be string`);
  }

  // Required: requires (array)
  if (!isArray(rule.requires)) {
    errors.push(`cooccurrenceRules[${index}]: 'requires' must be array`);
  } else {
    for (let i = 0; i < rule.requires.length; i++) {
      const req = rule.requires[i];
      if (!isObject(req)) {
        errors.push(`cooccurrenceRules[${index}].requires[${i}]: expected object`);
      } else {
        if (!isString(req.signalId)) {
          errors.push(`cooccurrenceRules[${index}].requires[${i}]: 'signalId' must be string`);
        }
        if (!isNumber(req.minCount)) {
          errors.push(`cooccurrenceRules[${index}].requires[${i}]: 'minCount' must be number`);
        }
      }
    }
  }

  // Required: escalates (array of strings)
  if (!isArray(rule.escalates)) {
    errors.push(`cooccurrenceRules[${index}]: 'escalates' must be array`);
  }

  // Required: severityBump (number)
  if (!isNumber(rule.severityBump)) {
    errors.push(`cooccurrenceRules[${index}]: 'severityBump' must be number`);
  }

  // Required: maxSeverity (string)
  if (!isString(rule.maxSeverity) || !VALID_SEVERITIES.has(rule.maxSeverity as string)) {
    errors.push(`cooccurrenceRules[${index}]: invalid 'maxSeverity'`);
  }

  // Required: enabled (boolean)
  if (!isBoolean(rule.enabled)) {
    errors.push(`cooccurrenceRules[${index}]: 'enabled' must be boolean`);
  }
}

/**
 * Validate PolicyInvariants shape
 */
function validateInvariants(
  invariants: unknown,
  errors: string[],
  warnings: string[],
  strictMode: boolean
): void {
  if (!isObject(invariants)) {
    errors.push("'invariants' must be object");
    return;
  }

  // Required: mandatorySignals (array of strings)
  if (!isArray(invariants.mandatorySignals)) {
    errors.push("'invariants.mandatorySignals' must be array");
  }

  // Required: mandatoryMinSeverity (severity)
  if (!isString(invariants.mandatoryMinSeverity) || !VALID_SEVERITIES.has(invariants.mandatoryMinSeverity as string)) {
    errors.push("'invariants.mandatoryMinSeverity' must be valid severity");
  }

  // Required: alwaysCritical (array of strings)
  if (!isArray(invariants.alwaysCritical)) {
    errors.push("'invariants.alwaysCritical' must be array");
  }
}

// ============================================================================
// MAIN VALIDATOR
// ============================================================================

/**
 * Validate policy configuration
 *
 * @param policy - Policy object to validate (unknown type for safety)
 * @param options - Validation options
 * @returns PolicyValidationResult with ok, errors, warnings, and validated policy
 */
export function validatePolicyConfig(
  policy: unknown,
  options: PolicyValidationOptions = {}
): PolicyValidationResult {
  const { strictMode = true, logResults = true } = options;

  const errors: string[] = [];
  const warnings: string[] = [];
  const stats = {
    signalCount: 0,
    localeOverrideCount: 0,
    departmentOverrideCount: 0,
    cooccurrenceRuleCount: 0,
  };

  // ========== ROOT SHAPE VALIDATION ==========

  if (!isObject(policy)) {
    errors.push('Policy must be an object');
    return createFailureResult(errors, warnings, stats, logResults);
  }

  // Required: version
  if (policy.version !== '1.0') {
    errors.push(`Unsupported policy version: ${policy.version} (expected '1.0')`);
  }

  // Required: name
  if (!isString(policy.name)) {
    errors.push("'name' must be string");
  }

  // Optional: description
  if (policy.description !== undefined && !isString(policy.description)) {
    warnings.push("'description' should be string");
  }

  // ========== SIGNALS VALIDATION ==========

  if (!isObject(policy.signals)) {
    errors.push("'signals' must be object");
  } else {
    const signalIds = Object.keys(policy.signals);
    stats.signalCount = signalIds.length;

    for (const signalId of signalIds) {
      validateSignalConfig(
        (policy.signals as Record<string, unknown>)[signalId],
        signalId,
        errors,
        warnings,
        strictMode
      );
    }
  }

  // ========== LOCALE OVERRIDES VALIDATION ==========

  if (!isArray(policy.localeOverrides)) {
    errors.push("'localeOverrides' must be array");
  } else {
    stats.localeOverrideCount = policy.localeOverrides.length;

    for (let i = 0; i < policy.localeOverrides.length; i++) {
      validateLocaleOverride(policy.localeOverrides[i], i, errors, warnings, strictMode);
    }
  }

  // ========== DEPARTMENT OVERRIDES VALIDATION ==========

  if (!isArray(policy.departmentOverrides)) {
    errors.push("'departmentOverrides' must be array");
  } else {
    stats.departmentOverrideCount = policy.departmentOverrides.length;

    for (let i = 0; i < policy.departmentOverrides.length; i++) {
      validateDepartmentOverride(policy.departmentOverrides[i], i, errors, warnings, strictMode);
    }
  }

  // ========== COOCCURRENCE RULES VALIDATION ==========

  if (!isArray(policy.cooccurrenceRules)) {
    errors.push("'cooccurrenceRules' must be array");
  } else {
    stats.cooccurrenceRuleCount = policy.cooccurrenceRules.length;

    for (let i = 0; i < policy.cooccurrenceRules.length; i++) {
      validateCooccurrenceRule(policy.cooccurrenceRules[i], i, errors, warnings, strictMode);
    }
  }

  // ========== INVARIANTS VALIDATION ==========

  if (!isObject(policy.invariants)) {
    errors.push("'invariants' must be object");
  } else {
    validateInvariants(policy.invariants, errors, warnings, strictMode);
  }

  // ========== RESULT ==========

  const ok = errors.length === 0;

  if (logResults) {
    logValidationResult(ok, errors, warnings, stats, strictMode);
  }

  if (!ok && strictMode) {
    // Strict mode with errors: fallback to defaults
    return {
      ok: false,
      errors,
      warnings,
      policy: DEFAULT_POLICY_SCHEMA,
      stats,
    };
  }

  // Success or non-strict mode: return validated policy
  return {
    ok,
    errors,
    warnings,
    policy: policy as unknown as PolicySchema,
    stats,
  };
}

// ============================================================================
// TAXONOMY VALIDATION (against canonical sources)
// ============================================================================

/**
 * Validate that signal types in policy mappings are known
 *
 * @param signalTypes - Array of signal type strings to validate
 * @param context - Context string for error messages
 * @param errors - Error array to append to
 * @param warnings - Warning array to append to
 * @param strictMode - Whether to treat unknown as error or warning
 */
export function validateSignalTypes(
  signalTypes: string[],
  context: string,
  errors: string[],
  warnings: string[],
  strictMode: boolean
): void {
  const canonical = getCanonicalSignalTypes();

  for (const signalType of signalTypes) {
    if (!canonical.has(signalType)) {
      const msg = `${context}: unknown signalType '${signalType}'`;
      (strictMode ? errors : warnings).push(msg);
    }
  }
}

/**
 * Validate that explanation IDs are known
 *
 * @param explanationIds - Array of explanation ID strings to validate
 * @param context - Context string for error messages
 * @param errors - Error array to append to
 * @param warnings - Warning array to append to
 * @param strictMode - Whether to treat unknown as error or warning
 */
export function validateExplanationIds(
  explanationIds: string[],
  context: string,
  errors: string[],
  warnings: string[],
  strictMode: boolean
): void {
  const canonical = getCanonicalExplanationIds();

  for (const explanationId of explanationIds) {
    if (!canonical.has(explanationId)) {
      const msg = `${context}: unknown explanationId '${explanationId}'`;
      (strictMode ? errors : warnings).push(msg);
    }
  }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Create a failure result with defaults
 */
function createFailureResult(
  errors: string[],
  warnings: string[],
  stats: PolicyValidationResult['stats'],
  logResults: boolean
): PolicyValidationResult {
  if (logResults) {
    logValidationResult(false, errors, warnings, stats, true);
  }

  return {
    ok: false,
    errors,
    warnings,
    policy: DEFAULT_POLICY_SCHEMA,
    stats,
  };
}

/**
 * Log validation result to console (admin diagnostics)
 */
function logValidationResult(
  ok: boolean,
  errors: string[],
  warnings: string[],
  stats: PolicyValidationResult['stats'],
  strictMode: boolean
): void {
  if (ok) {
    console.log(
      `${LOG_PREFIX} Policy validated successfully:`,
      `signals=${stats.signalCount}`,
      `locales=${stats.localeOverrideCount}`,
      `departments=${stats.departmentOverrideCount}`,
      `rules=${stats.cooccurrenceRuleCount}`
    );
  } else {
    console.error(
      `${LOG_PREFIX} Policy validation FAILED (${errors.length} errors, ${warnings.length} warnings)`
    );
    for (const error of errors) {
      console.error(`${LOG_PREFIX} ERROR: ${error}`);
    }
    for (const warning of warnings) {
      console.warn(`${LOG_PREFIX} WARNING: ${warning}`);
    }
    if (strictMode) {
      console.warn(`${LOG_PREFIX} Falling back to default policy`);
    }
  }

  if (DEBUG_VALIDATION && warnings.length > 0) {
    for (const warning of warnings) {
      console.warn(`${LOG_PREFIX} WARNING: ${warning}`);
    }
  }
}

// ============================================================================
// CONVENIENCE EXPORTS
// ============================================================================

/**
 * Get canonical signal types (for external use/testing)
 */
export function getKnownSignalTypes(): string[] {
  return Array.from(getCanonicalSignalTypes());
}

/**
 * Get canonical explanation IDs (for external use/testing)
 */
export function getKnownExplanationIds(): string[] {
  return Array.from(getCanonicalExplanationIds());
}

/**
 * Get known severity values
 */
export function getKnownSeverities(): string[] {
  return Array.from(VALID_SEVERITIES);
}

/**
 * Get known locale values
 */
export function getKnownLocales(): string[] {
  return Array.from(VALID_LOCALES);
}

/**
 * Get known department values
 */
export function getKnownDepartments(): string[] {
  return Array.from(VALID_DEPARTMENTS);
}
