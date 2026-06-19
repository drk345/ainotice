/**
 * AgentGuard Activation Gate (AG-PROMPT-058)
 *
 * ============================================================================
 * PRIVACY CONTRACT - CRITICAL
 * ============================================================================
 *
 * This module determines whether AgentGuard should activate on the current page.
 * It is the FIRST code to run and gates ALL subsequent functionality.
 *
 * ON NON-TARGET PAGES:
 * - ONLY window.location.hostname is accessed (for target matching)
 * - NO DOM access, scraping, or manipulation
 * - NO content extraction or text analysis
 * - NO event listeners (drag/drop, paste, file input)
 * - NO network interception or monitoring
 * - NO storage access beyond managed policy read
 * - Script exits immediately after hostname check
 *
 * ON TARGET PAGES:
 * - Full AgentGuard functionality activates
 * - File upload interception enabled
 * - Risk analysis on user-initiated uploads only
 *
 * This ensures "last-mile only" semantics: AgentGuard only monitors file uploads
 * on explicitly configured AI platforms, never general browsing.
 *
 * @see ADR-026: Policy-Driven Target Selection
 * @see AG-PROMPT-057: Policy-Driven Targets
 * @see AG-PROMPT-058: Activation Gating
 * ============================================================================
 */

import {
  BUILTIN_TARGETS_EXACT,
  BUILTIN_TARGETS_SUFFIX,
  shouldActivate,
  normalizeTargetPolicy,
  loadTargetPolicyFromManagedStorage,
  type NormalizedTargetConfig,
  type ActivationResult,
} from '../policy/targetPolicy';

// ============================================================================
// RULE IDS
// ============================================================================

export const ACTIVATION_GATE_RULE_IDS = {
  BUILTIN_SYNC: 'GATE-001-builtin-sync',
  POLICY_ASYNC: 'GATE-002-policy-async',
  NO_MATCH_SYNC: 'GATE-003-no-match-sync',
  NO_MATCH_ASYNC: 'GATE-004-no-match-async',
} as const;

// ============================================================================
// SYNCHRONOUS BUILT-IN CHECK (Fast Path)
// ============================================================================

/**
 * Check if hostname matches built-in targets (synchronous).
 *
 * This is the fast path for built-in AI platforms.
 * No async, no storage access - pure hostname matching.
 *
 * @param hostname - Current page hostname
 * @returns true if hostname matches a built-in target
 */
export function isBuiltinTarget(hostname: string): boolean {
  if (!hostname) return false;

  const normalizedHost = hostname.toLowerCase().trim();

  // Check exact matches (fast path)
  if (BUILTIN_TARGETS_EXACT.has(normalizedHost)) {
    return true;
  }

  // Check suffix patterns
  for (const suffix of BUILTIN_TARGETS_SUFFIX) {
    if (normalizedHost === suffix || normalizedHost.endsWith('.' + suffix)) {
      return true;
    }
  }

  return false;
}

/**
 * Synchronous activation check for built-in targets only.
 *
 * Returns immediately for built-in targets.
 * Returns null if hostname is not a built-in (requires async policy check).
 *
 * @param hostname - Current page hostname
 * @returns ActivationResult if built-in, null if needs async check
 */
export function checkBuiltinActivation(hostname: string): ActivationResult | null {
  if (!hostname) {
    return {
      activate: false,
      reason: 'Empty hostname',
      ruleId: ACTIVATION_GATE_RULE_IDS.NO_MATCH_SYNC,
    };
  }

  const normalizedHost = hostname.toLowerCase().trim();

  if (isBuiltinTarget(normalizedHost)) {
    return {
      activate: true,
      reason: 'Built-in target (sync)',
      ruleId: ACTIVATION_GATE_RULE_IDS.BUILTIN_SYNC,
      matchedTarget: normalizedHost,
    };
  }

  // Not a built-in - needs async policy check
  return null;
}

// ============================================================================
// ASYNC POLICY CHECK (Extended Targets)
// ============================================================================

/** Cached policy config for subsequent checks */
let cachedConfig: NormalizedTargetConfig | null = null;

/**
 * Full activation check including policy-driven targets.
 *
 * Loads policy from managed storage and checks against all targets.
 * Use this when synchronous built-in check returns null.
 *
 * @param hostname - Current page hostname
 * @returns Promise resolving to activation decision
 */
export async function checkPolicyActivation(hostname: string): Promise<ActivationResult> {
  // Load policy if not cached
  if (!cachedConfig) {
    const policy = await loadTargetPolicyFromManagedStorage();
    cachedConfig = normalizeTargetPolicy(policy);
  }

  // Use full target matching
  const result = shouldActivate(hostname, cachedConfig);

  // Adjust rule ID for gate context
  if (result.activate && result.ruleId.startsWith('TGT-003') || result.ruleId.startsWith('TGT-004')) {
    return {
      ...result,
      ruleId: ACTIVATION_GATE_RULE_IDS.POLICY_ASYNC,
    };
  }

  if (!result.activate) {
    return {
      ...result,
      ruleId: ACTIVATION_GATE_RULE_IDS.NO_MATCH_ASYNC,
    };
  }

  return result;
}

// ============================================================================
// MAIN ACTIVATION GATE
// ============================================================================

/**
 * Result of the activation gate check.
 */
export interface GateResult {
  /** Whether to activate AgentGuard on this page */
  shouldActivate: boolean;

  /** Reason for the decision (for logging) */
  reason: string;

  /** Rule ID for audit trail */
  ruleId: string;

  /** Which target matched (if any) */
  matchedTarget?: string;

  /** Whether policy was loaded (vs sync built-in check) */
  policyLoaded: boolean;
}

/**
 * Main activation gate function.
 *
 * Call this FIRST before any DOM access or event listener setup.
 * If result.shouldActivate is false, exit immediately.
 *
 * Flow:
 * 1. Check hostname against built-in targets (sync, fast)
 * 2. If no match, check against policy targets (async)
 * 3. Return decision
 *
 * @param hostname - Current page hostname (window.location.hostname)
 * @returns Promise resolving to activation decision
 */
export async function checkActivationGate(hostname: string): Promise<GateResult> {
  // Fast path: synchronous built-in check
  const builtinResult = checkBuiltinActivation(hostname);

  if (builtinResult !== null) {
    return {
      shouldActivate: builtinResult.activate,
      reason: builtinResult.reason,
      ruleId: builtinResult.ruleId,
      matchedTarget: builtinResult.matchedTarget,
      policyLoaded: false,
    };
  }

  // Slow path: async policy check
  const policyResult = await checkPolicyActivation(hostname);

  return {
    shouldActivate: policyResult.activate,
    reason: policyResult.reason,
    ruleId: policyResult.ruleId,
    matchedTarget: policyResult.matchedTarget,
    policyLoaded: true,
  };
}

/**
 * Synchronous-only activation check (for environments without async support).
 *
 * Only checks built-in targets. Policy-driven targets are NOT checked.
 * Use checkActivationGate() for full policy support.
 *
 * @param hostname - Current page hostname
 * @returns Activation decision (built-ins only)
 */
export function checkActivationGateSync(hostname: string): GateResult {
  const builtinResult = checkBuiltinActivation(hostname);

  if (builtinResult !== null && builtinResult.activate) {
    return {
      shouldActivate: true,
      reason: builtinResult.reason,
      ruleId: builtinResult.ruleId,
      matchedTarget: builtinResult.matchedTarget,
      policyLoaded: false,
    };
  }

  // Not a built-in - cannot check policy synchronously
  return {
    shouldActivate: false,
    reason: 'Not a built-in target (sync-only check)',
    ruleId: ACTIVATION_GATE_RULE_IDS.NO_MATCH_SYNC,
    policyLoaded: false,
  };
}

// ============================================================================
// TEST HELPERS
// ============================================================================

/**
 * Clear cached policy config (for testing).
 */
export function clearActivationCache(): void {
  cachedConfig = null;
}

/**
 * Check if hostname is a protected target (convenience function for tests).
 *
 * @param hostname - Hostname to check
 * @returns Promise resolving to true if protected
 */
export async function isProtectedHost(hostname: string): Promise<boolean> {
  const result = await checkActivationGate(hostname);
  return result.shouldActivate;
}

/**
 * Check if hostname is a protected target (sync, built-ins only).
 *
 * @param hostname - Hostname to check
 * @returns true if protected (built-in only)
 */
export function isProtectedHostSync(hostname: string): boolean {
  return isBuiltinTarget(hostname);
}
