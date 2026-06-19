/**
 * AgentGuard Policy-Driven Target Selection (AG-PROMPT-057)
 *
 * Implements admin-configurable domain targeting via managed browser policy JSON.
 * Allows enterprises to extend scanning to additional AI platforms beyond built-ins.
 *
 * Design principles:
 * - Deterministic: Same policy + same URL => same activation decision
 * - Backward compatible: No policy = built-in targets only
 * - Safe defaults: Empty allowlist doesn't disable protection unless explicit
 * - Hostname-based: No regex, only hostname matching (auditability)
 * - Local-only: No cloud, no login, policy via browser management only
 *
 * Modes:
 * - hybrid (default): Built-in targets + admin additionalDomains
 * - allowlist: ONLY configured domains (built-ins excluded unless listed)
 *
 * @see ADR-026: Policy-Driven Target Selection
 * @see AG-PROMPT-057
 */

import { isDebugMode } from '../debug';

// ============================================================================
// TYPES
// ============================================================================

/**
 * Target selection mode.
 * - hybrid: Built-in targets + admin additions (recommended, default)
 * - allowlist: Only configured domains (explicit control)
 */
export type TargetMode = 'hybrid' | 'allowlist';

/**
 * Policy schema for target selection.
 * Delivered via managed browser policy JSON.
 */
export interface TargetPolicy {
  /**
   * Selection mode.
   * - hybrid: Built-ins + additionalDomains
   * - allowlist: Only domains list
   * Default: 'hybrid' if omitted
   */
  mode?: TargetMode;

  /**
   * Whether to match subdomains of configured domains.
   * - true: "example.com" matches "example.com" and "*.example.com"
   * - false: exact hostname match only
   * Default: true
   */
  includeSubdomains?: boolean;

  /**
   * Additional domains to protect (hybrid mode).
   * Added to built-in targets.
   */
  additionalDomains?: string[];

  /**
   * Domains to protect (allowlist mode).
   * Replaces built-in targets entirely.
   */
  domains?: string[];

  /**
   * Safety guardrail: what to do if allowlist resolves to empty.
   * - true: allow empty (disables protection entirely)
   * - false: fall back to built-in targets (default, safer)
   * Default: false
   */
  allowEmptyAllowlist?: boolean;
}

/**
 * Validated and normalized target configuration.
 * Used internally after policy parsing.
 */
export interface NormalizedTargetConfig {
  /** Effective mode */
  mode: TargetMode;

  /** Whether to match subdomains */
  includeSubdomains: boolean;

  /** Normalized target hostnames (lowercase, no scheme/path) */
  targets: string[];

  /** Whether empty allowlist falls back to built-ins */
  allowEmptyAllowlist: boolean;

  /** Audit: was policy explicitly configured? */
  policyConfigured: boolean;

  /** Audit: any invalid entries that were ignored */
  invalidEntries: string[];
}

/**
 * Result of hostname activation check.
 */
export interface ActivationResult {
  /** Whether to activate scanning on this hostname */
  activate: boolean;

  /** Why this decision was made */
  reason: string;

  /** Rule ID for audit trail */
  ruleId: string;

  /** Which target matched (if any) */
  matchedTarget?: string;
}

/**
 * Rule IDs for audit trail.
 */
export const TARGET_POLICY_RULE_IDS = {
  // Activation rules
  BUILTIN_EXACT: 'TGT-001-builtin-exact',
  BUILTIN_SUBDOMAIN: 'TGT-002-builtin-subdomain',
  POLICY_EXACT: 'TGT-003-policy-exact',
  POLICY_SUBDOMAIN: 'TGT-004-policy-subdomain',
  NO_MATCH: 'TGT-005-no-match',
  AUTH_PAGE_EXCLUDED: 'TGT-006-auth-page',
  EMPTY_FALLBACK: 'TGT-007-empty-fallback',
} as const;

// ============================================================================
// BUILT-IN TARGETS
// ============================================================================

/**
 * Built-in target domains (exact match).
 * These are the default AI platforms protected without any policy configuration.
 * Matches PUBLIC_AI_EXACT_HOSTS from destination.ts.
 */
export const BUILTIN_TARGETS_EXACT = new Set([
  'chatgpt.com',
  'chat.openai.com',
  'claude.ai',
  'gemini.google.com',
  'aistudio.google.com',
  'copilot.microsoft.com',
  'perplexity.ai',
  'poe.com',
  'v0.dev',
  'cursor.com',
]);

/**
 * Built-in target domain suffixes (subdomain match).
 * These allow subdomains like api.openai.com.
 * Matches PUBLIC_AI_SUFFIX_PATTERNS from destination.ts.
 */
export const BUILTIN_TARGETS_SUFFIX = [
  'openai.com',
  'anthropic.com',
  'perplexity.ai',
  'bing.com',
];

/**
 * Authentication pages - always excluded from scanning.
 * Users paste credentials here; never classify as AI destination.
 */
const AUTH_PAGE_PATTERNS = [
  'accounts.google.com',
  'login.microsoftonline.com',
  'login.live.com',
  '.okta.com',
  '.auth0.com',
];

// ============================================================================
// HOSTNAME SANITIZATION
// ============================================================================

/**
 * Sanitize and normalize a domain input.
 * Accepts hostnames, URLs, or paths and extracts just the hostname.
 *
 * @param input - Raw input (could be "example.com", "https://example.com/path", etc.)
 * @returns Normalized lowercase hostname, or null if invalid
 */
export function sanitizeHostname(input: string): string | null {
  if (!input || typeof input !== 'string') {
    return null;
  }

  let hostname = input.trim().toLowerCase();

  // Handle URLs: extract hostname
  if (hostname.includes('://')) {
    try {
      const url = new URL(hostname);
      hostname = url.hostname;
    } catch {
      // Invalid URL, try to extract manually
      const match = hostname.match(/^[a-z]+:\/\/([^/:]+)/);
      hostname = match ? match[1] : hostname;
    }
  }

  // Remove any path, query, or port
  hostname = hostname.split('/')[0].split('?')[0].split(':')[0];

  // Remove leading dots
  hostname = hostname.replace(/^\.+/, '');

  // Basic hostname validation
  // - Must have at least one dot (TLD)
  // - No spaces
  // - Only valid hostname characters
  if (!hostname.includes('.') ||
      hostname.includes(' ') ||
      !/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(hostname)) {
    return null;
  }

  return hostname;
}

/**
 * Sanitize an array of domain inputs.
 * Returns valid hostnames and tracks invalid entries.
 *
 * @param inputs - Array of raw domain inputs
 * @returns Object with valid hostnames and invalid entries
 */
export function sanitizeDomainList(inputs: unknown): {
  valid: string[];
  invalid: string[];
} {
  const valid: string[] = [];
  const invalid: string[] = [];

  if (!Array.isArray(inputs)) {
    return { valid, invalid };
  }

  for (const input of inputs) {
    if (typeof input !== 'string') {
      invalid.push(String(input));
      continue;
    }

    const sanitized = sanitizeHostname(input);
    if (sanitized) {
      valid.push(sanitized);
    } else {
      invalid.push(input);
    }
  }

  // Deduplicate
  return {
    valid: [...new Set(valid)],
    invalid,
  };
}

// ============================================================================
// POLICY NORMALIZATION
// ============================================================================

/**
 * Normalize and validate a target policy.
 * Applies defaults, sanitizes inputs, and produces a consistent config.
 *
 * @param policy - Raw policy input (may be undefined, null, or partial)
 * @returns Normalized configuration
 */
export function normalizeTargetPolicy(policy?: TargetPolicy | null): NormalizedTargetConfig {
  // No policy: use built-ins only
  if (!policy || typeof policy !== 'object') {
    return {
      mode: 'hybrid',
      includeSubdomains: true,
      targets: [],
      allowEmptyAllowlist: false,
      policyConfigured: false,
      invalidEntries: [],
    };
  }

  // Validate mode
  const mode: TargetMode = policy.mode === 'allowlist' ? 'allowlist' : 'hybrid';

  // Default includeSubdomains to true
  const includeSubdomains = policy.includeSubdomains !== false;

  // Sanitize domain lists
  const additionalResult = sanitizeDomainList(policy.additionalDomains);
  const allowlistResult = sanitizeDomainList(policy.domains);

  // Determine effective targets based on mode
  let targets: string[];
  let invalidEntries: string[];

  if (mode === 'allowlist') {
    targets = allowlistResult.valid;
    invalidEntries = allowlistResult.invalid;
  } else {
    // Hybrid mode: just the additional domains (built-ins added during matching)
    targets = additionalResult.valid;
    invalidEntries = additionalResult.invalid;
  }

  // Safety guardrail
  const allowEmptyAllowlist = policy.allowEmptyAllowlist === true;

  return {
    mode,
    includeSubdomains,
    targets,
    allowEmptyAllowlist,
    policyConfigured: true,
    invalidEntries,
  };
}

// ============================================================================
// HOSTNAME MATCHING
// ============================================================================

/**
 * Check if a hostname is an authentication page.
 * Auth pages are always excluded from scanning.
 *
 * @param hostname - Hostname to check (should be lowercase)
 * @returns true if this is an auth page
 */
function isAuthPage(hostname: string): boolean {
  for (const pattern of AUTH_PAGE_PATTERNS) {
    if (pattern.startsWith('.')) {
      // Suffix match
      if (hostname.endsWith(pattern) || hostname === pattern.slice(1)) {
        return true;
      }
    } else {
      // Exact match
      if (hostname === pattern) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Check if a hostname matches a target with optional subdomain support.
 *
 * @param hostname - Hostname to check (lowercase)
 * @param target - Target domain to match against (lowercase)
 * @param includeSubdomains - Whether to match subdomains
 * @returns true if hostname matches target
 */
export function matchesTarget(
  hostname: string,
  target: string,
  includeSubdomains: boolean
): boolean {
  // Exact match
  if (hostname === target) {
    return true;
  }

  // Subdomain match
  if (includeSubdomains) {
    // "www.example.com" should match target "example.com"
    const suffix = '.' + target;
    if (hostname.endsWith(suffix)) {
      return true;
    }
  }

  return false;
}

/**
 * Check if a hostname matches any built-in target.
 *
 * @param hostname - Hostname to check (lowercase)
 * @returns Match result with matched target if found
 */
function matchesBuiltinTarget(hostname: string): {
  matched: boolean;
  target?: string;
  isSubdomain: boolean;
} {
  // Check exact matches first (fast path)
  if (BUILTIN_TARGETS_EXACT.has(hostname)) {
    return { matched: true, target: hostname, isSubdomain: false };
  }

  // Check suffix patterns (subdomain support)
  for (const suffix of BUILTIN_TARGETS_SUFFIX) {
    if (hostname === suffix || hostname.endsWith('.' + suffix)) {
      return { matched: true, target: suffix, isSubdomain: hostname !== suffix };
    }
  }

  return { matched: false, isSubdomain: false };
}

/**
 * Check if a hostname matches any policy-configured target.
 *
 * @param hostname - Hostname to check (lowercase)
 * @param targets - Configured targets
 * @param includeSubdomains - Whether to match subdomains
 * @returns Match result with matched target if found
 */
function matchesPolicyTarget(
  hostname: string,
  targets: string[],
  includeSubdomains: boolean
): { matched: boolean; target?: string; isSubdomain: boolean } {
  for (const target of targets) {
    if (matchesTarget(hostname, target, includeSubdomains)) {
      return {
        matched: true,
        target,
        isSubdomain: hostname !== target,
      };
    }
  }

  return { matched: false, isSubdomain: false };
}

// ============================================================================
// ACTIVATION DECISION
// ============================================================================

/**
 * Determine if scanning should activate for a given hostname.
 *
 * This is the main entry point for target policy decisions.
 *
 * Flow:
 * 1. Normalize hostname
 * 2. Check auth page exclusion
 * 3. Apply policy rules based on mode
 *
 * @param hostname - Current page hostname (window.location.hostname)
 * @param config - Normalized target configuration
 * @returns Activation decision with reason and audit info
 */
export function shouldActivate(
  hostname: string,
  config: NormalizedTargetConfig
): ActivationResult {
  // Normalize hostname
  const normalizedHost = hostname?.toLowerCase()?.trim();

  if (!normalizedHost) {
    return {
      activate: false,
      reason: 'Empty or invalid hostname',
      ruleId: TARGET_POLICY_RULE_IDS.NO_MATCH,
    };
  }

  // Auth pages are always excluded
  if (isAuthPage(normalizedHost)) {
    return {
      activate: false,
      reason: 'Authentication page excluded',
      ruleId: TARGET_POLICY_RULE_IDS.AUTH_PAGE_EXCLUDED,
    };
  }

  // Mode-based matching
  if (config.mode === 'allowlist') {
    return shouldActivateAllowlist(normalizedHost, config);
  } else {
    return shouldActivateHybrid(normalizedHost, config);
  }
}

/**
 * Activation logic for hybrid mode.
 * Built-in targets + policy additionalDomains.
 */
function shouldActivateHybrid(
  hostname: string,
  config: NormalizedTargetConfig
): ActivationResult {
  // Check built-in targets first
  const builtinMatch = matchesBuiltinTarget(hostname);
  if (builtinMatch.matched) {
    return {
      activate: true,
      reason: `Built-in target${builtinMatch.isSubdomain ? ' (subdomain)' : ''}`,
      ruleId: builtinMatch.isSubdomain
        ? TARGET_POLICY_RULE_IDS.BUILTIN_SUBDOMAIN
        : TARGET_POLICY_RULE_IDS.BUILTIN_EXACT,
      matchedTarget: builtinMatch.target,
    };
  }

  // Check policy additional domains
  if (config.targets.length > 0) {
    const policyMatch = matchesPolicyTarget(
      hostname,
      config.targets,
      config.includeSubdomains
    );
    if (policyMatch.matched) {
      return {
        activate: true,
        reason: `Policy target${policyMatch.isSubdomain ? ' (subdomain)' : ''}`,
        ruleId: policyMatch.isSubdomain
          ? TARGET_POLICY_RULE_IDS.POLICY_SUBDOMAIN
          : TARGET_POLICY_RULE_IDS.POLICY_EXACT,
        matchedTarget: policyMatch.target,
      };
    }
  }

  // No match
  return {
    activate: false,
    reason: 'No matching target',
    ruleId: TARGET_POLICY_RULE_IDS.NO_MATCH,
  };
}

/**
 * Activation logic for allowlist mode.
 * Only configured domains, built-ins excluded unless listed.
 */
function shouldActivateAllowlist(
  hostname: string,
  config: NormalizedTargetConfig
): ActivationResult {
  // Safety: empty allowlist fallback
  if (config.targets.length === 0) {
    if (config.allowEmptyAllowlist) {
      // Explicit: empty allowlist disables protection
      return {
        activate: false,
        reason: 'Empty allowlist (explicit)',
        ruleId: TARGET_POLICY_RULE_IDS.NO_MATCH,
      };
    } else {
      // Safety fallback: use built-ins
      const builtinMatch = matchesBuiltinTarget(hostname);
      if (builtinMatch.matched) {
        return {
          activate: true,
          reason: `Built-in fallback (empty allowlist)${builtinMatch.isSubdomain ? ' (subdomain)' : ''}`,
          ruleId: TARGET_POLICY_RULE_IDS.EMPTY_FALLBACK,
          matchedTarget: builtinMatch.target,
        };
      }
      return {
        activate: false,
        reason: 'No match (empty allowlist fallback)',
        ruleId: TARGET_POLICY_RULE_IDS.NO_MATCH,
      };
    }
  }

  // Check policy domains
  const policyMatch = matchesPolicyTarget(
    hostname,
    config.targets,
    config.includeSubdomains
  );
  if (policyMatch.matched) {
    return {
      activate: true,
      reason: `Allowlist target${policyMatch.isSubdomain ? ' (subdomain)' : ''}`,
      ruleId: policyMatch.isSubdomain
        ? TARGET_POLICY_RULE_IDS.POLICY_SUBDOMAIN
        : TARGET_POLICY_RULE_IDS.POLICY_EXACT,
      matchedTarget: policyMatch.target,
    };
  }

  // No match in allowlist
  return {
    activate: false,
    reason: 'Not in allowlist',
    ruleId: TARGET_POLICY_RULE_IDS.NO_MATCH,
  };
}

// ============================================================================
// POLICY LOADING (Managed Storage)
// ============================================================================

/**
 * Load target policy from browser managed storage.
 *
 * Managed storage is set by enterprise administrators via:
 * - Firefox: policies.json or GPO
 * - Chrome: registry (Windows) or managed preferences (macOS/Linux)
 *
 * @returns Promise resolving to target policy (or null if not configured)
 */
export async function loadTargetPolicyFromManagedStorage(): Promise<TargetPolicy | null> {
  try {
    // Check if running in extension context
    if (typeof chrome === 'undefined' || !chrome.storage?.managed) {
      if (isDebugMode()) {
        console.log('[AgentGuard][TargetPolicy] No managed storage API available');
      }
      return null;
    }

    // Read from managed storage
    const result = await chrome.storage.managed.get('targets');

    if (!result || !result.targets) {
      if (isDebugMode()) {
        console.log('[AgentGuard][TargetPolicy] No targets policy in managed storage');
      }
      return null;
    }

    if (isDebugMode()) {
      console.log('[AgentGuard][TargetPolicy] Loaded policy from managed storage:', {
        mode: result.targets.mode,
        includeSubdomains: result.targets.includeSubdomains,
        additionalDomainsCount: result.targets.additionalDomains?.length,
        domainsCount: result.targets.domains?.length,
      });
    }

    return result.targets as TargetPolicy;
  } catch (error) {
    // Managed storage not available or access denied
    if (isDebugMode()) {
      console.log('[AgentGuard][TargetPolicy] Failed to load managed storage:', error);
    }
    return null;
  }
}

// ============================================================================
// CONVENIENCE FUNCTIONS
// ============================================================================

/** Cached normalized config */
let cachedConfig: NormalizedTargetConfig | null = null;

/**
 * Get the current normalized target configuration.
 * Loads from managed storage on first call, then caches.
 *
 * @param forceReload - Force reload from storage
 * @returns Normalized target configuration
 */
export async function getTargetConfig(forceReload = false): Promise<NormalizedTargetConfig> {
  if (cachedConfig && !forceReload) {
    return cachedConfig;
  }

  const policy = await loadTargetPolicyFromManagedStorage();
  cachedConfig = normalizeTargetPolicy(policy);

  if (isDebugMode() && cachedConfig.invalidEntries.length > 0) {
    console.warn('[AgentGuard][TargetPolicy] Invalid entries ignored:',
      cachedConfig.invalidEntries);
  }

  return cachedConfig;
}

/**
 * Check if a hostname should be scanned (convenience wrapper).
 *
 * @param hostname - Hostname to check
 * @returns Promise resolving to activation decision
 */
export async function shouldActivateForHostname(hostname: string): Promise<ActivationResult> {
  const config = await getTargetConfig();
  return shouldActivate(hostname, config);
}

/**
 * Get built-in targets as an array (for testing/debugging).
 */
export function getBuiltinTargets(): string[] {
  return [
    ...Array.from(BUILTIN_TARGETS_EXACT),
    ...BUILTIN_TARGETS_SUFFIX.map(s => `*.${s}`),
  ];
}

/**
 * Clear the cached config (for testing).
 */
export function clearTargetConfigCache(): void {
  cachedConfig = null;
}

// ============================================================================
// EXPORTS
// ============================================================================

export {
  AUTH_PAGE_PATTERNS,
};
