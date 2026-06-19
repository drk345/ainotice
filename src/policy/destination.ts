/**
 * AgentGuard Destination Detection v1.1
 *
 * Local-only, hostname-based classification of where data is being sent.
 * Conservative approach: unknown > guessing.
 *
 * Destination types:
 * - public_ai: Known public AI services (ChatGPT, Claude, Gemini, etc.)
 * - internal_ai: Organization-internal AI (requires explicit override)
 * - unknown: Default for everything else
 *
 * Privacy: No telemetry, no tracking. Pure function, no side effects.
 *
 * AG-PROMPT-057: Integrates with targetPolicy.ts for policy-driven target selection.
 * The built-in lists below remain for backward compatibility and synchronous checks.
 * Policy-driven targeting extends these via managed storage configuration.
 *
 * @see ADR-016: Policy Mapper Resolver
 * @see ADR-026: Policy-Driven Target Selection
 * @see AG-PROMPT-027: Destination Detection
 * @see AG-PROMPT-057: Policy-Driven Targets
 */

// ============================================================================
// TYPES
// ============================================================================

/**
 * Destination type for context-aware policy decisions
 */
export type DestinationType = 'public_ai' | 'internal_ai' | 'unknown';

// ============================================================================
// ALLOWLISTS
// ============================================================================

/**
 * Exact hostname matches for public AI services
 * These are authoritative - no suffix matching needed
 */
const PUBLIC_AI_EXACT_HOSTS = new Set([
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
 * Allowed suffix matches for public AI services
 * These are TIGHT - only specific AI-related domains
 *
 * DO NOT add broad domains like:
 * - *.google.com (would match Gmail, Docs, etc.)
 * - *.microsoft.com (would match Office, Azure, etc.)
 * - *.amazon.com (would match AWS Console, etc.)
 */
const PUBLIC_AI_SUFFIX_PATTERNS = [
  '.openai.com',      // api.openai.com, platform.openai.com
  '.anthropic.com',   // console.anthropic.com, api.anthropic.com
  '.perplexity.ai',   // labs.perplexity.ai
  '.bing.com',        // copilot.bing.com, chat.bing.com (Bing AI)
];

/**
 * Authentication and login pages that should ALWAYS return 'unknown'
 * Users paste credentials here - never classify as AI destination
 */
const AUTH_PAGE_PATTERNS = [
  'accounts.google.com',
  'login.microsoftonline.com',
  'login.live.com',
  '.okta.com',
  '.auth0.com',
];

/**
 * Internal AI allowlist (override-only for v1)
 *
 * In v1, we do NOT infer internal_ai from hostname patterns like:
 * - *.corp, *.internal, ai.*, llm.*
 *
 * Internal AI detection requires explicit configuration.
 * This will be managed via PolicySchema in future versions.
 */
const INTERNAL_AI_HOSTS = new Set<string>([
  // Add explicit internal AI hostnames here when configured
  // e.g., 'ai.internal.company.com'
]);

// ============================================================================
// DETECTION FUNCTIONS
// ============================================================================

/**
 * Check if hostname matches authentication/login pages
 *
 * @param hostname - Hostname to check (lowercase)
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
 * Check if hostname is a known public AI service
 *
 * @param hostname - Hostname to check
 * @returns true if this is a public AI service
 */
export function isPublicAiHost(hostname: string): boolean {
  if (!hostname) return false;

  const normalizedHost = hostname.toLowerCase();

  // Auth pages are NEVER classified as AI
  if (isAuthPage(normalizedHost)) {
    return false;
  }

  // Check exact matches first (fast path)
  if (PUBLIC_AI_EXACT_HOSTS.has(normalizedHost)) {
    return true;
  }

  // Check suffix patterns
  for (const suffix of PUBLIC_AI_SUFFIX_PATTERNS) {
    if (normalizedHost.endsWith(suffix)) {
      return true;
    }
  }

  return false;
}

/**
 * Check if hostname is a configured internal AI service
 *
 * In v1, this is override-only - requires explicit configuration.
 * We do NOT infer from patterns like *.corp or ai.*.
 *
 * @param hostname - Hostname to check
 * @returns true if this is a configured internal AI service
 */
function isInternalAiHost(hostname: string): boolean {
  if (!hostname) return false;

  const normalizedHost = hostname.toLowerCase();

  // Auth pages are NEVER classified as AI
  if (isAuthPage(normalizedHost)) {
    return false;
  }

  // Exact match only - no suffix inference
  return INTERNAL_AI_HOSTS.has(normalizedHost);
}

/**
 * Derive destination type from hostname
 *
 * Uses window.location.hostname at moment of intent (paste/drop/submit).
 * Ignores iframe internals - top-level hostname is authoritative.
 *
 * Priority:
 * 1. Auth pages → unknown (always)
 * 2. Internal AI (explicit override) → internal_ai
 * 3. Public AI (exact + suffix match) → public_ai
 * 4. Everything else → unknown
 *
 * @param hostname - Current page hostname (window.location.hostname)
 * @returns DestinationType based on hostname matching
 */
export function deriveDestination(hostname: string): DestinationType {
  if (!hostname) {
    return 'unknown';
  }

  const normalizedHost = hostname.toLowerCase();

  // 1. Auth pages are always unknown
  if (isAuthPage(normalizedHost)) {
    return 'unknown';
  }

  // 2. Check internal AI first (higher priority - org-specific)
  if (isInternalAiHost(normalizedHost)) {
    return 'internal_ai';
  }

  // 3. Check public AI services
  if (isPublicAiHost(normalizedHost)) {
    return 'public_ai';
  }

  // 4. Default to unknown (conservative)
  return 'unknown';
}

// ============================================================================
// CONFIGURATION (Future: PolicySchema-managed)
// ============================================================================

/**
 * Add an internal AI hostname override
 *
 * This is a programmatic API for testing and future admin configuration.
 * In production, this will be managed via PolicySchema.
 *
 * @param hostname - Internal AI hostname to add
 */
export function addInternalAiHost(hostname: string): void {
  if (hostname) {
    INTERNAL_AI_HOSTS.add(hostname.toLowerCase());
  }
}

/**
 * Remove an internal AI hostname override
 *
 * @param hostname - Internal AI hostname to remove
 */
export function removeInternalAiHost(hostname: string): void {
  if (hostname) {
    INTERNAL_AI_HOSTS.delete(hostname.toLowerCase());
  }
}

/**
 * Clear all internal AI hostname overrides
 * Useful for testing
 */
export function clearInternalAiHosts(): void {
  INTERNAL_AI_HOSTS.clear();
}

/**
 * Get current internal AI hostname overrides
 * Useful for debugging and testing
 */
export function getInternalAiHosts(): string[] {
  return Array.from(INTERNAL_AI_HOSTS);
}
