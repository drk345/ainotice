/**
 * AgentGuard Policy Layer
 * 
 * Provides configurable signal severity mapping and escalation rules.
 * Designed for future admin UI integration while maintaining local-only processing.
 * 
 * Privacy: No content logging, no telemetry. Only counts/booleans in debug output.
 * 
 * v1.1 - Added severity caps and transactional document detection
 * v1.2 - Added locale-aware signal processing
 */

import {
  LocaleKey,
  LocaleConfidence,
  LocaleDetectionResult,
  LocaleProfile,
  detectLikelyLocale,
  getLocaleProfile,
  shouldEscalatePhones,
  LocaleContext,
} from './locale';

import type { RiskSignal, Severity, SignalType } from '../types/riskSignal';

// ============================================================================
// CONFIGURATION
// ============================================================================

/** Set to true to enable policy debug logging (counts/decisions only, no content) */
const DEBUG_POLICY = false;

// ============================================================================
// TYPES (re-exported from canonical source)
// ============================================================================

/**
 * Re-export canonical RiskSignal and related types from src/types/riskSignal.ts
 * @see AG-PROMPT-033B for centralization history
 */
export type { RiskSignal, Severity, SignalType, SignalSource } from '../types/riskSignal';

/** Configuration for a specific signal pattern */
export interface SignalConfig {
  /** Whether this signal is enabled (if false, filtered out) */
  enabled: boolean;
  
  /** Base severity before escalation rules apply */
  baseSeverity: Severity;
  
  /** 
   * Maximum severity this signal can reach (caps escalation)
   * Prevents high-volume signals like phones from becoming CRITICAL
   */
  maxSeverity?: Severity;
  
  /** 
   * Count thresholds for severity escalation
   * e.g., { 5: 'medium', 10: 'high' } means:
   *   - count < 5: use baseSeverity
   *   - count >= 5: escalate to medium
   *   - count >= 10: escalate to high
   */
  escalationThresholds?: Record<number, Severity>;
  
  /** If true, severity cannot be reduced below baseSeverity (for secrets) */
  hardFloor?: boolean;
  
  /** If true, apply transactional document downgrade (-1 severity) */
  transactionalDowngrade?: boolean;
}

/** Cross-signal escalation rules */
export interface EscalationRules {
  /** 
   * Co-occurrence rule: if multiple PII types appear together, escalate
   * Example: phones + emails in same doc suggests contact list
   */
  coOccurrence?: {
    /** Minimum combined count to trigger */
    threshold: number;
    /** Which signal patterns to escalate */
    affectedPatterns: string[];
    /** How much to bump severity (1 = one level up) */
    severityBump: number;
    /** Maximum severity after co-occurrence bump */
    maxSeverity?: Severity;
  };
  
  /**
   * PII density rule: if total PII count exceeds threshold, escalate all PII
   */
  piiDensity?: {
    threshold: number;
    severityBump: number;
    /** Maximum severity after density bump */
    maxSeverity?: Severity;
  };
}

/** Signal context for escalation decisions */
export interface SignalContext {
  emailCount: number;
  phoneCount: number;
  ssnCount: number;
  nameCount: number;
  /** Total characters scanned (for density calculation) */
  textLength?: number;
  /** Whether document appears to be transactional (receipt, invoice, order) */
  isTransactional?: boolean;
  /** Raw text for transactional detection (not logged) */
  bodyText?: string;
  /** Detected locale for locale-aware processing */
  locale?: LocaleKey;
  /** Confidence in locale detection */
  localeConfidence?: LocaleConfidence;
}

/** Complete policy configuration */
export interface Policy {
  /** Version for future compatibility */
  version: string;
  
  /** Per-pattern configurations keyed by pattern identifier */
  signals: Record<string, SignalConfig>;
  
  /** Cross-signal escalation rules */
  escalation: EscalationRules;
}

// ============================================================================
// SEVERITY UTILITIES
// ============================================================================

const SEVERITY_ORDER: Severity[] = ['low', 'medium', 'high', 'critical'];

/**
 * Get numeric index of severity (for comparison)
 */
function severityIndex(severity: Severity): number {
  return SEVERITY_ORDER.indexOf(severity);
}

/**
 * Bump severity by N levels (capped at critical)
 */
function bumpSeverity(severity: Severity, levels: number): Severity {
  const currentIndex = severityIndex(severity);
  const newIndex = Math.min(currentIndex + levels, SEVERITY_ORDER.length - 1);
  return SEVERITY_ORDER[newIndex];
}

/**
 * Reduce severity by N levels (floored at low)
 */
function reduceSeverity(severity: Severity, levels: number): Severity {
  const currentIndex = severityIndex(severity);
  const newIndex = Math.max(currentIndex - levels, 0);
  return SEVERITY_ORDER[newIndex];
}

/**
 * Get the higher of two severities
 */
function maxSeverity(a: Severity, b: Severity): Severity {
  return severityIndex(a) >= severityIndex(b) ? a : b;
}

/**
 * Get the lower of two severities (for capping)
 */
function minSeverity(a: Severity, b: Severity): Severity {
  return severityIndex(a) <= severityIndex(b) ? a : b;
}

/**
 * Cap severity at a maximum level
 */
function capSeverity(severity: Severity, cap: Severity): Severity {
  return minSeverity(severity, cap);
}

// ============================================================================
// TRANSACTIONAL DOCUMENT DETECTION
// ============================================================================

/**
 * Patterns that indicate a transactional document (receipt, invoice, order)
 * These documents often contain many number sequences that aren't phone numbers
 */
const TRANSACTIONAL_MARKERS = [
  // Currency and pricing
  /\b(kr|USD|EUR|GBP|DKK|SEK|NOK|\$|€|£)\b/i,
  /\b\d+[.,]\d{2}\s*(kr|USD|EUR|GBP|DKK|SEK|NOK)?\b/i,  // Price patterns like 1.599,00
  /\b(subtotal|total|moms|vat|tax|shipping|levering)\b/i,
  
  // Order/transaction terminology
  /\b(order|ordre|invoice|faktura|receipt|kvittering|purchase|køb)\s*(number|nummer|#|no\.?)?\s*:?\s*\d+/i,
  /\b(bestilling|transaction|betaling|payment)\b/i,
  
  // Masked payment info
  /\*{4}\s*\*{4}\s*\*{4}\s*\d{4}/,  // **** **** **** 1234
  /\b(visa|mastercard|amex|dankort|mobilepay)\b/i,
  
  // Product codes / SKUs
  /\b\d{3}\.\d{3}\.\d{2}\b/,  // IKEA-style product codes
  /\b(sku|item|produkt|vare|artikel)\s*(number|nummer|#|no\.?)?\s*:?\s*[\w-]+/i,
  
  // Delivery/shipping
  /\b(delivery|levering|shipping|forsendelse|tracking)\b/i,
  /\b(delivered|leveret|shipped|sendt)\b/i,
];

/**
 * Detect if document appears to be transactional (receipt, invoice, order)
 * Uses simple pattern matching - no NLP or heavy parsing
 * 
 * @param text - Document text (NOT logged)
 * @returns true if document has strong transactional signals
 */
function detectTransactionalDocument(text: string): boolean {
  if (!text || text.length < 50) return false;
  
  let matchCount = 0;
  const requiredMatches = 3; // Need multiple signals to confirm
  
  for (const pattern of TRANSACTIONAL_MARKERS) {
    if (pattern.test(text)) {
      matchCount++;
      if (matchCount >= requiredMatches) {
        return true;
      }
    }
  }
  
  return false;
}

// ============================================================================
// DEFAULT POLICY
// ============================================================================

/**
 * Default policy configuration
 * 
 * Philosophy:
 * - Secrets (API keys, AWS keys, passwords) are always HIGH/CRITICAL
 * - Phone/email have CAPS - can never exceed MEDIUM regardless of count
 * - Transactional documents get severity downgrade for contact-info signals
 * - High counts are reported accurately but don't cause panic
 */
export const DefaultPolicy: Policy = {
  version: '1.1.0',
  
  signals: {
    // === SECRETS (hard floor - never reduce, no cap) ===
    'api-key': {
      enabled: true,
      baseSeverity: 'critical',
      hardFloor: true,
    },
    'aws-key': {
      enabled: true,
      baseSeverity: 'critical',
      hardFloor: true,
    },
    'password': {
      enabled: true,
      baseSeverity: 'critical',
      hardFloor: true,
    },
    
    // === CRITICAL PII (hard floor, no cap) ===
    'ssn': {
      enabled: true,
      baseSeverity: 'critical',
      hardFloor: true,
    },
    'credit-card': {
      enabled: true,
      baseSeverity: 'critical',
      hardFloor: true,
    },
    
    // === CONFIDENTIAL MARKERS ===
    'confidential-marker': {
      enabled: true,
      baseSeverity: 'high',
      hardFloor: true,
    },
    'ma-terms': {
      enabled: true,
      baseSeverity: 'critical',
      hardFloor: true,
    },
    'legal-agreement': {
      enabled: true,
      baseSeverity: 'high',
    },
    
    // === CONTACT INFO (capped at MEDIUM, transactional downgrade) ===
    'phone': {
      enabled: true,
      baseSeverity: 'low',
      maxSeverity: 'medium',  // NEVER goes above medium
      transactionalDowngrade: true,
      escalationThresholds: {
        20: 'medium',   // 20+ phones → medium (capped)
        // No higher thresholds - medium is the max
      },
    },
    'email': {
      enabled: true,
      baseSeverity: 'low',
      maxSeverity: 'medium',  // NEVER goes above medium
      transactionalDowngrade: true,
      escalationThresholds: {
        10: 'medium',   // 10+ emails → medium (capped)
      },
    },
    
    // === FINANCIAL ===
    'iban': {
      enabled: true,
      baseSeverity: 'high',
    },
    'banking': {
      enabled: true,
      baseSeverity: 'high',
      transactionalDowngrade: true, // Bank info in receipts is less risky
    },
    'financial-data': {
      enabled: true,
      baseSeverity: 'high',
    },
    
    // === METADATA / LOW SEVERITY ===
    'author-name': {
      enabled: true,
      baseSeverity: 'low',
      maxSeverity: 'medium',
    },
    'company-name': {
      enabled: true,
      baseSeverity: 'low',
      maxSeverity: 'low',
    },
    'employee-data': {
      enabled: true,
      baseSeverity: 'high',
    },
    'ip-content': {
      enabled: true,
      baseSeverity: 'critical',
      hardFloor: true,
    },
    'sensitive-dept': {
      enabled: true,
      baseSeverity: 'high',
    },
  },
  
  escalation: {
    // Co-occurrence escalation (also capped)
    coOccurrence: {
      threshold: 10,
      affectedPatterns: ['phone', 'email'],
      severityBump: 1,
      maxSeverity: 'medium',  // Cap co-occurrence escalation
    },
    // Density escalation (also capped for contact info)
    piiDensity: {
      threshold: 50,  // Raised threshold
      severityBump: 1,
      maxSeverity: 'medium',  // Cap density escalation
    },
  },
};

// ============================================================================
// PATTERN MATCHING HELPERS
// ============================================================================

/**
 * Map a signal description to a policy pattern key
 * This bridges between the free-text descriptions in RiskSignal and our policy keys
 */
function getPatternKey(signal: RiskSignal): string | null {
  const desc = signal.description.toLowerCase();
  
  // Secrets
  if (desc.includes('api key') || desc.includes('access token')) return 'api-key';
  if (desc.includes('aws') && desc.includes('key')) return 'aws-key';
  if (desc.includes('password')) return 'password';
  
  // Critical PII
  if (desc.includes('ssn') || desc.includes('social security')) return 'ssn';
  if (desc.includes('credit card') || desc.includes('payment card')) return 'credit-card';
  
  // Confidential markers
  if (desc.includes('confidentiality') || desc.includes('confidential')) return 'confidential-marker';
  if (desc.includes('m&a') || desc.includes('merger') || desc.includes('acquisition')) return 'ma-terms';
  if (desc.includes('legal') && (desc.includes('agreement') || desc.includes('contract'))) return 'legal-agreement';
  
  // Contact info
  if (desc.includes('phone')) return 'phone';
  if (desc.includes('email')) return 'email';
  
  // Financial
  if (desc.includes('iban')) return 'iban';
  if (desc.includes('banking') || desc.includes('wire') || desc.includes('routing')) return 'banking';
  if (desc.includes('financial') || desc.includes('budget') || desc.includes('revenue')) return 'financial-data';
  
  // Metadata / Other
  if (desc.includes('author')) return 'author-name';
  if (desc.includes('corporate') && desc.includes('document')) return 'company-name';
  if (desc.includes('employee') || desc.includes('hr') || desc.includes('personnel')) return 'employee-data';
  if (desc.includes('patent') || desc.includes('intellectual') || desc.includes('trade secret')) return 'ip-content';
  if (desc.includes('sensitive department') || desc.includes('legal, finance')) return 'sensitive-dept';
  
  // No specific mapping - return null (signal passes through unchanged)
  return null;
}

/**
 * Extract count from signal description (e.g., "657 phone numbers" → 657)
 */
function extractCount(description: string): number {
  const match = description.match(/(\d+)\s+(email|phone|address)/i);
  if (match) {
    return parseInt(match[1], 10);
  }
  // If no count in description, assume 1
  return 1;
}

// ============================================================================
// POLICY APPLICATION
// ============================================================================

/**
 * Apply policy to a list of signals
 * 
 * @param signals - Raw signals from extraction
 * @param context - Optional context with counts for escalation decisions
 * @param policy - Policy to apply (defaults to DefaultPolicy)
 * @returns Transformed signals with adjusted severities
 */
export function applyPolicy(
  signals: RiskSignal[],
  context?: SignalContext,
  policy: Policy = DefaultPolicy
): RiskSignal[] {
  if (!signals || signals.length === 0) {
    return signals;
  }
  
  // Build context from signals if not provided
  const ctx: SignalContext = context || {
    emailCount: 0,
    phoneCount: 0,
    ssnCount: 0,
    nameCount: 0,
  };
  
  // If no context provided, estimate from signals
  if (!context) {
    for (const signal of signals) {
      const desc = signal.description.toLowerCase();
      if (desc.includes('email')) {
        ctx.emailCount += extractCount(signal.description);
      } else if (desc.includes('phone')) {
        ctx.phoneCount += extractCount(signal.description);
      } else if (desc.includes('ssn') || desc.includes('social security')) {
        ctx.ssnCount += 1;
      } else if (desc.includes('author') || desc.includes('name')) {
        ctx.nameCount += 1;
      }
    }
  }
  
  // Detect transactional document from body text if available
  const isTransactional = ctx.isTransactional ?? 
    (ctx.bodyText ? detectTransactionalDocument(ctx.bodyText) : false);
  
  // Get locale profile for locale-aware thresholds
  const localeProfile = ctx.locale ? getLocaleProfile(ctx.locale) : getLocaleProfile('unknown');
  const localeConfidence = ctx.localeConfidence ?? 'none';
  
  if (DEBUG_POLICY) {
    console.log(`[AgentGuard] Policy context: emails=${ctx.emailCount}, phones=${ctx.phoneCount}, ssn=${ctx.ssnCount}, transactional=${isTransactional}, locale=${ctx.locale ?? 'unknown'} (confidence=${localeConfidence})`);
  }
  
  // Check if co-occurrence escalation applies
  const coOccurrenceTriggered = policy.escalation.coOccurrence && 
    (ctx.emailCount + ctx.phoneCount) >= policy.escalation.coOccurrence.threshold;
  
  // Check if density escalation applies - use locale-aware threshold
  const totalPiiCount = ctx.emailCount + ctx.phoneCount + ctx.ssnCount;
  const densityThreshold = policy.escalation.piiDensity?.threshold ?? 50;
  const densityTriggered = policy.escalation.piiDensity && 
    totalPiiCount >= densityThreshold;
  
  // Locale-aware phone escalation: only escalate if meets locale threshold
  const phoneEscalationAllowed = shouldEscalatePhones(ctx.phoneCount, ctx.locale ?? 'unknown');
  
  if (DEBUG_POLICY) {
    console.log(`[AgentGuard] Policy escalation: coOccurrence=${coOccurrenceTriggered}, density=${densityTriggered}`);
  }
  
  // Process each signal
  const result: RiskSignal[] = [];
  
  for (const signal of signals) {
    const patternKey = getPatternKey(signal);
    const config = patternKey ? policy.signals[patternKey] : null;
    
    // If no config or disabled, check if we should filter
    if (config && !config.enabled) {
      if (DEBUG_POLICY) {
        console.log(`[AgentGuard] Policy filtered: ${patternKey}`);
      }
      continue; // Skip disabled signals
    }

    // === LOCALE GATING: SSN is US-specific (ADR-010) ===
    // SSN pattern (XXX-XX-XXXX) should only trigger for US locale
    // Non-US documents with this pattern are likely CPR, reference numbers, etc.
    if (patternKey === 'ssn' && ctx.locale && ctx.locale !== 'US' && ctx.locale !== 'unknown') {
      if (DEBUG_POLICY) {
        console.log(`[AgentGuard] SSN filtered: locale=${ctx.locale} is not US`);
      }
      // Downgrade to low with explanation instead of filtering entirely
      // This preserves visibility while reducing false positive impact
      result.push({
        ...signal,
        severity: 'low',
        detail: `${signal.detail} Note: Pattern detected in non-US document (${ctx.locale}) - may be a reference number or local ID format.`,
      });
      continue;
    }

    // Start with current severity (or base from config)
    let newSeverity: Severity = signal.severity;
    
    if (config) {
      // Apply base severity (may be lower than current)
      if (!config.hardFloor) {
        newSeverity = config.baseSeverity;
      } else {
        // Hard floor: never go below base
        newSeverity = maxSeverity(signal.severity, config.baseSeverity);
      }
      
      // Apply count-based escalation (locale-aware for phones)
      if (config.escalationThresholds) {
        const count = patternKey === 'phone' ? ctx.phoneCount :
                      patternKey === 'email' ? ctx.emailCount : 1;
        
        // For phones, only escalate if locale profile allows it
        const shouldEscalate = patternKey !== 'phone' || phoneEscalationAllowed;
        
        if (shouldEscalate) {
          // Find highest applicable threshold
          const thresholds = Object.keys(config.escalationThresholds)
            .map(Number)
            .sort((a, b) => b - a); // Descending
          
          for (const threshold of thresholds) {
            if (count >= threshold) {
              const escalatedSeverity = config.escalationThresholds[threshold];
              newSeverity = maxSeverity(newSeverity, escalatedSeverity);
              if (DEBUG_POLICY) {
                console.log(`[AgentGuard] Policy escalated ${patternKey}: count=${count} >= ${threshold} => ${escalatedSeverity}`);
              }
              break;
            }
          }
        } else if (DEBUG_POLICY && patternKey === 'phone') {
          console.log(`[AgentGuard] Phone escalation suppressed by locale ${ctx.locale}: count=${count} < threshold=${localeProfile.phoneEscalationThreshold}`);
        }
      }
      
      // Apply co-occurrence escalation
      if (coOccurrenceTriggered && patternKey !== null &&
          policy.escalation.coOccurrence?.affectedPatterns.includes(patternKey)) {
        const bump = policy.escalation.coOccurrence.severityBump;
        let bumped = bumpSeverity(newSeverity, bump);
        // Apply co-occurrence cap
        if (policy.escalation.coOccurrence.maxSeverity) {
          bumped = capSeverity(bumped, policy.escalation.coOccurrence.maxSeverity);
        }
        if (DEBUG_POLICY && bumped !== newSeverity) {
          console.log(`[AgentGuard] Policy co-occurrence bump: ${patternKey} ${newSeverity} => ${bumped}`);
        }
        newSeverity = bumped;
      }
      
      // Apply density escalation (affects all PII)
      if (densityTriggered && patternKey !== null && ['phone', 'email', 'ssn'].includes(patternKey)) {
        const bump = policy.escalation.piiDensity!.severityBump;
        let bumped = bumpSeverity(newSeverity, bump);
        // Apply density cap
        if (policy.escalation.piiDensity!.maxSeverity) {
          bumped = capSeverity(bumped, policy.escalation.piiDensity!.maxSeverity);
        }
        if (DEBUG_POLICY && bumped !== newSeverity) {
          console.log(`[AgentGuard] Policy density bump: ${patternKey} ${newSeverity} => ${bumped}`);
        }
        newSeverity = bumped;
      }
      
      // Apply transactional document downgrade
      if (isTransactional && config.transactionalDowngrade && !config.hardFloor) {
        const reduced = reduceSeverity(newSeverity, 1);
        if (DEBUG_POLICY && reduced !== newSeverity) {
          console.log(`[AgentGuard] Policy transactional downgrade: ${patternKey} ${newSeverity} => ${reduced}`);
        }
        newSeverity = reduced;
      }
      
      // Apply severity cap (CRITICAL step - ensures phones never go above medium)
      if (config.maxSeverity) {
        const capped = capSeverity(newSeverity, config.maxSeverity);
        if (DEBUG_POLICY && capped !== newSeverity) {
          console.log(`[AgentGuard] Policy capped ${patternKey} severity: count=${ctx.phoneCount} => ${capped}`);
        }
        newSeverity = capped;
      }
      
      // Enforce hard floor (after all adjustments)
      if (config.hardFloor) {
        newSeverity = maxSeverity(newSeverity, config.baseSeverity);
      }
    }
    
    // Create adjusted signal (only if severity changed)
    if (newSeverity !== signal.severity) {
      result.push({
        ...signal,
        severity: newSeverity,
      });
    } else {
      result.push(signal);
    }
  }
  
  return result;
}

/**
 * Build signal context from text analysis results
 * Call this from analyzeTextContent if returning stats
 */
export function buildSignalContext(stats: {
  emailCount?: number;
  phoneCount?: number;
  ssnCount?: number;
  nameCount?: number;
  textLength?: number;
  bodyText?: string;
  sourceUrl?: string;
  metadata?: {
    author?: string;
    creator?: string;
    language?: string;
  };
}): SignalContext {
  // Detect locale from available context
  const localeResult = detectLikelyLocale({
    text: stats.bodyText,
    sourceUrl: stats.sourceUrl,
    metadata: stats.metadata,
  });
  
  return {
    emailCount: stats.emailCount || 0,
    phoneCount: stats.phoneCount || 0,
    ssnCount: stats.ssnCount || 0,
    nameCount: stats.nameCount || 0,
    textLength: stats.textLength,
    bodyText: stats.bodyText,
    isTransactional: stats.bodyText ? detectTransactionalDocument(stats.bodyText) : undefined,
    locale: localeResult.locale,
    localeConfidence: localeResult.confidence,
  };
}

/**
 * Validate a policy object (for future admin UI import)
 */
export function validatePolicy(policy: unknown): policy is Policy {
  if (!policy || typeof policy !== 'object') return false;
  const p = policy as Policy;
  if (typeof p.version !== 'string') return false;
  if (!p.signals || typeof p.signals !== 'object') return false;
  if (!p.escalation || typeof p.escalation !== 'object') return false;
  return true;
}

/**
 * Check if text indicates a transactional document
 * Exported for use in signal context building
 */
export function isTransactionalDocument(text: string): boolean {
  return detectTransactionalDocument(text);
}

// ============================================================================
// POLICY CONTRACT V1.0 - WITH LOCALE OVERLAYS
// ============================================================================

import {
  CURRENT_POLICY_VERSION,
  PolicyContract,
  SignalPolicy,
  SignalId,
  CooccurrenceRule,
  Severity as ContractSeverity,
  bumpSeverity as contractBumpSeverity,
  capSeverity as contractCapSeverity,
  maxSeverity as contractMaxSeverity,
  severityGte,
} from './contract';

import {
  DEFAULT_POLICY,
  getEffectivePolicy,
  legacyKeyToSignalId,
} from './defaultPolicy';

/**
 * Department identifiers for scoped policy (Premium feature)
 * Used for department-specific dictionaries and risk priorities
 */
export type DepartmentId = 'finance' | 'hr' | 'legal' | 'engineering' | 'default';

/**
 * Destination type for context-aware policy decisions
 */
export type DestinationType = 'public_ai' | 'internal_ai' | 'unknown';

/**
 * Context for policy application (v2)
 */
export interface PolicyContext {
  locale: LocaleKey;
  localeConfidence: LocaleConfidence;
  counts: {
    phone: number;
    email: number;
    ssn: number;
    [key: string]: number;
  };
  isTransactional: boolean;
  bodyText?: string;
  /** Department scope for dictionary-based detections (Premium) */
  department?: DepartmentId;
  /** Document type hint for specialized detection */
  documentType?: string;
  /** Destination type (public_ai, internal_ai, unknown) - derived from hostname */
  destination?: DestinationType;
}

/**
 * Apply Policy Contract v1.0 with locale overlays
 *
 * Flow:
 * 1. Merge DefaultPolicy + locale overlay
 * 2. Filter disabled signals
 * 3. Apply baseSeverity + maxSeverity
 * 4. Apply density escalators
 * 5. Apply cooccurrence escalators
 * 6. Enforce invariants (secrets mandatory, min HIGH)
 */
export function applyPolicyContract(
  signals: RiskSignal[],
  context: PolicyContext,
  policy: PolicyContract = DEFAULT_POLICY
): RiskSignal[] {
  if (!signals || signals.length === 0) {
    return signals;
  }

  // 1. Get effective policy with locale overlay merged
  const effectivePolicy = getEffectivePolicy(context.locale, policy);

  if (DEBUG_POLICY) {
    console.log(`[AgentGuard] PolicyContract v${effectivePolicy.version}: locale=${context.locale}, phones=${context.counts.phone}, emails=${context.counts.email}, transactional=${context.isTransactional}`);
  }

  // 2. Check cooccurrence rules
  const cooccurrenceTriggered = new Set<SignalId>();
  for (const rule of effectivePolicy.cooccurrence) {
    const allConditionsMet = rule.conditions.every(cond => {
      const count = getCountForSignalId(cond.signalId, context.counts);
      return count >= cond.minCount;
    });
    if (allConditionsMet) {
      rule.affects.forEach(id => cooccurrenceTriggered.add(id));
      if (DEBUG_POLICY) {
        console.log(`[AgentGuard] Cooccurrence rule triggered: ${rule.id}`);
      }
    }
  }

  // 3. Process each signal
  const result: RiskSignal[] = [];

  for (const signal of signals) {
    const legacyKey = getPatternKey(signal);
    const signalId = legacyKey ? legacyKeyToSignalId(legacyKey) : null;
    const config = signalId ? effectivePolicy.signals[signalId] : null;

    // Check if disabled (but respect invariants)
    const isMandatory = signalId && effectivePolicy.invariants.mandatorySignals.includes(signalId);
    if (config && !config.enabled && !isMandatory) {
      if (DEBUG_POLICY) {
        console.log(`[AgentGuard] Signal filtered by policy: ${signalId}`);
      }
      continue;
    }

    let newSeverity: Severity = signal.severity;

    if (config) {
      // Apply base severity
      if (!config.mandatory) {
        newSeverity = config.baseSeverity as Severity;
      } else {
        // Mandatory: never go below base
        newSeverity = maxSeverity(signal.severity, config.baseSeverity as Severity);
      }

      // Apply density thresholds
      if (config.densityThresholds && signalId) {
        const count = getCountForSignalId(signalId, context.counts);
        const thresholds = Object.keys(config.densityThresholds)
          .map(Number)
          .sort((a, b) => b - a);  // Descending

        for (const threshold of thresholds) {
          if (count >= threshold) {
            newSeverity = config.densityThresholds[threshold] as Severity;
            if (DEBUG_POLICY) {
              console.log(`[AgentGuard] Density escalation: ${signalId} count=${count} >= ${threshold} -> ${newSeverity}`);
            }
            break;
          }
        }
      }

      // Apply cooccurrence bump
      if (signalId && cooccurrenceTriggered.has(signalId)) {
        const rule = effectivePolicy.cooccurrence.find(r => r.affects.includes(signalId));
        if (rule) {
          newSeverity = bumpSeverity(newSeverity, rule.severityBump);
          newSeverity = capSeverity(newSeverity, rule.maxSeverity as Severity);
          if (DEBUG_POLICY) {
            console.log(`[AgentGuard] Cooccurrence bump: ${signalId} -> ${newSeverity}`);
          }
        }
      }

      // Apply transactional downgrade
      if (context.isTransactional && config.transactionalDowngrade && !config.mandatory) {
        const reduced = reduceSeverity(newSeverity, 1);
        if (DEBUG_POLICY && reduced !== newSeverity) {
          console.log(`[AgentGuard] Transactional downgrade: ${signalId} ${newSeverity} -> ${reduced}`);
        }
        newSeverity = reduced;
      }

      // Apply severity cap
      if (config.maxSeverity) {
        newSeverity = capSeverity(newSeverity, config.maxSeverity as Severity);
      }

      // Enforce mandatory minimum
      if (isMandatory) {
        newSeverity = maxSeverity(newSeverity, effectivePolicy.invariants.mandatoryMinSeverity as Severity);
      }
    }

    // Create adjusted signal
    if (newSeverity !== signal.severity) {
      result.push({
        ...signal,
        severity: newSeverity,
      });
    } else {
      result.push(signal);
    }
  }

  return result;
}

/**
 * Get count for a SignalId from context counts
 */
function getCountForSignalId(signalId: SignalId, counts: PolicyContext['counts']): number {
  const mapping: Record<string, string> = {
    'pii.phone': 'phone',
    'pii.email': 'email',
    'pii.ssn_us': 'ssn',
  };
  const key = mapping[signalId] || signalId;
  return counts[key] || 0;
}

// Re-export contract types and values
export { CURRENT_POLICY_VERSION } from './contract';
export type { PolicyContract, SignalPolicy, SignalId, CooccurrenceRule } from './contract';

// Re-export default policy values
export { DEFAULT_POLICY, getEffectivePolicy, legacyKeyToSignalId } from './defaultPolicy';

export type { ContractSeverity };

// Re-export locale types and functions for convenience
export type {
  LocaleKey,
  LocaleConfidence,
  LocaleDetectionResult,
  LocaleProfile,
  LocaleContext,
} from './locale';

export {
  detectLikelyLocale,
  getLocaleProfile,
  shouldEscalatePhones,
  validateLocaleProfiles,
} from './locale';