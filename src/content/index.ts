/**
 * AgentGuard Content Script v11
 * Enterprise-grade file upload risk awareness for AI platforms
 * With improved UX copy and click interception for detached file inputs
 *
 * ============================================================================
 * PRIVACY CONTRACT - AG-PROMPT-058
 * ============================================================================
 *
 * This content script runs on ALL HTTPS pages due to policy-driven targeting.
 * However, it implements STRICT activation gating to ensure privacy:
 *
 * ON NON-TARGET PAGES (early exit):
 * - ONLY window.location.hostname is read (for target matching)
 * - NO DOM access, scraping, or manipulation
 * - NO content extraction or text analysis
 * - NO event listeners installed (drag/drop, paste, file input)
 * - NO network interception or monitoring
 * - Script exits IMMEDIATELY after hostname check
 *
 * ON TARGET PAGES (AI platforms):
 * - Full AgentGuard functionality activates
 * - File upload interception and risk analysis enabled
 * - User-initiated uploads only (no background monitoring)
 *
 * Target pages are determined by:
 * 1. Built-in targets (ChatGPT, Claude, Gemini, etc.) - checked synchronously
 * 2. Admin-configured targets via managed storage policy - checked async
 *
 * This ensures "last-mile only" protection: AgentGuard monitors file uploads
 * ONLY on explicitly configured AI platforms, never general browsing activity.
 *
 * @see ADR-026: Policy-Driven Target Selection
 * @see AG-PROMPT-057: Policy-Driven Targets
 * @see AG-PROMPT-058: Activation Gating
 * ============================================================================
 */

import { extractMetadata, type DocumentMetadata, type RiskSignal, type SignalSource } from './metadataExtractor';
// AG-PROMPT-218: metadata risk-signal generation now lives behind a detection-owned boundary
import { analyzeMetadataForRisks } from '../detection/metadataSignals';
import { runDetection, type DetectionContext, type RiskSignal as DetectionRiskSignal } from '../detection';
import { validatePaymentCard } from '../detection/paymentCardValidation';
import {
  applyPolicyContract,
  detectLikelyLocale,
  isTransactionalDocument,
  validateLocaleProfiles,
  type PolicyContext,
  type LocaleContext,
  type LocaleKey,
  type DepartmentId,
} from '../policy/policy';
import { runDictionaryDetections } from '../policy/dictionaries';
// AG-PROMPT-237: reuse canonical 5-level severity rank helper instead of local duplicate maps
import { rankSeverityOrNone, SEVERITY_ORDER_WITH_NONE } from '../policy/severityRank';
// AG-PHASE-2-046: Registry detection removed — all patterns now in pack-based detection
import { validateSchema, DEFAULT_POLICY_SCHEMA } from '../policy/schema';
import { validatePolicyConfig } from '../policy/policyValidation';
import {
  buildExplanationBundle,
  getSignalKey,
  type ExplanationBundle,
  type RiskExplanation,
} from '../policy/explanations';
import {
  buildDecisionExplanation,
  enforceAwarenessVisibility,
  assertFrameComplete,
  type DecisionExplanation,
  type AwarenessVisibility,
  type ReasonCode,
  NOTICE_AUTO_DISMISS_MS,
} from '../policy/decisionExplanation';
import { FRAME_MAP } from '../data/awareness-frames';
import { sanitizeHeadlineForRender } from '../policy/awarenessFraming';
import { aggregateSeverity } from '../policy/severityAggregation';
import { deriveDestination, type DestinationType } from '../policy/destination';
import {
  calibrateInterpretation,
  extractDrivingSignals,
  type CalibrationResult,
} from '../policy/interpretationCalibration';
import {
  applyHumanHeuristics,
  type HeuristicResult,
} from '../policy/humanHeuristicAnchors';
import {
  enforceDecisionConsistency,
  type ConsistencyResult,
} from '../policy/decisionConsistency';
import {
  enforceMedicalRecordEscalation,
  type MedicalEscalationResult,
} from '../policy/medicalRecordEscalation';
import {
  enforceRegulatedVisibility,
  type VisibilityGuardrailResult,
} from '../policy/regulatedVisibilityGuardrail';
import {
  enforceSeverityFloor,
  type SeverityFloorResult,
} from '../policy/severityFloorEnforcement';
import {
  applyDocumentClassAnchors,
  type DocumentClassResult,
} from '../policy/documentClassAnchors';
import {
  buildAuthoritativeDecision,
  type AuthoritativeDecision,
} from '../policy/decisionAuthority';
// AG-PROMPT-SIGNAL-BYPASS-FIX-028: Severity ladder caps
import { applySeverityCaps } from '../policy/severityLadder';
import { deriveSurfaceConfidence } from '../policy/awarenessFraming';
// AG-PHASE-5E-058: Degraded document fallback classification
import {
  classifyDegradedDocument,
  type FallbackClassificationResult,
} from '../policy/degradedDocumentFallback';
import { isEncryptedReadableState, type PdfEncryptionReadability } from '../types/pdfEncryption';
// AG-PROMPT-162: Feature flags + clinical reference bypass
import { FF } from '../config/featureFlags';
import { PROTECTED_SIGNAL_IDS, getArchetypeEffects } from '../policy/documentArchetypes';
import {
  getEffectiveHostname,
  isTopFrame,
} from './scanScheduler';
// AG-CODEX-057A: Proper ID-based signal deduplication
import { deduplicateSignals } from './signalDedupe';

// AG-PROMPT-031: Evidence tracing
import { AG_DEBUG_EVIDENCE, createEvidence } from '../detection/evidenceCapture';
import type { EvidenceItem } from '../types/riskSignal';

// AG-PROMPT-058: Activation gating for policy-driven targets
import {
  checkActivationGate,
  isBuiltinTarget,
  type GateResult,
} from './activationGate';

// AG-PROMPT-044: Debug diagnostics
import {
  isDebugMode,
  debugLog,
  countSignalsByType,
  logBoundaryCounters,
  emptyBoundaryCounters,
  storeDebugSummary,
  runCanaryDetection,
  CANARY_SIGNAL_TYPE,
  type BoundaryCounters,
  type DebugSummary,
} from '../debug';

// AG-PROMPT-134: Decision quality blocks
import {
  deriveDecisionQualityBlocks,
} from './decisionQualityBlocks';

// AG-SECURITY-HARDENING-SEC-01: Safe DOM rendering utilities
import {
  buildDragOverlay,
  buildLoadingModal,
  buildRiskModal,
  buildAwarenessNotice,
  buildAwarenessBanner,
  buildSignalsSection,
  buildMetadataSection,
  buildLicenseNotice,
  showPostDecisionToast,
  type UploadTriggerSource,
  type ModalOptions,
  type NoticeOptions,
  type BannerOptions,
} from './uiComponents';
import { el, setChildren } from '../lib/safeDom';
// AG-PROMPT-214: extracted modal CSS + render/format helpers
import { createStyles } from './modalStyles';
import {
  formatFileSize,
  formatScannedSources,
  hasMetadataToShow,
} from './modalRenderHelpers';

// Re-export types
export type { RiskSignal, SignalSource };
export type { ExplanationBundle, RiskExplanation };
export type { DecisionExplanation };

// ============================================================================
// CONFIGURATION
// ============================================================================

const ENFORCE_BLOCKING = false;

// ============================================================================
// STARTUP VALIDATION (one-time)
// ============================================================================

let startupValidated = false;

function runStartupValidation(): void {
  if (startupValidated) return;
  startupValidated = true;

  // Validate policy schema (legacy validation)
  const schemaResult = validateSchema(DEFAULT_POLICY_SCHEMA);
  console.log(`[AgentGuard] Policy schema validated: ok=${schemaResult.valid}`);
  if (!schemaResult.valid) {
    console.warn('[AgentGuard] Schema errors:', schemaResult.errors.length);
  }

  // Enhanced policy validation (AG-PROMPT-034)
  // Uses strict mode by default - falls back to defaults on error
  const policyResult = validatePolicyConfig(DEFAULT_POLICY_SCHEMA, {
    strictMode: true,
    logResults: true,
  });
  // policyResult.policy contains the validated policy (or defaults on error)

  // Validate locale profiles
  const localeOk = validateLocaleProfiles();
  console.log(`[AgentGuard] LocaleProfiles active: ok=${localeOk}`);
}

// ============================================================================
// DEPARTMENT OVERRIDE (TEST/PREMIUM)
// ============================================================================

const VALID_DEPARTMENTS: DepartmentId[] = ['default', 'finance', 'hr', 'legal', 'engineering'];

/**
 * Get department override for testing/premium features.
 * Priority: URL query param > localStorage > 'default'
 *
 * Usage:
 *   - localStorage.setItem('ainotice.department', 'finance')  (preferred)
 *   - localStorage.setItem('agentguard.department', 'finance')  (legacy alias)
 *   - URL: ?ag_department=hr
 *
 * @returns Valid DepartmentId or 'default'
 */
function getDepartmentOverride(): DepartmentId {
  // 1. Check URL query param (highest priority)
  try {
    const urlParams = new URLSearchParams(window.location.search);
    const urlDept = urlParams.get('ag_department');
    if (urlDept && VALID_DEPARTMENTS.includes(urlDept as DepartmentId)) {
      console.log(`[AgentGuard] Department override active: ${urlDept} (from URL)`);
      return urlDept as DepartmentId;
    }
  } catch {
    // URL parsing failed, continue to localStorage
  }

  // 2. Check localStorage (current key first, then legacy alias)
  try {
    const storedDept = localStorage.getItem('ainotice.department') ??
                       localStorage.getItem('agentguard.department');
    if (storedDept && VALID_DEPARTMENTS.includes(storedDept as DepartmentId)) {
      console.log(`[AgentGuard] Department override active: ${storedDept} (from localStorage)`);
      return storedDept as DepartmentId;
    }
  } catch {
    // localStorage access failed (e.g., privacy mode)
  }

  // 3. Default
  return 'default';
}

// ============================================================================
// TYPES
// ============================================================================

interface FileRiskAssessment {
  filename: string;
  size: number;
  type: string;
  /** All detected signals (raw, for internal use) */
  signals: RiskSignal[];
  /**
   * Signals to display in the UI (AG-PROMPT-043).
   * These are consistency-enforced: no signal severity exceeds overallRisk.
   * UI MUST use this field instead of `signals` to avoid decision/signal contradictions.
   */
  visibleSignals: RiskSignal[];
  /**
   * Overall risk level including 'none' for zero-signal state.
   * AG-PROMPT-061: Added 'none' to support zero-signal UI messaging.
   */
  overallRisk: 'none' | 'low' | 'medium' | 'high' | 'critical';
  metadata?: DocumentMetadata;
  scannedSources: Set<SignalSource>;
  /** Optional structured explanations (data-only, for future UI) */
  explanations?: ExplanationBundle;
  /** Optional decision explanation payload (AG-PROMPT-036, data-only) */
  decisionExplanation?: DecisionExplanation;
  /** AG-PROMPT-073: PDF extraction status for awareness frame selection */
  pdfExtractionFailed?: boolean;
  /** Encryption readability classification for encrypted-PDF edge cases */
  pdfEncryptionReadability?: PdfEncryptionReadability;
  /** AG-PROMPT-196: What user action triggered this scan — drives modal copy selection */
  triggerSource?: UploadTriggerSource;
}

// ============================================================================
// STATE
// ============================================================================

let overlayElement: HTMLDivElement | null = null;
let modalElement: HTMLDivElement | null = null;
let bannerElement: HTMLDivElement | null = null;  // AG-PROMPT-067: Awareness banner
let isProcessingUpload = false;
let recentlyInjectedFiles: Set<string> = new Set();

/**
 * AG-PROMPT-01: Memory cap for recentlyInjectedFiles Set.
 * Reduced from 200 (clear-all) to 100 (FIFO eviction).
 * JavaScript Set preserves insertion order, so the oldest entry is
 * always values().next().value. On cap, we evict the oldest entry
 * rather than clearing the whole Set, preventing dedup thrash.
 * Worst case: a recently-seen file key is re-processed once after eviction.
 * This is cosmetic, not a security boundary.
 */
const RECENTLY_INJECTED_FILES_CAP = 100;

// ============================================================================
// AG-AUDIT-FIX-001: DETECTION TIMEOUT CONSTANT
// ============================================================================

/**
 * Maximum time allowed for detection pipeline execution.
 * If detection exceeds this threshold, results are discarded (fail-open)
 * and a warning is logged. This prevents pathological documents from
 * stalling the content script indefinitely.
 */
const DETECTION_TIMEOUT_MS = 2000;

// CLIP-RT-01: Minimum character count for raw clipboard text to trigger awareness scan.
// Below this threshold, pastes are allowed through without scanning.
const RAW_CLIPBOARD_TEXT_MIN_CHARS = 20;

// ============================================================================
// UX-02: SAFE MESSAGE WRAPPER
// ============================================================================

/**
 * UX-02: Safely send a message to the background script with fail-open semantics.
 * Handles extension disconnect (e.g., extension updated/unloaded while page is open)
 * and any other runtime errors gracefully.
 *
 * Returns the response on success, or undefined on failure.
 * NEVER throws — all errors are caught and logged as warnings.
 */
async function safeSendMessage(message: { type: string; payload?: unknown }): Promise<unknown | undefined> {
  try {
    const response = await chrome.runtime.sendMessage(message);
    // Check for chrome.runtime.lastError (set when extension context is invalidated)
    if (chrome.runtime.lastError) {
      console.warn('[AgentGuard] sendMessage error:', chrome.runtime.lastError.message);
      return undefined;
    }
    return response;
  } catch (e) {
    // Extension context invalidated (unloaded, updated, or crashed)
    console.warn('[AgentGuard] sendMessage failed (extension may be disconnected):', e);
    return undefined;
  }
}

// ============================================================================
// SAFE DEBUG MODE (AG-PROMPT-095)
// ============================================================================

/**
 * Safe debug flag - set window.__AINOTICE_DEBUG_SAFE = true to enable.
 * Legacy alias: window.__AGENTGUARD_DEBUG_SAFE = true also works.
 * All debug logs are structured JSON and never contain sensitive content.
 */
declare global {
  interface Window {
    __AINOTICE_DEBUG_SAFE?: boolean;
    __AGENTGUARD_DEBUG_SAFE?: boolean; // legacy alias
  }
}

/**
 * Check if safe debug mode is enabled.
 */
function isSafeDebugEnabled(): boolean {
  return typeof window !== 'undefined' &&
    (window.__AINOTICE_DEBUG_SAFE === true || window.__AGENTGUARD_DEBUG_SAFE === true);
}

/**
 * Safe debug log - only logs when debug mode is enabled.
 * All logs are structured JSON with counts/codes only, no sensitive content.
 */
function safeDebugLog(event: string, data: Record<string, unknown>): void {
  if (!isSafeDebugEnabled()) return;
  console.log(`[AgentGuard:DEBUG] ${event}`, JSON.stringify(data));
}

// ============================================================================
// RISK DETECTION (Filename-based)
// ============================================================================

const RISK_PATTERNS: Array<{
  pattern: RegExp;
  type: RiskSignal['type'];
  description: string;
  severity: RiskSignal['severity'];
  detail: string;
}> = [
  { pattern: /passport/i, type: 'pii', description: 'Passport document', severity: 'critical', detail: 'Passport documents contain highly sensitive personal identification information.' },
  { pattern: /ssn|social.?security/i, type: 'pii', description: 'Social Security Number', severity: 'critical', detail: 'SSN is a critical identifier that can enable identity theft.' },
  { pattern: /driver.?licen[sc]e/i, type: 'pii', description: 'Driver license', severity: 'high', detail: 'Driver license contains personal identification information.' },
  { pattern: /birth.?cert/i, type: 'pii', description: 'Birth certificate', severity: 'high', detail: 'Birth certificates are primary identity documents.' },
  { pattern: /tax.?return|w-?2|1099|w-?9/i, type: 'financial', description: 'Tax document', severity: 'critical', detail: 'Tax documents contain SSN, income details, and financial information.' },
  { pattern: /bank.?statement/i, type: 'financial', description: 'Bank statement', severity: 'high', detail: 'Bank statements reveal account numbers and financial transactions.' },
  { pattern: /invoice|payment|salary|payroll/i, type: 'financial', description: 'Financial document', severity: 'medium', detail: 'Contains payment or compensation information.' },
  { pattern: /budget|forecast|revenue/i, type: 'financial', description: 'Financial planning', severity: 'medium', detail: 'May contain confidential business financial projections.' },
  { pattern: /confidential|secret|classified/i, type: 'confidential', description: 'Marked confidential', severity: 'critical', detail: 'Document is explicitly marked as confidential in filename.' },
  { pattern: /nda|non.?disclosure/i, type: 'legal', description: 'NDA/Legal agreement', severity: 'high', detail: 'Non-disclosure agreements contain confidential obligations.' },
  { pattern: /contract|agreement|terms/i, type: 'legal', description: 'Contract/Agreement', severity: 'medium', detail: 'Legal documents often contain sensitive terms and conditions.' },
  { pattern: /patent|trademark|copyright/i, type: 'ip', description: 'IP document', severity: 'high', detail: 'Intellectual property documents may contain proprietary innovations.' },
  { pattern: /proprietary|trade.?secret/i, type: 'ip', description: 'Proprietary information', severity: 'critical', detail: 'Trade secrets lose protection if disclosed publicly.' },
  { pattern: /employee|personnel|hr|human.?resource/i, type: 'sensitive', description: 'HR document', severity: 'medium', detail: 'HR documents contain employee personal information.' },
  { pattern: /performance.?review|evaluation/i, type: 'sensitive', description: 'Employee evaluation', severity: 'high', detail: 'Performance reviews contain sensitive personal assessments.' },
  { pattern: /medical|health|hipaa|diagnosis/i, type: 'pii', description: 'Health information', severity: 'critical', detail: 'Health data is protected under privacy laws (e.g., GDPR health data rules).' },
  { pattern: /resume|cv|curriculum/i, type: 'pii', description: 'Resume/CV', severity: 'medium', detail: 'Resumes contain personal contact and career information.' },
  { pattern: /\.env|credentials|api.?key|secret/i, type: 'confidential', description: 'Credentials file', severity: 'critical', detail: 'May contain API keys, passwords, or access tokens.' },
  { pattern: /private.?key|\.pem|\.key$/i, type: 'confidential', description: 'Private key', severity: 'critical', detail: 'Private keys enable authentication and decryption — never share.' },
];

function analyzeFilename(filename: string): RiskSignal[] {
  const signals: RiskSignal[] = [];
  for (const { pattern, type, description, severity, detail } of RISK_PATTERNS) {
    // AG-PROMPT-031: Use exec when evidence is enabled
    if (AG_DEBUG_EVIDENCE) {
      pattern.lastIndex = 0;
      const execMatch = pattern.exec(filename);
      if (execMatch) {
        let evidence: EvidenceItem[] | undefined;
        const ev = createEvidence({
          signal_id: `filename.${description.toLowerCase().replace(/\s+/g, '_')}`,
          origin_path: 'filename',
          producer: 'index.analyzeFilename',
          rule_id: null,
          matched_text: execMatch[0],
          start_index: execMatch.index,
          end_index: execMatch.index + execMatch[0].length,
          full_text: filename,
          location: 'FILENAME',
          field: null,
        });
        if (ev) evidence = [ev];
        signals.push({ type, description, severity, detail, source: 'filename', detectedAt: Date.now(), evidence });
      }
    } else if (pattern.test(filename)) {
      signals.push({ type, description, severity, detail, source: 'filename', detectedAt: Date.now() });
    }
  }
  return signals;
}

/**
 * Legacy text content analysis (AG-PROMPT-051)
 *
 * FALLBACK ONLY: This function contains hardcoded patterns that predate the
 * locale-aware detection pack system. It runs ONLY when detection packs
 * yield 0 signals, to catch edge cases the packs may miss.
 *
 * DO NOT ADD NEW PATTERNS HERE. Add them to detection packs instead.
 * See src/detection/packs/ for the primary detection mechanism.
 */
function analyzeTextContentLegacy(content: string, source: SignalSource): RiskSignal[] {
  const signals: RiskSignal[] = [];
  const loc: EvidenceItem['source']['location'] = source === 'content' ? 'CONTENT' : source === 'metadata' ? 'METADATA' : 'FILENAME';

  // AG-PROMPT-031: Helper for legacy evidence capture
  function legacyEvidence(regex: RegExp, signalId: string): EvidenceItem[] | undefined {
    if (!AG_DEBUG_EVIDENCE) return undefined;
    const execMatch = regex.exec(content);
    if (execMatch) {
      const ev = createEvidence({
        signal_id: signalId,
        origin_path: 'legacy',
        producer: 'index.analyzeTextContentLegacy',
        rule_id: null,
        matched_text: execMatch[0],
        start_index: execMatch.index,
        end_index: execMatch.index + execMatch[0].length,
        full_text: content,
        location: loc,
        field: null,
      });
      return ev ? [ev] : undefined;
    }
    return undefined;
  }

  if (/\b\d{3}-\d{2}-\d{4}\b/.test(content)) {
    signals.push({ type: 'pii', description: 'SSN pattern detected', severity: 'critical', detail: 'File contains text matching Social Security Number format (XXX-XX-XXXX).', source, detectedAt: Date.now(), evidence: legacyEvidence(/\b\d{3}-\d{2}-\d{4}\b/, 'legacy.ssn') });
  }
  // AG-PROMPT-SIGNAL-VALIDATION-GATES-024: Payment card validation gates
  // Only emit payment card signal if Luhn + issuer prefix validation passes
  const cardRegex = /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g;
  let cardMatch: RegExpExecArray | null;
  while ((cardMatch = cardRegex.exec(content)) !== null) {
    const validationResult = validatePaymentCard(cardMatch[0], content, cardMatch.index);
    if (validationResult.isValidCard) {
      let cardEvidence: EvidenceItem[] | undefined;
      if (AG_DEBUG_EVIDENCE) {
        const ev = createEvidence({
          signal_id: 'legacy.payment_card',
          origin_path: 'legacy',
          producer: 'index.analyzeTextContentLegacy',
          rule_id: null,
          matched_text: cardMatch[0],
          start_index: cardMatch.index,
          end_index: cardMatch.index + cardMatch[0].length,
          full_text: content,
          location: loc,
          field: null,
        });
        if (ev) cardEvidence = [ev];
      }
      signals.push({ type: 'financial', description: 'Payment card pattern', severity: 'critical', detail: 'File contains text matching credit/debit card number format.', source, detectedAt: Date.now(), evidence: cardEvidence });
      break; // Only need one signal
    }
  }
  const emailCount = (content.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g) || []).length;
  if (emailCount > 5) {
    signals.push({ type: 'pii', description: `${emailCount} email addresses`, severity: 'medium', detail: 'File contains multiple email addresses which may be personal data.', source, detectedAt: Date.now(), evidence: legacyEvidence(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/, 'legacy.email') });
  }
  if (/\b(sk-|pk_|api[_-]?key|bearer\s+[a-z0-9]+)/i.test(content)) {
    signals.push({ type: 'confidential', description: 'API key pattern', severity: 'critical', detail: 'File appears to contain API keys or access tokens.', source, detectedAt: Date.now(), evidence: legacyEvidence(/\b(sk-|pk_|api[_-]?key|bearer\s+[a-z0-9]+)/i, 'legacy.api_key') });
  }
  if (/AKIA[0-9A-Z]{16}/.test(content)) {
    signals.push({ type: 'confidential', description: 'AWS access key', severity: 'critical', detail: 'File contains an AWS access key ID pattern.', source, detectedAt: Date.now(), evidence: legacyEvidence(/AKIA[0-9A-Z]{16}/, 'legacy.aws_key') });
  }
  if (/password\s*[:=]\s*\S+/i.test(content)) {
    signals.push({ type: 'confidential', description: 'Password detected', severity: 'critical', detail: 'File appears to contain a password.', source, detectedAt: Date.now(), evidence: legacyEvidence(/password\s*[:=]\s*\S+/i, 'legacy.password') });
  }
  // NOTE: Phone detection removed from here - now handled by locale-aware detection packs
  // See src/detection/packs/nordic.ts for conservative phone patterns
  if (/\b(confidential|secret|classified|internal\s+only|restricted|proprietary)\b/i.test(content)) {
    signals.push({ type: 'confidential', description: 'Confidentiality marker in text', severity: 'high', detail: 'Document text contains confidentiality markers.', source, detectedAt: Date.now(), evidence: legacyEvidence(/\b(confidential|secret|classified|internal\s+only|restricted|proprietary)\b/i, 'legacy.confidential') });
  }
  if (/\b(bank\s+account|routing\s+number|swift|iban|wire\s+transfer)\b/i.test(content)) {
    signals.push({ type: 'financial', description: 'Banking information', severity: 'high', detail: 'File contains banking or wire transfer details.', source, detectedAt: Date.now(), evidence: legacyEvidence(/\b(bank\s+account|routing\s+number|swift|iban|wire\s+transfer)\b/i, 'legacy.banking') });
  }
  if (/\b(whereas|hereby|indemnify|liability|jurisdiction|arbitration|governing\s+law)\b/i.test(content)) {
    signals.push({ type: 'legal', description: 'Legal language detected', severity: 'medium', detail: 'File contains legal contract language.', source, detectedAt: Date.now(), evidence: legacyEvidence(/\b(whereas|hereby|indemnify|liability|jurisdiction|arbitration|governing\s+law)\b/i, 'legacy.legal') });
  }
  if (/\b(acquisition|merger|due\s+diligence|letter\s+of\s+intent|term\s+sheet|valuation)\b/i.test(content)) {
    signals.push({ type: 'confidential', description: 'M&A content detected', severity: 'critical', detail: 'File contains merger/acquisition-related content.', source, detectedAt: Date.now(), evidence: legacyEvidence(/\b(acquisition|merger|due\s+diligence|letter\s+of\s+intent|term\s+sheet|valuation)\b/i, 'legacy.ma') });
  }
  if (/\b(salary|compensation|performance\s+review|termination|disciplinary)\b/i.test(content)) {
    signals.push({ type: 'pii', description: 'HR/Employee data', severity: 'high', detail: 'File contains HR or employee-related information.', source, detectedAt: Date.now(), evidence: legacyEvidence(/\b(salary|compensation|performance\s+review|termination|disciplinary)\b/i, 'legacy.hr') });
  }

  return signals;
}

/**
 * Wrapper for backward compatibility with document file path (AG-PROMPT-051).
 * TODO: Migrate document file path to runTextDetectionStrategy() in future prompt.
 */
function analyzeTextContent(content: string, source: SignalSource): RiskSignal[] {
  return analyzeTextContentLegacy(content, source);
}

// ============================================================================
// TEXT DETECTION STRATEGY (AG-PROMPT-051)
// ============================================================================

/**
 * Unified text detection strategy (AG-PROMPT-051)
 *
 * Strategy: Detection packs PRIMARY, legacy heuristics FALLBACK-ONLY
 *
 * 1. Run locale-aware detection packs (primary mechanism)
 * 2. If packs yield 0 signals, run legacy heuristics as fallback
 * 3. Return combined result with timing
 *
 * This consolidates text file detection into a single, predictable path.
 * The legacy fallback catches edge cases the packs may miss until the
 * packs are fully comprehensive.
 *
 * @param text - Extracted text content
 * @param source - Signal source ('content' or 'metadata')
 * @param filename - Original filename (for context)
 * @param mimeType - MIME type (for context)
 * @returns Detection result with signals and diagnostics
 */
interface TextDetectionResult {
  /** All detected signals */
  signals: RiskSignal[];
  /** Whether legacy fallback was used */
  usedLegacyFallback: boolean;
  /** Detection timing in ms */
  detectionMs: number;
}

function runTextDetectionStrategy(
  text: string,
  source: SignalSource,
  filename: string,
  mimeType: string
): TextDetectionResult {
  const startTime = performance.now();
  const signals: RiskSignal[] = [];
  let usedLegacyFallback = false;

  // Step 1: Run detection packs (PRIMARY)
  const detectionContext: DetectionContext = {
    text,
    source,
    filename,
    mimeType,
  };
  // AG-AUDIT-FIX-002: Detection timeout — fail-open if exceeded
  const detectStartTimeout = performance.now();
  let packResult = runDetection(detectionContext);
  const detectElapsed = performance.now() - detectStartTimeout;
  if (detectElapsed > DETECTION_TIMEOUT_MS) {
    console.warn(`[AgentGuard] Detection timeout exceeded (${detectElapsed.toFixed(0)}ms > ${DETECTION_TIMEOUT_MS}ms) — fail-open, discarding results`);
    packResult = { signals: [], packsExecuted: packResult.packsExecuted };
  }
  const packSignals = packResult.signals.map(s => ({
    ...s,
    source: s.source as SignalSource,
  }));
  signals.push(...packSignals);

  // Step 2: FALLBACK - Run legacy heuristics only if packs found nothing
  if (packSignals.length === 0) {
    const legacySignals = analyzeTextContentLegacy(text, source);
    if (legacySignals.length > 0) {
      usedLegacyFallback = true;
      signals.push(...legacySignals);
      if (isDebugMode()) {
        debugLog('TextStrategy', `Legacy fallback activated: ${legacySignals.length} signals`, {
          filename,
          packSignals: 0,
          legacySignals: legacySignals.length,
        });
      }
    }
  } else if (isDebugMode()) {
    debugLog('TextStrategy', `Packs detected ${packSignals.length} signals, skipping legacy fallback`, {
      filename,
      packSignals: packSignals.length,
    });
  }

  const detectionMs = performance.now() - startTime;

  return {
    signals,
    usedLegacyFallback,
    detectionMs,
  };
}

// ============================================================================
// VISIBLE SIGNALS (AG-PROMPT-043)
// ============================================================================

/**
 * Create UI-visible signals with consistency enforcement (AG-PROMPT-043).
 *
 * Ensures no signal shown to user has severity > decision severity.
 * This prevents contradictions like "Low risk" banner with "Critical" signal.
 *
 * @param signals - Processed signals (post-calibration/heuristics/document class)
 * @param decisionSeverity - Authoritative decision severity
 * @returns Signals safe for UI display with capped severities
 */
function createVisibleSignals(
  signals: RiskSignal[],
  decisionSeverity: RiskSignal['severity']
): RiskSignal[] {
  const maxSeverityIndex = rankSeverityOrNone(decisionSeverity);

  return signals.map(signal => {
    const signalSeverityIndex = rankSeverityOrNone(signal.severity);

    // If signal severity exceeds decision, cap it
    if (signalSeverityIndex > maxSeverityIndex) {
      return {
        ...signal,
        severity: decisionSeverity,
        // Append note that severity was capped (for debugging, not shown to user)
        detail: signal.detail,
      };
    }

    return signal;
  });
}

/**
 * Performance timing for file assessment (AG-PROMPT-043).
 * Local-only metrics - no network/telemetry.
 */
interface AssessmentTiming {
  totalMs: number;
  extractionMs: number;
  detectionMs: number;
  policyMs: number;
}

/**
 * Performance budget thresholds (AG-PROMPT-043).
 * Conservative values to avoid flaky tests.
 */
const PERF_BUDGET = {
  /** Maximum time for small PDF extraction (< 1MB) */
  SMALL_PDF_EXTRACTION_MS: 2000,
  /** Maximum time for total small file assessment */
  SMALL_FILE_TOTAL_MS: 5000,
  /** Warning threshold for total assessment */
  TOTAL_WARNING_MS: 3000,
} as const;

async function assessFileRisk(file: File): Promise<FileRiskAssessment> {
  // AG-PROMPT-043: Performance timing (local-only)
  const perfStart = performance.now();
  let extractionMs = 0;
  let detectionMs = 0;
  let policyMs = 0;

  // AG-PROMPT-044: Initialize boundary counters for debug diagnostics
  const boundaryCounters: BoundaryCounters = emptyBoundaryCounters();
  let canaryDetected = false;

  // Run startup validation once
  runStartupValidation();

  const signals: RiskSignal[] = [];
  let metadata: DocumentMetadata | undefined;
  const scannedSources = new Set<SignalSource>();
  let bodyText: string | undefined;  // Track for locale detection + policy
  let pdfExtractionFailed = false;  // AG-PROMPT-073: Track PDF extraction failure
  let pdfEncryptionReadability: PdfEncryptionReadability = 'NOT_ENCRYPTED';
  let degradedFallbackResult: FallbackClassificationResult | null = null;  // AG-PHASE-5E-058: Degraded PDF fallback

  // AG-PROMPT-095: Safe debug log for assessment start
  safeDebugLog('ASSESSMENT_START', {
    filename: file.name,
    sizeBytes: file.size,
    mimeType: file.type || 'unknown',
  });

  // 1. Filename-based analysis (always)
  const filenameSignals = analyzeFilename(file.name);
  signals.push(...filenameSignals);
  scannedSources.add('filename');

  // 2. Content-based analysis for text files
  const textTypes = ['text/', 'application/json', 'application/xml', 'application/javascript'];
  const isTextFile = textTypes.some(t => file.type.startsWith(t)) ||
                     /\.(txt|md|json|xml|csv|tsv|js|ts|py|rb|java|c|cpp|h|css|html|yaml|yml|ini|cfg|conf|log|sql|env|pem|key|crt|cer|pub|eml|sh|bash|zsh|ps1|bat|cmd|properties|toml|htaccess|htpasswd|rst|adoc|tex)$/i.test(file.name);

  if (isTextFile && file.size < 1024 * 1024) {
    try {
      // AG-PROMPT-051: Unified text detection strategy
      // Extraction
      const extractStart = performance.now();
      const content = await file.text();
      extractionMs = performance.now() - extractStart;

      bodyText = content;  // Capture for policy
      scannedSources.add('content');

      // Detection: packs PRIMARY, legacy FALLBACK-ONLY
      if (content.length > 0) {
        const strategyResult = runTextDetectionStrategy(
          content,
          'content',
          file.name,
          file.type
        );
        signals.push(...strategyResult.signals);
        detectionMs = strategyResult.detectionMs;

        // AG-PROMPT-044: Run canary detection (debug-only)
        const canarySignals = runCanaryDetection(content, 'content');
        if (canarySignals.length > 0) {
          canaryDetected = true;
          signals.push(...canarySignals.map(s => ({
            ...s,
            source: s.source as SignalSource,
          })));
        }

        if (isDebugMode() && strategyResult.usedLegacyFallback) {
          debugLog('TextFile', `Legacy fallback used for ${file.name}`);
        }
      }
    } catch (e) {
      console.warn('[AgentGuard] Could not read file content:', e);
    }
  }
  
  // 3. Metadata and body extraction for Office documents and PDFs
  const extension = file.name.split('.').pop()?.toLowerCase();
  const isDocumentFile = ['pdf', 'docx', 'xlsx', 'pptx'].includes(extension || '');

  if (isDocumentFile && file.size < 50 * 1024 * 1024) {
    try {
      // AG-PROMPT-043: Time extraction
      const extractStart = performance.now();
      const result = await extractMetadata(file);
      extractionMs = performance.now() - extractStart;

      if (result.success && result.metadata) {
        metadata = result.metadata;
        const metadataSignals = analyzeMetadataForRisks(metadata);
        signals.push(...metadataSignals);
        scannedSources.add('metadata');

        // AG-PROMPT-073: Check PDF extraction status
        if (result.fileType === 'pdf' && result.pdfExtractionStatus) {
          pdfEncryptionReadability = result.pdfExtractionStatus.encryptionReadability;
          if (result.pdfExtractionStatus.extractionFailed) {
            pdfExtractionFailed = true;
            console.log(`[AgentGuard] PDF extraction failed: ${result.pdfExtractionStatus.reasonCode}`);
          }
        }

        if (result.bodyText && result.bodyText.length > 0) {
          bodyText = result.bodyText;  // Capture for policy
          // AG-PROMPT-SIGNAL-PARITY-029: REMOVED legacy analyzeTextContent() for PDFs.
          // It ran bare-keyword regexes (matching "swift", "diagnosis", etc.) without
          // quality gates, producing false positives. PDFs now use ONLY:
          //   - Detection packs (runDetection) with quality gates
          //   - Registry patterns (runContentDetection) with structural validation
          //   - Dictionary detections (runDictionaryDetections) with minHits thresholds
          scannedSources.add('content');

          // AG-PROMPT-043: Time detection packs
          const detectStart = performance.now();

          // Run locale-aware detection packs (for phone detection etc.)
          // Uses metadata hints to determine locale confidence
          const detectionContext: DetectionContext = {
            text: result.bodyText,
            source: 'content',
            filename: file.name,
            mimeType: file.type,
            metadata: metadata ? {
              author: metadata.author,
              creator: metadata.creator,
              producer: metadata.producer,
            } : undefined,
          };
          // AG-AUDIT-FIX-002: Detection timeout — fail-open if exceeded
          const detectStartTimeout2 = performance.now();
          let detectionResult = runDetection(detectionContext);
          const detectElapsed2 = performance.now() - detectStartTimeout2;
          if (detectElapsed2 > DETECTION_TIMEOUT_MS) {
            console.warn(`[AgentGuard] Detection timeout exceeded (${detectElapsed2.toFixed(0)}ms > ${DETECTION_TIMEOUT_MS}ms) — fail-open, discarding results`);
            detectionResult = { signals: [], packsExecuted: detectionResult.packsExecuted };
          }
          // Add signals from detection packs (phones will only appear if locale confidence is sufficient)
          signals.push(...detectionResult.signals.map(s => ({
            ...s,
            source: s.source as SignalSource,
          })));

          // AG-PROMPT-044: Run canary detection (debug-only)
          const canarySignals = runCanaryDetection(result.bodyText, 'content');
          if (canarySignals.length > 0) {
            canaryDetected = true;
            signals.push(...canarySignals.map(s => ({
              ...s,
              source: s.source as SignalSource,
            })));
          }

          detectionMs = performance.now() - detectStart;
        } else if (result.fileType === 'pdf') {
          // AG-PROMPT-073: PDF with no body text - mark as extraction failed
          if (!isEncryptedReadableState(result.pdfExtractionStatus?.encryptionReadability)) {
            pdfExtractionFailed = true;
          }
        }

        // AG-PROMPT-184/WS-01: Surface degraded/blocked extraction as extraction-limited.
        // Previously, pdfExtractionFailed was only set when bodyText was empty.
        // Degraded quality (e.g. font-encoded garbage) with non-empty bodyText was silently
        // passed through, producing zero signals and no user warning. Now degraded/blocked
        // quality also sets pdfExtractionFailed so the extraction-limited frame shows.
        //
        // AG-PHASE-5E-058: Apply degraded document fallback classification
        // When PDF extraction is degraded or blocked, use filename/metadata to infer document class
        if (result.fileType === 'pdf' && result.pdfExtractionStatus?.quality) {
          const quality = result.pdfExtractionStatus.quality;
          if (quality === 'degraded' || quality === 'blocked') {
            if (!pdfExtractionFailed) {
              pdfExtractionFailed = true;
            }
            degradedFallbackResult = classifyDegradedDocument(
              file.name,
              metadata ? {
                title: metadata.title,
                subject: metadata.subject,
                keywords: metadata.keywords,
                author: metadata.author,
              } : undefined,
              quality
            );
            if (degradedFallbackResult.applied) {
              console.log(`[AgentGuard] Degraded fallback: domain=${degradedFallbackResult.domain} tokenCount=${degradedFallbackResult.matchedTokens.length} source=${degradedFallbackResult.source}`);
            }
          }
        }
      }
    } catch (e) {
      console.warn('[AgentGuard] Metadata extraction error:', e);
    }
  }

  // AG-PROMPT-151: Truthful unscanned-file notification
  // If file content was not scanned (no content or metadata extraction succeeded),
  // notify the user. This replaces the old allowlist approach (AG-AUDIT-FIX-003)
  // with an inverted check: ANY unscanned file gets notified, not just known binaries.
  // This eliminates the silent-skip trust gap for legacy Office, OpenDocument, etc.
  if (!scannedSources.has('content') && !scannedSources.has('metadata')) {
    signals.push({
      type: 'sensitive',
      id: 'info.unscanned_file_type',
      description: `File type not analyzed for content (${extension || 'unknown'})`,
      severity: 'low',
      source: 'filename',
      detectedAt: Date.now(),
    });
  }

  // Deduplicate signals using canonical ID-based deduplication (AG-CODEX-057A)
  // FIXED: Previously used type+description which could miss duplicates with same ID but different descriptions
  const uniqueSignals = deduplicateSignals(signals);

  // === POLICY LAYER (ADR-009 + ADR-010) ===
  // Detect locale from document context
  const localeContext: LocaleContext = {
    text: bodyText?.substring(0, 5000),  // Limit for performance
    sourceUrl: window.location.href,
    metadata: metadata ? {
      author: metadata.author,
      creator: metadata.creator,
      language: undefined,  // Could extract from PDF if available
    } : undefined,
  };
  const localeResult = detectLikelyLocale(localeContext);

  // Compute counts from signal descriptions (for density/escalation)
  let phoneCount = 0;
  let emailCount = 0;
  let ssnCount = 0;
  for (const signal of uniqueSignals) {
    const desc = signal.description.toLowerCase();
    if (desc.includes('phone')) {
      const match = signal.description.match(/(\d+)\s*phone/i);
      phoneCount += match ? parseInt(match[1], 10) : 1;
    } else if (desc.includes('email')) {
      const match = signal.description.match(/(\d+)\s*email/i);
      emailCount += match ? parseInt(match[1], 10) : 1;
    } else if (desc.includes('ssn') || desc.includes('social security')) {
      ssnCount += 1;
    }
  }

  // Build policy context for v1.0 contract (ADR-011)
  const department = getDepartmentOverride();
  const policyContext: PolicyContext = {
    locale: localeResult.locale as LocaleKey,
    localeConfidence: localeResult.confidence,
    counts: {
      phone: phoneCount,
      email: emailCount,
      ssn: ssnCount,
    },
    isTransactional: bodyText ? isTransactionalDocument(bodyText) : false,
    bodyText,
    department,  // From localStorage or URL param (test/premium)
  };

  // === DICTIONARY DETECTION (ADR-012) ===
  // Run department-scoped dictionary detections on body text
  // These signals are added BEFORE policy application so caps still apply
  const dictionarySignals = bodyText
    ? runDictionaryDetections(bodyText, policyContext)
    : [];

  // AG-PHASE-2-046: Registry detection removed — all 7 patterns now run via
  // pack-based runDetection() above, emitting signals into uniqueSignals.
  // Signal IDs are preserved (registry-*) so policy references remain stable.

  // Merge all signals BEFORE policy application
  const allSignals = [
    ...uniqueSignals,
    ...dictionarySignals.map(s => ({ ...s, source: s.source as SignalSource, detectedAt: s.detectedAt ?? Date.now() })),
  ];

  // AG-PROMPT-044: Boundary counter [A] - after detection (raw signals)
  if (isDebugMode()) {
    boundaryCounters.afterDetection = {
      total: allSignals.length,
      byType: countSignalsByType(allSignals),
    };
    // Count canary signals separately (using string comparison since canary type is debug-only)
    const canaryCount = allSignals.filter(s => (s.type as string) === CANARY_SIGNAL_TYPE).length;
    if (canaryCount > 0) {
      boundaryCounters.afterDetection.byType.canary = canaryCount;
    }
  }

  // Apply policy contract to adjust severities (ADR-009, ADR-011, ADR-012, ADR-013)
  const policySignals = applyPolicyContract(allSignals, policyContext);

  // AG-PROMPT-044: Boundary counter [B] - after policy
  if (isDebugMode()) {
    boundaryCounters.afterPolicy = {
      total: policySignals.length,
      byType: countSignalsByType(policySignals),
    };
  }

  // Log policy application (counters only, no content - ADR-002)
  if (phoneCount > 0 || localeResult.locale !== 'unknown') {
    console.log(`[AgentGuard] Policy applied: locale=${localeResult.locale} phones=${phoneCount} emails=${emailCount} -> ${policySignals.length} signals`);
  }

  // === INTERPRETATION CALIBRATION (AG-PROMPT-038) ===
  // Calibrate signal interpretation to reduce false positives:
  // - Universal signals: Always decision-driving (secrets, critical PII)
  // - Region-sensitive signals: Modified by locale (SSN, IBAN)
  // - Contextual signals: Suppressed unless threshold/proximity met (emails, phones)
  const calibrationResult = calibrateInterpretation(policySignals, policyContext);
  const calibratedDrivingSignals = extractDrivingSignals(calibrationResult);

  // Log calibration stats (counters only, no content - ADR-002)
  if (calibrationResult.stats.suppressedCount > 0 || calibrationResult.stats.promotedByCount > 0 || calibrationResult.stats.rescuedRegulated > 0 || calibrationResult.stats.singleStrongAwareness > 0) {
    console.log(`[AgentGuard] Calibration: driving=${calibrationResult.stats.drivingCount} suppressed=${calibrationResult.stats.suppressedCount} promoted=${calibrationResult.stats.promotedByCount + calibrationResult.stats.promotedByProximity}${calibrationResult.stats.rescuedRegulated > 0 ? ` rescued=${calibrationResult.stats.rescuedRegulated}` : ''}${calibrationResult.stats.singleStrongAwareness > 0 ? ` singleStrong=${calibrationResult.stats.singleStrongAwareness}` : ''}`);
  }

  // === HUMAN HEURISTIC ANCHORS (AG-PROMPT-039) ===
  // Apply human-aligned heuristics for zone-based suppression and finality:
  // - Zone: Header/footer/metadata signals suppressed unless near universal anchors
  // - List: Many distinct values promoted as "contact list"
  // - Finality: Legal boilerplate alone suppressed, markers with sensitive content kept
  const heuristicResult = applyHumanHeuristics({
    signals: calibratedDrivingSignals,
    locale: { locale: localeResult.locale as import('../policy/policy').LocaleKey, confidence: localeResult.confidence },
    destination: { hostname: getEffectiveHostname(), category: deriveDestination(getEffectiveHostname()) },
    documentLength: bodyText?.length,
    allSignals: policySignals,
  });
  const drivingSignals = heuristicResult.signals;

  // Log heuristic stats (counters only, no content - ADR-002)
  if (heuristicResult.stats.suppressedCount > 0 || heuristicResult.stats.promotedCount > 0) {
    console.log(`[AgentGuard] Heuristics: driving=${heuristicResult.stats.outputCount} suppressed=${heuristicResult.stats.suppressedCount} zone=${heuristicResult.stats.zoneSuppressed} finality=${heuristicResult.stats.finalitySuppressed}`);
  }

  // === DOCUMENT CLASS ANCHORS (AG-PROMPT-041) ===
  // Apply document-level classification for inherently sensitive document types:
  // - doc.payroll → baseline HIGH
  // - doc.hr_record → baseline HIGH
  // - doc.medical_record → baseline CRITICAL
  // Also suppresses noisy patterns (card noise, URL noise) within sensitive documents.
  const documentClassResult = applyDocumentClassAnchors({
    signals: drivingSignals,
    textContent: bodyText,
    filename: file.name,
  });
  const classifiedSignals = documentClassResult.signals;

  // Log document class detection (counters only, no content - ADR-002)
  // AG-PROMPT-077: Enhanced logging for medical escalation diagnosis
  console.log(`[AgentGuard] DocumentClass: ${documentClassResult.classification.documentClass || 'none'} hasPatientContext=${documentClassResult.hasPatientContext} baseline=${documentClassResult.classification.baselineSeverity || 'none'}`);
  if (documentClassResult.stats.classDetected) {
    console.log(`[AgentGuard] DocumentClass indicators: ${documentClassResult.classification.indicators.length} noiseSuppressed=${documentClassResult.stats.noiseSuppressed}`);
  }

  // AG-PHASE-5E-058: Determine effective document class, using degraded fallback when needed
  // If signal-based classification didn't find a class, use the degraded fallback classification
  let effectiveDocumentClass = documentClassResult.classification.documentClass;
  if (!effectiveDocumentClass && degradedFallbackResult?.applied && degradedFallbackResult.documentClass) {
    effectiveDocumentClass = degradedFallbackResult.documentClass;
    console.log(`[AgentGuard] Using degraded fallback documentClass: ${effectiveDocumentClass}`);
  }

  // AG-PROMPT-044: Boundary counter [C] - after dedup/filtering
  // This tracks signals after all filtering (calibration, heuristics, document class)
  if (isDebugMode()) {
    const removedCount = policySignals.length - classifiedSignals.length;
    boundaryCounters.afterDedup = {
      total: classifiedSignals.length,
      removed: removedCount > 0 ? removedCount : 0,
    };
  }

  // === AUTHORITATIVE DECISION (AG-PROMPT-042) ===
  // SINGLE SOURCE OF TRUTH for final decision severity.
  // Core rule: FinalSeverity = MAX(DocumentBaselineSeverity, AggregatedSignalSeverity)
  // All downstream derivations (overallRisk, UI, explanations) MUST use this.
  const rawAggregatedResult = aggregateSeverity(classifiedSignals);
  // AG-PROMPT-SIGNAL-BYPASS-FIX-028: Pass identityConfidence to gate baseline severity
  // AG-PHASE-5E-058: Use effectiveDocumentClass to include degraded fallback
  const authoritativeDecision = buildAuthoritativeDecision({
    aggregatedResult: rawAggregatedResult,
    documentClass: effectiveDocumentClass,
    identityConfidence: documentClassResult.identityConfidence,
  });

  // Log authoritative decision (counters only, no content - ADR-002)
  if (authoritativeDecision.baselineApplied) {
    console.log(`[AgentGuard] AuthoritativeDecision: ${authoritativeDecision.reason} (rule=${authoritativeDecision.ruleId})`);
  }

  // Derive overallRisk FROM authoritative decision (single source of truth)
  // This ensures overallRisk ALWAYS respects document class baseline floors
  const overallRisk = authoritativeDecision.severity as FileRiskAssessment['overallRisk'];

  // Create aggregatedResult with authoritative severity for downstream compatibility
  const aggregatedResult = {
    ...rawAggregatedResult,
    severity: authoritativeDecision.severity,
  };

  // === BUILD EXPLANATIONS (ADR-015) ===
  // Data-only layer for future UI progressive disclosure
  // No content logged - only counts
  // Uses classified signals (including document class anchors) for explanations
  // Note: overallRisk can be 'none' but buildExplanationBundle expects Severity (without 'none')
  // In practice, when overallRisk is 'none', there are no signals, so explanations are minimal
  const explanations = buildExplanationBundle(
    classifiedSignals as import('../policy/explanations').RiskSignal[],
    overallRisk as import('../types/riskSignal').Severity,
    policyContext,
    {
      phoneCount,
      emailCount,
      ssnCount,
      totalSignals: classifiedSignals.length,
    }
  );
  console.log(`[AgentGuard] Explanations built: ${Object.keys(explanations.perSignal).length} signals (${calibrationResult.stats.suppressedCount} suppressed)`);
  const destination = deriveDestination(getEffectiveHostname());
  // AG-PROMPT-086: Derive ontologyDriven from classification indicators
  // Clinical ontology anchors (COA-*) indicate ontology-driven classification
  const ontologyDriven = documentClassResult.classification.indicators.some(
    ind => ind.signalId.startsWith('COA-')
  );
  // AG-PROMPT-086: Pass all context to buildDecisionExplanation for proper framing
  // AG-PROMPT-SIGNAL-BYPASS-FIX-028: Pass identityConfidence for frame selection gating
  const rawDecisionExplanation = buildDecisionExplanation({
    aggregatedSeverity: aggregatedResult,
    explanations: {
      signals: Object.values(explanations.perSignal).map(exp => ({
        id: exp.id,
        severity: undefined, // Severity comes from aggregatedResult
        uiEscalation: exp.uiEscalation,
      })),
      overall: {
        uiEscalation: explanations.overall.uiEscalation,
      },
    },
    destination,
    textContent: bodyText,  // AG-PROMPT-080: For context inference in signal dominance
    documentClass: effectiveDocumentClass,  // AG-PHASE-5E-058: Use effective class
    ontologyDriven,
    pdfExtractionFailed,
    pdfEncryptionReadability,
    singleStrongAwareness: calibrationResult.stats.singleStrongAwareness > 0,
    identityConfidence: documentClassResult.identityConfidence,
    // AG-PHASE-5E-058: Pass degraded fallback for domain-specific framing
    degradedFallback: degradedFallbackResult?.applied ? {
      domain: degradedFallbackResult.domain!,
      matchedTokens: degradedFallbackResult.matchedTokens,
      source: degradedFallbackResult.source!,
    } : undefined,
  });

  // === DECISION/UI CONSISTENCY CONTRACT (AG-PROMPT-040) ===
  // Enforce that no visible signal can have severity higher than the decision.
  // This prevents UI contradictions like "Low risk" with "Critical issue detected".
  const consistencyResult = enforceDecisionConsistency(
    rawDecisionExplanation,
    new Set(aggregatedResult.drivingSignalIds)
  );

  // Log consistency enforcement (counters only, no content - ADR-002)
  if (consistencyResult.hadContradictions) {
    console.log(`[AgentGuard] Consistency: fixed ${consistencyResult.stats.downgraded} contradictions`);
  }

  // === VISIBLE SIGNALS (AG-PROMPT-043) ===
  // Create UI-safe signal list where no signal severity exceeds the authoritative decision.
  // This ensures the UI cannot show "Low risk" banner alongside "Critical" signals.
  // Note: overallRisk can be 'none' but createVisibleSignals uses SEVERITY_INDEX which handles 'none'
  let visibleSignals = createVisibleSignals(classifiedSignals, overallRisk as RiskSignal['severity']);

  // === MEDICAL RECORD AWARENESS ESCALATION (AG-PROMPT-070) ===
  // Enforce that patient-identifiable medical content NEVER resolves to:
  // - severity: none/low
  // - uiEscalation: 'inline'
  // - "No risk detected" copy
  // This is a POST-consistency enforcement that overrides calibration suppression.
  // AG-PHASE-5E-058: Use effectiveDocumentClass
  // AG-PROMPT-162-AREA1: Compute clinical reference bypass
  // Skip medical escalation for clinical reference material (drug guides, ICD code tables)
  // UNLESS real patient-identifying PII (SSN, national ID) is present among the signals.
  const clinicalRefBypass = FF.ff_archetype_clinical_reference_v1
    && (documentClassResult.archetypeMatches ?? []).some(
      m => m.archetypeId === 'clinical_reference' && m.confidence === 'strong'
    )
    && !classifiedSignals.some(s => s.id && PROTECTED_SIGNAL_IDS.has(s.id));

  const medicalEscalationResult = enforceMedicalRecordEscalation({
    explanation: consistencyResult.explanation,
    documentClass: effectiveDocumentClass,
    hasPatientContext: documentClassResult.hasPatientContext,
    visibleSignals,
    clinicalReferenceBypass: clinicalRefBypass,
  });
  const decisionExplanation = medicalEscalationResult.explanation;

  // If a signal was rescued for awareness, add it to visible signals
  if (medicalEscalationResult.awarenessRescued && medicalEscalationResult.rescuedSignal) {
    visibleSignals = [...visibleSignals, medicalEscalationResult.rescuedSignal];
  }

  // Log medical escalation (counters only, no content - ADR-002)
  if (medicalEscalationResult.escalated) {
    console.log(`[AgentGuard] MedicalEscalation: ${medicalEscalationResult.reason} (rule=${medicalEscalationResult.ruleId})`);
  }

  // === AG-PROMPT-080: SEVERITY FLOOR ENFORCEMENT ===
  // Ensure regulated evidence NEVER resolves to severity=low.
  // Floors by category: secrets→HIGH, PII→MEDIUM (HIGH if batch), HR→MEDIUM, etc.
  // AG-PHASE-5E-058: Use effectiveDocumentClass
  const severityFloorResult = enforceSeverityFloor({
    signals: policySignals,
    severity: decisionExplanation.severity as 'none' | 'low' | 'medium' | 'high' | 'critical',
    documentClass: effectiveDocumentClass,
    hasPatientContext: documentClassResult.hasPatientContext,
  });

  // Apply severity floor to decision explanation
  let floorEnforcedExplanation = decisionExplanation;
  if (severityFloorResult.elevated) {
    floorEnforcedExplanation = {
      ...decisionExplanation,
      severity: severityFloorResult.severity,
    };
    console.log(`[AgentGuard] SeverityFloor: ${severityFloorResult.reason} (rule=${severityFloorResult.ruleId})`);
  }

  // === AG-PROMPT-162-2A: AGGREGATE HR/FINANCE SEVERITY CAP ===
  // When aggregate_hr_finance archetype is detected AND no protected PII signals
  // are present, cap severity to prevent over-alerting on summary/dashboard docs.
  const aggregateCapMatch = FF.ff_hr_aggregate_cap_v1
    ? (documentClassResult.archetypeMatches ?? []).find(
        m => m.archetypeId === 'aggregate_hr_finance' && m.confidence === 'strong'
      )
    : undefined;
  if (aggregateCapMatch && !classifiedSignals.some(s => s.id && PROTECTED_SIGNAL_IDS.has(s.id))) {
    const effects = getArchetypeEffects(aggregateCapMatch.archetypeId);
    if (effects.mayCapSeverity && effects.severityCap) {
      const currentRank = rankSeverityOrNone(floorEnforcedExplanation.severity);
      // Preserve the deliberate medium-rank (2) fallback for an unrecognized cap value
      // (previously `SEVERITY_RANK[effects.severityCap] ?? 2`); rankSeverityOrNone()
      // alone would fall back to 0, which would silently change capping behavior.
      const capRank = (SEVERITY_ORDER_WITH_NONE as readonly string[]).includes(effects.severityCap)
        ? rankSeverityOrNone(effects.severityCap)
        : 2;
      if (currentRank > capRank) {
        floorEnforcedExplanation = {
          ...floorEnforcedExplanation,
          severity: effects.severityCap,
        };
        console.log(`[AgentGuard] AggregateHRCap: severity capped from ${floorEnforcedExplanation.severity} to ${effects.severityCap} (archetype=${aggregateCapMatch.archetypeId}, markerCount=${aggregateCapMatch.matchedMarkers.length})`);
      }
    }
  }

  // === AG-PROMPT-SIGNAL-BYPASS-FIX-028: SEVERITY LADDER CAPS ===
  // Apply confidence-based severity caps AFTER floor enforcement but BEFORE
  // the regulated visibility guardrail. This prevents over-assertion of severity
  // when evidence quality is low (fallback→max MEDIUM, inferred→max HIGH).
  // AG-PHASE-5E-058: Use effectiveDocumentClass
  const surfaceConfidenceResult = deriveSurfaceConfidence({
    documentClass: effectiveDocumentClass,
    severity: floorEnforcedExplanation.severity as 'low' | 'medium' | 'high' | 'critical' | 'none',
    drivingSignalIds: rawAggregatedResult.drivingSignalIds,
    signalCount: rawAggregatedResult.signalCount,
  });
  // AG-PHASE-5E-058: Use effectiveDocumentClass
  const severityCapsResult = applySeverityCaps({
    surfaceConfidence: surfaceConfidenceResult.confidence,
    documentClass: effectiveDocumentClass,
    signals: classifiedSignals.map(s => ({
      id: s.id,
      severity: s.severity,
      match: (s as any).match,
      offset: (s as any).offset,
    })),
    textContent: bodyText,
  });

  if (severityCapsResult.anyCapped) {
    console.log(`[AgentGuard] SeverityCaps: ${severityCapsResult.capsApplied.length} signal(s) capped (confidence=${surfaceConfidenceResult.confidence})`);
  }

  // === REGULATED VISIBILITY GUARDRAIL (AG-PROMPT-071, AG-PROMPT-074) ===
  // Final safety net: if ANY regulated evidence was detected at any stage,
  // the user MUST see at least one visible signal and severity >= LOW.
  // This prevents "No risk detected" UI when regulated content was found.
  //
  // AG-PROMPT-074 FIX: Must pass policySignals (BEFORE calibration suppressed signals),
  // not classifiedSignals (AFTER calibration). Otherwise the guardrail can't see
  // signals that were detected but later suppressed.
  const visibilityGuardrailResult = enforceRegulatedVisibility({
    allSignals: policySignals,      // Full set BEFORE calibration/dedup
    visibleSignals,                 // Current visible set
    severity: floorEnforcedExplanation.severity as 'none' | 'low' | 'medium' | 'high' | 'critical',
    uiEscalation: (floorEnforcedExplanation.uiEscalation ?? 'none') as 'none' | 'inline' | 'modal',
  });

  // Apply guardrail enforcement to visible signals
  if (visibilityGuardrailResult.signalRescued && visibilityGuardrailResult.rescuedSignal) {
    visibleSignals = visibilityGuardrailResult.visibleSignals;
  }

  // Apply severity/escalation floor to decision explanation
  let finalDecisionExplanation = floorEnforcedExplanation;
  if (visibilityGuardrailResult.severityElevated || visibilityGuardrailResult.escalationElevated) {
    finalDecisionExplanation = {
      ...floorEnforcedExplanation,
      severity: visibilityGuardrailResult.severity,
      uiEscalation: visibilityGuardrailResult.uiEscalation,
    };
  }

  // Log visibility guardrail (counters only, no content - ADR-002)
  if (visibilityGuardrailResult.enforced) {
    console.log(`[AgentGuard] VisibilityGuardrail: ${visibilityGuardrailResult.reason} (rule=${visibilityGuardrailResult.ruleId})`);
  }

  // === AG-PROMPT-164/WS-01: EXPLANATION INTEGRITY ===
  // Explanation must be generated after all severity overrides so user-facing
  // text always matches the final decision. If post-decision overrides (medical
  // escalation, severity floor, aggregate cap, regulated visibility) changed
  // the severity, regenerate the explanation with the final severity.
  if (finalDecisionExplanation.severity !== aggregatedResult.severity) {
    finalDecisionExplanation = buildDecisionExplanation({
      aggregatedSeverity: {
        ...aggregatedResult,
        severity: finalDecisionExplanation.severity,
      },
      explanations: {
        signals: Object.values(explanations.perSignal).map(exp => ({
          id: exp.id,
          severity: undefined,
          uiEscalation: exp.uiEscalation,
        })),
        overall: {
          uiEscalation: explanations.overall.uiEscalation,
        },
      },
      destination,
      textContent: bodyText,
      documentClass: effectiveDocumentClass,
      ontologyDriven,
      pdfExtractionFailed,
      pdfEncryptionReadability,
      singleStrongAwareness: calibrationResult.stats.singleStrongAwareness > 0,
      identityConfidence: documentClassResult.identityConfidence,
      degradedFallback: degradedFallbackResult?.applied ? {
        domain: degradedFallbackResult.domain!,
        matchedTokens: degradedFallbackResult.matchedTokens,
        source: degradedFallbackResult.source!,
      } : undefined,
    });
    console.log(`[AgentGuard] ExplanationIntegrity: regenerated for final severity=${finalDecisionExplanation.severity} (was ${aggregatedResult.severity})`);
  }

  // SEC-05: Explicit bodyText nulling — narrow memory window for extracted content.
  // bodyText is function-scoped and would be GC'd on return, but explicit nulling
  // releases the potentially large string immediately after its last use.
  //
  // AG-PROMPT-164: bodyText must survive until AFTER explanation regeneration above,
  // because buildDecisionExplanation uses textContent for frame selection. This null
  // is placed at the earliest safe point after regeneration. The ephemeral-processing
  // intent is preserved — bodyText is cleared immediately once the final explanation
  // no longer needs it. No detection behavior is widened by this placement.
  bodyText = undefined;

  // === AG-PROMPT-095: GUARDRAIL REASON CODES ===
  // Add reason codes for guardrails that were enforced
  const guardrailReasonCodes: ReasonCode[] = [];
  if (medicalEscalationResult.escalated) {
    guardrailReasonCodes.push('MEDICAL_ESCALATION_ENFORCED');
  }
  if (visibilityGuardrailResult.signalRescued) {
    guardrailReasonCodes.push('REGULATED_VISIBILITY_RESCUE');
  }
  if (pdfExtractionFailed) {
    guardrailReasonCodes.push('PDF_EXTRACTION_FAILED');
  }
  if (pdfEncryptionReadability === 'ENCRYPTED_PASSWORD_REQUIRED') {
    guardrailReasonCodes.push('PDF_ENCRYPTED_PASSWORD_REQUIRED');
  }

  // Merge guardrail reason codes into explanation
  if (guardrailReasonCodes.length > 0) {
    const existingCodes = finalDecisionExplanation.reasonCodes || [];
    const mergedCodes = [...existingCodes, ...guardrailReasonCodes].sort();
    finalDecisionExplanation = {
      ...finalDecisionExplanation,
      reasonCodes: mergedCodes,
    };
  }

  // === AG-PHASE-5E-UI-DIGNITY-MIGRATION-COMPLETE-059: AWARENESS VISIBILITY INVARIANTS ===
  // Recompute awarenessVisibility from POLICY OUTPUTS (severity + frameId).
  // This ensures invariants are enforced AFTER all guardrails:
  // - severity >= medium => always interrupt
  // - extraction-limited frame => always interrupt
  // - uiEscalation === 'modal' => always interrupt
  // NOTE: Legacy params (visibleSignals.length, pdfExtractionFailed) are NOT passed.
  // Visibility is derived solely from finalDecisionExplanation.frameId and severity.
  finalDecisionExplanation = enforceAwarenessVisibility(finalDecisionExplanation);

  // AG-PROMPT-095: Safe debug log for guardrail outcomes
  safeDebugLog('GUARDRAILS_APPLIED', {
    medicalEscalated: medicalEscalationResult.escalated,
    visibilityRescued: visibilityGuardrailResult.signalRescued,
    severityFloorApplied: severityFloorResult.elevated,
    pdfExtractionFailed,
    finalSeverity: finalDecisionExplanation.severity,
    finalVisibility: finalDecisionExplanation.awarenessVisibility,
    reasonCodes: finalDecisionExplanation.reasonCodes || [],
  });

  console.log(`[AgentGuard] DecisionExplanation: action=${finalDecisionExplanation.action} severity=${finalDecisionExplanation.severity} uiEscalation=${finalDecisionExplanation.uiEscalation} visibility=${finalDecisionExplanation.awarenessVisibility}`);

  // AG-PROMPT-044: Boundary counter [D] - what UI receives
  if (isDebugMode()) {
    boundaryCounters.uiReceives = {
      total: policySignals.length,
      visible: visibleSignals.length,
    };

    // Log all boundary counters
    logBoundaryCounters(boundaryCounters);

    // Store debug summary for programmatic access (test scripts)
    const debugSummary: DebugSummary = {
      debugEnabled: true,
      boundaries: boundaryCounters,
      canaryDetected,
    };
    storeDebugSummary(debugSummary);
  }

  // AG-PROMPT-043: Performance logging (local-only)
  const totalMs = performance.now() - perfStart;
  if (totalMs > PERF_BUDGET.TOTAL_WARNING_MS) {
    console.warn(`[AgentGuard] Perf warning: assessment took ${totalMs.toFixed(0)}ms (extract=${extractionMs.toFixed(0)}ms, detect=${detectionMs.toFixed(0)}ms)`);
  } else {
    console.log(`[AgentGuard] Perf: ${totalMs.toFixed(0)}ms total (extract=${extractionMs.toFixed(0)}ms, detect=${detectionMs.toFixed(0)}ms)`);
  }

  // AG-PROMPT-070/071: Use final severity from medical escalation or visibility guardrail (if elevated)
  const finalOverallRisk = (medicalEscalationResult.severityElevated || visibilityGuardrailResult.severityElevated)
    ? (finalDecisionExplanation.severity as FileRiskAssessment['overallRisk'])
    : overallRisk;

  return {
    filename: file.name,
    size: file.size,
    type: file.type || 'unknown',
    signals: policySignals,
    visibleSignals,
    overallRisk: finalOverallRisk,
    metadata,
    scannedSources,
    explanations,
    decisionExplanation: finalDecisionExplanation,
    pdfExtractionFailed,
    pdfEncryptionReadability,
    triggerSource: 'file',
  };
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function getDestinationHostname(): string {
  // Use effective hostname (handles iframes correctly)
  return getEffectiveHostname();
}

/**
 * @deprecated AG-PROMPT-087: Use DecisionExplanation.summary (from frames) instead.
 * This function is retained ONLY for internal logging/diagnostics.
 * DO NOT use in UI rendering paths - frames are the only source of UI copy.
 *
 * Get risk summary message for logging/diagnostics only.
 *
 * AG-PROMPT-061: Three-state UI message mapping:
 * - ZERO-SIGNAL (none): Neutral message, no "indicators found" language
 * - LOW/MEDIUM: "Indicators found" with guidance
 * - HIGH/CRITICAL: Strong warning language
 *
 * AG-PROMPT-073: PDF extraction failure overrides with "Unable to analyze" message
 *
 * @param risk - Overall risk level
 * @param hasVisibleSignals - Whether there are any visible signals
 * @param pdfExtractionFailed - Whether PDF extraction failed (AG-PROMPT-073)
 */
function getRiskSummaryLegacyInternal(risk: FileRiskAssessment['overallRisk'], hasVisibleSignals: boolean = true, pdfExtractionFailed: boolean = false): string {
  // AG-PROMPT-073: PDF extraction failure - show warning about inability to analyze
  if (pdfExtractionFailed && (risk === 'none' || !hasVisibleSignals)) {
    return "We couldn't read text from this PDF. Some details may not have been checked.";
  }

  // AG-PROMPT-061: Zero-signal state - neutral messaging
  // AG-PROMPT-083: Supportive co-pilot tone
  if (risk === 'none' || !hasVisibleSignals) {
    return 'Looks good — no sensitive details found. This file will be shared with an external service.';
  }

  // AG-PROMPT-083: Supportive, non-accusatory language
  switch (risk) {
    case 'low': return 'Just a heads up — this file may contain some personal details.';
    case 'medium': return 'This file contains some details worth reviewing before sharing.';
    case 'high': return 'Heads up — this file contains sensitive information.';
    case 'critical': return 'This file contains highly sensitive information that needs your attention.';
  }
}

// ============================================================================
// UI COMPONENTS
// ============================================================================

function showDragOverlay(): void {
  if (overlayElement) return;
  createStyles();
  // AG-SECURITY-HARDENING-SEC-01: Use safe DOM builder (no innerHTML)
  overlayElement = buildDragOverlay();
  document.body.appendChild(overlayElement);
}

function hideDragOverlay(): void {
  if (overlayElement) { overlayElement.remove(); overlayElement = null; }
}

/**
 * AG-PROMPT-093: Ensure DecisionExplanation has complete frame data before UI rendering.
 * AG-PROMPT-SURFACE-HEADLINE-POLICY-CONSOLIDATION-021: Sanitize fallback headlines.
 *
 * This is the final governance gate. If frame data is missing, applies
 * FRAME_GENERAL_SENSITIVE as safe default. Then validates via assertFrameComplete.
 *
 * IMPORTANT: When using fallback headlines from FRAME_MAP, we apply headline
 * sanitization with documentClass=null because fallback scenarios indicate
 * we don't have proper document classification context.
 *
 * NEVER returns without valid frame data — UI copy MUST come from frames.
 *
 * @param explanation - The DecisionExplanation to validate/repair
 * @returns DecisionExplanation with guaranteed complete frame data
 */
function ensureFrameCompleteForUI(explanation: DecisionExplanation | undefined): DecisionExplanation {
  // Safe default frame from frames.json
  const defaultFrame = FRAME_MAP['FRAME_GENERAL_SENSITIVE'];

  // AG-PROMPT-021: Use noClassHeadline when available for fallbacks (no documentClass context)
  const safeDefaultHeadline = sanitizeHeadlineForRender(
    defaultFrame.noClassHeadline || defaultFrame.headline,
    null // Fallback = no documentClass context
  );

  // If no explanation at all, build minimal one from default frame
  if (!explanation) {
    const fallback: DecisionExplanation = {
      severity: 'low',
      action: 'allow',
      headline: safeDefaultHeadline,
      summary: defaultFrame.summary,
      guidance: defaultFrame.guidance,
      frameId: 'FRAME_GENERAL_SENSITIVE',
      createdAt: Date.now(),
    };
    console.warn('[AgentGuard] AG-PROMPT-093: No DecisionExplanation - applied FRAME_GENERAL_SENSITIVE default');
    assertFrameComplete(fallback);
    return fallback;
  }

  // Check if frame data is incomplete
  const needsRepair = !explanation.frameId || !explanation.headline || !explanation.summary || !explanation.guidance;

  if (needsRepair) {
    // AG-PROMPT-021: Sanitize fallback headline (no documentClass context in repair scenario)
    const repairedHeadline = explanation.headline || safeDefaultHeadline;
    const finalHeadline = sanitizeHeadlineForRender(repairedHeadline, null);

    const repaired: DecisionExplanation = {
      ...explanation,
      frameId: explanation.frameId || 'FRAME_GENERAL_SENSITIVE',
      headline: finalHeadline,
      summary: explanation.summary || defaultFrame.summary,
      guidance: explanation.guidance || defaultFrame.guidance,
    };
    console.warn('[AgentGuard] AG-PROMPT-093: Incomplete frame data - applied FRAME_GENERAL_SENSITIVE defaults');
    assertFrameComplete(repaired);
    return repaired;
  }

  // Explanation is complete - validate and return
  assertFrameComplete(explanation);
  return explanation;
}

function showRiskModal(assessments: FileRiskAssessment[], onProceed: () => void, onCancel: () => void): void {
  createStyles();
  hideRiskModal();

  // AG-PROMPT-061: Include 'none' in risk ordering for zero-signal cases
  const overallRisk = assessments.reduce((max, a) => {
    const order = ['none', 'low', 'medium', 'high', 'critical'];
    return order.indexOf(a.overallRisk) > order.indexOf(max) ? a.overallRisk : max;
  }, 'none' as FileRiskAssessment['overallRisk']);

  // AG-PROMPT-043: Use visibleSignals for UI display (consistency-enforced)
  const totalSignals = assessments.reduce((sum, a) => sum + a.visibleSignals.length, 0);
  const allSignals = assessments.flatMap(a => a.visibleSignals);
  const allScannedSources = new Set<SignalSource>();
  assessments.forEach(a => a.scannedSources.forEach(s => allScannedSources.add(s)));

  // AG-PROMPT-073: Check if any PDF extraction failed
  const anyPdfExtractionFailed = assessments.some(a => a.pdfExtractionFailed === true);

  const destination = getDestinationHostname();

  // AG-PROMPT-093: Frames-only governance - ensure complete frame data before rendering.
  // This is the final gate. All UI copy MUST come from frames.json, never inline fallbacks.
  const firstExplanation = ensureFrameCompleteForUI(assessments[0]?.decisionExplanation);

  // Use frame-validated copy (fallbacks removed - AG-PROMPT-093)
  const riskSummary = firstExplanation.summary;
  const needsFriction = overallRisk === 'high' || overallRisk === 'critical';
  const isBlocked = ENFORCE_BLOCKING && overallRisk === 'critical';
  
  // AG-PROMPT-134: Derive decision quality blocks from existing primitives
  const anyPdfExtractionFailedForDQ = assessments.some(a => a.pdfExtractionFailed === true);
  const decisionQuality = firstExplanation.severity !== 'none'
    ? deriveDecisionQualityBlocks({
        decisionExplanation: firstExplanation,
        pdfExtractionFailed: anyPdfExtractionFailedForDQ,
      })
    : undefined;

  // AG-PROMPT-196: Derive trigger source from assessments (all same source in practice).
  // Defaults to 'file' for backwards compat with any assessment missing the field.
  const triggerSource: UploadTriggerSource = assessments[0]?.triggerSource ?? 'file';

  // Build file cards as safe DOM element (no innerHTML).
  // AG-PROMPT-196: Only shown for file triggers — paste/send have no meaningful file metadata.
  const filesElement = triggerSource === 'file'
    ? el('div', {}, assessments.map(a => {
        const metaEl = hasMetadataToShow(a.metadata)
          ? buildMetadataSection(a.metadata)
          : null;
        const children: (HTMLElement | string | null)[] = [
          el('div', { className: 'agentguard-file-name' }, [a.filename]),
          el('div', { className: 'agentguard-file-meta' }, [
            `${formatFileSize(a.size)} \u2022 ${a.type || 'Unknown type'}`,
          ]),
          metaEl,
        ];
        return el('div', { className: 'agentguard-file-card' }, children.filter(Boolean) as (HTMLElement | string)[]);
      })) as HTMLDivElement
    : null;

  // UIR-01: Capture focus before modal opens for keyboard accessibility restoration
  const previousFocus = document.activeElement as HTMLElement | null;
  let focusTrapHandler: ((e: KeyboardEvent) => void) | null = null;

  const removeFocusTrap = (): void => {
    if (focusTrapHandler) {
      document.removeEventListener('keydown', focusTrapHandler);
      focusTrapHandler = null;
    }
    try { previousFocus?.focus(); } catch (_) { /* element may no longer be in DOM */ }
  };

  // AG-PROMPT-134: Use canonical safe component path (UX-01)
  const overlay = buildRiskModal({
    modalTitle: firstExplanation.headline,
    // AG-PROMPT-196: subtitle only meaningful for file triggers
    modalSubtitle: triggerSource === 'file'
      ? (assessments.length === 1 ? assessments[0].filename : `${assessments.length} files`)
      : '',
    riskSummary,
    guidance: firstExplanation.guidance,
    destination,
    scannedSourcesText: formatScannedSources(allScannedSources),
    // AG-PROMPT-196: file cards only for file triggers
    filesHtml: filesElement,
    signals: allSignals,
    licenseState: cachedLicenseState,
    isBlocked,
    needsFriction,
    decisionQuality,
    hasDetectedSignals: totalSignals > 0,
    overallRisk,
    isExtractionLimited: decisionQuality?.confidence.label === 'Reduced',
    triggerSource,
    onCancel: () => { removeFocusTrap(); hideRiskModal(); onCancel(); showPostDecisionToast('cancel', triggerSource); },
    onProceed: () => { removeFocusTrap(); hideRiskModal(); onProceed(); showPostDecisionToast('proceed', triggerSource); },
  });

  const escHandler = (e: KeyboardEvent) => {
    if (e.key === 'Escape') {
      removeFocusTrap();
      hideRiskModal();
      onCancel();
      document.removeEventListener('keydown', escHandler);
    }
  };
  document.addEventListener('keydown', escHandler);

  document.body.appendChild(overlay);
  modalElement = overlay as HTMLDivElement;

  // UIR-01: Focus trap — Tab and Shift+Tab cycle within modal while it is open.
  // Selector covers all standard interactive elements; excludes disabled ones.
  const FOCUSABLE_SELECTORS = 'button:not([disabled]),input:not([disabled]),a[href],[tabindex]:not([tabindex="-1"])';
  const getFocusableEls = (): HTMLElement[] =>
    Array.from(overlay.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTORS));

  focusTrapHandler = (e: KeyboardEvent) => {
    if (e.key !== 'Tab') return;
    const els = getFocusableEls();
    if (els.length === 0) return;
    const first = els[0];
    const last = els[els.length - 1];
    if (e.shiftKey) {
      if (document.activeElement === first) { e.preventDefault(); last.focus(); }
    } else {
      if (document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  };
  document.addEventListener('keydown', focusTrapHandler);

  // AG-PROMPT-168/WS-01: Initial focus on "Go back" (cancel) button — the safer action.
  // Falls back to first focusable if cancel not found.
  const cancelBtn = overlay.querySelector<HTMLElement>('[data-action="cancel"]');
  const initialFocus = cancelBtn || getFocusableEls()[0];
  if (initialFocus) initialFocus.focus();

  // AG-PROMPT-168/WS-01: Re-query focusable elements after accordion expand/collapse
  overlay.addEventListener('agentguard:accordion-toggle', () => {
    // getFocusableEls() already re-queries the DOM each call — this
    // listener exists to ensure the focus trap handler always gets a
    // fresh list on the next Tab press. No additional action needed
    // because getFocusableEls is called inside focusTrapHandler.
  });
}

function hideRiskModal(): void {
  document.getElementById('agentguard-modal-overlay')?.remove();
  modalElement = null;
}

// ============================================================================
// AG-PROMPT-067: AWARENESS BANNER (Inline notification for informational cases)
// ============================================================================

/**
 * Determine if assessments should show inline banner instead of modal.
 * Returns true if ALL assessments have uiEscalation='inline' AND low/none severity.
 */
function shouldShowInlineBanner(assessments: FileRiskAssessment[]): boolean {
  if (assessments.length === 0) return false;

  // All assessments must have inline escalation
  const allInline = assessments.every(a =>
    a.decisionExplanation?.uiEscalation === 'inline'
  );
  if (!allInline) return false;

  // All assessments must be low or none severity
  const allLowRisk = assessments.every(a =>
    a.overallRisk === 'low' || a.overallRisk === 'none'
  );
  return allLowRisk;
}

/**
 * Hide awareness banner if visible.
 */
function hideAwarenessBanner(): void {
  document.getElementById('agentguard-awareness-banner')?.remove();
  bannerElement = null;
}

/**
 * @deprecated AG-PROMPT-085: Legacy bottom-right banner. Use showAwarenessNotice() instead.
 *
 * This function shows a banner in the bottom-right corner. As of AG-PROMPT-076/077,
 * all awareness UI should be centered for consistency. This function is preserved
 * for backward compatibility but should NOT be used in new code.
 *
 * Original purpose: Show awareness banner for informational (low-risk) cases.
 * Replacement: showAwarenessNotice() provides centered, auto-dismiss notice.
 */
function showAwarenessBanner(
  assessments: FileRiskAssessment[],
  onProceed: () => void,
  onCancel: () => void
): void {
  createStyles();
  hideAwarenessBanner();
  hideRiskModal();

  // Aggregate signals across all files
  const totalSignals = assessments.reduce((sum, a) => sum + a.visibleSignals.length, 0);
  const allSignals = assessments.flatMap(a => a.visibleSignals);

  // Get headline and summary from awareness framing (if available) or use defaults
  // AG-PROMPT-083: Supportive co-pilot language
  // AG-PROMPT-021: Sanitize headline at render point (no documentClass in banner context)
  const firstExplanation = assessments[0]?.decisionExplanation;
  const rawHeadline = firstExplanation?.headline || 'Quick heads up';
  const headline = sanitizeHeadlineForRender(rawHeadline, null);
  const summary = firstExplanation?.summary ||
    'This file may contain some personal details. If that\'s expected, you\'re good to go.';

  // Build detected items description
  let detectedText = '';
  if (totalSignals > 0) {
    const signalCounts = new Map<string, number>();
    for (const signal of allSignals) {
      const key = signal.description || signal.type;
      signalCounts.set(key, (signalCounts.get(key) || 0) + 1);
    }
    const items = Array.from(signalCounts.entries())
      .slice(0, 3)  // Max 3 items in banner
      .map(([desc, count]) => count > 1 ? `${count} ${desc}` : desc);
    detectedText = items.join(', ');
  }

  // AG-SECURITY-HARDENING-SEC-01: Use safe DOM builder (no innerHTML)
  const banner = buildAwarenessBanner({
    headline,
    summary,
    detectedText,
    onClose: () => {
      hideAwarenessBanner();
      onCancel();
    },
    onReview: () => {
      hideAwarenessBanner();
      // Show full modal for review
      showRiskModal(assessments, onProceed, onCancel);
    },
    onProceed: () => {
      hideAwarenessBanner();
      onProceed();
    },
  });

  // ESC key to dismiss
  const escHandler = (e: KeyboardEvent) => {
    if (e.key === 'Escape') {
      hideAwarenessBanner();
      onCancel();
      document.removeEventListener('keydown', escHandler);
    }
  };
  document.addEventListener('keydown', escHandler);

  document.body.appendChild(banner);
  bannerElement = banner;

  console.log(`[AgentGuard] Showing awareness banner (${totalSignals} signal${totalSignals !== 1 ? 's' : ''}, uiEscalation=inline)`);
}

// ============================================================================
// AG-PROMPT-076/077: CENTERED NOTICE FOR LOW/NO-RISK SCANS
// ============================================================================

/**
 * AG-PROMPT-076/077/084/085: Centered notice for low/no-risk scans.
 *
 * UX PATHS:
 * - NO-RISK (0 signals): "Continue (N)" countdown button, auto-proceeds at 0
 * - LOW-RISK (signals exist but low severity): Progress bar + Details button
 *
 * POSITION: Always centered (never bottom-right). Use overlay for visual hierarchy.
 *
 * DISMISSAL:
 * - No-risk: Click countdown button OR wait for auto-continue
 * - Low-risk: Click anywhere OR wait for progress bar to complete
 * - Both: Click "Details" to open full modal (cancels auto-dismiss)
 *
 * @see showAwarenessBanner - DEPRECATED legacy bottom-right banner
 */
function showAwarenessNotice(
  assessments: FileRiskAssessment[],
  onProceed: () => void,
  onShowDetails: () => void,
  autoDismissMs: number = NOTICE_AUTO_DISMISS_MS
): void {
  createStyles();
  hideRiskModal();
  hideAwarenessBanner();
  hideAwarenessNotice();

  // AG-PHASE-5E-UI-DIGNITY-MIGRATION-COMPLETE-059: Derive notice variant from POLICY OUTPUTS
  // NOT from totalSignals (which includes suppressed signals).
  // - isLowRisk=true: severity > 'none' OR has visible details in explanation
  // - isLowRisk=false: severity='none' with no visible details (clean scan)
  const rawExplanation = assessments[0]?.decisionExplanation;
  const severity = rawExplanation?.severity || assessments[0]?.overallRisk || 'none';
  const hasVisibleDetails = (rawExplanation?.details?.length ?? 0) > 0;
  const isLowRisk = severity !== 'none' || hasVisibleDetails;

  // AG-PROMPT-093: Frames-only governance - ensure complete frame data before rendering.
  // This is the final gate. All UI copy MUST come from frames.json, never inline fallbacks.
  const firstExplanation = ensureFrameCompleteForUI(rawExplanation);

  // Use frame-validated copy (fallbacks removed - AG-PROMPT-093)
  const headline = firstExplanation.headline;
  const summary = firstExplanation.summary;
  const iconClass = isLowRisk ? 'agentguard-notice-icon-low' : '';

  let dismissed = false;
  let autoDismissTimer: ReturnType<typeof setTimeout> | null = null;

  const dismiss = () => {
    if (dismissed) return;
    dismissed = true;
    if (autoDismissTimer) clearTimeout(autoDismissTimer);
    hideAwarenessNotice();
    onProceed();
  };

  const handleDetails = () => {
    if (dismissed) return;
    dismissed = true;
    if (autoDismissTimer) clearTimeout(autoDismissTimer);
    hideAwarenessNotice();
    onShowDetails();
  };

  // AG-SECURITY-HARDENING-SEC-01: Use safe DOM builder (no innerHTML)
  const notice = buildAwarenessNotice({
    headline,
    summary,
    isLowRisk,
    onContinue: dismiss,
    onDetails: isLowRisk ? handleDetails : undefined,
  });

  // Click overlay (not the notice itself) to dismiss
  notice.addEventListener('click', (e) => {
    if (e.target === notice) {
      dismiss();
    }
  });

  // Click the notice card to dismiss (but not action buttons)
  const noticeCard = notice.querySelector('.agentguard-notice');
  if (noticeCard) {
    noticeCard.addEventListener('click', (e) => {
      const action = (e.target as HTMLElement).dataset?.action;
      if (action !== 'details' && action !== 'continue') {
        dismiss();
      }
    });
  }

  document.body.appendChild(notice);

  // AG-PRODUCT-PROMPT-DOCTRINE-001: No countdown display (prohibited pattern).
  // Auto-dismiss still works but without visible countdown pressure.
  autoDismissTimer = setTimeout(() => {
    dismiss();
  }, autoDismissMs);

  console.log(`[AgentGuard] Showing awareness notice (${isLowRisk ? 'low-risk' : 'no-risk'}, auto-dismiss in ${autoDismissMs}ms)`);
}

function hideAwarenessNotice(): void {
  document.getElementById('agentguard-notice-overlay')?.remove();
}

/**
 * AG-PROMPT-076/077/079/085: Determine aggregate visibility for multi-file uploads.
 *
 * AG-PROMPT-079 INVARIANTS (enforced here as safety net):
 * - Invariant A: ANY file with severity >= medium => modal (interrupt)
 * - Invariant B: ANY file with visibleSignals > 0 => modal (interrupt)
 * - Invariant C: ANY file with uiEscalation === 'modal' => modal (interrupt)
 * - Invariant D: ANY file with awarenessVisibility === 'interrupt' => modal
 * - Invariant E: ANY file with pdfExtractionFailed => modal (interrupt) [AG-PROMPT-085]
 *
 * Notice is ONLY allowed when ALL files are clean (no signals, no risk).
 *
 * Rules:
 * - If ANY file triggers ANY invariant → modal (interrupt)
 * - Else if ALL files are clean → notice (auto-dismiss)
 * - Else default to interrupt for safety
 */
function determineAggregateVisibility(
  assessments: FileRiskAssessment[]
): AwarenessVisibility {
  // AG-PROMPT-079/085: Enforce invariants first
  for (const a of assessments) {
    const severity = a.decisionExplanation?.severity;
    const uiEscalation = a.decisionExplanation?.uiEscalation;
    const visibility = a.decisionExplanation?.awarenessVisibility;
    const visibleSignalCount = a.visibleSignals?.length ?? 0;

    // Invariant E (AG-PROMPT-085): PDF extraction failure => interrupt
    // User must be informed that analysis was incomplete
    if (a.pdfExtractionFailed) {
      return 'interrupt';
    }

    // Invariant A: severity >= medium => interrupt
    if (severity === 'medium' || severity === 'high' || severity === 'critical') {
      return 'interrupt';
    }

    // Invariant B: visible signals > 0 => interrupt
    if (visibleSignalCount > 0) {
      return 'interrupt';
    }

    // Invariant C: explicit modal escalation => interrupt
    if (uiEscalation === 'modal') {
      return 'interrupt';
    }

    // Invariant D: explicit interrupt visibility => interrupt
    if (visibility === 'interrupt') {
      return 'interrupt';
    }
  }

  // All files passed invariant checks - check for notice
  const anyNotice = assessments.some(
    a => a.decisionExplanation?.awarenessVisibility === 'notice'
  );

  if (anyNotice) {
    return 'notice';
  }

  // Default to interrupt for safety (undefined visibility)
  return 'interrupt';
}

/**
 * Show appropriate awareness UI based on awarenessVisibility.
 * AG-PROMPT-076/077: All awareness is now centered.
 * - 'notice': Auto-dismiss popup (low/no-risk)
 * - 'interrupt': Modal requiring user review (medium+ risk)
 */
function showAwarenessUI(
  assessments: FileRiskAssessment[],
  onProceed: () => void,
  onCancel: () => void
): void {
  const visibility = determineAggregateVisibility(assessments);

  // AG-PROMPT-259: Support/diagnostic bundle and aggregate outcome counters removed.
  // Consumer runtime keeps no scan/outcome/frame/severity history and exposes no
  // exportable diagnostic bundle containing filenames, filename hashes, or risk/decision
  // traces. Signals are ephemeral per document lifecycle (see ADR-063 doctrine).

  if (visibility === 'notice') {
    // Low/no-risk: centered auto-dismiss notice
    // Pass callback to open modal if user clicks "Details"
    showAwarenessNotice(
      assessments,
      onProceed,
      () => showRiskModal(assessments, onProceed, onCancel)
    );
  } else {
    // Medium+ risk or policy-required modal: centered modal
    showRiskModal(assessments, onProceed, onCancel);
  }
}

function showLoadingModal(): void {
  createStyles();
  hideRiskModal();
  // AG-SECURITY-HARDENING-SEC-01: Use safe DOM builder (no innerHTML)
  const overlay = buildLoadingModal();
  document.body.appendChild(overlay);
  modalElement = overlay;
}

// ============================================================================
// FORCE HIDE HOST DRAG OVERLAY
// ============================================================================

/**
 * AG-PHASE-1-RUNTIME-HARDENING-001: Improved overlay suppression.
 *
 * Strategy: structural heuristics first, text fallback second.
 *  - Structural: position:fixed + covers >80% viewport + high z-index or backdrop-filter.
 *  - Fallback: host-specific text patterns for ChatGPT/Claude overlays.
 *  - Guard: never hide AgentGuard's own overlays (class/id check).
 *
 * Assumptions documented:
 *  - Host AI services use fixed-position full-viewport overlays for drag hints.
 *  - Text matching is English-only; non-English host UIs may need future patterns.
 */
function isAgentGuardElement(el: HTMLElement): boolean {
  return el.classList.contains('agentguard-overlay') ||
    el.classList.contains('agentguard-drag-overlay') ||
    el.id === 'agentguard-modal-overlay';
}

function isLikelyDragOverlay(el: HTMLElement): boolean {
  const style = window.getComputedStyle(el);
  if (style.position !== 'fixed') return false;
  const rect = el.getBoundingClientRect();
  const coversViewport = rect.width > window.innerWidth * 0.8 && rect.height > window.innerHeight * 0.8;
  if (!coversViewport) return false;
  // Structural signals (any one is sufficient alongside position:fixed + viewport coverage)
  if (style.backdropFilter !== 'none') return true;
  const zIndex = parseInt(style.zIndex, 10);
  if (zIndex > 999) return true;
  if (el.getAttribute('aria-dropeffect')) return true;
  if (el.getAttribute('role') === 'presentation') return true;
  const testId = el.getAttribute('data-testid') || '';
  if (testId.toLowerCase().includes('drop')) return true;
  // Fallback: host-specific text patterns (English-only; documented limitation)
  const text = el.innerText || '';
  if (text.includes('Add anything') || text.includes('Drop any file') || text.includes('Drop files here')) return true;
  return false;
}

function forceHideHostDragOverlay(): void {
  document.querySelectorAll('div').forEach(el => {
    const htmlEl = el as HTMLElement;
    if (isAgentGuardElement(htmlEl)) return;
    if (isLikelyDragOverlay(htmlEl)) {
      htmlEl.style.display = 'none';
      const parent = htmlEl.parentElement;
      if (parent && !isAgentGuardElement(parent)) {
        const parentStyle = window.getComputedStyle(parent);
        if (['fixed', 'absolute'].includes(parentStyle.position)) {
          parent.style.display = 'none';
        }
      }
    }
  });
  setTimeout(() => {
    document.querySelectorAll('div').forEach(el => {
      const htmlEl = el as HTMLElement;
      if (isAgentGuardElement(htmlEl)) return;
      if (isLikelyDragOverlay(htmlEl)) {
        htmlEl.style.display = 'none';
      }
    });
  }, 100);
}

// ============================================================================
// FILE INJECTION
// ============================================================================

function findFileInput(): HTMLInputElement | null {
  const inputs = Array.from(document.querySelectorAll('input[type="file"]')) as HTMLInputElement[];
  return inputs.find(input => input.multiple || !input.accept || input.accept === '*/*') || inputs[0] || null;
}

function generateFileKey(file: File): string {
  return `${file.name}-${file.size}-${file.lastModified}`;
}

/**
 * Check if an element is attached to the document.
 * Used to detect if a file input has been removed from the DOM by the platform.
 */
function isElementInDocument(el: Element | null): boolean {
  if (!el) return false;
  return document.body.contains(el);
}

/**
 * Inject files into a file input element.
 *
 * @param files - Files to inject
 * @param preferredInput - Optional preferred input element (from original event)
 * @returns true if injection succeeded, false if no valid input found
 */
function injectFilesViaInput(files: File[], preferredInput?: HTMLInputElement | null): boolean {
  // AG-PROMPT-101: Use preferred input if it's still in the DOM, otherwise find a new one
  let fileInput: HTMLInputElement | null = null;

  if (preferredInput && isElementInDocument(preferredInput)) {
    fileInput = preferredInput;
  } else {
    fileInput = findFileInput();
  }

  if (!fileInput) {
    console.warn('[AgentGuard] No file input found for injection');
    return false;
  }

  // AG-PROMPT-101: Final check - ensure input is still in DOM at injection time
  if (!isElementInDocument(fileInput)) {
    console.warn('[AgentGuard] File input detached from DOM before injection');
    return false;
  }

  try {
    // AG-PROMPT-01: FIFO eviction — evict oldest entries when at cap
    // Set preserves insertion order; values().next().value is always oldest.
    for (let i = 0; i < files.length && recentlyInjectedFiles.size >= RECENTLY_INJECTED_FILES_CAP; i++) {
      const oldest = recentlyInjectedFiles.values().next().value;
      if (oldest !== undefined) recentlyInjectedFiles.delete(oldest);
    }
    files.forEach(f => recentlyInjectedFiles.add(generateFileKey(f)));
    setTimeout(() => files.forEach(f => recentlyInjectedFiles.delete(generateFileKey(f))), 2000);

    const dt = new DataTransfer();
    files.forEach(f => dt.items.add(f));
    fileInput.files = dt.files;
    fileInput.dispatchEvent(new Event('input', { bubbles: true, cancelable: true }));
    fileInput.dispatchEvent(new Event('change', { bubbles: true, cancelable: true }));

    forceHideHostDragOverlay();
    setTimeout(forceHideHostDragOverlay, 200);
    setTimeout(forceHideHostDragOverlay, 500);

    return true;
  } catch (e) {
    console.error('[AgentGuard] Injection failed:', e);
    return false;
  }
}

// ============================================================================
// EVENT HANDLERS
// ============================================================================

let dragEnterCount = 0;

function handleDragEnter(event: DragEvent): void {
  // Guard: prevent double-triggering across frames
  if (event.defaultPrevented) return;
  if (!event.dataTransfer?.types.includes('Files')) return;
  dragEnterCount++;
  if (dragEnterCount === 1) showDragOverlay();
}

function handleDragOver(event: DragEvent): void {
  // Guard: prevent double-triggering across frames
  if (event.defaultPrevented) return;
  if (!event.dataTransfer?.types.includes('Files')) return;
  event.preventDefault();
  if (event.dataTransfer) event.dataTransfer.dropEffect = 'copy';
}

function handleDragLeave(): void {
  dragEnterCount--;
  if (dragEnterCount === 0) hideDragOverlay();
}

async function handleDrop(event: DragEvent): Promise<void> {
  // Guard: prevent double-triggering across frames
  if (event.defaultPrevented) return;

  dragEnterCount = 0;
  hideDragOverlay();

  const files = Array.from(event.dataTransfer?.files || []);
  if (files.length === 0) return;

  // Prevent default browser behavior (open file) and stop propagation to other frames
  event.preventDefault();
  event.stopPropagation();
  
  if (isProcessingUpload) return;
  isProcessingUpload = true;
  showLoadingModal();
  
  try {
    const assessments = await Promise.all(files.map(f => assessFileRisk(f)));
    // AG-PROMPT-067: Route to banner or modal based on uiEscalation
    showAwarenessUI(assessments, () => {
      if (!injectFilesViaInput(files)) {
        alert('Ai Notice: Could not upload. Try using the upload button.');
        forceHideHostDragOverlay();
      }
      setTimeout(() => { isProcessingUpload = false; }, 100);
    }, () => {
      isProcessingUpload = false;
      forceHideHostDragOverlay();
    });
  } catch (e) {
    console.error('[AgentGuard] Error:', e);
    hideRiskModal();
    hideAwarenessBanner();
    forceHideHostDragOverlay();
    isProcessingUpload = false;
  }
}

async function handleFileInputChange(event: Event): Promise<void> {
  const input = event.target as HTMLInputElement;
  if (!input.files || input.files.length === 0 || isProcessingUpload) return;
  
  const files = Array.from(input.files);
  if (files.every(f => recentlyInjectedFiles.has(generateFileKey(f)))) return;
  
  isProcessingUpload = true;
  const originalFiles = [...files];
  input.value = '';
  showLoadingModal();
  
  try {
    const assessments = await Promise.all(originalFiles.map(f => assessFileRisk(f)));
    // AG-PROMPT-067: Route to banner or modal based on uiEscalation
    // AG-PROMPT-101: Pass original input to injection (with DOM detachment fallback)
    showAwarenessUI(assessments, () => {
      if (!injectFilesViaInput(originalFiles, input)) {
        alert('Ai Notice: Could not upload. Try using the upload button.');
      }
      setTimeout(() => { isProcessingUpload = false; }, 100);
    }, () => { isProcessingUpload = false; });
  } catch (e) {
    console.error('[AgentGuard] Error:', e);
    hideRiskModal();
    hideAwarenessBanner();
    isProcessingUpload = false;
  }
}

// ============================================================================
// CLIP-RT-02: RAW CLIPBOARD TEXT RISK ASSESSMENT
// ============================================================================

/**
 * Assess risk for raw pasted text using the same detection + policy pipeline
 * used for plain-text files, returning a synthetic FileRiskAssessment.
 *
 * Intentionally minimal: skips document-class anchors, medical escalation,
 * and PDF-specific logic that are irrelevant for clipboard text.
 *
 * CLIP-RT-03: This function is always called within a fail-open try/catch.
 */
// AG-PROMPT-196: source defaults to clipboard_paste; prompt_send callers pass explicitly.
function assessRawTextRisk(text: string, source: UploadTriggerSource = 'clipboard_paste'): FileRiskAssessment {
  const strategyResult = runTextDetectionStrategy(text, 'content', 'clipboard-paste', 'text/plain');
  const localeResult = detectLikelyLocale({ text });
  const policyContext: PolicyContext = {
    locale: localeResult.locale as LocaleKey,
    localeConfidence: localeResult.confidence,
    counts: { phone: 0, email: 0, ssn: 0 },
    isTransactional: false,
    bodyText: text,
    department: getDepartmentOverride(),
  };
  const policySignals = applyPolicyContract(strategyResult.signals, policyContext);
  const aggregated = aggregateSeverity(policySignals);
  const overallRisk = aggregated.severity as FileRiskAssessment['overallRisk'];
  const visibleSignals = overallRisk === 'none'
    ? []
    : createVisibleSignals(policySignals, overallRisk);
  return {
    filename: 'clipboard-paste',
    size: text.length,
    type: 'text/plain',
    signals: policySignals,
    visibleSignals,
    overallRisk,
    scannedSources: new Set<SignalSource>(['content']),
    triggerSource: source,
  };
}

/**
 * FOCUS-01: Re-insert raw clipboard text into the paste target element.
 * Called after awareness UI proceed (or on fail-open) when we have already
 * called event.preventDefault() to intercept the original paste.
 *
 * Focus is restored to pasteTarget before insertion. After modal interaction
 * the modal button owns focus; without re-focusing, execCommand and setRangeText
 * both miss the original editor. el.focus() does NOT fire a paste event, so
 * re-entry into handlePaste is impossible.
 *
 * Insertion is type-specific:
 *  - textarea/input: setRangeText (preserves selection, reliable post-focus)
 *    + input event dispatch for React/framework state sync
 *  - contenteditable/other: execCommand('insertText') fires beforeinput+input
 *    events required by ProseMirror, Lexical, and similar editors;
 *    DOM insertion fallback if execCommand returns false
 */
function insertRawText(text: string, target: Element | null): void {
  const el = (target instanceof HTMLElement ? target : document.activeElement) as HTMLElement | null;
  if (!el) return;

  // Restore focus to the original paste target. After modal interaction, focus
  // has moved to the modal button. Re-focusing restores the editing context
  // so insertion lands in the correct element at the correct cursor position.
  try { el.focus(); } catch { /* ignore cross-origin frame permission errors */ }

  if (el instanceof HTMLTextAreaElement ||
      (el instanceof HTMLInputElement && el.type !== 'file')) {
    // FOCUS-01a: textarea / text input path.
    // setRangeText replaces the current selection and advances the cursor.
    // selectionStart/End are preserved across blur/focus on all major browsers.
    const start = el.selectionStart ?? el.value.length;
    const end   = el.selectionEnd   ?? el.value.length;
    el.setRangeText(text, start, end, 'end');
    // Dispatch input event so React/Vue/framework event systems sync state.
    el.dispatchEvent(new InputEvent('input', { bubbles: true, cancelable: true }));
  } else {
    // FOCUS-01b: contenteditable and other editable elements.
    // execCommand('insertText') fires beforeinput + input events, which
    // ProseMirror, Lexical, and Draft.js rely on for internal state sync.
    // After el.focus() above, execCommand now operates on the correct element.
    const inserted = document.execCommand('insertText', false, text);
    if (!inserted) {
      // DOM fallback when execCommand is unavailable or returns false.
      const sel = window.getSelection();
      if (sel && sel.rangeCount > 0) {
        const range = sel.getRangeAt(0);
        range.deleteContents();
        range.insertNode(document.createTextNode(text));
        sel.collapseToEnd();
      }
      // Notify framework event systems of the DOM change.
      el.dispatchEvent(new InputEvent('input', { bubbles: true, cancelable: true }));
    }
  }
}

// PASTE-FALLBACK-01: One-shot bypass flag for send-time re-send after modal proceed.
// Set to true so the next Enter keydown is allowed through without re-scanning.
let allowNextPromptSend = false;

/**
 * PASTE-FALLBACK-01: Pre-send awareness scan.
 *
 * Intercepts Enter-key send gestures in contenteditable / textarea editors on
 * monitored AI destinations. Scans the prompt content for risk signals using
 * the same pipeline as paste. Acts as a safety net if paste observation was
 * missed for any reason (RC-1, timing, typed content).
 *
 * Security invariants:
 * - Reads ONLY document.activeElement text — never broader DOM scraping.
 * - Does NOT log content (detection pipeline only, ephemeral signals).
 * - Fails open: any error allows the send to proceed unblocked.
 * - AI destinations only (DEST-02 check).
 * - Shift+Enter (newline) is never intercepted.
 */
function handlePromptSend(event: KeyboardEvent): void {
  // Only intercept Enter without Shift (send gesture, not newline)
  if (event.key !== 'Enter' || event.shiftKey) return;

  // One-shot bypass: allow the re-send after modal proceed
  if (allowNextPromptSend) {
    allowNextPromptSend = false;
    return;
  }

  // Only on monitored AI destinations
  const destinationType = deriveDestination(getEffectiveHostname());
  if (destinationType === 'unknown') return;

  // Don't nest modals
  if (isProcessingUpload) return;

  // Read the active element's prompt text
  const target = document.activeElement as HTMLElement | null;
  if (!target) return;

  let promptText = '';
  if (target instanceof HTMLTextAreaElement) {
    promptText = target.value;
  } else if (target.isContentEditable) {
    promptText = target.innerText || target.textContent || '';
  } else {
    return; // Not a text editor — never intercept
  }

  // CLIP-RT-05/06: Align with paste-path fix from AG-PROMPT-196.
  // Do NOT gate by raw length before running detection — structured short
  // identifiers (CPR: 11 chars, SSN: 11 chars) are below the 20-char constant
  // but are high-confidence signals that must not be silently skipped.
  // assessRawTextRisk() is synchronous and trivially cheap on short text.
  // For empty prompts there is nothing to assess; everything else gets scanned.
  if (promptText.length < 1) return;

  // PASTE-FALLBACK-01 fail-open wrapper
  let assessment: ReturnType<typeof assessRawTextRisk>;
  try {
    assessment = assessRawTextRisk(promptText, 'prompt_send');
  } catch {
    return; // Assessment error — fail open, allow send
  }

  if (assessment.overallRisk === 'none') return; // No risk — allow send

  // Risk found — intercept the send
  event.preventDefault();
  event.stopPropagation();
  isProcessingUpload = true;

  showAwarenessUI(
    [assessment],
    () => {
      // Proceed: allow the user's next Enter to send without re-scan
      isProcessingUpload = false;
      allowNextPromptSend = true;
      // Re-focus the editor so the user can press Enter naturally
      try { target.focus(); } catch { /* ignore */ }
    },
    () => {
      // Cancel: user chose not to send — restore state
      isProcessingUpload = false;
      allowNextPromptSend = false;
    },
  );
}

async function handlePaste(event: ClipboardEvent): Promise<void> {
  // PASTE-RC6: Privacy-safe paste observability (no content logged).
  // Logs only event metadata so a tester can verify the handler fires.
  console.log('[AgentGuard] handlePaste fired',
    `defaultPrevented=${event.defaultPrevented}`,
    `clipboardData=${!!event.clipboardData}`,
    `items=${event.clipboardData?.items?.length ?? 'null'}`,
    `types=${event.clipboardData?.types?.join(',') ?? 'none'}`,
  );

  // PASTE-RC1/RC4/RC6: Do NOT guard on event.defaultPrevented here.
  // Our listener is registered on window (capture) synchronously at module load
  // (document_start), so we fire before any page-registered handlers.
  // The guard is applied later — only on the file path where double-injection
  // of files must be prevented. Raw text scanning proceeds regardless.

  // IMPORTANT: ClipboardData trap guard (AG-PROMPT-030)
  // ClipboardData is only available synchronously during the paste event.
  // After the event handler returns, event.clipboardData becomes null/empty.
  // We MUST extract all data synchronously here before any await.
  // Never pass the event object to async functions - only pass extracted data.
  //
  // PASTE-RC7: Separate the clipboardData null-check from the items null-check.
  // Prior code did `const items = event.clipboardData?.items; if (!items) return;`
  // which exits early if items is null — but getData() can still work even when
  // items is null (observed in Firefox MV2 for certain paste contexts).
  if (!event.clipboardData) {
    console.log('[AgentGuard] paste-early-exit: no-clipboardData');
    return;
  }
  const cd = event.clipboardData;
  const items = cd.items; // may be null on some browser/context combinations

  // Extract files synchronously (clipboard data won't be available after await)
  const files: File[] = [];
  if (items) {
    for (const item of Array.from(items)) {
      if (item.kind === 'file') {
        const file = item.getAsFile();
        if (file) files.push(file);
      }
    }
  }

  // CLIP-RT-01: Extract raw text synchronously when no files are present.
  // getData() is only valid during the synchronous phase of the paste event.
  //
  // PASTE-RC5: Some editors (ChatGPT/Lexical) call preventDefault() on the
  // paste event at window capture level before our handler fires. In some
  // browsers, getData() returns empty after preventDefault(). As a fallback,
  // read the first text/plain item via DataTransferItem if getData() fails.
  //
  // PASTE-RC7: If getData() returns empty AND items has a text/plain entry,
  // flag for async fallback via getAsString(). Firefox MV2 content scripts can
  // receive real paste events where getData() returns '' but getAsString()
  // works correctly (different code path through the Xray wrapper).
  let rawText = '';
  let asyncTextItem: DataTransferItem | null = null;
  if (files.length === 0) {
    rawText = cd.getData('text/plain') ?? '';
    if (!rawText && items) {
      for (const item of Array.from(items)) {
        if (item.kind === 'string' && item.type === 'text/plain') {
          // RC-5: try exact MIME type match (works in some browsers)
          rawText = cd.getData(item.type) ?? '';
          if (!rawText) {
            // getData() failed on both attempts — flag for getAsString() fallback
            asyncTextItem = item;
          }
          break;
        }
      }
    }
  }

  // PASTE-RC7: Privacy-safe observability — log getData result and item presence.
  // No content logged — only whether getData succeeded and types present.
  const getDataResult = rawText.length > 0 ? 'ok' : 'empty';
  const hasTextItem = asyncTextItem !== null;
  console.log('[AgentGuard] paste-extract',
    `getDataResult=${getDataResult}`,
    `hasTextItem=${hasTextItem}`,
    `files=${files.length}`,
    `itemsNull=${items === null || items === undefined}`,
  );

  if (files.length === 0) {
    // DEST-02: Only intercept raw clipboard text on monitored AI destinations.
    // Non-AI sites (banks, email, docs) must paste normally with no interception.
    // File-paste interception (below) remains active on all sites — unchanged.
    const destinationType = deriveDestination(getEffectiveHostname());
    // PASTE-RC6/RC7: Privacy-safe decision trace (no content logged — length bucket only)
    const textLenBucket = rawText.length === 0 ? '0' : rawText.length < 20 ? '<20' : rawText.length < 100 ? '20-99' : '100+';
    console.log('[AgentGuard] paste-text-path',
      `dest=${destinationType}`,
      `host=${getEffectiveHostname()}`,
      `textLen=${textLenBucket}`,
      `files=${files.length}`,
      `isProcessing=${isProcessingUpload}`,
      `asyncFallback=${hasTextItem}`,
    );
    if (destinationType === 'unknown') return;

    // PASTE-RC7: Async getAsString() fallback for Firefox MV2 where getData()
    // returns empty for real browser paste events from content script context.
    // Only enters when: getData() failed, a text/plain item exists, not processing.
    // Preemptively prevents the paste, then re-inserts from async callback.
    if (rawText.length === 0 && asyncTextItem && !isProcessingUpload) {
      const pasteTarget = document.activeElement;
      // Capture synchronously before anything async runs.
      event.preventDefault();
      event.stopPropagation();
      isProcessingUpload = true;
      console.log('[AgentGuard] paste-async-fallback-start');
      asyncTextItem.getAsString((asyncText: string) => {
        const asyncLenBucket = asyncText.length === 0 ? '0' : asyncText.length < 20 ? '<20' : asyncText.length < 100 ? '20-99' : '100+';
        console.log('[AgentGuard] paste-async-result', `textLen=${asyncLenBucket}`);
        if (asyncText.length === 0) {
          // Empty clipboard: nothing to assess or re-insert.
          isProcessingUpload = false;
          return;
        }
        // CLIP-RT-05: event.preventDefault() was already called before entering this
        // callback, so we must always re-insert the text. Run detection regardless of
        // length — this correctly handles short structured identifiers (e.g. CPR).
        try {
          const assessment = assessRawTextRisk(asyncText);
          console.log('[AgentGuard] paste-assessment',
            `risk=${assessment.overallRisk}`,
            `signals=${assessment.signals.length}`,
          );
          if (assessment.overallRisk === 'none') {
            insertRawText(asyncText, pasteTarget);
            isProcessingUpload = false;
          } else {
            showAwarenessUI([assessment], () => {
              insertRawText(asyncText, pasteTarget);
              setTimeout(() => { isProcessingUpload = false; }, 100);
            }, () => { isProcessingUpload = false; });
          }
        } catch (e) {
          // Fail-open: assessment error must not block the paste.
          console.warn('[AgentGuard] async paste assessment failed, re-inserting:', e);
          insertRawText(asyncText, pasteTarget);
          isProcessingUpload = false;
        }
      });
      return;
    }

    // CLIP-RT-01/02/03: Raw clipboard text awareness path (synchronous getData path).
    //
    // CLIP-RT-05: Short-text structured-identifier bypass.
    // The original gate (rawText.length >= 20) was designed to suppress noise from
    // incidental short pastes (greetings, single words). However it also silently
    // passes structured national IDs (e.g. Danish CPR: 11 chars) that are
    // inherently short by format.
    //
    // Fix: for short text (1–19 chars) run detection first (synchronously, cheap).
    //   - If signals found → intercept exactly as for long text.
    //   - If no signals   → fall through; browser pastes normally (no preventDefault).
    // For long text (>= 20 chars) the existing behaviour is unchanged: prevent first
    // for responsiveness, then detect, then re-insert or show modal.
    if (rawText.length >= 1 && !isProcessingUpload) {
      const pasteTarget = document.activeElement;

      if (rawText.length < RAW_CLIPBOARD_TEXT_MIN_CHARS) {
        // SHORT TEXT PATH: detect first, only intercept if signals found.
        // event.preventDefault() is NOT called pre-emptively; if no signals the
        // browser handles the insertion and we do nothing.
        try {
          const assessment = assessRawTextRisk(rawText);
          console.log('[AgentGuard] paste-short-assessment',
            `risk=${assessment.overallRisk}`,
            `signals=${assessment.signals.length}`,
            `textLen=${rawText.length}`,
          );
          if (assessment.overallRisk !== 'none') {
            // High-confidence short structured identifier detected — intercept.
            event.preventDefault();
            event.stopPropagation();
            isProcessingUpload = true;
            showAwarenessUI([assessment], () => {
              insertRawText(rawText, pasteTarget);
              setTimeout(() => { isProcessingUpload = false; }, 100);
            }, () => { isProcessingUpload = false; });
          }
          // overallRisk === 'none': fall through, browser inserts normally.
        } catch {
          // CLIP-RT-03: fail-open — detection error must never block a paste.
        }
      } else {
        // LONG TEXT PATH (unchanged): prevent first for responsive UX, then detect.
        event.preventDefault();
        event.stopPropagation();
        isProcessingUpload = true;
        try {
          const assessment = assessRawTextRisk(rawText);
          console.log('[AgentGuard] paste-assessment',
            `risk=${assessment.overallRisk}`,
            `signals=${assessment.signals.length}`,
          );
          if (assessment.overallRisk === 'none') {
            // No risk signals — re-insert immediately so the user sees no interruption.
            insertRawText(rawText, pasteTarget);
            isProcessingUpload = false;
          } else {
            showAwarenessUI([assessment], () => {
              insertRawText(rawText, pasteTarget);
              setTimeout(() => { isProcessingUpload = false; }, 100);
            }, () => { isProcessingUpload = false; });
          }
        } catch (e) {
          // CLIP-RT-03: Fail-open — any error allows the paste to proceed unblocked.
          console.warn('[AgentGuard] Raw clipboard text assessment failed, allowing paste:', e);
          insertRawText(rawText, pasteTarget);
          isProcessingUpload = false;
        }
      }
    }
    return;
  }

  // PASTE-RC1 (file path only): Guard against double-processing if another
  // handler already claimed this paste event. Files must never be double-injected.
  // This guard intentionally does NOT exist on the raw text path above.
  if (event.defaultPrevented) return;

  if (isProcessingUpload) return;

  // Prevent default and stop propagation to other frames
  event.preventDefault();
  event.stopPropagation();
  isProcessingUpload = true;
  showLoadingModal();

  try {
    const assessments = await Promise.all(files.map(f => assessFileRisk(f)));
    // AG-PROMPT-067: Route to banner or modal based on uiEscalation
    // AG-PROMPT-101: Check injection result and alert on failure
    showAwarenessUI(assessments, () => {
      if (!injectFilesViaInput(files)) {
        alert('Ai Notice: Could not upload. Try using the upload button.');
      }
      setTimeout(() => { isProcessingUpload = false; }, 100);
    }, () => { isProcessingUpload = false; });
  } catch (e) {
    console.error('[AgentGuard] Error:', e);
    hideRiskModal();
    hideAwarenessBanner();
    isProcessingUpload = false;
  }
}

// ============================================================================
// INIT
// ============================================================================

function attachFileInputHandler(input: HTMLInputElement): void {
  if (input.dataset.agentguardAttached) return;
  input.dataset.agentguardAttached = 'true';
  input.addEventListener('change', handleFileInputChange, { capture: true });
}

// Intercept .click() on file inputs to catch dynamically created inputs
// that are never added to the DOM (common pattern in React/modern apps)
function installClickInterceptor(): void {
  const originalClick = HTMLInputElement.prototype.click;
  
  HTMLInputElement.prototype.click = function(this: HTMLInputElement) {
    // Only intercept file inputs
    if (this.type === 'file') {
      // Attach our handler if not already attached
      attachFileInputHandler(this);
    }
    // Always call the original click
    return originalClick.call(this);
  };
}

function init(): void {
  // Frame detection logging (no content - ADR-017)
  const isTop = isTopFrame();
  const effectiveHost = getEffectiveHostname();
  console.log(`[AgentGuard] Init frame: top=${isTop} host=${effectiveHost}`);

  createStyles();
  
  // Install click interceptor for file inputs (catches detached inputs)
  installClickInterceptor();
  
  document.addEventListener('dragenter', handleDragEnter, { capture: true });
  document.addEventListener('dragover', handleDragOver, { capture: true });
  document.addEventListener('dragleave', handleDragLeave, { capture: true });
  document.addEventListener('drop', handleDrop, { capture: true });
  // NOTE: paste listener is registered SYNCHRONOUSLY at module scope (PASTE-RC6),
  // not here. This ensures it fires before any page-registered handler.
  // PASTE-FALLBACK-01: Pre-send awareness scan (Enter key intercept)
  document.addEventListener('keydown', handlePromptSend, { capture: true });

  // PASTE-RC2: SPA navigation guard — reset isProcessingUpload on history navigation.
  // In SPAs like ChatGPT, URL changes do not reload the page. If a modal was open
  // when navigation occurred the proceed/cancel callbacks may never fire.
  // popstate fires on Back/Forward and programmatic pushState-triggered navigation.
  window.addEventListener('popstate', () => {
    if (isProcessingUpload) {
      isProcessingUpload = false;
    }
  });

  document.querySelectorAll('input[type="file"]').forEach(input => attachFileInputHandler(input as HTMLInputElement));

  /**
   * AG-PROMPT-01 + AG-PHASE-1-RUNTIME-HARDENING-001: Shadow DOM resilience helper.
   * Scans an element's open shadow root (if any) for file inputs and
   * attaches a secondary MutationObserver to catch dynamic injection.
   * Closed shadow roots (mode: 'closed') are inaccessible by design —
   * this is a documented limitation (see AG-PROMPT-01-Shadow-DOM-Coverage.md).
   *
   * Hardening:
   *  - WeakSet dedup prevents re-observing the same shadow root.
   *  - Counter cap (200) prevents unbounded observer creation.
   */
  const observedShadowRoots = new WeakSet<ShadowRoot>();
  const SHADOW_ROOT_OBSERVER_CAP = 200;
  let shadowRootObserverCount = 0;

  function observeOpenShadowRoot(host: HTMLElement): void {
    const root = host.shadowRoot; // null if closed or absent
    if (!root) return;
    if (observedShadowRoots.has(root)) return; // dedup
    if (shadowRootObserverCount >= SHADOW_ROOT_OBSERVER_CAP) return; // cap
    observedShadowRoots.add(root);
    shadowRootObserverCount++;
    root.querySelectorAll('input[type="file"]').forEach(input => attachFileInputHandler(input as HTMLInputElement));
    new MutationObserver(shadowMutations => {
      for (const sm of shadowMutations) {
        for (const node of Array.from(sm.addedNodes)) {
          if (node instanceof HTMLElement) {
            if (node.tagName === 'INPUT' && (node as HTMLInputElement).type === 'file') {
              attachFileInputHandler(node as HTMLInputElement);
            }
            node.querySelectorAll?.('input[type="file"]').forEach(input => attachFileInputHandler(input as HTMLInputElement));
            observeOpenShadowRoot(node); // recurse for nested shadow hosts
          }
        }
      }
    }).observe(root, { childList: true, subtree: true });
  }

  new MutationObserver(mutations => {
    for (const mutation of mutations) {
      for (const node of Array.from(mutation.addedNodes)) {
        if (node instanceof HTMLElement) {
          if (node.tagName === 'INPUT' && (node as HTMLInputElement).type === 'file') {
            attachFileInputHandler(node as HTMLInputElement);
          }
          node.querySelectorAll?.('input[type="file"]').forEach(input => attachFileInputHandler(input as HTMLInputElement));
          // AG-PROMPT-01: Check if newly added element is a shadow host with open root
          observeOpenShadowRoot(node);
        }
      }
    }
  }).observe(document.body, { childList: true, subtree: true });

  // AG-PROMPT-01: Scan existing shadow hosts on page load
  document.querySelectorAll('*').forEach(el => {
    if (el instanceof HTMLElement) observeOpenShadowRoot(el);
  });
}

// ============================================================================
// AG-PROMPT-LICENSE-UX-002: LICENSE STATE CACHE
// ============================================================================
// Caches license state for display inside AgentGuard modal only.
// HOST_PAGE_BANNERS_FOR_LICENSE = forbidden
// License messaging must appear ONLY inside AgentGuard UI surfaces (modal, popup).
// ============================================================================

type CachedLicenseState = 'valid' | 'expired' | 'invalid' | 'unknown';
let cachedLicenseState: CachedLicenseState = 'unknown';

/**
 * Fetch and cache license status for modal display.
 * Does NOT inject any elements into the host page.
 */
async function fetchAndCacheLicenseState(): Promise<void> {
  // UX-02: Use safeSendMessage for fail-open behavior on extension disconnect
  const response = await safeSendMessage({ type: 'VALIDATE_LICENSE' }) as
    { success?: boolean; data?: { status?: { state?: string }; valid?: boolean; expired?: boolean } } | undefined;

  if (!response?.success || !response.data) {
    cachedLicenseState = 'invalid';
    return;
  }

  const { status, valid, expired } = response.data;
  const state = status?.state ?? (valid ? 'valid' : expired ? 'expired' : 'invalid');
  cachedLicenseState = state as CachedLicenseState;
}

/**
 * Get HTML for license status line to display inside modal header.
 * Returns empty string for valid licenses.
 *
 * AG-PROMPT-SURFACE-AND-LICENSE-003: Attribution-safe copy uses Ai Notice product name
 * INVARIANT: License state is meta-information. It must never visually
 * compete with document headline or guidance.
 */
function getLicenseNoticeHtml(): string {
  if (cachedLicenseState === 'valid' || cachedLicenseState === 'unknown') {
    return '';
  }

  // Both expired and invalid show Courtesy Mode message
  // AG-PROMPT-SURFACE-AND-LICENSE-003: Prefer "administrator" over "license holder"
  return `
    <div class="agentguard-license-status">
      Ai Notice is operating in Courtesy Mode.
      The license could not be verified. Please contact your administrator.
    </div>
  `;
}

// ============================================================================
// AG-PROMPT-058: ACTIVATION GATING
// ============================================================================
// The script runs on all HTTPS pages but MUST exit immediately on non-target
// pages. The gate check happens BEFORE any DOM access or event listener setup.
// ============================================================================

/**
 * Gated initialization - only runs on target pages.
 * Non-target pages exit before this function is called.
 */
async function gatedInit(): Promise<void> {
  // Get current hostname (this is the ONLY page access before gate check)
  const hostname = window.location.hostname;

  // Check activation gate
  const gateResult = await checkActivationGate(hostname);

  if (!gateResult.shouldActivate) {
    // NOT a target page - exit immediately
    // No DOM access, no event listeners, no content analysis
    if (isDebugMode()) {
      console.log(`[AgentGuard] Inactive on ${hostname}: ${gateResult.reason}`);
    }
    return;
  }

  // Target page - proceed with full initialization
  if (isDebugMode()) {
    console.log(`[AgentGuard] Activating on ${hostname}: ${gateResult.reason}`,
      gateResult.matchedTarget ? `(target: ${gateResult.matchedTarget})` : '');
  }

  // Run startup validation (once per extension lifetime)
  runStartupValidation();

  // AG-PROMPT-LICENSE-UX-002: Fetch license state for modal display (no host-page injection)
  await fetchAndCacheLicenseState();

  // Initialize based on document state
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
}

// PASTE-RC6: Register paste listener SYNCHRONOUSLY at document_start, BEFORE
// any async work. This is the only way to guarantee our handler fires before
// any page-registered handler (same target + phase = registration order).
//
// Prior bug: the paste listener was registered inside init(), which runs after
// two await calls (checkActivationGate + fetchAndCacheLicenseState). By the time
// init() ran, ChatGPT's Lexical editor had already registered its own
// window-level capture paste handler — ours fired SECOND, after Lexical's
// handler had already called stopImmediatePropagation().
//
// handlePaste itself has destination gating (DEST-02) for raw text, so
// registering early does NOT enable interception on non-target pages. The
// raw-text path checks deriveDestination() and returns immediately if unknown.
// The file-paste path has no destination gate (intentional — existing behavior).
window.addEventListener('paste', handlePaste as unknown as EventListener, { capture: true });

// Start the gated initialization
// This is an async IIFE that catches errors silently on non-target pages
(async () => {
  try {
    await gatedInit();
  } catch (error) {
    // Only log errors in debug mode and on target pages
    if (isDebugMode() && isBuiltinTarget(window.location.hostname)) {
      console.error('[AgentGuard] Initialization error:', error);
    }
  }
})();

export { assessFileRisk, showRiskModal, hideRiskModal, showAwarenessUI };
