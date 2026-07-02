/**
 * AG-PHASE-3-048: Quality gate functions for detection match filtering.
 *
 * Extracted from registry.ts during Phase 3 decomposition.
 * Contains quality assessment heuristics for:
 * - URL credential matches (AG-PROMPT-URL-FALSEPOS-005)
 * - Confidentiality marker matches (AG-PROMPT-CONFIDENTIAL-QUALITY-007)
 *
 * These are imported by packRegistry.ts to filter false positives
 * from detection pattern matches.
 */

import { FF } from '../config/featureFlags';

// ============================================================================
// URL CREDENTIAL MATCH QUALITY HEURISTICS (AG-PROMPT-URL-FALSEPOS-005)
// ============================================================================

/**
 * URL credential pattern IDs that should have quality assessment.
 */
export const URL_CREDENTIAL_PATTERN_IDS = new Set([
  'global-url-credentials',
  'global-url-query-credentials',
  'global-db-connection-string',
]);

/**
 * AG-PROMPT-URL-FALSEPOS-005: URL credential match quality category.
 */
export type UrlCredentialMatchQuality = 'plausible' | 'low_quality' | 'noise';

/**
 * AG-PROMPT-URL-FALSEPOS-005: URL credential match quality assessment result.
 * Privacy-safe: contains only metrics, never raw content.
 */
export interface UrlCredentialMatchQualityResult {
  quality: UrlCredentialMatchQuality;
  /** Reason for classification (for debugging) */
  reason: string;
  /** Whether to reject this match entirely */
  shouldReject: boolean;
  /** Metrics used for assessment (privacy-safe) */
  metrics: {
    matchLength: number;
    separatorDensity: number;
    spansLineBreaks: boolean;
    containsWhitespaceInside: boolean;
    hasHttpPrefix: boolean;
    hasPlausibleHost: boolean;
    hasRepeatedPunctuation: boolean;
  };
}

/**
 * AG-PROMPT-URL-FALSEPOS-005: Assess URL credential match quality.
 *
 * This function determines if a URL-with-credentials pattern match is:
 * - plausible: Looks like a real URL with embedded credentials
 * - low_quality: Suspicious but not definitively noise
 * - noise: Clearly an artifact (PDF text drift, coordinates, etc.)
 *
 * REJECT if:
 * - Match spans line breaks OR contains multiple whitespace runs (PDF drift)
 * - Extreme separator density (> 0.45) AND lacks http/https prefix
 * - Match length > 200 chars (real URL creds are much shorter)
 * - Contains many repeated punctuation sequences (:::, ///, @@@)
 *
 * KEEP if:
 * - Contains "http://" or "https://" prefix
 * - Has plausible host structure (at least one dot after @, no spaces in host)
 * - Match length is reasonable (< 150 chars)
 *
 * @param matchString - The matched URL credential string
 * @returns Quality assessment result
 */
// FQ-2 (AG-PROMPT-360): Loopback/dev host helpers for URL credential quality assessment.
// Token-class query params on localhost/127.0.0.1/[::1]/*.local/*.test are dev
// session/preview tokens — not real secrets. Password-class params are NOT exempted.
function isLoopbackOrDevHost(url: string): boolean {
  if (/^https?:\/\/\[::1\][/:?#]?/i.test(url)) return true;
  const hostMatch = /^https?:\/\/([^/?#:]+)/i.exec(url);
  if (!hostMatch) return false;
  const host = hostMatch[1].toLowerCase();
  return host === 'localhost' || host === '127.0.0.1' || host.endsWith('.local') || host.endsWith('.test');
}

function hasInlineAuthCredentials(url: string): boolean {
  const authMatch = /^https?:\/\/([^/?#]+)/i.exec(url);
  return authMatch ? authMatch[1].includes('@') : false;
}

export function assessUrlCredentialMatchQuality(
  matchString: string
): UrlCredentialMatchQualityResult {
  const matchLength = matchString.length;

  // Check for line breaks
  const spansLineBreaks = /[\r\n]/.test(matchString);

  // Check for whitespace inside (excluding start/end)
  const trimmed = matchString.trim();
  const containsWhitespaceInside = /\s/.test(trimmed);

  // Calculate separator density (non-alphanumeric / total)
  const nonAlnum = matchString.replace(/[a-zA-Z0-9]/g, '').length;
  const separatorDensity = matchLength > 0 ? nonAlnum / matchLength : 0;

  // URL prefix checks
  const hasHttpPrefix = /^https?:\/\//i.test(matchString);

  // Plausible host check: after @, should have at least one dot and no spaces
  const atIndex = matchString.indexOf('@');
  const afterAt = atIndex !== -1 ? matchString.slice(atIndex + 1) : '';
  const hostPart = afterAt.split('/')[0];
  const hasPlausibleHost = hostPart.includes('.') && !/\s/.test(hostPart);

  // Repeated punctuation (artifact indicator)
  const hasRepeatedPunctuation = /[:]{2,}|[\/]{3,}|[@]{2,}|[.]{4,}/.test(matchString);

  const metrics = {
    matchLength,
    separatorDensity,
    spansLineBreaks,
    containsWhitespaceInside,
    hasHttpPrefix,
    hasPlausibleHost,
    hasRepeatedPunctuation,
  };

  // Heuristic 1: Matches spanning line breaks are PDF extraction artifacts
  if (spansLineBreaks) {
    return {
      quality: 'noise',
      reason: 'spans_line_breaks',
      shouldReject: true,
      metrics,
    };
  }

  // Heuristic 2: Whitespace inside the match indicates text drift
  if (containsWhitespaceInside) {
    return {
      quality: 'noise',
      reason: 'contains_whitespace_inside',
      shouldReject: true,
      metrics,
    };
  }

  // Heuristic 3: Excessively long matches are artifacts (real URLs < 200 chars)
  if (matchLength > 200) {
    return {
      quality: 'noise',
      reason: 'excessive_length',
      shouldReject: true,
      metrics,
    };
  }

  // Heuristic 4: High separator density without HTTP prefix
  if (separatorDensity > 0.45 && !hasHttpPrefix) {
    return {
      quality: 'noise',
      reason: 'high_separator_density_no_http',
      shouldReject: true,
      metrics,
    };
  }

  // Heuristic 5: Repeated punctuation indicates artifacts
  if (hasRepeatedPunctuation) {
    return {
      quality: 'low_quality',
      reason: 'repeated_punctuation',
      shouldReject: false, // Flag but don't reject
      metrics,
    };
  }

  // Heuristic 6: No HTTP prefix and no plausible host
  if (!hasHttpPrefix && !hasPlausibleHost) {
    return {
      quality: 'low_quality',
      reason: 'no_http_no_host',
      shouldReject: false, // Conservative - don't reject
      metrics,
    };
  }

  // FQ-2 (AG-PROMPT-360): Token-class query params on loopback/dev hosts are dev-workflow
  // artifacts, not real secrets (preview tokens, session keys, etc.). Password-class params
  // (password=, passwd=, pwd=, pass=) are NOT exempted — they warn even on loopback.
  // Inline user:pass@ credentials are also NOT exempted regardless of host.
  if (!hasInlineAuthCredentials(matchString) && isLoopbackOrDevHost(matchString)) {
    if (/[?&](token|secret|api_key|apikey)=[^&\s]{4,}/i.test(matchString)) {
      return {
        quality: 'noise',
        reason: 'loopback_dev_query_token',
        shouldReject: true,
        metrics,
      };
    }
  }

  // Default: Plausible URL credential
  return {
    quality: 'plausible',
    reason: 'passes_quality_checks',
    shouldReject: false,
    metrics,
  };
}

// ============================================================================
// CONFIDENTIALITY MARKER QUALITY HEURISTICS (AG-PROMPT-CONFIDENTIAL-QUALITY-007)
// ============================================================================

/**
 * Confidentiality pattern IDs that should have quality assessment.
 * These patterns match keywords like "secret", "confidential", etc.
 * that can appear idiomatically in business documents.
 */
export const CONFIDENTIAL_PATTERN_IDS = new Set([
  // Global multi-language confidentiality markers
  'global-confidential-en',
  'global-confidential-de',
  'global-confidential-fr',
  'global-confidential-es',
  'global-confidential-nordic',
  // Language pack confidentiality markers
  'english-gov-clearance', // Contains "classified", "secret clearance" - needs quality check
  'romance-confidential',  // Romance language markers
  'nordic-confidential',   // Nordic language markers
]);

/**
 * AG-PROMPT-CONFIDENTIAL-QUALITY-007: Confidentiality match quality category.
 */
export type ConfidentialMatchQuality = 'classification_marker' | 'low_quality' | 'narrative_usage';

/**
 * AG-PROMPT-CONFIDENTIAL-QUALITY-007: Confidentiality match quality assessment result.
 * Privacy-safe: contains only metrics, never raw content.
 */
export interface ConfidentialMatchQualityResult {
  quality: ConfidentialMatchQuality;
  /** Reason for classification (for debugging) */
  reason: string;
  /** Whether to reject this match entirely */
  shouldReject: boolean;
  /** Metrics used for assessment (privacy-safe) */
  metrics: {
    matchLength: number;
    isAllCaps: boolean;
    isTitleCase: boolean;
    isLowercase: boolean;
    isStandaloneLine: boolean;
    isNearLineStart: boolean;
    isNearLineEnd: boolean;
    documentPositionRatio: number;
    isEarlyInDocument: boolean;
    isLateInDocument: boolean;
    hasNearbyPolicyPhrase: boolean;
    isEmbeddedInProse: boolean;
  };
}

/**
 * AG-PROMPT-162 (5C): Self-referential confidentiality phrases.
 * These patterns identify when a document explicitly classifies itself
 * (e.g. "This document is confidential"). Such phrases must never be
 * rejected as narrative — the document IS making a classification claim.
 *
 * Only matches when the confidential keyword is part of a self-referential
 * construction. Generic narrative uses remain subject to quality gating.
 */
const SELF_REFERENTIAL_CONFIDENTIAL_PHRASES = [
  // "This [document/information/report/email/communication/file/content/material] is [strictly] confidential"
  /\bthis\s+(?:document|information|report|email|communication|file|content|material|letter|memo|notice)\s+is\s+(?:strictly\s+)?/i,
  // "The following [is/are] confidential"
  /\bthe\s+following\s+(?:is|are)\s+/i,
  // "Contains confidential [information/data/material]"
  /\bcontains?\s+(?:strictly\s+)?/i,
  // "Marked [as] confidential"
  /\bmarked\s+(?:as\s+)?/i,
  // "Deemed/considered confidential"
  /\b(?:deemed|considered)\s+/i,
  // "Treated as confidential"
  /\btreated\s+as\s+/i,
  // "[is/are] privileged and confidential"
  /\b(?:is|are)\s+privileged\s+and\s+/i,
  // "Attorney-client privileged"
  /\battorney[\s-]*client\s+/i,
];

/**
 * Policy phrases that indicate true confidentiality context.
 * Proximity to these phrases increases confidence in classification markers.
 */
const CONFIDENTIALITY_POLICY_PHRASES = [
  /\bdo\s+not\s+distribute\b/i,
  /\bauthorized\s+personnel\s+only\b/i,
  /\bfor\s+internal\s+use\s+only\b/i,
  /\binternal\s+use\s+only\b/i,
  /\brestricted\s+distribution\b/i,
  /\bnot\s+for\s+public\s+release\b/i,
  /\bproprietary\s+and\s+confidential\b/i,
  /\bstrictly\s+confidential\b/i,
  /\btop\s+secret\b/i,
  /\bclassified\s+information\b/i,
  /\bneed\s+to\s+know\b/i,
  /\bnur\s+für\s+den\s+internen\s+gebrauch\b/i, // German
  /\bstreng\s+vertraulich\b/i, // German
  /\busage\s+interne\s+(uniquement|seulement)\b/i, // French
  /\bne\s+pas\s+diffuser\b/i, // French
  /\bkun\s+til\s+intern\s+brug\b/i, // Danish
  /\bstrengt\s+fortroligt\b/i, // Danish/Norwegian
];

/**
 * AG-PROMPT-CONFIDENTIAL-QUALITY-007: Assess confidentiality marker match quality.
 *
 * This function determines if a confidentiality keyword match is:
 * - classification_marker: Looks like a real document classification header
 * - low_quality: Suspicious but not definitively narrative
 * - narrative_usage: Clearly idiomatic/narrative usage (should be rejected)
 *
 * TRUE POSITIVES typically:
 * - Are ALL CAPS or Title Case
 * - Appear on standalone lines or near line boundaries
 * - Are in early/late document positions (headers/footers)
 * - Are near policy phrases ("do not distribute", etc.)
 *
 * FALSE POSITIVES typically:
 * - Are lowercase
 * - Are embedded in prose sentences
 * - Appear mid-document in body text
 * - Have no nearby policy phrases
 *
 * REJECT if ALL of the following are true:
 * - Match is lowercase
 * - Embedded in prose (not standalone)
 * - Not near policy phrases
 * - Not in header/footer position
 *
 * @param matchString - The matched confidentiality keyword
 * @param fullText - The full document text (for context analysis)
 * @param matchIndex - The index of the match in fullText
 * @returns Quality assessment result
 */
export function assessConfidentialMatchQuality(
  matchString: string,
  fullText: string,
  matchIndex: number
): ConfidentialMatchQualityResult {
  const matchLength = matchString.length;
  const textLength = fullText.length;

  // === Capitalization Analysis ===
  const isAllCaps = matchString === matchString.toUpperCase() && /[A-Z]/.test(matchString);
  const isTitleCase = /^[A-Z][a-z]*$/.test(matchString) || /^[A-Z][a-z]*\s+[A-Z][a-z]*/.test(matchString);
  const isLowercase = matchString === matchString.toLowerCase();

  // === Line Context Analysis ===
  // Find the line containing the match
  const lineStartIndex = fullText.lastIndexOf('\n', matchIndex) + 1;
  const lineEndIndex = fullText.indexOf('\n', matchIndex + matchLength);
  const effectiveLineEnd = lineEndIndex === -1 ? textLength : lineEndIndex;
  const line = fullText.slice(lineStartIndex, effectiveLineEnd);
  const matchPositionInLine = matchIndex - lineStartIndex;

  // Check if match is on a standalone line (only whitespace/punctuation around it)
  const lineWithoutMatch = line.slice(0, matchPositionInLine) + line.slice(matchPositionInLine + matchLength);
  const isStandaloneLine = /^\s*[-–—:]*\s*$/.test(lineWithoutMatch.trim());

  // Check if near line boundaries (within 10 chars of start/end)
  const isNearLineStart = matchPositionInLine <= 10;
  const isNearLineEnd = (effectiveLineEnd - (matchIndex + matchLength)) <= 10;

  // === Document Position Analysis ===
  const documentPositionRatio = textLength > 0 ? matchIndex / textLength : 0;
  const isEarlyInDocument = documentPositionRatio < 0.05; // First 5%
  const isLateInDocument = documentPositionRatio > 0.95; // Last 5%

  // === Policy Phrase Proximity ===
  // Check 200 chars before and after for policy phrases
  const contextRadius = 200;
  const contextStart = Math.max(0, matchIndex - contextRadius);
  const contextEnd = Math.min(textLength, matchIndex + matchLength + contextRadius);
  const contextWindow = fullText.slice(contextStart, contextEnd);

  let hasNearbyPolicyPhrase = false;
  for (const phrase of CONFIDENTIALITY_POLICY_PHRASES) {
    phrase.lastIndex = 0;
    if (phrase.test(contextWindow)) {
      hasNearbyPolicyPhrase = true;
      break;
    }
  }

  // === Prose Embedding Analysis ===
  // Check if surrounded by prose (letters before and after on same line)
  const charsBeforeOnLine = line.slice(0, matchPositionInLine);
  const charsAfterOnLine = line.slice(matchPositionInLine + matchLength);

  // Embedded in prose if there's substantial text both before and after
  const hasProseBeforeStrong = /[a-zA-Z]{4,}\s*$/.test(charsBeforeOnLine);
  const hasProseAfterStrong = /^\s*[a-zA-Z]{4,}/.test(charsAfterOnLine);
  const isEmbeddedInProse = hasProseBeforeStrong && hasProseAfterStrong;

  const metrics = {
    matchLength,
    isAllCaps,
    isTitleCase,
    isLowercase,
    isStandaloneLine,
    isNearLineStart,
    isNearLineEnd,
    documentPositionRatio,
    isEarlyInDocument,
    isLateInDocument,
    hasNearbyPolicyPhrase,
    isEmbeddedInProse,
  };

  // === Quality Decision Logic ===

  // AG-PROMPT-162 (5C): Self-referential confidentiality bypass.
  // If the matched keyword is part of a self-referential phrase
  // ("This document is confidential"), accept as classification_marker.
  // This check runs BEFORE reject paths to prevent quality-gate rejection
  // of genuine document self-classification statements.
  if (FF.ff_confidential_self_bypass_v1) {
    // Check the text immediately before the match (up to 60 chars) for
    // a self-referential phrase pattern that ends right at the match.
    const prefixStart = Math.max(0, matchIndex - 60);
    const prefix = fullText.slice(prefixStart, matchIndex);
    for (const selfRefPattern of SELF_REFERENTIAL_CONFIDENTIAL_PHRASES) {
      selfRefPattern.lastIndex = 0;
      if (selfRefPattern.test(prefix)) {
        return {
          quality: 'classification_marker',
          reason: 'self_referential_phrase',
          shouldReject: false,
          metrics,
        };
      }
    }
  }

  // Strong accept: ALL CAPS (definite classification marker)
  if (isAllCaps) {
    return {
      quality: 'classification_marker',
      reason: 'all_caps',
      shouldReject: false,
      metrics,
    };
  }

  // Strong accept: Standalone line (header/footer style)
  if (isStandaloneLine) {
    return {
      quality: 'classification_marker',
      reason: 'standalone_line',
      shouldReject: false,
      metrics,
    };
  }

  // Strong accept: Near policy phrase (explicit classification context)
  if (hasNearbyPolicyPhrase) {
    return {
      quality: 'classification_marker',
      reason: 'near_policy_phrase',
      shouldReject: false,
      metrics,
    };
  }

  // Strong accept: Early or late in document AND at line boundary (header/footer)
  if ((isEarlyInDocument || isLateInDocument) && (isNearLineStart || isNearLineEnd)) {
    return {
      quality: 'classification_marker',
      reason: 'header_footer_position',
      shouldReject: false,
      metrics,
    };
  }

  // REJECT: Lowercase + embedded in prose + no policy context = narrative usage
  if (isLowercase && isEmbeddedInProse && !hasNearbyPolicyPhrase) {
    return {
      quality: 'narrative_usage',
      reason: 'lowercase_embedded_prose',
      shouldReject: true,
      metrics,
    };
  }

  // REJECT: Lowercase + mid-document + no structural markers
  if (isLowercase && !isEarlyInDocument && !isLateInDocument && !isStandaloneLine && !isNearLineStart) {
    return {
      quality: 'narrative_usage',
      reason: 'lowercase_mid_document',
      shouldReject: true,
      metrics,
    };
  }

  // Low quality but don't reject: Title case or ambiguous positioning
  if (isTitleCase && !isEmbeddedInProse) {
    return {
      quality: 'low_quality',
      reason: 'title_case_not_prose',
      shouldReject: false,
      metrics,
    };
  }

  // Check if line looks like prose (long sentence) vs. classification label (short)
  // Classification labels are typically short and terse
  const lineLength = line.length;
  const isLongLine = lineLength > 40;
  const startsWithArticle = /^\s*(the|a|an|this|that|our|my|your|their|it|its|some|many|most|few)\s+/i.test(line);
  const isProseLine = isLongLine || startsWithArticle;

  // REJECT: Lowercase near line boundary BUT in a prose-like line
  if (isLowercase && (isNearLineStart || isNearLineEnd) && isProseLine && !hasNearbyPolicyPhrase) {
    return {
      quality: 'narrative_usage',
      reason: 'lowercase_prose_line',
      shouldReject: true,
      metrics,
    };
  }

  // Default: Lowercase at line boundary - conservative accept (short/label-like lines only)
  if (isNearLineStart || isNearLineEnd) {
    return {
      quality: 'low_quality',
      reason: 'line_boundary_position',
      shouldReject: false,
      metrics,
    };
  }

  // Final fallback: Reject ambiguous lowercase matches
  if (isLowercase) {
    return {
      quality: 'narrative_usage',
      reason: 'lowercase_ambiguous',
      shouldReject: true,
      metrics,
    };
  }

  // Conservative default: Accept if we reach here
  return {
    quality: 'low_quality',
    reason: 'default_accept',
    shouldReject: false,
    metrics,
  };
}

// ============================================================================
// ICD-10 / MEDICAL CODE MATCH QUALITY HEURISTICS (AG-PROMPT-360 FQ-1)
// ============================================================================

/**
 * ICD-10 pattern IDs that require medical context corroboration before firing.
 * The ICD-like regex (/\b[A-Z]\d{2}\.\d{1,2}\b/) also matches software version
 * tokens (V20.11, A12.3). Context gating prevents false positives in dev text.
 */
export const ICD_PATTERN_IDS = new Set([
  'registry-icd10-code',
]);

/** Medical vocabulary terms used to corroborate ICD-like code matches. */
const MEDICAL_CONTEXT_TERMS = /\b(patient|diagnosis|diagnosed|clinical|prescription|medication|prognosis|treatment|symptom|disease|disorder|syndrome|pathology|laboratory|specimen|physician|hospital|surgery|dosage|chronic|acute|comorbidity|medical\s+record|health\s+record|diagnostic|therapy|therapist|nurse|doctor|ailment|morbidity|biopsy|radiology|oncology|cardiology|neurology|pediatric|anesthesia|pharmacology|immunology|hematology|psychiatry|dermatology)\b/i;

export interface Icd10MatchQualityResult {
  quality: 'medical_context' | 'no_medical_context';
  reason: string;
  shouldReject: boolean;
}

/**
 * AG-PROMPT-360 (FQ-1): ICD-10 context corroboration quality gate.
 *
 * Rejects matches that lack nearby medical vocabulary. Prevents software version
 * tokens (e.g. V20.11, A12.3) from triggering the ICD-10 / medical-code signal.
 * Clinical documents contain medical vocabulary adjacent to ICD codes and pass.
 *
 * @param matchString - The matched code token (e.g. "V20.11")
 * @param fullText - Full document text for context scanning
 * @param matchIndex - Position of the match within fullText
 */
export function assessIcd10MatchQuality(
  matchString: string,
  fullText: string,
  matchIndex: number
): Icd10MatchQualityResult {
  const contextRadius = 200;
  const contextStart = Math.max(0, matchIndex - contextRadius);
  const contextEnd = Math.min(fullText.length, matchIndex + matchString.length + contextRadius);
  const contextWindow = fullText.slice(contextStart, contextEnd);
  if (MEDICAL_CONTEXT_TERMS.test(contextWindow)) {
    return { quality: 'medical_context', reason: 'medical_vocabulary_nearby', shouldReject: false };
  }
  return { quality: 'no_medical_context', reason: 'no_medical_vocabulary', shouldReject: true };
}
