/**
 * AgentGuard Dictionary Detection Engine
 *
 * Thin engine for deterministic dictionary-based detection.
 * Data is loaded from JSON files in src/data/dictionaries/.
 *
 * Design principles:
 * - Local-only, no telemetry
 * - Deterministic matching (no LLM/probabilistic logic)
 * - Explainable matches (which dictionary, which term)
 * - Composable with policy layer (severity caps still apply)
 *
 * @see ADR-012: Department-Scoped Dictionaries
 * @see AG-PROMPT-062: Datafy dictionaries
 */

import type { DepartmentId, PolicyContext } from './policy';
import { ALL_DICTIONARY_DATA } from '../data/dictionaries';
// AG-PROMPT-231: canonical severity rank — replaces the local 4-level SEVERITY_ORDER constant.
import { SEVERITY_ORDER_NO_NONE as SEVERITY_ORDER } from './severityRank';

// AG-PROMPT-031: Evidence tracing
import { AG_DEBUG_EVIDENCE, createEvidence } from '../detection/evidenceCapture';
import type { EvidenceItem } from '../types/riskSignal';

// ============================================================================
// TYPES
// ============================================================================

export type MatchType = 'keyword' | 'phrase';
export type SignalType = 'pii' | 'confidential' | 'sensitive' | 'ip' | 'financial' | 'legal';
export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type SignalSource = 'content' | 'metadata' | 'filename';

/** JSON dictionary entry schema */
interface JsonDictionaryEntry {
  id: string;
  label: string;
  values: string[];
  severity: Severity;
  signalType: SignalType;
  matchType?: MatchType;
  minHits?: number;
  maxSeverity?: Severity;
  sources?: SignalSource[];
}

/** JSON dictionary schema */
interface JsonDictionary {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  entries: JsonDictionaryEntry[];
}

/** Risk signal output (compatible with canonical RiskSignal type) */
export interface DictionaryRiskSignal {
  /** AG-PROMPT-SIGNAL-PARITY-029: Stable ID for classification */
  id?: string;
  type: SignalType;
  description: string;
  severity: Severity;
  detail: string;
  source: SignalSource;
  detectedAt: number;
  /** AG-PROMPT-031: Evidence trace (only when AG_DEBUG_EVIDENCE is true) */
  evidence?: EvidenceItem[];
}

// ============================================================================
// CONFIGURATION
// ============================================================================

const DEBUG_DICTIONARIES = false;

// ============================================================================
// TEXT NORMALIZATION & MATCHING
// ============================================================================

function normalizeText(text: string): string {
  return text.toLowerCase().replace(/\s+/g, ' ').trim();
}

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Match with word boundaries (keyword mode) */
function matchKeywords(text: string, keywords: string[]): number {
  const normalizedText = normalizeText(text);
  let count = 0;
  for (const keyword of keywords) {
    const pattern = new RegExp(`\\b${escapeRegex(normalizeText(keyword))}\\b`, 'gi');
    const matches = normalizedText.match(pattern);
    if (matches) count += matches.length;
  }
  return count;
}

/** Match phrases (substring after normalization) */
function matchPhrases(text: string, phrases: string[]): number {
  const normalizedText = normalizeText(text);
  let count = 0;
  for (const phrase of phrases) {
    const pattern = new RegExp(escapeRegex(normalizeText(phrase)), 'gi');
    const matches = normalizedText.match(pattern);
    if (matches) count += matches.length;
  }
  return count;
}

/** Run matching for an entry */
function matchEntry(text: string, entry: JsonDictionaryEntry): number {
  const matchType = entry.matchType || 'phrase';
  return matchType === 'keyword'
    ? matchKeywords(text, entry.values)
    : matchPhrases(text, entry.values);
}

/** AG-PROMPT-031: Get first match position for evidence capture */
function getFirstMatchInfo(text: string, entry: JsonDictionaryEntry): { matched: string; index: number } | null {
  if (!AG_DEBUG_EVIDENCE) return null;
  const normalizedText = normalizeText(text);
  for (const value of entry.values) {
    const normalizedValue = normalizeText(value);
    const idx = normalizedText.indexOf(normalizedValue);
    if (idx !== -1) {
      return { matched: normalizedValue, index: idx };
    }
  }
  return null;
}

// ============================================================================
// DICTIONARY LOADING
// ============================================================================

/** Map department ID to dictionary ID */
const DEPARTMENT_TO_DICT: Record<DepartmentId, string | null> = {
  finance: 'finance',
  hr: 'hr',
  legal: 'legal',
  engineering: null,
  default: null,
};

/** Load dictionaries for a given context */
function getDictionariesForContext(context: PolicyContext): JsonDictionary[] {
  const department = context.department || 'default';
  const dictId = DEPARTMENT_TO_DICT[department];
  if (!dictId) return [];

  const dict = ALL_DICTIONARY_DATA.find(d => d.id === dictId && d.enabled);
  return dict ? [dict as JsonDictionary] : [];
}

// ============================================================================
// DETECTION ENGINE
// ============================================================================

// Severity ordering imported from ./severityRank (AG-PROMPT-231)

/**
 * Run dictionary-based detections on text content.
 * Deterministic: same input => same signals.
 */
export function runDictionaryDetections(
  text: string,
  context: PolicyContext
): DictionaryRiskSignal[] {
  if (!text || text.length === 0) return [];

  const dictionaries = getDictionariesForContext(context);
  if (dictionaries.length === 0) return [];

  const signals: DictionaryRiskSignal[] = [];
  let totalEntries = 0;
  let matchedEntries = 0;

  for (const dictionary of dictionaries) {
    for (const entry of dictionary.entries) {
      totalEntries++;

      // Check source filter (default: content only)
      const allowedSources = entry.sources || ['content'];
      if (!allowedSources.includes('content')) continue;

      const hitCount = matchEntry(text, entry);
      const minHits = entry.minHits || 1;

      if (hitCount >= minHits) {
        matchedEntries++;

        // Apply severity cap if specified
        let severity = entry.severity;
        if (entry.maxSeverity) {
          const currentIdx = SEVERITY_ORDER.indexOf(severity);
          const maxIdx = SEVERITY_ORDER.indexOf(entry.maxSeverity);
          if (currentIdx > maxIdx) severity = entry.maxSeverity;
        }

        // AG-PROMPT-031: Evidence capture for dictionary match
        let evidence: EvidenceItem[] | undefined;
        if (AG_DEBUG_EVIDENCE) {
          const firstMatch = getFirstMatchInfo(text, entry);
          if (firstMatch) {
            const ev = createEvidence({
              signal_id: entry.id,
              origin_path: 'dictionary',
              producer: `dictionaries/${dictionary.id}`,
              rule_id: entry.id,
              matched_text: firstMatch.matched,
              start_index: firstMatch.index,
              end_index: firstMatch.index + firstMatch.matched.length,
              full_text: text,
              location: 'CONTENT',
              field: null,
            });
            if (ev) evidence = [ev];
          }
        }

        signals.push({
          id: entry.id, // AG-PROMPT-SIGNAL-PARITY-029: stable ID for classification
          type: entry.signalType,
          description: entry.label,
          severity,
          detail: `Dictionary match: ${entry.label} (${hitCount} hit${hitCount > 1 ? 's' : ''}) [${dictionary.name}]`,
          source: 'content',
          detectedAt: Date.now(),
          evidence,
        });
      }
    }
  }

  if (DEBUG_DICTIONARIES && matchedEntries > 0) {
    console.log(`[Ai Notice] Dictionary match: department=${context.department || 'default'} entries=${matchedEntries}/${totalEntries}`);
  }

  return signals;
}

// ============================================================================
// PUBLIC API (for admin UI / inspection)
// ============================================================================

/** Get all available dictionaries */
export function getAvailableDictionaries(): JsonDictionary[] {
  return ALL_DICTIONARY_DATA.filter(d => d.enabled) as JsonDictionary[];
}

/** Get dictionary for a specific department */
export function getDictionaryForDepartment(department: DepartmentId): JsonDictionary | null {
  const dictId = DEPARTMENT_TO_DICT[department];
  if (!dictId) return null;
  return (ALL_DICTIONARY_DATA.find(d => d.id === dictId) as JsonDictionary) || null;
}
