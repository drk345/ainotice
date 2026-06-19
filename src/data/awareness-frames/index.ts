/**
 * Awareness Frames Data Index
 *
 * Static imports of JSON awareness frame configuration.
 * This enables deterministic loading without dynamic FS access.
 *
 * @see AG-PROMPT-064: Datafy awareness framing
 */

import framesData from './frames.json';
import selectionRulesData from './selection-rules.json';
import forbiddenWordsData from './forbidden-words.json';
import signalPatternsData from './signal-patterns.json';

export {
  framesData,
  selectionRulesData,
  forbiddenWordsData,
  signalPatternsData,
};

// Type definitions for JSON data
export interface FrameData {
  id: string;
  headline: string;
  noClassHeadline?: string;  // AG-PROMPT-SURFACE-EPISTEMIC-BOUNDARIES-018: Indicator-centric headline when no documentClass
  inferredHeadline?: string;  // AG-PROMPT-SURFACE-AUTHORITY-CALIBRATION-016: Association-based headline for inferred confidence
  noClassInferredHeadline?: string;  // AG-PROMPT-SURFACE-EPISTEMIC-BOUNDARIES-018: Indicator-centric inferred headline
  summary: string;
  lowSeveritySummary: string;
  guidance: string;  // AG-PROMPT-089: Actionable guidance for the user
  notes?: string;
}

export interface SelectionRule {
  ruleId: string;
  frameId: string;
  condition: Record<string, unknown>;
  priority: number;
  notes?: string;
}

export interface SuppressionRule {
  ruleId: string;
  condition: Record<string, unknown>;
  notes?: string;
}

// Typed access to frame data
export const FRAMES_DATA = framesData.frames as FrameData[];
export const SELECTION_RULES = selectionRulesData.rules as SelectionRule[];
export const SUPPRESSION_RULES = selectionRulesData.suppressionRules as SuppressionRule[];

// Build frame lookup map
export const FRAME_MAP: Record<string, FrameData> = {};
for (const frame of FRAMES_DATA) {
  FRAME_MAP[frame.id] = frame;
}

// AG-PROMPT-094: Sanity check for FRAME_GENERAL_SENSITIVE (fail closed with clear error)
// This is the default frame used by ensureFrameCompleteForUI(). If missing, fail loudly
// at module load rather than causing a confusing TypeError later.
if (!FRAME_MAP['FRAME_GENERAL_SENSITIVE']) {
  throw new Error(
    'AG-PROMPT-094: FRAME_MAP missing FRAME_GENERAL_SENSITIVE. ' +
    'Check frames.json integrity. Frame governance requires this default frame.'
  );
}

// Flatten forbidden words for easy checking
export const FORBIDDEN_WORDS_LIST: string[] = [
  ...forbiddenWordsData.categories.alarming.words,
  ...forbiddenWordsData.categories.technical.words,
  ...forbiddenWordsData.categories.dlpStyle.words,
];

// Signal patterns
export const REGULATED_PATTERNS = signalPatternsData.regulatedPatterns.patterns as string[];
export const LEGAL_PATTERNS = signalPatternsData.legalPatterns.patterns as string[];

// AG-PROMPT-CONFIDENTIAL-QUALITY-008: Distribution vs content sensitivity patterns
export const DISTRIBUTION_PATTERNS = (signalPatternsData as Record<string, { patterns?: string[] }>).distributionPatterns?.patterns || [];
export const SECRETS_PATTERNS = (signalPatternsData as Record<string, { patterns?: string[] }>).secretsPatterns?.patterns || [];

// AG-PROMPT-SURFACE-COMPOSITE-001: Signal families for composite detection
export interface SignalFamily {
  id: string;
  label: string;
  patterns: string[];
}
export const SIGNAL_FAMILIES = (signalPatternsData.signalFamilies?.families || []) as SignalFamily[];
