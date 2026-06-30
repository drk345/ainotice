/**
 * AgentGuard modal render/format helpers.
 * AG-PROMPT-214: extracted verbatim from src/content/index.ts (behavior-preserving).
 * Pure presentation helpers — no interception, orchestration, detection, or policy logic.
 */
import type { RiskSignal, SignalSource, DocumentMetadata } from './metadataExtractor';
import { isDebugMode } from '../debug';

/** Resolves identically to FileRiskAssessment['overallRisk'] (which stays in index.ts). */
export type OverallRisk = 'none' | 'low' | 'medium' | 'high' | 'critical';

export type SignalType = RiskSignal['type'];
const SIGNAL_TYPE_ORDER: SignalType[] = ['confidential', 'pii', 'financial', 'legal', 'ip', 'sensitive'];
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'] as const;
const MAX_VISIBLE_SIGNALS = 3;

/**
 * Get risk label for UI display.
 * AG-PROMPT-061: Added 'none' state for zero-signal scenarios.
 * AG-PROMPT-073: PDF extraction failure overrides with "Unable to analyze" label.
 */
export function getRiskLabel(risk: OverallRisk, pdfExtractionFailed: boolean = false): string {
  // AG-PROMPT-073: PDF extraction failure - show "Unable to analyze" label
  if (pdfExtractionFailed && risk === 'none') {
    return 'Unable to analyze this PDF';
  }

  switch (risk) {
    case 'none': return 'No risk detected';
    case 'low': return 'Low risk';
    case 'medium': return 'Medium risk';
    case 'high': return 'High risk';
    case 'critical': return 'High risk';
  }
}

export function groupSignalsByType(signals: RiskSignal[]): Map<SignalType, RiskSignal[]> {
  const groups = new Map<SignalType, RiskSignal[]>();
  for (const type of SIGNAL_TYPE_ORDER) {
    const typeSignals = signals.filter(s => s.type === type);
    if (typeSignals.length > 0) {
      // Deterministic sort: severity first, then stable id tiebreaker (AG-PROMPT-099A)
      typeSignals.sort((a, b) => {
        const severityCmp = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
        if (severityCmp !== 0) return severityCmp;
        return (a.id ?? '').localeCompare(b.id ?? '');
      });
      groups.set(type, typeSignals);
    }
  }
  return groups;
}

export function getTopSignals(signals: RiskSignal[], limit: number): { visible: RiskSignal[]; hidden: RiskSignal[] } {
  // Deterministic sort: severity first, then stable id tiebreaker (AG-PROMPT-099A)
  const sorted = [...signals].sort((a, b) => {
    const severityCmp = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
    if (severityCmp !== 0) return severityCmp;
    return (a.id ?? '').localeCompare(b.id ?? '');
  });
  return { visible: sorted.slice(0, limit), hidden: sorted.slice(limit) };
}

export function getTypeLabel(type: SignalType): string {
  const labels: Record<SignalType, string> = {
    confidential: 'Confidential',
    pii: 'Personal Information',
    financial: 'Financial',
    legal: 'Legal',
    ip: 'Intellectual Property',
    sensitive: 'Sensitive'
  };
  return labels[type];
}

export function getSourceLabel(source: SignalSource): string {
  const labels: Record<SignalSource, string> = {
    content: 'Content',
    metadata: 'Metadata',
    filename: 'Filename'
  };
  return labels[source];
}

export function formatScannedSources(sources: Set<SignalSource>): string {
  const labels: string[] = [];
  if (sources.has('filename')) labels.push('filename');
  if (sources.has('metadata')) labels.push('document properties');
  if (sources.has('content')) labels.push('content');
  return labels.join(' • ');
}

export function formatFileSize(bytes: number): string {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

/**
 * AG-PRODUCT-PROMPT-DOCTRINE-001: Get icon for risk level.
 * Per UI spec: max 1 icon per prompt, no warning triangle or exclamation marks.
 * Icons must never carry meaning alone - always paired with text.
 */
export function getRiskIcon(risk: string): string {
  // UI spec prohibits alarmist icons (warning triangle, exclamation, stop sign)
  // Use neutral document/info icons instead
  switch (risk) {
    case 'critical':
    case 'high':
    case 'medium':
      return '📋'; // Neutral document icon
    default:
      return '✓';
  }
}

/**
 * @deprecated AG-SECURITY-HARDENING-SEC-01: Do not use escapeHtml.
 * Use SafeDom utilities from uiComponents.ts instead.
 * This function remains for backward compatibility during migration
 * but will be removed in a future release.
 */
export function escapeHtml(str: string): string {
  // SEC-01: Log deprecation warning in debug mode
  if (isDebugMode()) {
    console.warn('[Ai Notice:SEC-01] escapeHtml is deprecated. Migrate to SafeDom utilities.');
  }
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

/**
 * AG-PROMPT-085/088: Check if metadata value is displayable.
 * Filters out garbled/corrupted values (non-printable chars, hex codes, etc.)
 * AG-PROMPT-088: Strengthened to filter UTF-16 BOM, NULL chars, and replacement chars.
 */
export function isDisplayableMetadata(value: string | undefined): boolean {
  if (!value || value.length === 0) return false;
  // Filter out: control characters, excessive hex-like patterns, or very long strings
  if (value.length > 200) return false;
  // AG-PROMPT-088: Filter UTF-16 BOM patterns (þÿ at start) common in corrupted PDF metadata
  if (value.startsWith('þÿ') || value.startsWith('\uFEFF')) return false;
  // AG-PROMPT-088: Filter strings with NULL characters (common in UTF-16 encoded strings)
  if (value.includes('\u0000')) return false;
  // AG-PROMPT-088: Filter strings with Unicode replacement character (indicates encoding issues)
  if (value.includes('\uFFFD')) return false;
  // Check for garbled content: high ratio of non-printable or unusual characters
  const printableRatio = value.replace(/[^\x20-\x7E\u00A0-\uFFFF]/g, '').length / value.length;
  if (printableRatio < 0.8) return false;
  // Filter hex-like noise patterns (common in corrupted PDF metadata)
  if (/^[0-9A-Fa-f]{8,}$/.test(value)) return false;
  return true;
}

export function hasMetadataToShow(metadata: DocumentMetadata | undefined): boolean {
  if (!metadata) return false;
  // AG-PROMPT-085: Only consider human-readable fields (exclude creator/producer as low-value)
  return isDisplayableMetadata(metadata.title) || isDisplayableMetadata(metadata.author) ||
         isDisplayableMetadata(metadata.company) || isDisplayableMetadata(metadata.lastModifiedBy) ||
         isDisplayableMetadata(metadata.manager) || isDisplayableMetadata(metadata.subject);
}

/**
 * AG-PROMPT-085: Render document metadata, filtering garbled values.
 * Technical fields (creator, producer) are omitted to reduce information density.
 */
export function renderMetadata(metadata: DocumentMetadata): string {
  const items: string[] = [];
  // Human-readable fields only - creator/producer are technical noise
  if (isDisplayableMetadata(metadata.title)) items.push(`<div class="ainotice-metadata-item"><span class="ainotice-metadata-label">Title:</span><span class="ainotice-metadata-value">${escapeHtml(metadata.title!)}</span></div>`);
  if (isDisplayableMetadata(metadata.author)) items.push(`<div class="ainotice-metadata-item"><span class="ainotice-metadata-label">Author:</span><span class="ainotice-metadata-value">${escapeHtml(metadata.author!)}</span></div>`);
  if (isDisplayableMetadata(metadata.company)) items.push(`<div class="ainotice-metadata-item"><span class="ainotice-metadata-label">Company:</span><span class="ainotice-metadata-value">${escapeHtml(metadata.company!)}</span></div>`);
  if (isDisplayableMetadata(metadata.lastModifiedBy)) items.push(`<div class="ainotice-metadata-item"><span class="ainotice-metadata-label">Modified by:</span><span class="ainotice-metadata-value">${escapeHtml(metadata.lastModifiedBy!)}</span></div>`);
  if (isDisplayableMetadata(metadata.manager)) items.push(`<div class="ainotice-metadata-item"><span class="ainotice-metadata-label">Manager:</span><span class="ainotice-metadata-value">${escapeHtml(metadata.manager!)}</span></div>`);
  if (isDisplayableMetadata(metadata.subject)) items.push(`<div class="ainotice-metadata-item"><span class="ainotice-metadata-label">Subject:</span><span class="ainotice-metadata-value">${escapeHtml(metadata.subject!)}</span></div>`);
  // AG-PROMPT-085: Omit creator/producer - these are low-value technical details
  // that add noise without helping the user make a decision
  if (items.length === 0) return '';
  return `<div class="ainotice-metadata"><div class="ainotice-metadata-title">Properties</div>${items.join('')}</div>`;
}

/**
 * AG-PROMPT-088/097B: Get the primary finding for minimal view.
 *
 * AG-PROMPT-097B: Now dominance-aware. Uses dominanceOrderedIds (from
 * decisionExplanation.details) to prefer context-appropriate signals.
 * In legal/HR documents, PII signals should be primary, not payment card patterns.
 *
 * @deprecated AG-PROMPT-099A: This function is currently dead code (never called).
 * Kept for potential future use. Consider removing if still unused after review.
 *
 * @param signals - All visible signals
 * @param dominanceOrderedIds - Optional signal IDs ordered by dominance resolution
 * @returns The primary signal to display, or null if none
 */
export function getPrimaryFinding(
  signals: RiskSignal[],
  dominanceOrderedIds?: string[]
): RiskSignal | null {
  if (signals.length === 0) return null;

  // AG-PROMPT-097B: If dominance ordering is provided, use it
  if (dominanceOrderedIds && dominanceOrderedIds.length > 0) {
    const primaryId = dominanceOrderedIds[0];
    const dominanceMatch = signals.find(s => s.id === primaryId);
    if (dominanceMatch) {
      return dominanceMatch;
    }
    // Fall through to severity sort if dominance ID not found in signals
  }

  // Fallback: Sort by severity (critical > high > medium > low) and return first
  const severityOrder = ['critical', 'high', 'medium', 'low'];
  const sorted = [...signals].sort((a, b) => {
    return severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity);
  });
  return sorted[0];
}

/**
 * AG-PROMPT-088: Render primary finding for minimal default view.
 *
 * @deprecated AG-PROMPT-099A: This function is currently dead code (never called).
 * Kept for potential future use. Consider removing if still unused after review.
 */
export function renderPrimaryFinding(signal: RiskSignal): string {
  return `
    <div class="ainotice-primary-finding">
      <div class="ainotice-primary-finding-label">Primary finding</div>
      <div class="ainotice-primary-finding-content">
        <span class="ainotice-signal-badge ${signal.severity}">${signal.severity}</span>
        <span class="ainotice-primary-finding-text">${escapeHtml(signal.description)}</span>
      </div>
    </div>
  `;
}

export function renderGroupedSignals(signals: RiskSignal[], showAll: boolean): string {
  // INSTRUMENT PANEL: Observational, structural language
  if (signals.length === 0) {
    return '<div class="ainotice-no-signals">No patterns detected</div>';
  }

  const limit = showAll ? signals.length : MAX_VISIBLE_SIGNALS;
  const { visible, hidden } = getTopSignals(signals, limit);
  const grouped = groupSignalsByType(visible);

  let html = '<div class="ainotice-signals-section">';
  html += `<div class="ainotice-signals-header">Detected patterns${signals.length > MAX_VISIBLE_SIGNALS && !showAll ? ` (${visible.length} of ${signals.length})` : ''}</div>`;

  for (const [type, typeSignals] of grouped) {
    html += `<div class="ainotice-signal-group"><div class="ainotice-signal-group-title">${getTypeLabel(type)}</div>`;
    html += typeSignals.map(signal => `
      <div class="ainotice-signal">
        <div class="ainotice-signal-header">
          <span class="ainotice-signal-badge ${signal.severity}">${signal.severity}</span>
          <span class="ainotice-signal-title">${escapeHtml(signal.description)}</span>
          <span class="ainotice-signal-source">${getSourceLabel(signal.source)}</span>
        </div>
        ${signal.detail ? `<div class="ainotice-signal-detail">${escapeHtml(signal.detail)}</div>` : ''}
      </div>
    `).join('');
    html += '</div>';
  }

  if (hidden.length > 0 && !showAll) {
    html += `<div class="ainotice-show-more" data-action="show-more">${hidden.length} more</div>`;
  }

  html += '<div class="ainotice-confidence">Pattern matching is deterministic.</div>';
  html += '</div>';
  return html;
}

/**
 * Get proceed button text based on risk level.
 * AG-PROMPT-061: Added 'none' state - same as low risk (just "Proceed").
 * AG-PROMPT-083: Simplified to neutral language, removed moralizing/threatening phrasing.
 * AG-PRODUCT-PROMPT-DOCTRINE-001: Primary action must not imply danger or wrongdoing.
 * Use neutral "Continue" for all cases - affirmative continuation tone.
 */
export function getProceedButtonText(risk: OverallRisk): string {
  // UI spec: primary action tone must be neutral, non-alarming
  // "Upload anyway" implies wrongdoing - use neutral "Continue" instead
  return 'Continue';
}
