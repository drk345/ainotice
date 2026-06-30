/**
 * UI Components - Safe DOM rendering for Ai Notice overlays
 *
 * AG-SECURITY-HARDENING-SEC-01: All UI rendering uses SafeDom utilities.
 * No innerHTML, no escapeHtml - safe by construction.
 *
 * AG-PROMPT-167: Trust-first modal redesign.
 * These components replace the innerHTML templates in index.ts.
 */

import { el, text, on, cx, when, map, fragment, setChildren, appendChild } from '../lib/safeDom';
import type { RiskSignal, SignalSource, Severity } from '../types/riskSignal';
import type { DocumentMetadata } from './metadataExtractor';
import type { DecisionQualityBlocks } from './decisionQualityBlocks';

// ============================================================================
// AG-PROMPT-196: UPLOAD TRIGGER SOURCE
// Kept in the content/UI path — not signal-domain metadata.
// ============================================================================

/** What user action triggered the awareness scan. Drives modal copy selection. */
export type UploadTriggerSource = 'file' | 'clipboard_paste' | 'prompt_send';

// ============================================================================
// CONSTANTS
// ============================================================================

const MAX_VISIBLE_SIGNALS = 5;
const MAX_EVIDENCE_PREVIEW = 3;

// ============================================================================
// TYPE HELPERS
// ============================================================================

function getTypeLabel(type: string): string {
  const labels: Record<string, string> = {
    pii: 'Personal Information',
    financial: 'Financial Data',
    medical: 'Medical Information',
    confidential: 'Confidential',
    legal: 'Legal Information',
    secret: 'Secrets & Credentials',
    metadata: 'Document Metadata',
  };
  return labels[type] || type;
}

// AG-PROMPT-196/Stage-2: Severity display label for header row
function getSeverityLabel(severity: string | undefined): string {
  const labels: Record<string, string> = {
    critical: 'Critical',
    high:     'High Risk',
    medium:   'Medium Risk',
    low:      'Low Risk',
  };
  return labels[severity || ''] || '';
}

// AG-PROMPT-196/Stage-2: Confidence pill — colored tag per design system §8.2
// Colors are analysis-quality indicators, orthogonal to severity doctrine.
// AG-PROMPT-326: in high/critical danger states, "Confirmed" must NOT render green — a green
// pill reads as "safe/pass" next to a danger warning. Use a neutral slate treatment instead
// (still legible as "Confirmed", but not a positive green badge). Inferred/Reduced unchanged.
function buildConfidenceTag(label: string, severity?: string): HTMLElement {
  type C = { color: string; bg: string; border: string };
  const isDanger = severity === 'high' || severity === 'critical';
  const confirmedStyle: C = isDanger
    ? { color: '#334155', bg: '#F1F5F9', border: '#CBD5E1' }   // neutral slate — no green-implies-safe in danger
    : { color: '#059669', bg: '#D1FAE5', border: '#A7F3D0' };  // green — calm states only
  const cfg: Record<string, C> = {
    Confirmed: confirmedStyle,
    Inferred:  { color: '#D97706', bg: '#FFFBEB', border: '#FDE68A' },
    Reduced:   { color: '#64748B', bg: '#F8FAFC', border: '#E2E8F0' },
  };
  const c = cfg[label] || cfg['Reduced'];
  return el('span', {
    className: 'ainotice-conf-tag',
    style: `color:${c.color};background:${c.bg};border-color:${c.border};`,
  }, [
    el('span', { className: 'ainotice-conf-dot', style: `background:${c.color};` }, []),
    label,
  ]);
}

function getSourceLabel(source: string): string {
  const labels: Record<string, string> = {
    content: 'content',
    metadata: 'properties',
    filename: 'filename',
  };
  return labels[source] || source;
}

// ============================================================================
// SIGNAL GROUPING
// ============================================================================

function groupSignalsByType(signals: RiskSignal[]): Map<string, RiskSignal[]> {
  const grouped = new Map<string, RiskSignal[]>();
  for (const signal of signals) {
    const type = signal.type || 'other';
    if (!grouped.has(type)) {
      grouped.set(type, []);
    }
    grouped.get(type)!.push(signal);
  }
  return grouped;
}

function getTopSignals(signals: RiskSignal[], limit: number): { visible: RiskSignal[]; hidden: RiskSignal[] } {
  const severityOrder = ['critical', 'high', 'medium', 'low'];
  const sorted = [...signals].sort((a, b) => {
    return severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity);
  });
  return {
    visible: sorted.slice(0, limit),
    hidden: sorted.slice(limit),
  };
}

// ============================================================================
// EVIDENCE PREVIEW (UX-05: up to 3 content-free evidence bullets)
// ============================================================================

function deriveEvidenceBullets(signals: RiskSignal[]): string[] {
  const severityOrder = ['critical', 'high', 'medium', 'low'];
  const sorted = [...signals].sort((a, b) =>
    severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity)
  );
  const seen = new Set<string>();
  const bullets: string[] = [];
  for (const signal of sorted) {
    const label = signal.description || getTypeLabel(signal.type);
    if (!seen.has(label) && bullets.length < MAX_EVIDENCE_PREVIEW) {
      seen.add(label);
      // AG-PROMPT-171/Fix-8: Clean label only — no "(found in content)" qualifier
      bullets.push(label);
    }
  }
  return bullets;
}

/**
 * AG-PROMPT-169/WS-01: Show 1 evidence label by default; rest behind expandable.
 * Label: "What did we find?"
 */
function buildEvidencePreview(signals: RiskSignal[]): HTMLDivElement | null {
  if (signals.length === 0) return null;
  const bullets = deriveEvidenceBullets(signals);
  if (bullets.length === 0) return null;

  const firstBullet = bullets[0];
  const remaining = bullets.slice(1);

  // AG-PROMPT-171/Fix-5+9: Evidence is inside a collapsed expandable now.
  // Show all bullets flat (no inline expand toggle — the accordion handles expand/collapse).
  const container = el('div', { className: 'ainotice-evidence-preview' }, [
    el('ul', { className: 'ainotice-evidence-preview-list' },
      bullets.map(b => el('li', {}, [b]))
    ),
  ]) as HTMLDivElement;

  return container;
}

// ============================================================================
// POST-DECISION TOAST (AG-PROMPT-168/WS-03)
// ============================================================================

const TOAST_DURATION_MS = 2000;

// AG-PROMPT-196: Cancel message varies by what was actually intercepted.
const CANCEL_TOAST_MESSAGE: Record<UploadTriggerSource, string> = {
  file:            'Decision applied. File was not shared.',
  clipboard_paste: 'Decision applied. Content was not pasted.',
  prompt_send:     'Decision applied. Message was not sent.',
};

export function showPostDecisionToast(action: 'proceed' | 'cancel', triggerSource: UploadTriggerSource = 'file'): void {
  const message = action === 'cancel'
    ? CANCEL_TOAST_MESSAGE[triggerSource]
    : 'Decision applied. You chose to continue.';

  const toast = el('div', {
    className: 'ainotice-toast',
    role: 'status',
    'aria-live': 'polite',
  }, [message]) as HTMLDivElement;

  document.body.appendChild(toast);

  // Auto-dismiss after TOAST_DURATION_MS
  setTimeout(() => {
    toast.classList.add('ainotice-toast-exit');
    setTimeout(() => toast.remove(), 300); // exit animation duration
  }, TOAST_DURATION_MS);
}

// ============================================================================
// DRAG OVERLAY
// ============================================================================

export function buildDragOverlay(): HTMLDivElement {
  return el('div', { className: 'ainotice-drag-overlay' }, [
    el('div', { className: 'ainotice-drag-indicator' }, [
      el('h3', {}, ['Ai Notice']),
      el('p', {}, ['Drop to inspect']),
    ]),
  ]) as HTMLDivElement;
}

// ============================================================================
// LOADING MODAL
// ============================================================================

export function buildLoadingModal(): HTMLDivElement {
  return el('div', { className: 'ainotice-overlay', id: 'ainotice-modal-overlay', role: 'alert', 'aria-live': 'polite' }, [
    el('div', { className: 'ainotice-modal' }, [
      el('div', { className: 'ainotice-body' }, [
        el('div', { className: 'ainotice-loading' }, [
          el('div', { className: 'ainotice-spinner' }, []),
          el('span', {}, ['Scanning\u2026']),
        ]),
      ]),
    ]),
  ]) as HTMLDivElement;
}

// ============================================================================
// LICENSE NOTICE
// ============================================================================

export function buildLicenseNotice(state: string): HTMLDivElement | null {
  // AG-PROMPT-315: Consumer Edition shows NO license/trial/admin banner in the warning modal.
  // The consumer build runs without a license; "Trial mode \u00B7 Contact admin for full license" is
  // enterprise/admin framing and must not appear in consumer-facing UI. This suppresses only the
  // (screenshot-visible) modal banner \u2014 license VALIDATION logic is unchanged, and the historical
  // enterprise notice copy still lives in the (unrendered) getLicenseNoticeHtml() that the
  // license-UX guardrail statically asserts.
  void state;
  return null;
}

// ============================================================================
// METADATA SECTION
// ============================================================================

export interface DisplayableMetadata {
  title?: string;
  author?: string;
  company?: string;
  lastModifiedBy?: string;
  manager?: string;
  subject?: string;
}

function isDisplayableValue(value: string | undefined): boolean {
  if (!value || value.length === 0) return false;
  if (value.length > 200) return false;
  if (value.startsWith('\u00FE\u00FF') || value.startsWith('\uFEFF')) return false;
  if (value.includes('\u0000')) return false;
  if (value.includes('\uFFFD')) return false;
  const printableRatio = value.replace(/[^\x20-\x7E\u00A0-\uFFFF]/g, '').length / value.length;
  if (printableRatio < 0.8) return false;
  if (/^[0-9A-Fa-f]{8,}$/.test(value)) return false;
  return true;
}

export function buildMetadataSection(metadata: DocumentMetadata | undefined): HTMLDivElement | null {
  if (!metadata) return null;

  const items: Array<{ label: string; value: string }> = [];

  if (isDisplayableValue(metadata.title)) items.push({ label: 'Title:', value: metadata.title! });
  if (isDisplayableValue(metadata.author)) items.push({ label: 'Author:', value: metadata.author! });
  if (isDisplayableValue(metadata.company)) items.push({ label: 'Company:', value: metadata.company! });
  if (isDisplayableValue(metadata.lastModifiedBy)) items.push({ label: 'Modified by:', value: metadata.lastModifiedBy! });
  if (isDisplayableValue(metadata.manager)) items.push({ label: 'Manager:', value: metadata.manager! });
  if (isDisplayableValue(metadata.subject)) items.push({ label: 'Subject:', value: metadata.subject! });

  if (items.length === 0) return null;

  return el('div', { className: 'ainotice-metadata' }, [
    el('div', { className: 'ainotice-metadata-title' }, ['Properties']),
    ...items.map(item =>
      el('div', { className: 'ainotice-metadata-item' }, [
        el('span', { className: 'ainotice-metadata-label' }, [item.label]),
        el('span', { className: 'ainotice-metadata-value' }, [item.value]),
      ])
    ),
  ]) as HTMLDivElement;
}

// ============================================================================
// SIGNALS SECTION
// ============================================================================

function buildSignalItem(signal: RiskSignal): HTMLDivElement {
  return el('div', { className: 'ainotice-signal' }, [
    el('div', { className: 'ainotice-signal-header' }, [
      el('span', { className: cx('ainotice-signal-badge', signal.severity) }, [signal.severity]),
      el('span', { className: 'ainotice-signal-title' }, [signal.description]),
      el('span', { className: 'ainotice-signal-source' }, [getSourceLabel(signal.source)]),
    ]),
    when(!!signal.detail,
      el('div', { className: 'ainotice-signal-detail' }, [signal.detail || ''])
    ),
  ]) as HTMLDivElement;
}

function buildSignalGroup(type: string, signals: RiskSignal[]): HTMLDivElement {
  return el('div', { className: 'ainotice-signal-group' }, [
    el('div', { className: 'ainotice-signal-group-title' }, [getTypeLabel(type)]),
    ...signals.map(buildSignalItem),
  ]) as HTMLDivElement;
}

export function buildSignalsSection(
  signals: RiskSignal[],
  showAll: boolean,
  onShowMore?: () => void
): HTMLDivElement {
  if (signals.length === 0) {
    return el('div', { className: 'ainotice-no-signals' }, ['No patterns detected']) as HTMLDivElement;
  }

  const limit = showAll ? signals.length : MAX_VISIBLE_SIGNALS;
  const { visible, hidden } = getTopSignals(signals, limit);
  const grouped = groupSignalsByType(visible);

  const headerText = signals.length > MAX_VISIBLE_SIGNALS && !showAll
    ? `Detected patterns (${visible.length} of ${signals.length})`
    : 'Detected patterns';

  const section = el('div', { className: 'ainotice-signals-section' }, [
    el('div', { className: 'ainotice-signals-header' }, [headerText]),
    ...Array.from(grouped.entries()).map(([type, typeSignals]) =>
      buildSignalGroup(type, typeSignals)
    ),
    when(hidden.length > 0 && !showAll,
      el('button', { className: 'ainotice-show-more', 'data-action': 'show-more' }, [`${hidden.length} more`])
    ),
    el('div', { className: 'ainotice-confidence' }, ['Pattern matching is deterministic.']),
  ]) as HTMLDivElement;

  // Attach show-more handler if provided
  if (onShowMore && hidden.length > 0 && !showAll) {
    const showMoreBtn = section.querySelector('[data-action="show-more"]');
    if (showMoreBtn) {
      on(showMoreBtn, 'click', onShowMore);
    }
  }

  return section;
}

// ============================================================================
// AWARENESS NOTICE
// ============================================================================

export interface NoticeOptions {
  headline: string;
  summary: string;
  isLowRisk: boolean;
  onContinue: () => void;
  onDetails?: () => void;
}

export function buildAwarenessNotice(options: NoticeOptions): HTMLDivElement {
  const { headline, summary, isLowRisk, onContinue, onDetails } = options;

  const notice = el('div', {
    className: 'ainotice-overlay ainotice-notice-overlay',
    id: 'ainotice-notice-overlay',
  }, [
    el('div', { className: cx('ainotice-notice', { 'ainotice-notice-low': isLowRisk }) }, [
      el('div', { className: cx('ainotice-notice-icon', { 'ainotice-notice-icon-low': isLowRisk }) }, [
        isLowRisk ? '\u2139' : '\u2713',
      ]),
      el('div', { className: 'ainotice-notice-content' }, [
        el('div', { className: 'ainotice-notice-branding' }, [
          el('span', { className: 'ainotice-notice-branding-icon' }, ['\uD83D\uDEE1\uFE0F']),
          'Ai Notice',
        ]),
        el('h3', { className: 'ainotice-notice-title' }, [headline]),
        el('p', { className: 'ainotice-notice-summary' }, [summary]),
        when(Boolean(isLowRisk && onDetails),
          el('button', { className: 'ainotice-notice-details', 'data-action': 'details' }, ['Details'])
        ),
      ]),
      when(!isLowRisk,
        el('button', { className: 'ainotice-notice-continue', 'data-action': 'continue' }, ['Continue'])
      ),
    ]),
  ]) as HTMLDivElement;

  // Attach event handlers
  const detailsBtn = notice.querySelector('[data-action="details"]');
  if (detailsBtn && onDetails) {
    on(detailsBtn, 'click', (e) => {
      e.stopPropagation();
      onDetails();
    });
  }

  const continueBtn = notice.querySelector('[data-action="continue"]');
  if (continueBtn) {
    on(continueBtn, 'click', (e) => {
      e.stopPropagation();
      onContinue();
    });
  }

  return notice;
}

// ============================================================================
// AWARENESS BANNER (DEPRECATED)
// ============================================================================

export interface BannerOptions {
  headline: string;
  summary: string;
  detectedText: string;
  onClose: () => void;
  onReview: () => void;
  onProceed: () => void;
}

export function buildAwarenessBanner(options: BannerOptions): HTMLDivElement {
  const { headline, summary, detectedText, onClose, onReview, onProceed } = options;

  const banner = el('div', { className: 'ainotice-banner', id: 'ainotice-awareness-banner' }, [
    el('button', { className: 'ainotice-banner-close', 'data-action': 'close', title: 'Dismiss' }, ['\u00D7']),
    el('div', { className: 'ainotice-banner-content' }, [
      el('div', { className: 'ainotice-banner-header' }, [
        el('div', { className: 'ainotice-banner-icon' }, ['\u2139']),
        el('div', { className: 'ainotice-banner-text' }, [
          el('h3', { className: 'ainotice-banner-title' }, [headline]),
          el('p', { className: 'ainotice-banner-summary' }, [summary]),
        ]),
      ]),
      when(!!detectedText,
        el('div', { className: 'ainotice-banner-detected' }, [
          el('span', { className: 'ainotice-banner-detected-icon' }, ['\uD83D\uDD0D']),
          el('span', {}, ['Found: ', detectedText]),
        ])
      ),
      el('div', { className: 'ainotice-banner-actions' }, [
        el('button', { className: 'ainotice-banner-btn ainotice-banner-btn-secondary', 'data-action': 'review' }, ['Review']),
        el('button', { className: 'ainotice-banner-btn ainotice-banner-btn-primary', 'data-action': 'proceed' }, ['Continue']),
      ]),
    ]),
  ]) as HTMLDivElement;

  // Attach event handlers
  on(banner.querySelector('[data-action="close"]')!, 'click', onClose);
  on(banner.querySelector('[data-action="review"]')!, 'click', onReview);
  on(banner.querySelector('[data-action="proceed"]')!, 'click', onProceed);

  return banner;
}

// ============================================================================
// RISK MODAL
// ============================================================================

export interface ModalOptions {
  modalTitle: string;
  modalSubtitle: string;
  riskSummary: string;
  guidance: string;
  destination: string;
  scannedSourcesText: string;
  filesHtml: HTMLElement | null;
  signals: RiskSignal[];
  licenseState: string;
  isBlocked: boolean;
  needsFriction: boolean;
  /** AG-PROMPT-134: Decision-quality blocks */
  decisionQuality?: DecisionQualityBlocks;
  /** AG-PROMPT-134: Whether to show "Continue anyway" label (has detected signals) */
  hasDetectedSignals?: boolean;
  /** AG-PROMPT-167: Overall risk level for severity badge in header */
  overallRisk?: string;
  /** AG-PROMPT-169/WS-03: Extraction-limited state (confidence = limited_analysis) */
  isExtractionLimited?: boolean;
  /** AG-PROMPT-196: What triggered this scan — drives context line and file-section visibility */
  triggerSource?: UploadTriggerSource;
  onCancel: () => void;
  onProceed: () => void;
}

// ============================================================================
// SAFER MOVE HERO PANEL (AG-PROMPT-167/UX-03)
// ============================================================================

function buildSaferMovePanel(saferOption: string, overallRisk?: string): HTMLDivElement {
  const riskClass = overallRisk && overallRisk !== 'none' ? `ainotice-safer-panel-${overallRisk}` : '';
  return el('div', { className: cx('ainotice-safer-panel', riskClass), id: 'ainotice-safer-move' }, [
    el('div', { className: 'ainotice-safer-label' }, ['What to do instead']),
    el('p', { className: 'ainotice-safer-text' }, [saferOption]),
  ]) as HTMLDivElement;
}

// ============================================================================
// DECISION QUALITY CARD (AG-PROMPT-134, redesigned AG-PROMPT-167/UX-04)
// Labels: What we found / Why to pause / Confidence
// Safer move is promoted to its own hero panel above the card.
// ============================================================================

function buildDecisionQualityCard(dq: DecisionQualityBlocks, severity?: string): HTMLDivElement {
  // AG-PROMPT-196/Stage-2: Full concern card per design system §9.5.
  // Structure: inner padding (primary concern + why + confidence) + green safer-option footer strip.
  return el('div', { className: 'ainotice-dq-card' }, [
    el('div', { className: 'ainotice-dq-inner' }, [
      el('div', { className: 'ainotice-dq-block' }, [
        el('span', { className: 'ainotice-dq-label' }, ['Primary Concern']),
        el('p', { className: 'ainotice-dq-concern' }, [dq.primaryConcern]),
      ]),
      el('div', { className: 'ainotice-dq-block' }, [
        el('span', { className: 'ainotice-dq-label' }, ['Why This Matters']),
        el('p', { className: 'ainotice-dq-content' }, [dq.whyThisMatters]),
      ]),
      el('div', { className: 'ainotice-dq-confidence-row' }, [
        el('span', { className: 'ainotice-dq-label ainotice-dq-label-inline' }, ['Confidence']),
        buildConfidenceTag(dq.confidence.label, severity),
      ]),
    ]),
    // Green advisory footer strip — design system §9.5 safer-option footer
    el('div', { className: 'ainotice-safer-strip' }, [
      el('span', { className: 'ainotice-safer-arrow' }, ['\u2197']),
      el('p', { className: 'ainotice-safer-strip-text' }, [dq.saferOption]),
    ]),
  ]) as HTMLDivElement;
}

// ============================================================================
// SEVERITY BADGE HELPER (AG-PROMPT-167/UX-08)
// ============================================================================

function buildSeverityBadge(severity: string): HTMLElement | null {
  if (!severity || severity === 'none' || severity === 'low') return null;
  const displayLabel: Record<string, string> = {
    critical: 'Critical',
    high: 'High',
    medium: 'Review',
  };
  return el('span', { className: cx('ainotice-severity-chip', severity) }, [
    displayLabel[severity] || severity,
  ]);
}

export function buildRiskModal(options: ModalOptions): HTMLDivElement {
  const {
    modalTitle,
    modalSubtitle,
    riskSummary,
    guidance,
    destination,
    scannedSourcesText,
    filesHtml,
    signals,
    licenseState,
    isBlocked,
    needsFriction,
    decisionQuality,
    hasDetectedSignals,
    overallRisk,
    isExtractionLimited,
    triggerSource = 'file',
    onCancel,
    onProceed,
  } = options;

  const licenseNotice = buildLicenseNotice(licenseState);

  // Build signals container (will be updated on show-more)
  const signalsContainer = el('div', { id: 'ainotice-signals-container' }, []) as HTMLDivElement;
  if (signals.length > 0) {
    const signalsSection = buildSignalsSection(signals, false, () => {
      // Show-more handler: rebuild with all signals
      setChildren(signalsContainer, [buildSignalsSection(signals, true)]);
    });
    signalsContainer.appendChild(signalsSection);
  }

  // AG-PROMPT-169/WS-03: Suppress evidence when extraction-limited
  const evidencePreview = isExtractionLimited ? null : buildEvidencePreview(signals);

  // AG-PROMPT-168: Severity/confidence chips REMOVED from header per what_not_to_build.
  // sr-only severity label for screen readers only.
  const srOnlySeverity = overallRisk && overallRisk !== 'none'
    ? el('span', { className: 'ainotice-sr-only' }, [`Severity: ${overallRisk}`])
    : null;

  // AG-PROMPT-171/Fix-2: ALL states use Go back = primary filled, Continue = outlined
  const isHighOrCritical = overallRisk === 'high' || overallRisk === 'critical';

  // AG-PROMPT-169/WS-01: Top severity color bar class
  const severityBarClass = overallRisk && overallRisk !== 'none'
    ? `ainotice-modal-bar-${overallRisk}` : '';

  const overlay = el('div', { className: 'ainotice-overlay', id: 'ainotice-modal-overlay', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': 'ainotice-modal-title' }, [
    el('div', { className: cx('ainotice-modal', severityBarClass) }, [
      // Header — AG-PROMPT-196/Stage-2: dark navy, severity row, shield icon, filename chip
      el('div', { className: 'ainotice-header' }, [
        // Decorative circle (absolute, doctrine-tinted per severity)
        el('div', { className: cx('ainotice-header-circle', overallRisk && overallRisk !== 'none' ? `ainotice-header-circle-${overallRisk}` : '') }, []),
        // Top row: left block (severity label + title) + shield icon
        el('div', { className: 'ainotice-header-row' }, [
          el('div', { className: 'ainotice-header-left' }, [
            // Severity dot + label (omitted for 'none')
            when(!!(overallRisk && overallRisk !== 'none'),
              el('div', { className: 'ainotice-severity-row' }, [
                el('span', { className: cx('ainotice-sev-dot', `ainotice-sev-dot-${overallRisk}`) }, []),
                el('span', { className: cx('ainotice-sev-label', `ainotice-sev-label-${overallRisk}`) }, [
                  getSeverityLabel(overallRisk),
                ]),
              ])
            ),
            // Headline
            el('h2', { className: 'ainotice-title', id: 'ainotice-modal-title' }, [modalTitle]),
          ]),
          // Brand mark — consistent accent blue regardless of severity
          el('div', { className: 'ainotice-header-icon-box' }, ['\u25CE']),
        ]),
        licenseNotice,
        srOnlySeverity,
        // AG-PROMPT-196: Source-aware sub-header.
        // file → "destination · filename" (destination first, less technical read)
        // paste/send → "Pasting/Sending to destination"
        triggerSource === 'file' && modalSubtitle
          ? el('div', { className: 'ainotice-header-chips' }, [
              el('span', { className: 'ainotice-dest-chip' }, [destination]),
              el('span', { className: 'ainotice-header-sep' }, ['\u00B7']),
              el('span', { className: 'ainotice-filename-chip' }, [modalSubtitle]),
            ])
          : el('div', { className: 'ainotice-context-dest-row' }, [
              triggerSource === 'clipboard_paste' ? 'Pasting to\u00A0'
                : triggerSource === 'prompt_send' ? 'Sending to\u00A0'
                : 'Uploading to\u00A0',
              el('span', { className: 'ainotice-dest-name' }, [destination]),
            ]),
      ]),

      // Body — concern card (with integrated safer option), then evidence accordions
      el('div', { className: 'ainotice-body' }, [
        // AG-PROMPT-196/Stage-2: Unified content card (concern + why + confidence + safer option strip).
        // Suppressed for extraction-limited — reduced confidence makes the card misleading.
        decisionQuality && !isExtractionLimited ? buildDecisionQualityCard(decisionQuality, overallRisk) : null,
        // AG-PROMPT-169/WS-03: Extraction-limited — no evidence, distinct guidance
        when(!!isExtractionLimited,
          el('div', { className: 'ainotice-extraction-limited-note' }, [
            'This file could not be fully analyzed. The AI tool you\u2019re uploading to may be able to read more than we could.',
          ])
        ),
        // AG-PROMPT-173/Fix-1: DQ card removed — content lives inside "What did we find?" accordion only
        // AG-PROMPT-171/Fix-5+9: "What did we find?" as collapsed expandable (same pattern as "What's the risk?")
        !isExtractionLimited && evidencePreview ? el('div', { className: 'ainotice-accordion' }, [
          el('button', {
            className: 'ainotice-accordion-toggle',
            'aria-expanded': 'false',
            'data-action': 'toggle-evidence',
          }, [
            el('span', {}, ['What did we find?']),
            el('span', { className: 'ainotice-chevron' }, []),
          ]),
          el('div', { className: 'ainotice-accordion-content', id: 'ainotice-evidence-content' }, [
            evidencePreview,
          ]),
        ]) : null,
        // "What's the risk?" — details panel (collapsed by default)
        el('div', { className: 'ainotice-accordion' }, [
          el('button', {
            className: 'ainotice-accordion-toggle',
            'aria-expanded': 'false',
            'data-action': 'toggle-details',
          }, [
            el('span', {}, ['What\u2019s the risk?']),
            el('span', { className: 'ainotice-chevron' }, []),
          ]),
          el('div', { className: 'ainotice-accordion-content', id: 'ainotice-details-content' }, [
            el('div', { className: 'ainotice-context' }, [
              el('div', { className: 'ainotice-scanned' }, ['Sources: ', scannedSourcesText]),
            ]),
            filesHtml,
            signals.length > 0 ? signalsContainer : null,
          ]),
        ]),
      ]),

      // Footer — AG-PROMPT-168/WS-04: Button label policy by severity
      // HIGH/CRITICAL: "Continue anyway" outline + "Go back" primary filled
      // MEDIUM/other: "Continue" outline neutral
      el('div', { className: 'ainotice-footer' }, [
        when(isBlocked,
          el('div', { className: 'ainotice-blocked' }, ['This action is paused for review.'])
        ),
        // Friction acknowledgment — integrated row (no card border), stronger copy.
        when(needsFriction && !isBlocked,
          el('div', { className: 'ainotice-friction' }, [
            el('label', { className: 'ainotice-checkbox-label' }, [
              el('input', { type: 'checkbox', id: 'ainotice-confirm-checkbox' }, []),
              'I understand the risk and want to continue',
            ]),
          ])
        ),
        // Footer button hierarchy:
        // H/C: "Go back" (navy, flex:2) + "Continue anyway" (soft border, visible secondary).
        // M/L: "Go back" (navy, flex:2) + "Continue" (outline, flex:1).
        el('div', { className: 'ainotice-buttons' }, [
          el('button', {
            className: cx('ainotice-btn', 'ainotice-btn-primary-safe'),
            'data-action': 'cancel',
          }, ['Go back']),
          when(!isBlocked,
            el('button', {
              className: cx('ainotice-btn', isHighOrCritical ? 'ainotice-btn-proceed-soft' : 'ainotice-btn-proceed-outline'),
              'data-action': 'proceed',
              disabled: needsFriction,
            }, [isHighOrCritical ? 'Continue anyway' : 'Continue'])
          ),
        ]),
      ]),
    ]),
  ]) as HTMLDivElement;

  // Attach event handlers
  const cancelBtn = overlay.querySelector('[data-action="cancel"]');
  if (cancelBtn) {
    on(cancelBtn, 'click', onCancel);
  }

  const proceedBtn = overlay.querySelector('[data-action="proceed"]') as HTMLButtonElement | null;
  if (proceedBtn) {
    on(proceedBtn, 'click', onProceed);
  }

  // Click overlay background to cancel
  on(overlay, 'click', (e) => {
    if (e.target === overlay) {
      onCancel();
    }
  });

  // AG-PROMPT-171/Fix-9: Wire all accordion toggles with same pattern
  const allAccordionToggles = overlay.querySelectorAll('[data-action="toggle-details"], [data-action="toggle-evidence"]');
  allAccordionToggles.forEach((toggle) => {
    on(toggle, 'click', () => {
      const parentAccordion = toggle.closest('.ainotice-accordion');
      const content = parentAccordion?.querySelector('.ainotice-accordion-content');
      const isExpanded = toggle.getAttribute('aria-expanded') === 'true';
      toggle.setAttribute('aria-expanded', String(!isExpanded));
      content?.classList.toggle('open');
      // Notify focus trap that focusable elements may have changed
      overlay.dispatchEvent(new CustomEvent('ainotice:accordion-toggle'));
    });
  });

  // Friction checkbox handling
  if (needsFriction && !isBlocked && proceedBtn) {
    const confirmCheckbox = overlay.querySelector('#ainotice-confirm-checkbox') as HTMLInputElement | null;
    if (confirmCheckbox) {
      on(confirmCheckbox, 'change', () => {
        proceedBtn.disabled = !confirmCheckbox.checked;
      });
    }
  }

  return overlay;
}
