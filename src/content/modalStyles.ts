/**
 * Ai Notice modal/overlay CSS injection.
 * extracted verbatim from src/content/index.ts (behavior-preserving).
 * Injects the singleton #ainotice-styles <style> element into document.head.
 */

export const MODAL_CSS = `
    /* ============================================================
       WCAG AA compliant visual refinements
       Design tokens + Pattern Card layout + Action footer
       ============================================================ */

    /* --- DESIGN TOKENS (Forensic Calm) --- */
    /* AG-292: :host makes tokens resolve inside the modal's open shadow root;
       :root keeps them working for head-injected surfaces (drag overlay/banner/notice). */
    :host, :root {
      /* Surfaces & Backgrounds */
      --ag-bg-page: #f8fafc;        /* Soft off-white page surface */
      --ag-bg-card: #ffffff;        /* Clean card surface */
      --ag-border: #e2e8f0;         /* Slate 200 - deterministic boundaries */

      /* Typography (High Contrast / Low Fatigue) */
      --ag-text-primary: #0f172a;   /* Slate 900 - soft black, 15.4:1 on white */
      --ag-text-secondary: #475569; /* Slate 600 - body/descriptions, 7:1 */
      --ag-text-label: #64748b;     /* Slate 500 - labels/provenance, 4.6:1 */

      /* Severity — AG-177 approved color doctrine (restored in AG-197): high/critical = Rose, medium = Amber, low = Gray */
      --ag-crit-bg: #E11D48;        /* Rose 600 - filled badge + bar */
      --ag-crit-text: #ffffff;      /* White on Rose 600 - 8.6:1 */

      --ag-high-bg: #FEF2F2;        /* Rose 50 - soft rose surface */
      --ag-high-text: #E11D48;      /* Rose 600 - 5.2:1 on FEF2F2 */

      --ag-med-bg: #fffbeb;         /* Amber 50 - soft amber surface */
      --ag-med-text: #D97706;       /* Amber 600 - 4.6:1 on fffbeb */

      --ag-low-bg: #F9FAFB;         /* Gray 50 - soft gray surface */
      --ag-low-text: #6B7280;       /* Gray 500 - 4.6:1 on F9FAFB */

      /* Neutral (general-purpose non-severity surfaces) */
      --ag-neutral-bg: #f1f5f9;     /* Slate 100 */
      --ag-neutral-text: #334155;   /* Slate 700 */

      /* Typography Scale */
      --ag-font-headline: 1.125rem; /* 18px */
      --ag-font-body: 0.875rem;     /* 14px */
      --ag-font-meta: 0.75rem;      /* 12px */
      --ag-line-height-calm: 1.6;
      --ag-radius: 6px;
    }

    .ainotice-overlay {
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0, 0, 0, 0.3);
      z-index: 2147483646;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }
    .ainotice-modal {
      background: #ffffff;
      border-radius: 18px;
      box-shadow: 0 32px 64px rgba(11, 20, 35, 0.28);
      max-width: 468px;
      width: min(92vw, 468px);
      max-height: 88vh;
      overflow: hidden;
      display: flex;
      flex-direction: column;
    }
    /* Severity stripe — 3px flat fill, color keyed only off final severity
       (AG-177 doctrine, restored AG-197): critical/high = Rose, medium = Amber, low = Gray.
       Per-severity ::before rules map to --ag-* tokens; no frame/archetype influence. */
    .ainotice-modal::before {
      content: '';
      display: block;
      height: 3px;
      background: #e2e8f0;
      flex-shrink: 0;
    }
    .ainotice-modal-bar-critical::before { background: var(--ag-crit-bg); }
    .ainotice-modal-bar-high::before { background: var(--ag-high-text); }
    .ainotice-modal-bar-medium::before { background: var(--ag-med-text); }
    .ainotice-modal-bar-low::before { background: var(--ag-low-text); }

    /* --- HEADER: dark navy — design-system §9.4 --- */
    .ainotice-header {
      background: #0b1423;
      padding: 14px 18px 12px;
      position: relative;
      overflow: hidden;
      border-bottom: none;
    }
    /* Decorative circle (absolute, top-right) */
    .ainotice-header-circle {
      position: absolute; top: -20px; right: -20px;
      width: 70px; height: 70px; border-radius: 50%;
      background: rgba(99,102,241,.12);
      pointer-events: none;
    }
    /* doctrine-mapped tints aligned to the AG-177 severity ramp —
       rose (Rose 600 #E11D48) for crit/high, amber for medium, gray for low.
       Replaces the prior indigo(crit)/slate-gray(high) tints that understated danger. */
    .ainotice-header-circle-critical { background: rgba(225,29,72,.18); }
    .ainotice-header-circle-high     { background: rgba(225,29,72,.12); }
    .ainotice-header-circle-medium   { background: rgba(217,119,6,.12); }
    .ainotice-header-circle-low      { background: rgba(107,114,128,.12); }
    /* Row: left block + icon */
    .ainotice-header-row {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
    }
    .ainotice-header-left { flex: 1; min-width: 0; }
    /* Severity dot + label */
    .ainotice-severity-row {
      display: flex;
      align-items: center;
      gap: 6px;
      margin-bottom: 8px;
    }
    .ainotice-sev-dot {
      width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0;
      background: var(--ag-low-text);
    }
    /* severity dot aligned to the AG-177 ramp (same tokens as the bar/accent).
       crit/high = Rose 600, medium = Amber 600, low = Gray 500. No gray for High, no blue for Critical. */
    .ainotice-sev-dot-critical { background: var(--ag-crit-bg); }
    .ainotice-sev-dot-high     { background: var(--ag-high-text); }
    .ainotice-sev-dot-medium   { background: var(--ag-med-text); }
    .ainotice-sev-dot-low      { background: var(--ag-low-text); }
    .ainotice-sev-label {
      font-size: 9.5px; font-weight: 700;
      letter-spacing: 0.1em; text-transform: uppercase;
      font-family: 'DM Mono', 'Fira Mono', monospace;
      color: var(--ag-low-text);
    }
    /* severity label color aligned to the AG-177 ramp (matches the dot/bar). */
    .ainotice-sev-label-critical { color: var(--ag-crit-bg); }
    .ainotice-sev-label-high     { color: var(--ag-high-text); }
    .ainotice-sev-label-medium   { color: var(--ag-med-text); }
    .ainotice-sev-label-low      { color: var(--ag-low-text); }
    /* Title — white on dark header */
    .ainotice-title {
      font-size: 14px;
      font-weight: 700;
      color: #ffffff;
      line-height: 1.3;
      margin: 0;
    }
    /* Brand mark — matches site nav logo-mark: accent blue, consistent across severities */
    .ainotice-header-icon-box {
      width: 28px; height: 28px; border-radius: 8px;
      background: #2563eb;
      display: flex; align-items: center; justify-content: center;
      font-size: 14px; color: #ffffff;
      flex-shrink: 0; margin-left: 12px;
    }
    /* Source-aware sub-header chips (file trigger) */
    .ainotice-header-chips {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-top: 10px;
      flex-wrap: wrap;
    }
    .ainotice-filename-chip {
      display: inline-block;
      font-size: 10.5px;
      color: rgba(255,255,255,.55);
      font-family: 'DM Mono', 'Fira Mono', monospace;
      background: rgba(255,255,255,.07);
      padding: 2px 8px;
      border-radius: 5px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      max-width: 70%;
    }
    .ainotice-dest-chip {
      font-size: 10.5px;
      color: rgba(255,255,255,.5);
    }
    /* Source-aware context line (paste/send trigger) */
    .ainotice-context-dest-row {
      margin-top: 10px;
      font-size: 10.5px;
      color: rgba(255,255,255,.45);
    }
    .ainotice-dest-name {
      color: rgba(255,255,255,.6);
      font-weight: 500;
    }
    /* Legacy aliases — kept for safety */
    .ainotice-branding { display: none; }
    .ainotice-header-top { display: contents; }
    .ainotice-header-icon { display: none; }
    .ainotice-branding-icon { display: none; }
    .ainotice-context-line { display: none; }
    .ainotice-meta-filename { display: none; }
    .ainotice-dq-safer { font-style: normal; }

    /* Extraction-limited notice */
    .ainotice-extraction-limited-note {
      font-size: var(--ag-font-body);
      color: var(--ag-text-secondary);
      line-height: 1.6;
      padding: 12px 16px;
      background: var(--ag-neutral-bg);
      border-radius: var(--ag-radius);
      margin-bottom: 12px;
    }

    /* Screen-reader-only element */
    .ainotice-sr-only {
      position: absolute;
      width: 1px;
      height: 1px;
      padding: 0;
      margin: -1px;
      overflow: hidden;
      clip: rect(0, 0, 0, 0);
      white-space: nowrap;
      border: 0;
    }

    /* --- ZONE 2: BODY — design-system §9.5 (#FAFAFA) --- */
    .ainotice-body {
      padding: 12px 16px;
      background: #fafafa;
      overflow-y: auto;
      flex: 1;
    }
    /* .ainotice-frame-guidance removed — div was redundant with safer move */
    .ainotice-rationale {
      font-size: var(--ag-font-body);
      color: var(--ag-text-secondary);
      line-height: 1.6;
      margin-bottom: 16px;
    }
    .ainotice-evidence-toggle {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      font-size: var(--ag-font-meta);
      color: var(--ag-text-secondary);
      cursor: pointer;
      padding: 8px 12px;
      background: var(--ag-bg-card);
      border: 1px solid var(--ag-border);
      border-radius: 4px;
      margin-bottom: 16px;
    }
    .ainotice-evidence-toggle:hover {
      background: #f1f5f9;
      border-color: #cbd5e1;
    }
    .ainotice-evidence-toggle[aria-expanded="true"] {
      background: #f1f5f9;
    }
    .ainotice-evidence-icon {
      font-size: var(--ag-font-meta);
      color: var(--ag-text-label);
      transition: transform 0.15s;
    }
    .ainotice-evidence-toggle[aria-expanded="true"] .ainotice-evidence-icon {
      transform: rotate(90deg);
    }
    .ainotice-evidence-panel {
      display: none;
      padding: 16px;
      background: var(--ag-bg-card);
      border: 1px solid var(--ag-border);
      border-radius: 4px;
    }
    .ainotice-evidence-panel.open { display: block; }

    /* Evidence drawer contents */
    .ainotice-context {
      font-size: var(--ag-font-meta);
      color: var(--ag-text-label);
      margin-bottom: 16px;
      padding-bottom: 12px;
      border-bottom: 1px solid var(--ag-border);
    }
    .ainotice-destination-drawer {
      margin-bottom: 8px;
    }
    .ainotice-destination-drawer strong { color: var(--ag-text-primary); font-weight: 600; }
    .ainotice-scanned { color: var(--ag-text-label); }
    .ainotice-file-card {
      padding: 12px 0;
      border-bottom: 1px solid var(--ag-border);
    }
    .ainotice-file-card:last-child { border-bottom: none; }
    .ainotice-file-name {
      font-size: var(--ag-font-meta);
      font-weight: 600;
      color: var(--ag-text-primary);
      word-break: break-all;
      margin-bottom: 4px;
    }
    .ainotice-file-meta { font-size: var(--ag-font-meta); color: var(--ag-text-label); }
    .ainotice-metadata {
      margin-top: 12px;
      padding: 12px;
      background: var(--ag-bg-card);
      border: 1px solid var(--ag-border);
      border-radius: 4px;
    }
    .ainotice-metadata-title {
      font-size: var(--ag-font-meta);
      font-weight: 600;
      color: var(--ag-text-label);
      text-transform: uppercase;
      letter-spacing: 0.03em;
      margin-bottom: 8px;
    }
    .ainotice-metadata-item {
      display: flex;
      gap: 12px;
      margin: 4px 0;
      font-size: var(--ag-font-meta);
      line-height: 1.5;
    }
    .ainotice-metadata-label { color: var(--ag-text-label); font-weight: 500; min-width: 72px; }
    .ainotice-metadata-value { color: var(--ag-text-secondary); word-break: break-word; }

    /* --- PATTERN CARDS (Single card per pattern) --- */
    .ainotice-signals-section {
      margin-top: 16px;
      padding-top: 16px;
      border-top: 1px solid var(--ag-border);
    }
    .ainotice-signals-header {
      font-size: var(--ag-font-meta);
      font-weight: 600;
      color: var(--ag-text-label);
      text-transform: uppercase;
      letter-spacing: 0.03em;
      margin-bottom: 12px;
    }
    .ainotice-signal-group { margin-bottom: 16px; }
    .ainotice-signal-group:last-child { margin-bottom: 0; }
    .ainotice-signal-group-title {
      font-size: var(--ag-font-meta);
      font-weight: 600;
      color: var(--ag-text-secondary);
      margin-bottom: 8px;
    }
    /* Pattern Card: Single card layout */
    .ainotice-signal {
      padding: 12px 16px;
      background: var(--ag-bg-card);
      border: 1px solid var(--ag-border);
      border-radius: 6px;
      margin-bottom: 8px;
    }
    .ainotice-signal:last-child { margin-bottom: 0; }
    /* Pattern Card Header: [Severity Badge] [Pattern Name] ... [Provenance Tag] */
    .ainotice-signal-header {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }
    /* Severity badges: CRITICAL=Indigo, HIGH/MEDIUM=Slate (WCAG AA) */
    .ainotice-signal-badge {
      font-size: 10px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.03em;
      padding: 3px 8px;
      border-radius: 3px;
      flex-shrink: 0;
    }
    .ainotice-signal-badge.low {
      background: var(--ag-low-bg);
      color: var(--ag-low-text);
    }
    .ainotice-signal-badge.medium {
      background: var(--ag-med-bg);
      color: var(--ag-med-text);
    }
    .ainotice-signal-badge.high {
      background: var(--ag-high-bg);
      color: var(--ag-high-text);
    }
    .ainotice-signal-badge.critical {
      background: var(--ag-crit-bg);
      color: var(--ag-crit-text);
    }
    .ainotice-signal-title {
      font-size: var(--ag-font-body);
      font-weight: 500;
      color: var(--ag-text-primary);
      flex: 1;
      min-width: 0;
    }
    /* Provenance tag (CONTENT / METADATA) */
    .ainotice-signal-source {
      font-size: 10px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.03em;
      color: var(--ag-text-label);
      background: var(--ag-bg-card);
      border: 1px solid var(--ag-border);
      padding: 2px 8px;
      border-radius: 3px;
      flex-shrink: 0;
    }
    /* Pattern Card Description */
    .ainotice-signal-detail {
      font-size: var(--ag-font-meta);
      color: var(--ag-text-secondary);
      margin-top: 10px;
      line-height: 1.6;
    }
    .ainotice-show-more {
      font-size: var(--ag-font-meta);
      font-weight: 500;
      color: var(--ag-text-secondary);
      cursor: pointer;
      padding: 8px 0;
      margin-top: 8px;
    }
    .ainotice-show-more:hover { color: var(--ag-text-primary); }
    .ainotice-no-signals {
      font-size: var(--ag-font-meta);
      color: var(--ag-text-label);
      padding: 8px 0;
    }
    .ainotice-confidence {
      font-size: var(--ag-font-meta);
      color: var(--ag-text-label);
      margin-top: 16px;
      padding-top: 12px;
      border-top: 1px solid var(--ag-border);
    }

    /* Legacy header-bar — hidden, replaced by ainotice-header-row */
    .ainotice-header-bar { display: none; }
    .ainotice-destination-context { display: none; }
    .ainotice-header-meta { display: none; }
    /* Severity chip — kept for signal badges in drawer */
    .ainotice-severity-chip {
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.03em;
      padding: 2px 8px;
      border-radius: 3px;
      flex-shrink: 0;
    }
    .ainotice-severity-chip.critical { background: var(--ag-crit-bg); color: var(--ag-crit-text); }
    .ainotice-severity-chip.high     { background: var(--ag-high-bg); color: var(--ag-high-text); }
    .ainotice-severity-chip.medium   { background: var(--ag-med-bg);  color: var(--ag-med-text);  }
    .ainotice-confidence-chip { display: none; }

    /* Safer move hero panel — severity-colored left accent */
    .ainotice-safer-panel {
      padding: 14px 16px 14px 19px;
      background: var(--ag-bg-card);
      border: 1px solid var(--ag-border);
      border-left: 3px solid var(--ag-text-label);
      border-radius: var(--ag-radius);
      margin-bottom: 16px;
    }
    /* AG-177 doctrine (restored in AG-197): crit/high left-accent = Rose, soft rose tints */
    .ainotice-safer-panel-critical { border-left-color: var(--ag-crit-bg); background: #FEFAFA; }
    .ainotice-safer-panel-high { border-left-color: var(--ag-high-text); background: #FEFAFA; }
    .ainotice-safer-panel-medium { border-left-color: var(--ag-med-text); background: #FEFCF6; }
    .ainotice-safer-panel-low { border-left-color: var(--ag-low-text); background: #FAFAFA; }
    .ainotice-safer-label {
      font-size: var(--ag-font-meta);
      font-weight: 600;
      color: var(--ag-text-label);
      text-transform: uppercase;
      letter-spacing: 0.04em;
      margin-bottom: 4px;
    }
    .ainotice-safer-text {
      font-size: 16px;
      color: var(--ag-text-primary);
      line-height: 1.55;
      margin: 0;
    }

    /* Evidence preview bullets */
    .ainotice-evidence-preview {
      margin-bottom: 12px;
    }
    .ainotice-evidence-preview-label {
      font-size: var(--ag-font-meta);
      font-weight: 600;
      color: var(--ag-text-label);
      text-transform: uppercase;
      letter-spacing: 0.04em;
      margin-bottom: 6px;
    }
    .ainotice-evidence-preview-list {
      list-style: none;
      padding: 0;
      margin: 0;
    }
    .ainotice-evidence-preview-list li {
      font-size: var(--ag-font-body);
      color: var(--ag-text-secondary);
      line-height: 1.6;
      padding-left: 16px;
      position: relative;
    }
    .ainotice-evidence-preview-list li::before {
      content: '\u2022';
      position: absolute;
      left: 0;
      color: var(--ag-text-label);
    }
    /* Expandable evidence (1 shown, rest behind toggle) */
    .ainotice-evidence-more { display: none; }
    .ainotice-evidence-more.open { display: block; }
    .ainotice-evidence-expand {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      font-size: var(--ag-font-meta);
      font-weight: 500;
      color: var(--ag-text-secondary);
      cursor: pointer;
      background: none;
      border: none;
      padding: 4px 0;
      margin-top: 2px;
    }
    .ainotice-evidence-expand:hover { color: var(--ag-text-primary); }
    /* SVG chevron indicator */
    .ainotice-chevron {
      display: inline-block;
      width: 12px;
      height: 12px;
      background: currentColor;
      -webkit-mask: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 12 12'%3E%3Cpath d='M3 4.5l3 3 3-3' fill='none' stroke='%23000' stroke-width='1.5' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E") center/contain no-repeat;
      mask: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 12 12'%3E%3Cpath d='M3 4.5l3 3 3-3' fill='none' stroke='%23000' stroke-width='1.5' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E") center/contain no-repeat;
      transition: transform 0.15s ease;
      flex-shrink: 0;
    }
    [aria-expanded="true"] > .ainotice-chevron {
      transform: rotate(180deg);
    }

    /* Legacy elements */
    .ainotice-guidance { display: none; }
    .ainotice-reminder { display: none; }

    /* --- ZONE 3: ACTION FOOTER — design-system §9.6 --- */
    .ainotice-footer {
      padding: 0 16px 14px;
      background: #fafafa;
      border-top: 1px solid #f1f5f9;
    }
    .ainotice-action-label { display: none; }
    /* Friction acknowledgment — integrated row, no card border */
    .ainotice-friction {
      margin: 14px 0 0 0;
      padding: 0;
      background: none;
      border: none;
    }
    .ainotice-checkbox-label {
      display: flex;
      align-items: flex-start;
      gap: 8px;
      font-size: 11.5px;
      font-weight: 400;
      color: #475569;
      cursor: pointer;
      line-height: 1.4;
    }
    .ainotice-checkbox-label input {
      width: 15px;
      height: 15px;
      flex-shrink: 0;
      margin-top: 1px;
      accent-color: #3730a3;
      cursor: pointer;
    }
    /* Footer button row */
    .ainotice-buttons {
      display: flex;
      gap: 7px;
      padding-top: 10px;
      align-items: center;
    }
    .ainotice-btn {
      padding: 9px 0;
      border-radius: 10px;
      font-size: 12.5px;
      font-weight: 600;
      cursor: pointer;
      border: 1px solid transparent;
      transition: all 0.15s ease;
      font-family: inherit;
    }
    .ainotice-btn:focus-visible {
      outline: 2px solid var(--ag-crit-text);
      outline-offset: 2px;
    }
    .ainotice-btn:disabled { opacity: 0.35; cursor: not-allowed; }
    /* "Go back" — primary navy fill, flex:2 */
    .ainotice-btn-primary-safe {
      flex: 2;
      background: #0b1423;
      border-color: #0b1423;
      color: #ffffff;
    }
    .ainotice-btn-primary-safe:hover:not(:disabled) {
      background: #152035;
      border-color: #152035;
    }
    /* "Continue" — outline, flex:1 (medium/low severity) */
    .ainotice-btn-proceed-outline {
      flex: 1;
      background: #ffffff;
      border-color: #e2e8f0;
      color: #64748b;
    }
    .ainotice-btn-proceed-outline:hover:not(:disabled) {
      border-color: #cbd5e1;
      color: #334155;
    }
    /* "Continue anyway" — soft border, visibly secondary but not invisible (high/critical) */
    .ainotice-btn-proceed-soft {
      flex: 1;
      background: #ffffff;
      border: 1.5px solid #94a3b8;
      color: #374151;
      font-size: 12px;
      font-weight: 500;
    }
    .ainotice-btn-proceed-soft:hover:not(:disabled) {
      border-color: #64748b;
      color: #1e293b;
    }
    .ainotice-btn-proceed-soft:disabled {
      opacity: 0.35;
      cursor: not-allowed;
    }
    /* Legacy aliases */
    .ainotice-btn-cancel { color: var(--ag-text-label); }
    .ainotice-btn-proceed { background: var(--ag-text-primary); color: #fff; border-color: var(--ag-text-primary); }
    .ainotice-btn-proceed-ghost { display: none; }
    .ainotice-blocked {
      font-size: var(--ag-font-body);
      color: var(--ag-text-secondary);
      margin: 12px 0 0;
      padding: 10px 14px;
      background: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
    }

    /* --- CONCERN CARD — design-system §9.5 (white bordered, radius 10px) --- */
    .ainotice-dq-card {
      border-radius: 10px;
      border: 1px solid #e2e8f0;
      overflow: hidden;
      background: #ffffff;
      margin-bottom: 10px;
    }
    .ainotice-dq-inner {
      padding: 10px 12px;
    }
    .ainotice-dq-block {
      margin-bottom: 10px;
    }
    .ainotice-dq-block:last-child { margin-bottom: 0; }
    /* LABEL: 9.5px mono, wide letter-spacing, #94A3B8 — design-system §8.3 */
    .ainotice-dq-label {
      display: block;
      font-size: 9.5px;
      font-weight: 700;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: #94a3b8;
      margin-bottom: 4px;
      font-family: 'DM Mono', 'Fira Mono', monospace;
    }
    .ainotice-dq-label-inline {
      display: inline;
      margin-bottom: 0;
      margin-right: 8px;
    }
    .ainotice-dq-concern {
      font-size: 12.5px;
      font-weight: 600;
      color: #0f172a;
      margin: 0;
    }
    .ainotice-dq-content {
      font-size: 11.5px;
      color: #334155;
      line-height: 1.5;
      margin: 0;
    }
    .ainotice-dq-confidence-row {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }
    /* Confidence tag — colored pill with dot, design-system §9.5 */
    .ainotice-conf-tag {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      font-size: 11px;
      font-weight: 600;
      padding: 3px 9px;
      border-radius: 20px;
      border: 1px solid;
      font-family: 'DM Mono', 'Fira Mono', monospace;
    }
    .ainotice-conf-dot {
      width: 5px; height: 5px; border-radius: 50%; flex-shrink: 0;
    }
    /* Safer option footer strip — design-system §9.5 (green advisory, never a button) */
    .ainotice-safer-strip {
      border-top: 1px solid #dcfce7;
      background: #f0fdf4;
      padding: 8px 12px;
      display: flex;
      gap: 8px;
      align-items: flex-start;
    }
    .ainotice-safer-arrow {
      color: #059669;
      font-size: 13px;
      flex-shrink: 0;
      line-height: 1.45;
    }
    .ainotice-safer-strip-text {
      font-size: 11.5px;
      color: #166534;
      line-height: 1.45;
      margin: 0;
    }
    /* Legacy aliases */
    .ainotice-dq-confidence-badge { display: none; }
    .ainotice-dq-confidence-note  { display: none; }
    .ainotice-safer-panel { display: none; }
    .ainotice-safer-panel-critical,
    .ainotice-safer-panel-high,
    .ainotice-safer-panel-medium,
    .ainotice-safer-panel-low { display: none; }

    /* --- DRAG OVERLAY --- */
    .ainotice-drag-overlay {
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0, 0, 0, 0.08);
      z-index: 2147483645;
      display: flex;
      align-items: center;
      justify-content: center;
      pointer-events: none;
      border: 1px dashed var(--ag-text-label);
      box-sizing: border-box;
    }
    .ainotice-drag-indicator {
      background: var(--ag-bg-card);
      padding: 16px 24px;
      border-radius: 6px;
      text-align: center;
    }
    .ainotice-drag-indicator h3 { margin: 0 0 8px 0; color: var(--ag-text-primary); font-size: var(--ag-font-body); font-weight: 600; }
    .ainotice-drag-indicator p { margin: 0; color: var(--ag-text-label); font-size: var(--ag-font-meta); }
    .ainotice-loading { display: flex; align-items: center; gap: 12px; padding: 16px; color: var(--ag-text-secondary); font-size: var(--ag-font-body); }
    .ainotice-spinner {
      width: 24px; height: 24px;
      border: 2px solid var(--ag-border);
      border-top-color: var(--ag-text-secondary);
      border-radius: 50%;
      animation: ainotice-spin 0.8s linear infinite;
    }
    @keyframes ainotice-spin { to { transform: rotate(360deg); } }

    /* Awareness Banner (inline notification for informational cases) */
    .ainotice-banner {
      position: fixed;
      bottom: 24px;
      right: 24px;
      max-width: 420px;
      background: var(--ag-bg-page);
      border-radius: 8px;
      box-shadow: 0 4px 24px rgba(0, 0, 0, 0.12);
      z-index: 2147483646;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      overflow: hidden;
      animation: ainotice-banner-slide 0.3s ease-out;
    }
    @keyframes ainotice-banner-slide {
      from { transform: translateY(16px); opacity: 0; }
      to { transform: translateY(0); opacity: 1; }
    }

    /* S3-04: Respect user motion preferences */
    @media (prefers-reduced-motion: reduce) {
      .ainotice-spinner { animation: none; }
      .ainotice-banner { animation: none; }
    }

    .ainotice-banner-content {
      padding: 16px 24px;
      border-left: 4px solid var(--ag-text-label);
    }
    .ainotice-banner-header {
      display: flex;
      align-items: flex-start;
      gap: 12px;
    }
    .ainotice-banner-icon {
      width: 24px;
      height: 24px;
      background: var(--ag-high-bg);
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
      color: var(--ag-text-secondary);
      font-size: var(--ag-font-body);
    }
    .ainotice-banner-text { flex: 1; }
    .ainotice-banner-title {
      font-size: var(--ag-font-body);
      font-weight: 600;
      color: var(--ag-text-primary);
      margin: 0 0 8px 0;
    }
    .ainotice-banner-summary {
      font-size: var(--ag-font-body);
      color: var(--ag-text-secondary);
      line-height: 1.6;
      margin: 0;
    }
    .ainotice-banner-close {
      position: absolute;
      top: 12px;
      right: 12px;
      background: none;
      border: none;
      color: var(--ag-text-label);
      cursor: pointer;
      font-size: 16px;
      padding: 4px;
      line-height: 1;
    }
    .ainotice-banner-close:hover { color: var(--ag-text-secondary); }
    .ainotice-banner-close:focus-visible {
      outline: 2px solid var(--ag-crit-text);
      outline-offset: 2px;
    }
    .ainotice-banner-detected {
      margin-top: 12px;
      padding: 12px;
      background: var(--ag-bg-card);
      border-radius: 4px;
      font-size: var(--ag-font-meta);
      color: var(--ag-text-secondary);
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .ainotice-banner-detected-icon { font-size: var(--ag-font-body); }
    .ainotice-banner-actions {
      display: flex;
      gap: 8px;
      margin-top: 16px;
      justify-content: flex-end;
    }
    .ainotice-banner-btn {
      padding: 10px 20px;
      border-radius: 6px;
      font-size: var(--ag-font-body);
      font-weight: 500;
      cursor: pointer;
      border: none;
      transition: background 0.15s;
    }
    .ainotice-banner-btn:focus-visible {
      outline: 2px solid var(--ag-crit-text);
      outline-offset: 2px;
    }
    .ainotice-banner-btn-secondary {
      background: var(--ag-high-bg);
      color: var(--ag-text-primary);
    }
    .ainotice-banner-btn-secondary:hover { background: var(--ag-border); }
    .ainotice-banner-btn-primary {
      background: var(--ag-text-primary);
      color: white;
    }
    .ainotice-banner-btn-primary:hover { background: #1e293b; }

    /* Notice as minimal status indicator */
    .ainotice-notice-overlay {
      background: rgba(0, 0, 0, 0.15);
    }
    .ainotice-notice {
      background: var(--ag-bg-card);
      border: 1px solid var(--ag-border);
      border-radius: 6px;
      padding: 16px 24px;
      display: flex;
      align-items: flex-start;
      gap: 12px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.08);
      position: relative;
      cursor: pointer;
      min-width: 280px;
      max-width: 360px;
    }
    .ainotice-notice-icon {
      display: none;
    }
    .ainotice-notice-content {
      flex: 1;
    }
    .ainotice-notice-title {
      margin: 0 0 8px 0;
      font-size: var(--ag-font-body);
      font-weight: 600;
      color: var(--ag-text-primary);
    }
    .ainotice-notice-summary {
      margin: 0;
      font-size: var(--ag-font-body);
      color: var(--ag-text-secondary);
      line-height: 1.6;
    }
    /* Progress bar animation removed.
       Countdown timers and progress animations create urgency, which is prohibited. */
    .ainotice-notice-progress {
      display: none;
    }

    /* Low-risk notice */
    .ainotice-notice-low {
      border-color: var(--ag-border);
    }
    .ainotice-notice-icon-low {
      display: none;
    }
    .ainotice-notice-details {
      margin-top: 12px;
      padding: 8px 12px;
      background: var(--ag-high-bg);
      border: 1px solid var(--ag-border);
      border-radius: 4px;
      color: var(--ag-text-secondary);
      font-size: var(--ag-font-meta);
      font-weight: 500;
      cursor: pointer;
    }
    .ainotice-notice-details:hover {
      background: var(--ag-border);
      border-color: #cbd5e1;
    }

    /* Notice branding */
    .ainotice-notice-branding {
      font-size: var(--ag-font-meta);
      font-weight: 500;
      color: var(--ag-text-label);
      margin-bottom: 8px;
    }
    .ainotice-notice-branding-icon { display: none; }

    /* Primary finding */
    .ainotice-primary-finding {
      margin-bottom: 12px;
    }
    .ainotice-primary-finding-label {
      font-size: var(--ag-font-meta);
      font-weight: 600;
      color: var(--ag-text-label);
      margin-bottom: 4px;
    }
    .ainotice-primary-finding-content {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .ainotice-primary-finding-text {
      font-size: var(--ag-font-body);
      color: var(--ag-text-secondary);
      font-weight: 400;
    }

    /* Drawer toggle: button-like row with chevron */
    .ainotice-accordion {
      margin-top: 16px;
    }
    .ainotice-accordion-toggle {
      width: 100%;
      padding: 8px 12px;
      background: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 9px;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: space-between;
      font-size: 11.5px;
      font-weight: 500;
      color: #64748b;
    }
    .ainotice-accordion-toggle:hover {
      background: #f8fafc;
      border-color: #cbd5e1;
    }
    .ainotice-accordion-toggle:focus-visible {
      outline: 2px solid var(--ag-crit-text);
      outline-offset: 2px;
    }
    .ainotice-accordion-toggle[aria-expanded="true"] {
      margin-bottom: 3px;
      border-color: #cbd5e1;
      background: #f8fafc;
    }
    /* Accordion chevron handled by .ainotice-chevron above */
    .ainotice-accordion-content {
      display: none;
      padding: 16px;
      background: var(--ag-bg-card);
      border: 1px solid var(--ag-border);
      border-radius: 6px;
    }
    .ainotice-accordion-content.open {
      display: block;
    }

    /* Notice continue button */
    .ainotice-notice-continue {
      margin-left: auto;
      padding: 10px 20px;
      background: var(--ag-bg-card);
      border: 1px solid var(--ag-border);
      border-radius: 6px;
      color: var(--ag-text-secondary);
      font-size: var(--ag-font-body);
      font-weight: 500;
      cursor: pointer;
      white-space: nowrap;
    }
    .ainotice-notice-continue:hover {
      background: var(--ag-bg-card);
      border-color: #cbd5e1;
    }
    .ainotice-notice-continue:focus-visible {
      outline: 2px solid var(--ag-crit-text);
      outline-offset: 2px;
    }

    /* License status line inside modal only */
    /* HOST_PAGE_BANNERS_FOR_LICENSE = forbidden */
    /* INVARIANT: License state is meta-information. It must never visually
       compete with document classification or guidance. */
    .ainotice-license-status {
      font-size: 11px;
      line-height: 1.5;
      color: var(--ag-text-label);
      margin-bottom: 8px;
      /*ix-3: Thin muted banner */
    }
    .ainotice-license-contact {
      background: none;
      border: none;
      padding: 0;
      font: inherit;
      color: var(--ag-med-text);
      text-decoration: underline;
      cursor: pointer;
    }
    .ainotice-license-contact:hover { color: var(--ag-text-primary); }
    .ainotice-license-contact:focus-visible {
      outline: 2px solid var(--ag-crit-text);
      outline-offset: 2px;
    }

    /* Post-decision toast */
    .ainotice-toast {
      position: fixed;
      bottom: 24px;
      left: 50%;
      transform: translateX(-50%);
      background: var(--ag-text-primary);
      color: #fff;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      font-size: var(--ag-font-body);
      font-weight: 500;
      padding: 10px 20px;
      border-radius: 6px;
      z-index: 2147483647;
      box-shadow: 0 2px 12px rgba(0,0,0,0.18);
      opacity: 1;
      transition: opacity 0.3s ease;
    }
    .ainotice-toast-exit {
      opacity: 0;
    }

    /* Shadow DOM / host injection resilience.
       Reset inherited properties that host pages may set globally,
       ensuring our overlay renders consistently regardless of host CSS. */
    .ainotice-overlay,
    .ainotice-overlay * {
      box-sizing: border-box;
      text-decoration: none;
      text-transform: none;
      letter-spacing: normal;
      word-spacing: normal;
      text-indent: 0;
      text-shadow: none;
      float: none;
      clear: none;
      vertical-align: baseline;
      direction: ltr;
      writing-mode: horizontal-tb;
    }
    .ainotice-overlay {
      font-size: 16px;
      line-height: 1.5;
      color: var(--ag-text-primary);
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
    }
  `;

/**
 * Build a fresh <style> element containing the modal CSS.
 * Used to inject styles INSIDE the warning modal's open shadow root, so host-page
 * CSS cannot override modal styling and a removed/pre-clobbered head <style> cannot
 * suppress it. Not given the singleton id (the shadow scopes it).
 */
export function buildModalStyleEl(): HTMLStyleElement {
  const style = document.createElement('style');
  style.textContent = MODAL_CSS;
  return style;
}

export function createStyles(): void {
  if (document.getElementById('ainotice-styles')) return;

  const style = document.createElement('style');
  style.id = 'ainotice-styles';
  style.textContent = MODAL_CSS;
  document.head.appendChild(style);
}
