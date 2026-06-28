/**
 * AgentGuard modal/overlay CSS injection.
 * AG-PROMPT-214: extracted verbatim from src/content/index.ts (behavior-preserving).
 * Injects the singleton #agentguard-styles <style> element into document.head.
 */

export const MODAL_CSS = `
    /* ============================================================
       AG-PROMPT-SURFACE-A11Y-VISUAL-REFINEMENT-020
       WCAG AA compliant visual refinements
       Design tokens + Pattern Card layout + Action footer
       ============================================================ */

    /* --- DESIGN TOKENS (AG-PROMPT-030: Forensic Calm) --- */
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

    .agentguard-overlay {
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0, 0, 0, 0.3);
      z-index: 2147483646;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }
    .agentguard-modal {
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
    .agentguard-modal::before {
      content: '';
      display: block;
      height: 3px;
      background: #e2e8f0;
      flex-shrink: 0;
    }
    .agentguard-modal-bar-critical::before { background: var(--ag-crit-bg); }
    .agentguard-modal-bar-high::before { background: var(--ag-high-text); }
    .agentguard-modal-bar-medium::before { background: var(--ag-med-text); }
    .agentguard-modal-bar-low::before { background: var(--ag-low-text); }

    /* --- HEADER: dark navy — design-system §9.4 --- */
    .agentguard-header {
      background: #0b1423;
      padding: 14px 18px 12px;
      position: relative;
      overflow: hidden;
      border-bottom: none;
    }
    /* Decorative circle (absolute, top-right) */
    .agentguard-header-circle {
      position: absolute; top: -20px; right: -20px;
      width: 70px; height: 70px; border-radius: 50%;
      background: rgba(99,102,241,.12);
      pointer-events: none;
    }
    /* AG-PROMPT-326: doctrine-mapped tints aligned to the AG-177 severity ramp —
       rose (Rose 600 #E11D48) for crit/high, amber for medium, gray for low.
       Replaces the prior indigo(crit)/slate-gray(high) tints that understated danger. */
    .agentguard-header-circle-critical { background: rgba(225,29,72,.18); }
    .agentguard-header-circle-high     { background: rgba(225,29,72,.12); }
    .agentguard-header-circle-medium   { background: rgba(217,119,6,.12); }
    .agentguard-header-circle-low      { background: rgba(107,114,128,.12); }
    /* Row: left block + icon */
    .agentguard-header-row {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
    }
    .agentguard-header-left { flex: 1; min-width: 0; }
    /* Severity dot + label */
    .agentguard-severity-row {
      display: flex;
      align-items: center;
      gap: 6px;
      margin-bottom: 8px;
    }
    .agentguard-sev-dot {
      width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0;
      background: var(--ag-low-text);
    }
    /* AG-PROMPT-326: severity dot aligned to the AG-177 ramp (same tokens as the bar/accent).
       crit/high = Rose 600, medium = Amber 600, low = Gray 500. No gray for High, no blue for Critical. */
    .agentguard-sev-dot-critical { background: var(--ag-crit-bg); }
    .agentguard-sev-dot-high     { background: var(--ag-high-text); }
    .agentguard-sev-dot-medium   { background: var(--ag-med-text); }
    .agentguard-sev-dot-low      { background: var(--ag-low-text); }
    .agentguard-sev-label {
      font-size: 9.5px; font-weight: 700;
      letter-spacing: 0.1em; text-transform: uppercase;
      font-family: 'DM Mono', 'Fira Mono', monospace;
      color: var(--ag-low-text);
    }
    /* AG-PROMPT-326: severity label color aligned to the AG-177 ramp (matches the dot/bar). */
    .agentguard-sev-label-critical { color: var(--ag-crit-bg); }
    .agentguard-sev-label-high     { color: var(--ag-high-text); }
    .agentguard-sev-label-medium   { color: var(--ag-med-text); }
    .agentguard-sev-label-low      { color: var(--ag-low-text); }
    /* Title — white on dark header */
    .agentguard-title {
      font-size: 14px;
      font-weight: 700;
      color: #ffffff;
      line-height: 1.3;
      margin: 0;
    }
    /* Brand mark — matches site nav logo-mark: accent blue, consistent across severities */
    .agentguard-header-icon-box {
      width: 28px; height: 28px; border-radius: 8px;
      background: #2563eb;
      display: flex; align-items: center; justify-content: center;
      font-size: 14px; color: #ffffff;
      flex-shrink: 0; margin-left: 12px;
    }
    /* Source-aware sub-header chips (file trigger) */
    .agentguard-header-chips {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-top: 10px;
      flex-wrap: wrap;
    }
    .agentguard-filename-chip {
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
    .agentguard-dest-chip {
      font-size: 10.5px;
      color: rgba(255,255,255,.5);
    }
    /* Source-aware context line (paste/send trigger) */
    .agentguard-context-dest-row {
      margin-top: 10px;
      font-size: 10.5px;
      color: rgba(255,255,255,.45);
    }
    .agentguard-dest-name {
      color: rgba(255,255,255,.6);
      font-weight: 500;
    }
    /* Legacy aliases — kept for safety */
    .agentguard-branding { display: none; }
    .agentguard-header-top { display: contents; }
    .agentguard-header-icon { display: none; }
    .agentguard-branding-icon { display: none; }
    .agentguard-context-line { display: none; }
    .agentguard-meta-filename { display: none; }
    .agentguard-dq-safer { font-style: normal; }

    /* AG-PROMPT-169/WS-03: Extraction-limited notice */
    .agentguard-extraction-limited-note {
      font-size: var(--ag-font-body);
      color: var(--ag-text-secondary);
      line-height: 1.6;
      padding: 12px 16px;
      background: var(--ag-neutral-bg);
      border-radius: var(--ag-radius);
      margin-bottom: 12px;
    }

    /* AG-PROMPT-168/WS-01: Screen-reader-only element */
    .agentguard-sr-only {
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
    .agentguard-body {
      padding: 12px 16px;
      background: #fafafa;
      overflow-y: auto;
      flex: 1;
    }
    /* AG-PROMPT-170/WS-01: .agentguard-frame-guidance removed — div was redundant with safer move */
    .agentguard-rationale {
      font-size: var(--ag-font-body);
      color: var(--ag-text-secondary);
      line-height: 1.6;
      margin-bottom: 16px;
    }
    .agentguard-evidence-toggle {
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
    .agentguard-evidence-toggle:hover {
      background: #f1f5f9;
      border-color: #cbd5e1;
    }
    .agentguard-evidence-toggle[aria-expanded="true"] {
      background: #f1f5f9;
    }
    .agentguard-evidence-icon {
      font-size: var(--ag-font-meta);
      color: var(--ag-text-label);
      transition: transform 0.15s;
    }
    .agentguard-evidence-toggle[aria-expanded="true"] .agentguard-evidence-icon {
      transform: rotate(90deg);
    }
    .agentguard-evidence-panel {
      display: none;
      padding: 16px;
      background: var(--ag-bg-card);
      border: 1px solid var(--ag-border);
      border-radius: 4px;
    }
    .agentguard-evidence-panel.open { display: block; }

    /* Evidence drawer contents */
    .agentguard-context {
      font-size: var(--ag-font-meta);
      color: var(--ag-text-label);
      margin-bottom: 16px;
      padding-bottom: 12px;
      border-bottom: 1px solid var(--ag-border);
    }
    .agentguard-destination-drawer {
      margin-bottom: 8px;
    }
    .agentguard-destination-drawer strong { color: var(--ag-text-primary); font-weight: 600; }
    .agentguard-scanned { color: var(--ag-text-label); }
    .agentguard-file-card {
      padding: 12px 0;
      border-bottom: 1px solid var(--ag-border);
    }
    .agentguard-file-card:last-child { border-bottom: none; }
    .agentguard-file-name {
      font-size: var(--ag-font-meta);
      font-weight: 600;
      color: var(--ag-text-primary);
      word-break: break-all;
      margin-bottom: 4px;
    }
    .agentguard-file-meta { font-size: var(--ag-font-meta); color: var(--ag-text-label); }
    .agentguard-metadata {
      margin-top: 12px;
      padding: 12px;
      background: var(--ag-bg-card);
      border: 1px solid var(--ag-border);
      border-radius: 4px;
    }
    .agentguard-metadata-title {
      font-size: var(--ag-font-meta);
      font-weight: 600;
      color: var(--ag-text-label);
      text-transform: uppercase;
      letter-spacing: 0.03em;
      margin-bottom: 8px;
    }
    .agentguard-metadata-item {
      display: flex;
      gap: 12px;
      margin: 4px 0;
      font-size: var(--ag-font-meta);
      line-height: 1.5;
    }
    .agentguard-metadata-label { color: var(--ag-text-label); font-weight: 500; min-width: 72px; }
    .agentguard-metadata-value { color: var(--ag-text-secondary); word-break: break-word; }

    /* --- PATTERN CARDS (AG-PROMPT-020: Single card per pattern) --- */
    .agentguard-signals-section {
      margin-top: 16px;
      padding-top: 16px;
      border-top: 1px solid var(--ag-border);
    }
    .agentguard-signals-header {
      font-size: var(--ag-font-meta);
      font-weight: 600;
      color: var(--ag-text-label);
      text-transform: uppercase;
      letter-spacing: 0.03em;
      margin-bottom: 12px;
    }
    .agentguard-signal-group { margin-bottom: 16px; }
    .agentguard-signal-group:last-child { margin-bottom: 0; }
    .agentguard-signal-group-title {
      font-size: var(--ag-font-meta);
      font-weight: 600;
      color: var(--ag-text-secondary);
      margin-bottom: 8px;
    }
    /* Pattern Card: Single card layout */
    .agentguard-signal {
      padding: 12px 16px;
      background: var(--ag-bg-card);
      border: 1px solid var(--ag-border);
      border-radius: 6px;
      margin-bottom: 8px;
    }
    .agentguard-signal:last-child { margin-bottom: 0; }
    /* Pattern Card Header: [Severity Badge] [Pattern Name] ... [Provenance Tag] */
    .agentguard-signal-header {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }
    /* Severity badges: CRITICAL=Indigo, HIGH/MEDIUM=Slate (WCAG AA) */
    .agentguard-signal-badge {
      font-size: 10px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.03em;
      padding: 3px 8px;
      border-radius: 3px;
      flex-shrink: 0;
    }
    .agentguard-signal-badge.low {
      background: var(--ag-low-bg);
      color: var(--ag-low-text);
    }
    .agentguard-signal-badge.medium {
      background: var(--ag-med-bg);
      color: var(--ag-med-text);
    }
    .agentguard-signal-badge.high {
      background: var(--ag-high-bg);
      color: var(--ag-high-text);
    }
    .agentguard-signal-badge.critical {
      background: var(--ag-crit-bg);
      color: var(--ag-crit-text);
    }
    .agentguard-signal-title {
      font-size: var(--ag-font-body);
      font-weight: 500;
      color: var(--ag-text-primary);
      flex: 1;
      min-width: 0;
    }
    /* Provenance tag (CONTENT / METADATA) */
    .agentguard-signal-source {
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
    .agentguard-signal-detail {
      font-size: var(--ag-font-meta);
      color: var(--ag-text-secondary);
      margin-top: 10px;
      line-height: 1.6;
    }
    .agentguard-show-more {
      font-size: var(--ag-font-meta);
      font-weight: 500;
      color: var(--ag-text-secondary);
      cursor: pointer;
      padding: 8px 0;
      margin-top: 8px;
    }
    .agentguard-show-more:hover { color: var(--ag-text-primary); }
    .agentguard-no-signals {
      font-size: var(--ag-font-meta);
      color: var(--ag-text-label);
      padding: 8px 0;
    }
    .agentguard-confidence {
      font-size: var(--ag-font-meta);
      color: var(--ag-text-label);
      margin-top: 16px;
      padding-top: 12px;
      border-top: 1px solid var(--ag-border);
    }

    /* Legacy header-bar — hidden, replaced by agentguard-header-row */
    .agentguard-header-bar { display: none; }
    .agentguard-destination-context { display: none; }
    .agentguard-header-meta { display: none; }
    /* Severity chip — kept for signal badges in drawer */
    .agentguard-severity-chip {
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.03em;
      padding: 2px 8px;
      border-radius: 3px;
      flex-shrink: 0;
    }
    .agentguard-severity-chip.critical { background: var(--ag-crit-bg); color: var(--ag-crit-text); }
    .agentguard-severity-chip.high     { background: var(--ag-high-bg); color: var(--ag-high-text); }
    .agentguard-severity-chip.medium   { background: var(--ag-med-bg);  color: var(--ag-med-text);  }
    .agentguard-confidence-chip { display: none; }

    /* AG-PROMPT-169/WS-01: Safer move hero panel — severity-colored left accent */
    .agentguard-safer-panel {
      padding: 14px 16px 14px 19px;
      background: var(--ag-bg-card);
      border: 1px solid var(--ag-border);
      border-left: 3px solid var(--ag-text-label);
      border-radius: var(--ag-radius);
      margin-bottom: 16px;
    }
    /* AG-177 doctrine (restored in AG-197): crit/high left-accent = Rose, soft rose tints */
    .agentguard-safer-panel-critical { border-left-color: var(--ag-crit-bg); background: #FEFAFA; }
    .agentguard-safer-panel-high { border-left-color: var(--ag-high-text); background: #FEFAFA; }
    .agentguard-safer-panel-medium { border-left-color: var(--ag-med-text); background: #FEFCF6; }
    .agentguard-safer-panel-low { border-left-color: var(--ag-low-text); background: #FAFAFA; }
    .agentguard-safer-label {
      font-size: var(--ag-font-meta);
      font-weight: 600;
      color: var(--ag-text-label);
      text-transform: uppercase;
      letter-spacing: 0.04em;
      margin-bottom: 4px;
    }
    .agentguard-safer-text {
      font-size: 16px;
      color: var(--ag-text-primary);
      line-height: 1.55;
      margin: 0;
    }

    /* AG-PROMPT-167/UX-05: Evidence preview bullets */
    .agentguard-evidence-preview {
      margin-bottom: 12px;
    }
    .agentguard-evidence-preview-label {
      font-size: var(--ag-font-meta);
      font-weight: 600;
      color: var(--ag-text-label);
      text-transform: uppercase;
      letter-spacing: 0.04em;
      margin-bottom: 6px;
    }
    .agentguard-evidence-preview-list {
      list-style: none;
      padding: 0;
      margin: 0;
    }
    .agentguard-evidence-preview-list li {
      font-size: var(--ag-font-body);
      color: var(--ag-text-secondary);
      line-height: 1.6;
      padding-left: 16px;
      position: relative;
    }
    .agentguard-evidence-preview-list li::before {
      content: '\u2022';
      position: absolute;
      left: 0;
      color: var(--ag-text-label);
    }
    /* AG-PROMPT-169/WS-01: Expandable evidence (1 shown, rest behind toggle) */
    .agentguard-evidence-more { display: none; }
    .agentguard-evidence-more.open { display: block; }
    .agentguard-evidence-expand {
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
    .agentguard-evidence-expand:hover { color: var(--ag-text-primary); }
    /* AG-PROMPT-169/WS-02: SVG chevron indicator */
    .agentguard-chevron {
      display: inline-block;
      width: 12px;
      height: 12px;
      background: currentColor;
      -webkit-mask: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 12 12'%3E%3Cpath d='M3 4.5l3 3 3-3' fill='none' stroke='%23000' stroke-width='1.5' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E") center/contain no-repeat;
      mask: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 12 12'%3E%3Cpath d='M3 4.5l3 3 3-3' fill='none' stroke='%23000' stroke-width='1.5' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E") center/contain no-repeat;
      transition: transform 0.15s ease;
      flex-shrink: 0;
    }
    [aria-expanded="true"] > .agentguard-chevron {
      transform: rotate(180deg);
    }

    /* Legacy elements */
    .agentguard-guidance { display: none; }
    .agentguard-reminder { display: none; }

    /* --- ZONE 3: ACTION FOOTER — design-system §9.6 --- */
    .agentguard-footer {
      padding: 0 16px 14px;
      background: #fafafa;
      border-top: 1px solid #f1f5f9;
    }
    .agentguard-action-label { display: none; }
    /* Friction acknowledgment — integrated row, no card border */
    .agentguard-friction {
      margin: 14px 0 0 0;
      padding: 0;
      background: none;
      border: none;
    }
    .agentguard-checkbox-label {
      display: flex;
      align-items: flex-start;
      gap: 8px;
      font-size: 11.5px;
      font-weight: 400;
      color: #475569;
      cursor: pointer;
      line-height: 1.4;
    }
    .agentguard-checkbox-label input {
      width: 15px;
      height: 15px;
      flex-shrink: 0;
      margin-top: 1px;
      accent-color: #3730a3;
      cursor: pointer;
    }
    /* Footer button row */
    .agentguard-buttons {
      display: flex;
      gap: 7px;
      padding-top: 10px;
      align-items: center;
    }
    .agentguard-btn {
      padding: 9px 0;
      border-radius: 10px;
      font-size: 12.5px;
      font-weight: 600;
      cursor: pointer;
      border: 1px solid transparent;
      transition: all 0.15s ease;
      font-family: inherit;
    }
    .agentguard-btn:focus-visible {
      outline: 2px solid var(--ag-crit-text);
      outline-offset: 2px;
    }
    .agentguard-btn:disabled { opacity: 0.35; cursor: not-allowed; }
    /* "Go back" — primary navy fill, flex:2 */
    .agentguard-btn-primary-safe {
      flex: 2;
      background: #0b1423;
      border-color: #0b1423;
      color: #ffffff;
    }
    .agentguard-btn-primary-safe:hover:not(:disabled) {
      background: #152035;
      border-color: #152035;
    }
    /* "Continue" — outline, flex:1 (medium/low severity) */
    .agentguard-btn-proceed-outline {
      flex: 1;
      background: #ffffff;
      border-color: #e2e8f0;
      color: #64748b;
    }
    .agentguard-btn-proceed-outline:hover:not(:disabled) {
      border-color: #cbd5e1;
      color: #334155;
    }
    /* "Continue anyway" — soft border, visibly secondary but not invisible (high/critical) */
    .agentguard-btn-proceed-soft {
      flex: 1;
      background: #ffffff;
      border: 1.5px solid #94a3b8;
      color: #374151;
      font-size: 12px;
      font-weight: 500;
    }
    .agentguard-btn-proceed-soft:hover:not(:disabled) {
      border-color: #64748b;
      color: #1e293b;
    }
    .agentguard-btn-proceed-soft:disabled {
      opacity: 0.35;
      cursor: not-allowed;
    }
    /* Legacy aliases */
    .agentguard-btn-cancel { color: var(--ag-text-label); }
    .agentguard-btn-proceed { background: var(--ag-text-primary); color: #fff; border-color: var(--ag-text-primary); }
    .agentguard-btn-proceed-ghost { display: none; }
    .agentguard-blocked {
      font-size: var(--ag-font-body);
      color: var(--ag-text-secondary);
      margin: 12px 0 0;
      padding: 10px 14px;
      background: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
    }

    /* --- CONCERN CARD — design-system §9.5 (white bordered, radius 10px) --- */
    .agentguard-dq-card {
      border-radius: 10px;
      border: 1px solid #e2e8f0;
      overflow: hidden;
      background: #ffffff;
      margin-bottom: 10px;
    }
    .agentguard-dq-inner {
      padding: 10px 12px;
    }
    .agentguard-dq-block {
      margin-bottom: 10px;
    }
    .agentguard-dq-block:last-child { margin-bottom: 0; }
    /* LABEL: 9.5px mono, wide letter-spacing, #94A3B8 — design-system §8.3 */
    .agentguard-dq-label {
      display: block;
      font-size: 9.5px;
      font-weight: 700;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: #94a3b8;
      margin-bottom: 4px;
      font-family: 'DM Mono', 'Fira Mono', monospace;
    }
    .agentguard-dq-label-inline {
      display: inline;
      margin-bottom: 0;
      margin-right: 8px;
    }
    .agentguard-dq-concern {
      font-size: 12.5px;
      font-weight: 600;
      color: #0f172a;
      margin: 0;
    }
    .agentguard-dq-content {
      font-size: 11.5px;
      color: #334155;
      line-height: 1.5;
      margin: 0;
    }
    .agentguard-dq-confidence-row {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }
    /* Confidence tag — colored pill with dot, design-system §9.5 */
    .agentguard-conf-tag {
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
    .agentguard-conf-dot {
      width: 5px; height: 5px; border-radius: 50%; flex-shrink: 0;
    }
    /* Safer option footer strip — design-system §9.5 (green advisory, never a button) */
    .agentguard-safer-strip {
      border-top: 1px solid #dcfce7;
      background: #f0fdf4;
      padding: 8px 12px;
      display: flex;
      gap: 8px;
      align-items: flex-start;
    }
    .agentguard-safer-arrow {
      color: #059669;
      font-size: 13px;
      flex-shrink: 0;
      line-height: 1.45;
    }
    .agentguard-safer-strip-text {
      font-size: 11.5px;
      color: #166534;
      line-height: 1.45;
      margin: 0;
    }
    /* Legacy aliases */
    .agentguard-dq-confidence-badge { display: none; }
    .agentguard-dq-confidence-note  { display: none; }
    .agentguard-safer-panel { display: none; }
    .agentguard-safer-panel-critical,
    .agentguard-safer-panel-high,
    .agentguard-safer-panel-medium,
    .agentguard-safer-panel-low { display: none; }

    /* --- DRAG OVERLAY --- */
    .agentguard-drag-overlay {
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
    .agentguard-drag-indicator {
      background: var(--ag-bg-card);
      padding: 16px 24px;
      border-radius: 6px;
      text-align: center;
    }
    .agentguard-drag-indicator h3 { margin: 0 0 8px 0; color: var(--ag-text-primary); font-size: var(--ag-font-body); font-weight: 600; }
    .agentguard-drag-indicator p { margin: 0; color: var(--ag-text-label); font-size: var(--ag-font-meta); }
    .agentguard-loading { display: flex; align-items: center; gap: 12px; padding: 16px; color: var(--ag-text-secondary); font-size: var(--ag-font-body); }
    .agentguard-spinner {
      width: 24px; height: 24px;
      border: 2px solid var(--ag-border);
      border-top-color: var(--ag-text-secondary);
      border-radius: 50%;
      animation: agentguard-spin 0.8s linear infinite;
    }
    @keyframes agentguard-spin { to { transform: rotate(360deg); } }

    /* AG-PROMPT-067: Awareness Banner (inline notification for informational cases) */
    .agentguard-banner {
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
      animation: agentguard-banner-slide 0.3s ease-out;
    }
    @keyframes agentguard-banner-slide {
      from { transform: translateY(16px); opacity: 0; }
      to { transform: translateY(0); opacity: 1; }
    }

    /* S3-04: Respect user motion preferences */
    @media (prefers-reduced-motion: reduce) {
      .agentguard-spinner { animation: none; }
      .agentguard-banner { animation: none; }
    }

    .agentguard-banner-content {
      padding: 16px 24px;
      border-left: 4px solid var(--ag-text-label);
    }
    .agentguard-banner-header {
      display: flex;
      align-items: flex-start;
      gap: 12px;
    }
    .agentguard-banner-icon {
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
    .agentguard-banner-text { flex: 1; }
    .agentguard-banner-title {
      font-size: var(--ag-font-body);
      font-weight: 600;
      color: var(--ag-text-primary);
      margin: 0 0 8px 0;
    }
    .agentguard-banner-summary {
      font-size: var(--ag-font-body);
      color: var(--ag-text-secondary);
      line-height: 1.6;
      margin: 0;
    }
    .agentguard-banner-close {
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
    .agentguard-banner-close:hover { color: var(--ag-text-secondary); }
    .agentguard-banner-close:focus-visible {
      outline: 2px solid var(--ag-crit-text);
      outline-offset: 2px;
    }
    .agentguard-banner-detected {
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
    .agentguard-banner-detected-icon { font-size: var(--ag-font-body); }
    .agentguard-banner-actions {
      display: flex;
      gap: 8px;
      margin-top: 16px;
      justify-content: flex-end;
    }
    .agentguard-banner-btn {
      padding: 10px 20px;
      border-radius: 6px;
      font-size: var(--ag-font-body);
      font-weight: 500;
      cursor: pointer;
      border: none;
      transition: background 0.15s;
    }
    .agentguard-banner-btn:focus-visible {
      outline: 2px solid var(--ag-crit-text);
      outline-offset: 2px;
    }
    .agentguard-banner-btn-secondary {
      background: var(--ag-high-bg);
      color: var(--ag-text-primary);
    }
    .agentguard-banner-btn-secondary:hover { background: var(--ag-border); }
    .agentguard-banner-btn-primary {
      background: var(--ag-text-primary);
      color: white;
    }
    .agentguard-banner-btn-primary:hover { background: #1e293b; }

    /* Notice as minimal status indicator */
    .agentguard-notice-overlay {
      background: rgba(0, 0, 0, 0.15);
    }
    .agentguard-notice {
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
    .agentguard-notice-icon {
      display: none;
    }
    .agentguard-notice-content {
      flex: 1;
    }
    .agentguard-notice-title {
      margin: 0 0 8px 0;
      font-size: var(--ag-font-body);
      font-weight: 600;
      color: var(--ag-text-primary);
    }
    .agentguard-notice-summary {
      margin: 0;
      font-size: var(--ag-font-body);
      color: var(--ag-text-secondary);
      line-height: 1.6;
    }
    /* AG-PRODUCT-PROMPT-DOCTRINE-001: Progress bar animation removed.
       Countdown timers and progress animations create urgency, which is prohibited. */
    .agentguard-notice-progress {
      display: none;
    }

    /* Low-risk notice */
    .agentguard-notice-low {
      border-color: var(--ag-border);
    }
    .agentguard-notice-icon-low {
      display: none;
    }
    .agentguard-notice-details {
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
    .agentguard-notice-details:hover {
      background: var(--ag-border);
      border-color: #cbd5e1;
    }

    /* Notice branding */
    .agentguard-notice-branding {
      font-size: var(--ag-font-meta);
      font-weight: 500;
      color: var(--ag-text-label);
      margin-bottom: 8px;
    }
    .agentguard-notice-branding-icon { display: none; }

    /* Primary finding */
    .agentguard-primary-finding {
      margin-bottom: 12px;
    }
    .agentguard-primary-finding-label {
      font-size: var(--ag-font-meta);
      font-weight: 600;
      color: var(--ag-text-label);
      margin-bottom: 4px;
    }
    .agentguard-primary-finding-content {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .agentguard-primary-finding-text {
      font-size: var(--ag-font-body);
      color: var(--ag-text-secondary);
      font-weight: 400;
    }

    /* Drawer toggle: button-like row with chevron */
    .agentguard-accordion {
      margin-top: 16px;
    }
    .agentguard-accordion-toggle {
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
    .agentguard-accordion-toggle:hover {
      background: #f8fafc;
      border-color: #cbd5e1;
    }
    .agentguard-accordion-toggle:focus-visible {
      outline: 2px solid var(--ag-crit-text);
      outline-offset: 2px;
    }
    .agentguard-accordion-toggle[aria-expanded="true"] {
      margin-bottom: 3px;
      border-color: #cbd5e1;
      background: #f8fafc;
    }
    /* Accordion chevron handled by .agentguard-chevron above */
    .agentguard-accordion-content {
      display: none;
      padding: 16px;
      background: var(--ag-bg-card);
      border: 1px solid var(--ag-border);
      border-radius: 6px;
    }
    .agentguard-accordion-content.open {
      display: block;
    }

    /* Notice continue button */
    .agentguard-notice-continue {
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
    .agentguard-notice-continue:hover {
      background: var(--ag-bg-card);
      border-color: #cbd5e1;
    }
    .agentguard-notice-continue:focus-visible {
      outline: 2px solid var(--ag-crit-text);
      outline-offset: 2px;
    }

    /* AG-PROMPT-LICENSE-UX-002: License status line inside modal only */
    /* HOST_PAGE_BANNERS_FOR_LICENSE = forbidden */
    /* INVARIANT: License state is meta-information. It must never visually
       compete with document classification or guidance. */
    .agentguard-license-status {
      font-size: 11px;
      line-height: 1.5;
      color: var(--ag-text-label);
      margin-bottom: 8px;
      /* AG-PROMPT-171/Fix-3: Thin muted banner */
    }
    .agentguard-license-contact {
      background: none;
      border: none;
      padding: 0;
      font: inherit;
      color: var(--ag-med-text);
      text-decoration: underline;
      cursor: pointer;
    }
    .agentguard-license-contact:hover { color: var(--ag-text-primary); }
    .agentguard-license-contact:focus-visible {
      outline: 2px solid var(--ag-crit-text);
      outline-offset: 2px;
    }

    /* AG-PROMPT-168/WS-03: Post-decision toast */
    .agentguard-toast {
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
    .agentguard-toast-exit {
      opacity: 0;
    }

    /* AG-PROMPT-168/WS-06: Shadow DOM / host injection resilience.
       Reset inherited properties that host pages may set globally,
       ensuring our overlay renders consistently regardless of host CSS. */
    .agentguard-overlay,
    .agentguard-overlay * {
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
    .agentguard-overlay {
      font-size: 16px;
      line-height: 1.5;
      color: var(--ag-text-primary);
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
    }
  `;

/**
 * AG-PROMPT-292: Build a fresh <style> element containing the modal CSS.
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
  if (document.getElementById('agentguard-styles')) return;

  const style = document.createElement('style');
  style.id = 'agentguard-styles';
  style.textContent = MODAL_CSS;
  document.head.appendChild(style);
}
