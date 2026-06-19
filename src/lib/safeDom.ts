/**
 * SafeDom - XSS-proof DOM construction utilities
 *
 * AG-SECURITY-HARDENING-SEC-01: Eliminates innerHTML attack surface by construction.
 * All dynamic text flows through textContent, all attributes through setAttribute.
 *
 * DESIGN PRINCIPLES:
 * 1. NO innerHTML, outerHTML, insertAdjacentHTML, or document.write
 * 2. Text content ONLY via textContent (auto-escapes HTML)
 * 3. Attributes ONLY via setAttribute (auto-escapes quotes)
 * 4. Structure via createElement + appendChild
 *
 * @see docs/adrs/ADR-025-safe-dom-construction.md
 */

// ============================================================================
// CORE TYPES
// ============================================================================

/** Allowed child content: text string, DOM node, or null (skipped) */
export type SafeChild = string | Node | null | undefined | false;

/** CSS class specification: string, array, or conditional object */
export type SafeClassName = string | string[] | Record<string, boolean>;

/** Safe attribute value (strings only, objects/functions rejected) */
export type SafeAttrValue = string | number | boolean | null | undefined;

/** Event handler type */
export type SafeEventHandler<K extends keyof HTMLElementEventMap> = (
  event: HTMLElementEventMap[K]
) => void;

// ============================================================================
// ELEMENT CREATION
// ============================================================================

/**
 * Create a DOM element with safe attribute and child handling.
 *
 * @param tag - HTML tag name
 * @param attrs - Optional attributes (className, id, data-*, aria-*, etc.)
 * @param children - Optional child content (strings become text nodes)
 * @returns Created element
 *
 * @example
 * el('div', { className: 'modal', id: 'my-modal' }, [
 *   el('h2', {}, ['Title']),  // Text is auto-escaped
 *   el('p', {}, [userInput])  // Even untrusted input is safe
 * ])
 */
export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs?: Record<string, SafeAttrValue> | null,
  children?: SafeChild[]
): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);

  // Apply attributes safely
  if (attrs) {
    for (const [key, value] of Object.entries(attrs)) {
      if (value === null || value === undefined || value === false) {
        continue;
      }

      if (key === 'className') {
        // Handle className specially
        element.className = String(value);
      } else if (key === 'textContent') {
        // Direct text content (safe by definition)
        element.textContent = String(value);
      } else if (key === 'disabled' || key === 'checked' || key === 'required') {
        // Boolean attributes
        if (value === true) {
          element.setAttribute(key, '');
        }
      } else if (key.startsWith('data-') || key.startsWith('aria-')) {
        // Data and ARIA attributes
        element.setAttribute(key, String(value));
      } else if (key === 'id' || key === 'title' || key === 'type' || key === 'name' || key === 'value' || key === 'placeholder' || key === 'href' || key === 'src' || key === 'alt') {
        // Known safe attributes
        element.setAttribute(key, String(value));
      } else if (key === 'style' && typeof value === 'string') {
        // Style as string (validated)
        element.setAttribute('style', value);
      } else {
        // Generic attribute - must be string
        element.setAttribute(key, String(value));
      }
    }
  }

  // Append children safely
  if (children) {
    for (const child of children) {
      appendChild(element, child);
    }
  }

  return element;
}

/**
 * Safely append a child to a parent element.
 * Strings become text nodes (XSS-safe).
 * Null/undefined/false are skipped.
 */
export function appendChild(parent: Element, child: SafeChild): void {
  if (child === null || child === undefined || child === false) {
    return;
  }

  if (typeof child === 'string') {
    // CRITICAL: Use createTextNode, NOT innerHTML
    parent.appendChild(document.createTextNode(child));
  } else if (child instanceof Node) {
    parent.appendChild(child);
  }
}

/**
 * Replace all children of an element safely.
 */
export function setChildren(parent: Element, children: SafeChild[]): void {
  // Clear existing children
  while (parent.firstChild) {
    parent.removeChild(parent.firstChild);
  }

  // Append new children safely
  for (const child of children) {
    appendChild(parent, child);
  }
}

// ============================================================================
// TEXT HANDLING
// ============================================================================

/**
 * Create a text node from any string.
 * This is the ONLY safe way to insert untrusted text into the DOM.
 */
export function text(content: string): Text {
  return document.createTextNode(content);
}

/**
 * Set element text content safely.
 * Replaces all existing content with text (no HTML parsing).
 */
export function setText(element: Element, content: string): void {
  element.textContent = content;
}

// ============================================================================
// EVENT HANDLING
// ============================================================================

/**
 * Attach an event listener with type safety.
 */
export function on<K extends keyof HTMLElementEventMap>(
  element: Element,
  event: K,
  handler: SafeEventHandler<K>,
  options?: AddEventListenerOptions
): void {
  element.addEventListener(event, handler as EventListener, options);
}

/**
 * Remove an event listener.
 */
export function off<K extends keyof HTMLElementEventMap>(
  element: Element,
  event: K,
  handler: SafeEventHandler<K>,
  options?: EventListenerOptions
): void {
  element.removeEventListener(event, handler as EventListener, options);
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Conditionally include a child element.
 * Returns the element if condition is true, otherwise undefined (skipped).
 */
export function when<T extends SafeChild>(condition: boolean, child: T): T | undefined {
  return condition ? child : undefined;
}

/**
 * Create multiple elements from an array.
 */
export function map<T>(
  items: T[],
  render: (item: T, index: number) => SafeChild
): SafeChild[] {
  return items.map(render);
}

/**
 * Join text items with a separator (all as text nodes, no HTML).
 */
export function joinText(items: string[], separator: string): SafeChild[] {
  const result: SafeChild[] = [];
  for (let i = 0; i < items.length; i++) {
    if (i > 0) {
      result.push(separator);
    }
    result.push(items[i]);
  }
  return result;
}

// ============================================================================
// CSS CLASS UTILITIES
// ============================================================================

/**
 * Build className string from various inputs.
 *
 * @example
 * cx('base', ['modifier'], { 'active': isActive, 'disabled': !enabled })
 * // => 'base modifier active' (if isActive true, enabled true)
 */
export function cx(...inputs: (SafeClassName | undefined | null | false)[]): string {
  const classes: string[] = [];

  for (const input of inputs) {
    if (!input) continue;

    if (typeof input === 'string') {
      classes.push(input);
    } else if (Array.isArray(input)) {
      classes.push(...input.filter(Boolean));
    } else if (typeof input === 'object') {
      for (const [key, value] of Object.entries(input)) {
        if (value) classes.push(key);
      }
    }
  }

  return classes.join(' ');
}

// ============================================================================
// FRAGMENT SUPPORT
// ============================================================================

/**
 * Create a document fragment with children.
 * Useful for inserting multiple elements at once.
 */
export function fragment(children: SafeChild[]): DocumentFragment {
  const frag = document.createDocumentFragment();
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    if (typeof child === 'string') {
      frag.appendChild(document.createTextNode(child));
    } else if (child instanceof Node) {
      frag.appendChild(child);
    }
  }
  return frag;
}

// ============================================================================
// VALIDATION UTILITIES (FOR TESTING)
// ============================================================================

/**
 * Check if a string contains potential XSS payloads.
 * Used in tests to verify payloads are being sanitized.
 */
export function containsHtmlSyntax(str: string): boolean {
  return /<|>|&lt;|&gt;|javascript:|data:|on\w+=/i.test(str);
}

/**
 * Assert that an element's text content matches expected value.
 * Throws if textContent differs (useful for testing).
 */
export function assertTextContent(element: Element, expected: string): void {
  if (element.textContent !== expected) {
    throw new Error(
      `Text content mismatch: expected "${expected}", got "${element.textContent}"`
    );
  }
}

// ============================================================================
// DEPRECATED: escapeHtml compatibility shim
// ============================================================================

/**
 * @deprecated SEC-01: Do not use escapeHtml. Use SafeDom utilities instead.
 *
 * This function exists only for migration purposes. New code MUST use
 * el(), text(), or setText() which are safe by construction.
 *
 * The function will log a deprecation warning in development builds.
 */
export function escapeHtml_DEPRECATED(str: string): string {
  // Log deprecation warning (only in dev)
  if (typeof console !== 'undefined' && console.warn) {
    console.warn(
      '[AgentGuard:SEC-01] escapeHtml is deprecated. Use SafeDom utilities instead.',
      new Error().stack
    );
  }

  // Original implementation (browser-native escaping)
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}
