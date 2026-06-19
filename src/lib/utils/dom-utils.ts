export class DOMUtils {
  static isFileInput(element: Element): element is HTMLInputElement {
    return element.tagName === 'INPUT' && (element as HTMLInputElement).type === 'file';
  }

  static findFileInputs(root: Element = document.body): HTMLInputElement[] {
    return Array.from(root.querySelectorAll('input[type="file"]'));
  }

  static observeDOMChanges(
    callback: (mutations: MutationRecord[]) => void,
    options?: MutationObserverInit
  ): MutationObserver {
    const observer = new MutationObserver(callback);
    observer.observe(document.body, {
      childList: true,
      subtree: true,
      ...options
    });
    return observer;
  }

  static injectStyles(css: string): HTMLStyleElement {
    const style = document.createElement('style');
    style.textContent = css;
    document.head.appendChild(style);
    return style;
  }

  static createElement<K extends keyof HTMLElementTagNameMap>(
    tag: K,
    props?: Partial<HTMLElementTagNameMap[K]>,
    children?: (Node | string)[]
  ): HTMLElementTagNameMap[K] {
    const element = document.createElement(tag);
    
    if (props) {
      Object.assign(element, props);
    }

    if (children) {
      for (const child of children) {
        if (typeof child === 'string') {
          element.appendChild(document.createTextNode(child));
        } else {
          element.appendChild(child);
        }
      }
    }

    return element;
  }
}