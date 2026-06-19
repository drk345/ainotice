/**
 * Minimal interface for upload interceptor dependency.
 * The original upload-interceptor module was removed; this interface
 * defines only what DOMObserver needs for type safety.
 */
interface UploadInterceptor {
  // DOMObserver currently doesn't call any methods on interceptor,
  // it just holds a reference. This interface can be extended if needed.
}

export class DOMObserver {
  private observer: MutationObserver | null = null;
  private interceptor: UploadInterceptor;

  constructor(interceptor: UploadInterceptor) {
    this.interceptor = interceptor;
  }

  start(): void {
    this.observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        if (mutation.type === 'childList') {
          mutation.addedNodes.forEach((node) => {
            if (node.nodeType === Node.ELEMENT_NODE) {
              const element = node as Element;
              
              // Check for file inputs
              if (element.tagName === 'INPUT' && (element as HTMLInputElement).type === 'file') {
                // File input added dynamically, interceptor will handle it
              }
              
              // Check within added subtree
              const fileInputs = element.querySelectorAll('input[type="file"]');
              // Interceptor event listeners will capture these
            }
          });
        }
      }
    });

    this.observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  }

  stop(): void {
    if (this.observer) {
      this.observer.disconnect();
      this.observer = null;
    }
  }
}