import type { PdfEncryptionReadability } from '../types/pdfEncryption';

export interface PasswordExceptionLike {
  name?: string;
  code?: number | string;
}

interface PdfJsTextItemLike {
  str?: string;
}

interface PdfJsPageLike {
  getTextContent: () => Promise<{ items: PdfJsTextItemLike[] }>;
}

interface PdfJsDocumentLike {
  numPages: number;
  getPage: (pageNumber: number) => Promise<PdfJsPageLike>;
  destroy?: () => void | Promise<void>;
}

interface PdfJsLoadingTaskLike {
  promise: Promise<PdfJsDocumentLike>;
}

interface PdfJsLibLike {
  getDocument: (options: { data: Uint8Array; password?: string }) => PdfJsLoadingTaskLike;
}

const MAX_TEXT_CHARS = 500_000;

export interface EncryptedPdfProbeResult {
  state: PdfEncryptionReadability;
  text: string;
  reason: 'load_no_prompt' | 'load_blank_password' | 'password_required' | 'pdfjs_unavailable';
}

export function isPasswordException(error: unknown): boolean {
  const err = error as PasswordExceptionLike | undefined;
  if (!err) return false;
  if (err.name === 'PasswordException') return true;
  return err.code === 1 || err.code === 2 || err.code === 'NEED_PASSWORD' || err.code === 'INCORRECT_PASSWORD';
}

async function extractTextFromPdfJsDoc(doc: PdfJsDocumentLike): Promise<string> {
  const chunks: string[] = [];

  for (let pageNumber = 1; pageNumber <= doc.numPages; pageNumber += 1) {
    const page = await doc.getPage(pageNumber);
    const textContent = await page.getTextContent();
    for (const item of textContent.items) {
      if (typeof item?.str === 'string' && item.str.length > 0) {
        chunks.push(item.str);
      }
    }
  }

  return chunks.join(' ').replace(/\s+/g, ' ').trim().slice(0, MAX_TEXT_CHARS);
}

async function loadAndExtract(lib: PdfJsLibLike, bytes: Uint8Array, password?: string): Promise<string> {
  const task = password === undefined
    ? lib.getDocument({ data: bytes })
    : lib.getDocument({ data: bytes, password });
  const doc = await task.promise;
  try {
    return await extractTextFromPdfJsDoc(doc);
  } finally {
    if (typeof doc.destroy === 'function') {
      await doc.destroy();
    }
  }
}

function getPdfJsLibFromGlobal(): PdfJsLibLike | null {
  const candidate = (globalThis as unknown as { pdfjsLib?: PdfJsLibLike }).pdfjsLib;
  if (!candidate || typeof candidate.getDocument !== 'function') {
    // S3-03: Warn when pdf.js is unavailable (diagnostic observability)
    console.warn('[AgentGuard] pdf.js library not available — encrypted PDF probing disabled');
    return null;
  }
  return candidate;
}

export async function probeEncryptedPdfWithBlankPassword(file: File): Promise<EncryptedPdfProbeResult> {
  const lib = getPdfJsLibFromGlobal();
  if (!lib) {
    return {
      state: 'ENCRYPTED_PASSWORD_REQUIRED',
      text: '',
      reason: 'pdfjs_unavailable',
    };
  }

  const bytes = new Uint8Array(await file.arrayBuffer());

  try {
    const text = await loadAndExtract(lib, bytes);
    return {
      state: 'ENCRYPTED_READABLE_NO_PROMPT',
      text,
      reason: 'load_no_prompt',
    };
  } catch (error) {
    if (!isPasswordException(error)) {
      return {
        state: 'ENCRYPTED_PASSWORD_REQUIRED',
        text: '',
        reason: 'password_required',
      };
    }
  }

  try {
    const text = await loadAndExtract(lib, bytes, '');
    return {
      state: 'ENCRYPTED_READABLE_BLANK_PASSWORD',
      text,
      reason: 'load_blank_password',
    };
  } catch {
    return {
      state: 'ENCRYPTED_PASSWORD_REQUIRED',
      text: '',
      reason: 'password_required',
    };
  }
}
