/**
 * AG-PHASE-1-UNIFIED-PDF-EXTRACTION-SPINE: Shared PDF text extraction core.
 *
 * Platform-agnostic extraction logic used by both browser (content script)
 * and Node.js (CLI diagnostic scripts). Callers provide an InflateFn
 * for platform-specific decompression.
 *
 * Architecture promoted from scripts/lib/pdf-stream-decode.ts with
 * WinAnsiEncoding support ported from src/content/metadataExtractor.ts.
 *
 * Pipeline:
 *   1. Decompress all stream/endstream pairs
 *   2. Build per-font registry (CMap + encoding info)
 *   3. Extract text with per-font tracking (sequential)
 *   4. Fall back to merged CMap extraction
 *   5. Fall back to ASCII run extraction
 *   6. Assess quality
 */

import type {
  InflateFn,
  FontEntry,
  FontRegistry,
  FontEncoding,
  PdfExtractionResult,
  ExtractionDiagnostics,
} from './types';
import { assessExtractionQuality } from './pdfQualityAssessment';
import { decodeAscii85 } from '../util/ascii85Decode';

// ============================================================================
// CONSTANTS
// ============================================================================

const MAX_OUTPUT_CHARS = 500_000;
const MAX_STREAM_FOR_FULL_REGEX = 1_000_000;

// ============================================================================
// BYTE / STRING UTILITIES
// ============================================================================

/** Convert Uint8Array range to latin1 string */
function bytesToLatin1(bytes: Uint8Array, start = 0, end?: number): string {
  const stop = end !== undefined ? Math.min(end, bytes.length) : bytes.length;
  let result = '';
  for (let i = start; i < stop; i++) {
    result += String.fromCharCode(bytes[i]);
  }
  return result;
}

/** Unescape PDF literal string escape sequences */
function unescapePdfString(str: string): string {
  let result = '';
  let i = 0;
  while (i < str.length) {
    if (str[i] === '\\' && i + 1 < str.length) {
      const next = str[i + 1];
      switch (next) {
        case 'n': result += '\n'; i += 2; break;
        case 'r': result += '\r'; i += 2; break;
        case 't': result += '\t'; i += 2; break;
        case 'b': result += '\b'; i += 2; break;
        case 'f': result += '\f'; i += 2; break;
        case '(': result += '('; i += 2; break;
        case ')': result += ')'; i += 2; break;
        case '\\': result += '\\'; i += 2; break;
        default:
          if (next >= '0' && next <= '7') {
            let octal = next;
            let j = i + 2;
            while (j < str.length && j < i + 4 && str[j] >= '0' && str[j] <= '7') {
              octal += str[j];
              j++;
            }
            result += String.fromCharCode(parseInt(octal, 8));
            i = j;
          } else {
            result += next;
            i += 2;
          }
      }
    } else {
      result += str[i];
      i++;
    }
  }
  return result;
}

// ============================================================================
// WinAnsiEncoding SUPPORT (ported from production extractor)
// ============================================================================

/** Windows-1252 mapping for bytes 0x80-0x9F (other bytes map directly to Unicode) */
const WIN_ANSI_MAP: Record<number, number> = {
  0x80: 0x20AC, 0x82: 0x201A, 0x83: 0x0192, 0x84: 0x201E, 0x85: 0x2026,
  0x86: 0x2020, 0x87: 0x2021, 0x88: 0x02C6, 0x89: 0x2030, 0x8A: 0x0160,
  0x8B: 0x2039, 0x8C: 0x0152, 0x8E: 0x017D, 0x91: 0x2018, 0x92: 0x2019,
  0x93: 0x201C, 0x94: 0x201D, 0x95: 0x2022, 0x96: 0x2013, 0x97: 0x2014,
  0x98: 0x02DC, 0x99: 0x2122, 0x9A: 0x0161, 0x9B: 0x203A, 0x9C: 0x0153,
  0x9E: 0x017E, 0x9F: 0x0178,
};

function decodeWinAnsiByte(byte: number): string {
  if (byte >= 0x80 && byte <= 0x9F) {
    const mapped = WIN_ANSI_MAP[byte];
    return mapped ? String.fromCodePoint(mapped) : '';
  }
  return String.fromCodePoint(byte);
}

function decodeHexWithWinAnsi(hexStr: string): string {
  const clean = hexStr.replace(/\s/g, '').toUpperCase();
  let result = '';
  for (let i = 0; i + 1 < clean.length; i += 2) {
    const byte = parseInt(clean.substring(i, i + 2), 16);
    if (!isNaN(byte)) result += decodeWinAnsiByte(byte);
  }
  return result;
}

function decodeLiteralStringToBytes(str: string): number[] {
  const bytes: number[] = [];
  let i = 0;
  while (i < str.length) {
    if (str[i] === '\\' && i + 1 < str.length) {
      const next = str[i + 1];
      switch (next) {
        case 'n': bytes.push(0x0A); i += 2; break;
        case 'r': bytes.push(0x0D); i += 2; break;
        case 't': bytes.push(0x09); i += 2; break;
        case 'b': bytes.push(0x08); i += 2; break;
        case 'f': bytes.push(0x0C); i += 2; break;
        case '(': bytes.push(0x28); i += 2; break;
        case ')': bytes.push(0x29); i += 2; break;
        case '\\': bytes.push(0x5C); i += 2; break;
        default:
          if (next >= '0' && next <= '7') {
            let octal = next;
            let j = i + 2;
            while (j < str.length && j < i + 4 && str[j] >= '0' && str[j] <= '7') {
              octal += str[j];
              j++;
            }
            bytes.push(parseInt(octal, 8) & 0xFF);
            i = j;
          } else {
            bytes.push(str.charCodeAt(i + 1));
            i += 2;
          }
      }
    } else {
      bytes.push(str.charCodeAt(i) & 0xFF);
      i++;
    }
  }
  return bytes;
}

function decodeLiteralWithWinAnsi(str: string): string {
  const bytes = decodeLiteralStringToBytes(str);
  return bytes.map(b => decodeWinAnsiByte(b)).join('');
}

// ============================================================================
// ToUnicode CMap PARSING
// ============================================================================

function hexToUnicodeString(hex: string): string {
  let result = '';
  if (hex.length % 4 === 0 && hex.length >= 4) {
    for (let i = 0; i < hex.length; i += 4) {
      const cp = parseInt(hex.substring(i, i + 4), 16);
      if (cp > 0) result += String.fromCodePoint(cp);
    }
  } else {
    for (let i = 0; i + 1 < hex.length; i += 2) {
      const cp = parseInt(hex.substring(i, i + 2), 16);
      if (cp > 0) result += String.fromCodePoint(cp);
    }
  }
  return result;
}

interface CMapResult {
  cmap: Map<number, string>;
  byteWidth: 1 | 2;
}

function parseToUnicodeCMap(cmapContent: string): CMapResult {
  const cmap = new Map<number, string>();

  // Detect byte width from codespacerange
  let byteWidth: 1 | 2 = 2;
  const codeSpaceMatch = cmapContent.match(
    /begincodespacerange\s*[\r\n]+\s*<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>/,
  );
  if (codeSpaceMatch) {
    byteWidth = Math.ceil(codeSpaceMatch[1].length / 2) as 1 | 2;
  }

  // Parse bfchar sections: <srcCode> <dstUnicode>
  const bfcharRegex = /beginbfchar\s*([\s\S]*?)endbfchar/g;
  let blockMatch;
  while ((blockMatch = bfcharRegex.exec(cmapContent)) !== null) {
    const block = blockMatch[1];
    const lineRegex = /<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>/g;
    let lineMatch;
    while ((lineMatch = lineRegex.exec(block)) !== null) {
      const srcCode = parseInt(lineMatch[1], 16);
      const dstStr = hexToUnicodeString(lineMatch[2]);
      if (dstStr.length > 0) cmap.set(srcCode, dstStr);
    }
  }

  // Parse bfrange sections
  const bfrangeRegex = /beginbfrange\s*([\s\S]*?)endbfrange/g;
  while ((blockMatch = bfrangeRegex.exec(cmapContent)) !== null) {
    const block = blockMatch[1];
    const rangeRegex = /<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>\s*(?:<([0-9a-fA-F]+)>|\[([^\]]*)\])/g;
    let rangeMatch;
    while ((rangeMatch = rangeRegex.exec(block)) !== null) {
      const lo = parseInt(rangeMatch[1], 16);
      const hi = parseInt(rangeMatch[2], 16);
      if (rangeMatch[3]) {
        const dstLo = parseInt(rangeMatch[3], 16);
        for (let src = lo; src <= hi && src - lo < 1000; src++) {
          cmap.set(src, String.fromCodePoint(dstLo + (src - lo)));
        }
      } else if (rangeMatch[4]) {
        const dstEntries = rangeMatch[4].match(/<([0-9a-fA-F]+)>/g) || [];
        for (let i = 0; i < dstEntries.length && lo + i <= hi; i++) {
          const dstHex = dstEntries[i].replace(/[<>]/g, '');
          cmap.set(lo + i, hexToUnicodeString(dstHex));
        }
      }
    }
  }

  // Fallback: infer byte width from max key if codespacerange not found
  if (!codeSpaceMatch && cmap.size > 0) {
    let maxKey = 0;
    for (const key of cmap.keys()) {
      if (key > maxKey) maxKey = key;
    }
    byteWidth = maxKey > 255 ? 2 : 1;
  }

  return { cmap, byteWidth };
}

// ============================================================================
// FONT REGISTRY BUILDING
// ============================================================================

function parseFontEncoding(objDict: string): FontEncoding | null {
  const match = objDict.match(/\/Encoding\s*\/([A-Za-z0-9-]+)/);
  if (!match) return null;
  const enc = match[1];
  if (enc === 'WinAnsiEncoding') return 'WinAnsiEncoding';
  if (enc === 'MacRomanEncoding') return 'MacRomanEncoding';
  if (enc === 'StandardEncoding') return 'StandardEncoding';
  if (enc === 'Identity-H') return 'Identity-H';
  if (enc === 'Identity-V') return 'Identity-V';
  return 'Other';
}

function parseFontSubtype(objDict: string): string | null {
  const match = objDict.match(/\/Subtype\s*\/([A-Za-z0-9]+)/);
  return match ? match[1] : null;
}

/**
 * Build per-font registry by following PDF object references.
 *
 * Strategy (merged from scripts + production extractors):
 *   1. Find font aliases from /Font resource dicts (scripts approach — searches decompressed streams too)
 *   2. For each font object, detect encoding and subtype (production approach)
 *   3. Follow /ToUnicode references to CMap streams (both approaches)
 */
function buildFontRegistry(
  pdfRawText: string,
  objToContent: Map<number, string>,
): FontRegistry {
  const registry: FontRegistry = new Map();

  // Step 1: Find font name → object number from /Font resource dicts
  const fontNameToObj = new Map<string, number>();

  function extractFontRefs(text: string): void {
    // Match inline font dicts: /Font << /F1 N 0 R ... >>
    const fontDictRegex = /\/Font\s*<<([\s\S]*?)>>/g;
    let fm;
    while ((fm = fontDictRegex.exec(text)) !== null) {
      const entries = fm[1];
      const entryRegex = /\/([A-Za-z][A-Za-z0-9_-]*)\s+(\d+)\s+0\s+R/g;
      let em;
      while ((em = entryRegex.exec(entries)) !== null) {
        fontNameToObj.set(em[1], parseInt(em[2]));
      }
    }
  }

  /** Resolve indirect /Font N 0 R references (e.g. ReportLab PDFs) */
  function resolveIndirectFontRefs(text: string): void {
    const indirectFontRegex = /\/Font\s+(\d+)\s+0\s+R/g;
    let fm;
    while ((fm = indirectFontRegex.exec(text)) !== null) {
      const fontDictObjNum = parseInt(fm[1]);
      // Find the referenced object's content in raw PDF
      const marker = fontDictObjNum + ' 0 obj';
      const idx = text.indexOf(marker);
      if (idx < 0) continue;
      const snippet = text.slice(idx + marker.length, idx + marker.length + 500);
      // Parse font entries from the referenced dict
      const entryRegex = /\/([A-Za-z][A-Za-z0-9_-]*)\s+(\d+)\s+0\s+R/g;
      let em;
      while ((em = entryRegex.exec(snippet)) !== null) {
        // Stop at endobj
        if (snippet.indexOf('endobj') >= 0 && em.index > snippet.indexOf('endobj')) break;
        fontNameToObj.set(em[1], parseInt(em[2]));
      }
    }
  }

  // Search raw PDF text
  extractFontRefs(pdfRawText);
  resolveIndirectFontRefs(pdfRawText);
  // Also search decompressed streams (for font refs in page objects)
  for (const content of objToContent.values()) {
    if (content.length <= 100_000) {
      extractFontRefs(content);
      resolveIndirectFontRefs(content);
    }
  }

  if (fontNameToObj.size === 0) return registry;

  // Step 2: For each font object, extract encoding, subtype, and ToUnicode CMap
  for (const [fontName, fontObjNum] of fontNameToObj) {
    const marker = fontObjNum + ' 0 obj';
    let searchPos = 0;

    while (searchPos < pdfRawText.length) {
      const idx = pdfRawText.indexOf(marker, searchPos);
      if (idx < 0) break;

      // Verify word boundary
      if (idx > 0) {
        const cb = pdfRawText.charCodeAt(idx - 1);
        if (cb !== 10 && cb !== 13 && cb !== 32 && cb !== 9) {
          searchPos = idx + marker.length;
          continue;
        }
      }

      // Take next 500 chars for font object dict
      const snippet = pdfRawText.slice(idx, idx + 500);

      const encoding = parseFontEncoding(snippet);
      const subtype = parseFontSubtype(snippet);

      // Follow /ToUnicode reference
      let cmap: Map<number, string> | null = null;
      let byteWidth: 1 | 2 = 1;

      const tuMatch = snippet.match(/\/ToUnicode\s+(\d+)\s+0\s+R/);
      if (tuMatch) {
        const cmapObjNum = parseInt(tuMatch[1]);
        const cmapContent = objToContent.get(cmapObjNum);
        if (cmapContent && (cmapContent.includes('beginbfchar') || cmapContent.includes('beginbfrange'))) {
          const parsed = parseToUnicodeCMap(cmapContent);
          cmap = parsed.cmap;
          byteWidth = parsed.byteWidth;
        }
      }

      // For Type0 fonts with Identity-H/V encoding, default to 2-byte
      if (subtype === 'Type0' && (encoding === 'Identity-H' || encoding === 'Identity-V')) {
        byteWidth = 2;
      }

      registry.set(fontName, { cmap, byteWidth, encoding, subtype });
      break;
    }
  }

  return registry;
}

// ============================================================================
// HEX / LITERAL STRING DECODING WITH FONT AWARENESS
// ============================================================================

function decodeHexStringWithFont(hex: string, font: FontEntry): string {
  const cleanHex = hex.replace(/\s/g, '');
  if (cleanHex.length === 0) return '';

  // Strategy 1: Use ToUnicode CMap if available
  if (font.cmap && font.cmap.size > 0) {
    let result = '';
    if (font.byteWidth === 2 && cleanHex.length >= 4) {
      for (let i = 0; i + 3 < cleanHex.length; i += 4) {
        const glyphId = parseInt(cleanHex.substring(i, i + 4), 16);
        const mapped = font.cmap.get(glyphId);
        if (mapped) {
          result += mapped;
        } else if (glyphId >= 0x20) {
          result += String.fromCodePoint(glyphId);
        }
      }
    } else {
      for (let i = 0; i + 1 < cleanHex.length; i += 2) {
        const glyphId = parseInt(cleanHex.substring(i, i + 2), 16);
        const mapped = font.cmap.get(glyphId);
        if (mapped) {
          result += mapped;
        } else if (glyphId >= 0x20 && glyphId < 0x7F) {
          result += String.fromCharCode(glyphId);
        }
      }
    }
    return result;
  }

  // Strategy 2: Use WinAnsiEncoding for standard Latin fonts
  if (font.encoding === 'WinAnsiEncoding' ||
      font.encoding === 'MacRomanEncoding' ||
      font.encoding === 'StandardEncoding') {
    return decodeHexWithWinAnsi(cleanHex);
  }

  // Strategy 3: Simple TrueType/Type1 without explicit encoding — try Latin-1
  if ((font.subtype === 'TrueType' || font.subtype === 'Type1') &&
      font.encoding === 'Other') {
    return decodeHexWithWinAnsi(cleanHex);
  }

  // Strategy 4: Direct byte-to-char fallback
  let result = '';
  for (let i = 0; i + 1 < cleanHex.length; i += 2) {
    const byte = parseInt(cleanHex.substring(i, i + 2), 16);
    if (!isNaN(byte) && byte >= 0x20 && byte < 0x7F) {
      result += String.fromCharCode(byte);
    }
  }
  return result;
}

function decodeLiteralStringWithFont(str: string, font: FontEntry): string {
  // For CMap fonts, convert literal bytes to CMap lookup
  if (font.cmap && font.cmap.size > 0 && font.byteWidth === 1) {
    const bytes = decodeLiteralStringToBytes(str);
    let result = '';
    for (const byte of bytes) {
      const mapped = font.cmap.get(byte);
      if (mapped) {
        result += mapped;
      } else if (byte >= 0x20 && byte < 0x7F) {
        result += String.fromCharCode(byte);
      }
    }
    return result;
  }

  // For standard encodings, use WinAnsi decode
  if (font.encoding === 'WinAnsiEncoding' ||
      font.encoding === 'MacRomanEncoding' ||
      font.encoding === 'StandardEncoding' ||
      font.encoding === 'Other') {
    return decodeLiteralWithWinAnsi(str);
  }

  // Fallback: simple unescape
  return unescapePdfString(str);
}

// ============================================================================
// BT/ET TEXT EXTRACTION — SEQUENTIAL (per-font tracking)
// ============================================================================

/** Split large content streams into BT...ET blocks for performance */
function splitTextBlocks(content: string): string[] {
  if (content.length <= MAX_STREAM_FOR_FULL_REGEX) {
    return [content];
  }

  const blocks: string[] = [];
  const btRegex = /\bBT\b/g;
  let m;
  while ((m = btRegex.exec(content)) !== null) {
    const etIdx = content.indexOf('ET', m.index + 2);
    if (etIdx < 0) break;
    blocks.push(content.slice(m.index, etIdx + 2));
    btRegex.lastIndex = etIdx + 2;
  }

  return blocks.length > 0 ? blocks : [content.slice(0, MAX_STREAM_FOR_FULL_REGEX)];
}

/**
 * Extract text with per-font CMap and encoding tracking (sequential).
 * This is the primary extraction strategy for font-encoded PDFs.
 */
function extractTextSequential(content: string, fontRegistry: FontRegistry): string {
  const textParts: string[] = [];
  let currentFont: FontEntry | undefined;

  // Matches font changes + all text-showing operators in order
  const opRegex = /\/([A-Za-z][A-Za-z0-9+_-]*)\s+[\d.]+\s+Tf|\(([^)\\]*(?:\\.[^)\\]*)*)\)\s*Tj|<([0-9a-fA-F\s]+)>\s*Tj|\[([^\]]*)\]\s*TJ|\(([^)\\]*(?:\\.[^)\\]*)*)\)\s*'/g;

  const blocks = splitTextBlocks(content);
  for (const block of blocks) {
    opRegex.lastIndex = 0;
    let match;
    while ((match = opRegex.exec(block)) !== null) {
      if (match[1] !== undefined) {
        // Font change: /FontName size Tf
        currentFont = fontRegistry.get(match[1]);
      } else if (match[2] !== undefined && currentFont) {
        // (literal) Tj
        const text = decodeLiteralStringWithFont(match[2], currentFont);
        if (text.trim().length > 0) textParts.push(text);
      } else if (match[2] !== undefined) {
        // (literal) Tj without font — simple unescape
        const text = unescapePdfString(match[2]);
        if (text.trim().length > 0) textParts.push(text);
      } else if (match[3] !== undefined) {
        // <hex> Tj
        if (currentFont) {
          const decoded = decodeHexStringWithFont(match[3], currentFont);
          if (decoded.trim().length > 0) textParts.push(decoded);
        }
      } else if (match[4] !== undefined) {
        // [...] TJ array
        const arrayContent = match[4];
        let arrayText = '';
        const itemRegex = /\(([^)\\]*(?:\\.[^)\\]*)*)\)|<([0-9a-fA-F\s]+)>|(-?\d+(?:\.\d+)?)/g;
        let itemMatch;
        while ((itemMatch = itemRegex.exec(arrayContent)) !== null) {
          if (itemMatch[1] !== undefined) {
            arrayText += currentFont
              ? decodeLiteralStringWithFont(itemMatch[1], currentFont)
              : unescapePdfString(itemMatch[1]);
          } else if (itemMatch[2] !== undefined && currentFont) {
            const hex = itemMatch[2].replace(/\s/g, '');
            if (hex.length >= 2) arrayText += decodeHexStringWithFont(hex, currentFont);
          } else if (itemMatch[3] !== undefined) {
            const kern = parseFloat(itemMatch[3]);
            if (kern < -200) arrayText += ' ';
          }
        }
        if (arrayText.trim().length > 0) textParts.push(arrayText);
      } else if (match[5] !== undefined) {
        // (literal) '
        const text = currentFont
          ? decodeLiteralStringWithFont(match[5], currentFont)
          : unescapePdfString(match[5]);
        if (text.trim().length > 0) textParts.push(text);
      }
    }
  }

  return textParts.join(' ');
}

/**
 * Extract text using merged CMap (fallback for simple fonts / Chrome PDFs).
 */
function extractTextMultiPass(content: string, mergedCmap: Map<number, string>): string {
  const textParts: string[] = [];

  let maxKey = 0;
  for (const key of mergedCmap.keys()) {
    if (key > maxKey) maxKey = key;
  }
  const byteWidth: 1 | 2 = maxKey > 255 ? 2 : 1;

  const blocks = splitTextBlocks(content);
  for (const block of blocks) {
    // (literal) Tj
    const tjLiteralRegex = /\(([^)\\]*(?:\\.[^)\\]*)*)\)\s*Tj/g;
    let m;
    while ((m = tjLiteralRegex.exec(block)) !== null) {
      const text = unescapePdfString(m[1]);
      if (text.trim().length > 0) textParts.push(text);
    }

    // <hex> Tj
    const tjHexRegex = /<([0-9a-fA-F\s]+)>\s*Tj/g;
    while ((m = tjHexRegex.exec(block)) !== null) {
      const hex = m[1].replace(/\s/g, '');
      if (hex.length >= 2) {
        const font: FontEntry = { cmap: mergedCmap, byteWidth, encoding: null, subtype: null };
        const decoded = decodeHexStringWithFont(hex, font);
        if (decoded.trim().length > 0) textParts.push(decoded);
      }
    }

    // [...] TJ array
    const tjArrayRegex = /\[([^\]]*)\]\s*TJ/g;
    while ((m = tjArrayRegex.exec(block)) !== null) {
      const arrayContent = m[1];
      let arrayText = '';
      const itemRegex = /\(([^)\\]*(?:\\.[^)\\]*)*)\)|<([0-9a-fA-F\s]+)>|(-?\d+(?:\.\d+)?)/g;
      let itemMatch;
      while ((itemMatch = itemRegex.exec(arrayContent)) !== null) {
        if (itemMatch[1] !== undefined) {
          arrayText += unescapePdfString(itemMatch[1]);
        } else if (itemMatch[2] !== undefined) {
          const hex = itemMatch[2].replace(/\s/g, '');
          if (hex.length >= 2) {
            const font: FontEntry = { cmap: mergedCmap, byteWidth, encoding: null, subtype: null };
            arrayText += decodeHexStringWithFont(hex, font);
          }
        } else if (itemMatch[3] !== undefined) {
          const kern = parseFloat(itemMatch[3]);
          if (kern < -200) arrayText += ' ';
        }
      }
      if (arrayText.trim().length > 0) textParts.push(arrayText);
    }

    // (literal) '
    const quoteRegex = /\(([^)\\]*(?:\\.[^)\\]*)*)\)\s*'/g;
    while ((m = quoteRegex.exec(block)) !== null) {
      const text = unescapePdfString(m[1]);
      if (text.trim().length > 0) textParts.push(text);
    }
  }

  return textParts.join(' ');
}

// ============================================================================
// STREAM DECOMPRESSION
// ============================================================================

interface DecompressedStream {
  objNum: number;
  content: string;
}

function hasFlateDecode(dict: string): boolean {
  return /\/Filter\s*\/FlateDecode/i.test(dict) ||
         /\/Filter\s*\[\s*\/FlateDecode\s*\]/i.test(dict);
}

function hasAscii85AndFlateDecode(dict: string): boolean {
  return /\/Filter\s*\[\s*\/ASCII85Decode\s+\/FlateDecode\s*\]/i.test(dict);
}

/**
 * Decompress all stream/endstream pairs in a PDF.
 * Returns array of {objNum, content} for each successfully decompressed stream.
 *
 * Architecture from scripts extractor: manual loop skipping binary stream data
 * to avoid false regex matches inside compressed content.
 */
function decompressAllStreams(
  bytes: Uint8Array,
  pdfText: string,
  inflate: InflateFn,
): DecompressedStream[] {
  const results: DecompressedStream[] = [];
  const objPattern = /(\d+)\s+0\s+obj/g;
  let pos = 0;

  while (pos < pdfText.length) {
    objPattern.lastIndex = pos;
    const objMatch = objPattern.exec(pdfText);
    if (!objMatch) break;

    const objNum = parseInt(objMatch[1]);
    const afterObj = objMatch.index + objMatch[0].length;

    // Look for "stream\r?\n" within a reasonable window
    const headerEnd = Math.min(afterObj + 2000, pdfText.length);
    const headerRegion = pdfText.slice(afterObj, headerEnd);
    const streamMatch = headerRegion.match(/stream\r?\n/);

    if (!streamMatch || streamMatch.index === undefined) {
      pos = afterObj;
      continue;
    }

    // Check for endobj BEFORE stream keyword
    const endObjIdx = headerRegion.indexOf('endobj');
    if (endObjIdx >= 0 && endObjIdx < streamMatch.index) {
      pos = afterObj + endObjIdx + 6;
      continue;
    }

    const headerText = headerRegion.slice(0, streamMatch.index);
    const dataStart = afterObj + streamMatch.index + streamMatch[0].length;

    // Find endstream
    const endstreamIdx = pdfText.indexOf('endstream', dataStart);
    if (endstreamIdx === -1) {
      pos = dataStart;
      continue;
    }

    let dataEnd = endstreamIdx;
    while (dataEnd > dataStart && (pdfText.charCodeAt(dataEnd - 1) === 10 || pdfText.charCodeAt(dataEnd - 1) === 13)) {
      dataEnd--;
    }

    const streamBytes = bytes.slice(dataStart, dataEnd);
    let decompressedBytes: Uint8Array | null = null;

    if (hasAscii85AndFlateDecode(headerText)) {
      const ascii85Decoded = decodeAscii85(streamBytes);
      decompressedBytes = inflate(ascii85Decoded);
    } else if (hasFlateDecode(headerText)) {
      decompressedBytes = inflate(streamBytes);
    } else {
      decompressedBytes = streamBytes;
    }

    if (decompressedBytes !== null) {
      results.push({ objNum, content: bytesToLatin1(decompressedBytes) });
    }

    // Skip past endstream to avoid matching inside binary stream data
    pos = endstreamIdx + 9;
  }

  return results;
}

// ============================================================================
// ASCII RUN FALLBACK
// ============================================================================

/**
 * Extract printable ASCII runs from raw bytes.
 * Catches readable text when font-based extraction fails.
 */
function extractAsciiRuns(bytes: Uint8Array, minRunLength = 6): string {
  const chunks: string[] = [];
  let currentRun = '';

  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i];
    if (byte >= 0x20 && byte < 0x7f) {
      currentRun += String.fromCharCode(byte);
    } else {
      if (currentRun.length >= minRunLength) {
        chunks.push(currentRun);
      }
      currentRun = '';
    }
  }

  if (currentRun.length >= minRunLength) {
    chunks.push(currentRun);
  }

  return chunks.join(' ').replace(/\s+/g, ' ').trim();
}

// ============================================================================
// MAIN EXPORT
// ============================================================================

/**
 * Extract text from a PDF byte array.
 *
 * Platform-agnostic: caller provides an InflateFn for decompression.
 *
 * Pipeline:
 *   1. Decompress all stream/endstream pairs
 *   2. Build per-font registry (CMap + encoding info)
 *   3. Extract text with per-font tracking (sequential)
 *   4. Fall back to merged CMap extraction
 *   5. Fall back to ASCII run extraction
 *   6. Assess quality and return result
 *
 * @param bytes - Raw PDF file bytes
 * @param inflate - Platform-specific inflate function
 * @returns PdfExtractionResult with text, quality, and diagnostics
 */
export function extractPdfTextFromBytes(
  bytes: Uint8Array,
  inflate: InflateFn,
): PdfExtractionResult {
  // NOTE: extractPdfText is a convenience alias — see bottom of file
  const pdfRawText = bytesToLatin1(bytes);

  // Phase 1: Decompress all streams
  const streams = decompressAllStreams(bytes, pdfRawText, inflate);

  // Phase 2: Build object → content map
  const objToContent = new Map<number, string>();
  for (const { objNum, content } of streams) {
    objToContent.set(objNum, content);
  }

  // Phase 3: Build per-font registry
  const fontRegistry = buildFontRegistry(pdfRawText, objToContent);

  // Phase 4: Build merged CMap as fallback
  const mergedCmap = new Map<number, string>();
  for (const { content } of streams) {
    if (content.includes('beginbfchar') || content.includes('beginbfrange')) {
      const parsed = parseToUnicodeCMap(content);
      for (const [k, v] of parsed.cmap) mergedCmap.set(k, v);
    }
  }

  // Phase 5: Extract text from content streams
  const textParts: string[] = [];
  let btEtChars = 0;
  let extractionMethod: ExtractionDiagnostics['extractionMethod'] = 'none';

  for (const { content } of streams) {
    // Skip CMap streams themselves
    if (content.includes('beginbfchar') || content.includes('begincmap')) continue;

    let text = '';

    // Try sequential extraction with per-font registry first
    if (fontRegistry.size > 0) {
      text = extractTextSequential(content, fontRegistry);
      if (text.trim().length > 0 && extractionMethod === 'none') {
        extractionMethod = 'font-aware';
      }
    }

    // Fall back to multi-pass with merged CMap (runs even with empty CMap
    // to extract (literal) Tj text from standard-encoded fonts)
    if (text.trim().length === 0) {
      text = extractTextMultiPass(content, mergedCmap);
      if (text.trim().length > 0 && extractionMethod === 'none') {
        extractionMethod = mergedCmap.size > 0 ? 'merged-cmap' : 'literal-fallback';
      }
    }

    if (text.trim().length > 0) {
      textParts.push(text);
      btEtChars += text.length;
    }
  }

  // Phase 6: Combine text
  let finalText = '';
  let asciiChars = 0;

  if (textParts.length > 0) {
    finalText = textParts.join(' ').replace(/\s+/g, ' ').trim();
  }

  // Phase 7: ASCII fallback if BT/ET extraction yielded nothing
  if (finalText.length === 0) {
    finalText = extractAsciiRuns(bytes);
    asciiChars = finalText.length;
    if (finalText.length > 0) {
      extractionMethod = 'ascii-fallback';
    }
  }

  // Cap output
  finalText = finalText.slice(0, MAX_OUTPUT_CHARS);

  // Phase 8: Assess quality
  const quality = assessExtractionQuality(finalText);

  // Count font stats
  let fontsWithCmap = 0;
  let fontsWithEncoding = 0;
  for (const [, entry] of fontRegistry) {
    if (entry.cmap && entry.cmap.size > 0) fontsWithCmap++;
    if (entry.encoding && entry.encoding !== 'Other') fontsWithEncoding++;
  }

  const diagnostics: ExtractionDiagnostics = {
    streamsProcessed: streams.length,
    streamsInflated: streams.length, // All successfully decompressed streams are returned
    streamsFailed: 0, // We don't track failures in the current architecture
    btEtChars,
    asciiChars,
    nonPrintableRatio: quality.nonPrintableRatio,
    fontsFound: fontRegistry.size,
    fontsWithCmap,
    fontsWithEncoding,
    extractionMethod,
  };

  return {
    text: finalText,
    quality: quality.quality,
    diagnostics,
  };
}

/**
 * Convenience alias for extractPdfTextFromBytes.
 * Identical behavior and signature — provided for ergonomic imports.
 */
export const extractPdfText = extractPdfTextFromBytes;
