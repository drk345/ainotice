/**
 * AG-PHASE-1-UNIFIED-PDF-EXTRACTION-SPINE: Browser inflate adapter.
 *
 * Pure-JavaScript DEFLATE decompression (RFC 1951) for use in Firefox
 * content script sandbox where Node.js zlib is not available.
 *
 * Ported from src/content/metadataExtractor.ts inflate implementation.
 *
 * AG-SECURITY-HARDENING-INPUT-01: Output size cap enforced during expansion
 * to prevent memory DoS attacks from malicious compressed streams.
 */

import type { InflateFn, InflateErrorContext } from './types';

// ============================================================================
// AG-SECURITY-HARDENING-INPUT-01: INFLATE OUTPUT CAP
// ============================================================================

/**
 * Maximum allowed decompressed output size in bytes.
 *
 * Rationale:
 * - PDF streams rarely exceed 10MB when decompressed
 * - Large decompression ratios (e.g., zip bombs) can cause memory DoS
 * - 50MB provides headroom for legitimate large documents
 * - Cap is enforced DURING expansion, not post-hoc, to prevent memory exhaustion
 *
 * @see ADR-026-inflate-output-caps.md
 */
export const MAX_INFLATE_OUTPUT_BYTES = 50 * 1024 * 1024; // 50MB

// ============================================================================
// ERROR CONTEXT TRACKING (AG-ERROR-DIAGNOSTICS-INFLATERAW-NO-SILENT-FAIL)
// ============================================================================

/**
 * Last inflate error context, if any.
 * Preserved deterministically when inflateRaw fails.
 * Contains ONLY safe diagnostic fields — no user content.
 */
let lastInflateError: InflateErrorContext | null = null;

/**
 * Get the last inflate error context (for diagnostics).
 * Returns null if last inflate succeeded or no inflate has been attempted.
 */
export function getLastInflateError(): InflateErrorContext | null {
  return lastInflateError;
}

/**
 * Clear the last inflate error context (for test isolation).
 */
export function clearLastInflateError(): void {
  lastInflateError = null;
}

// ============================================================================
// HUFFMAN TABLE BUILDER
// ============================================================================

function buildHuffmanTable(lengths: number[]): { codes: Int32Array; bits: number } {
  const maxLen = Math.max(...lengths);
  if (maxLen === 0) return { codes: new Int32Array(1).fill(-1), bits: 0 };
  const size = 1 << maxLen;
  const codes = new Int32Array(size);
  codes.fill(-1);

  let code = 0;
  for (let len = 1; len <= maxLen; len++) {
    for (let sym = 0; sym < lengths.length; sym++) {
      if (lengths[sym] === len) {
        let reversed = 0;
        let temp = code;
        for (let i = 0; i < len; i++) {
          reversed = (reversed << 1) | (temp & 1);
          temp >>= 1;
        }
        const step = 1 << len;
        for (let i = reversed; i < size; i += step) {
          codes[i] = (sym << 8) | len;
        }
        code++;
      }
    }
    code <<= 1;
  }

  return { codes, bits: maxLen };
}

// ============================================================================
// FIXED HUFFMAN TABLES
// ============================================================================

function getFixedLitLenTable(): { codes: Int32Array; bits: number } {
  const lengths = new Array(288);
  for (let i = 0; i <= 143; i++) lengths[i] = 8;
  for (let i = 144; i <= 255; i++) lengths[i] = 9;
  for (let i = 256; i <= 279; i++) lengths[i] = 7;
  for (let i = 280; i <= 287; i++) lengths[i] = 8;
  return buildHuffmanTable(lengths);
}

function getFixedDistTable(): { codes: Int32Array; bits: number } {
  const lengths = new Array(32).fill(5);
  return buildHuffmanTable(lengths);
}

// ============================================================================
// DEFLATE CONSTANTS
// ============================================================================

const LENGTH_EXTRA_BITS = [0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0];
const LENGTH_BASE = [3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258];
const DIST_EXTRA_BITS = [0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13];
const DIST_BASE = [1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577];
const CODE_LENGTH_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

// ============================================================================
// RAW DEFLATE DECOMPRESSION
// ============================================================================

/**
 * Capture error context from a caught exception.
 * Only extracts safe diagnostic fields — no user content.
 */
function captureExceptionContext(
  error: unknown,
  inputLength: number,
  mode: 'zlib-wrapped' | 'raw-deflate'
): InflateErrorContext {
  const ctx: InflateErrorContext = {
    failureMode: 'exception',
    errorType: 'Unknown',
    inputLength,
    attemptedMode: mode,
    timestamp: Date.now(),
  };

  if (error instanceof Error) {
    ctx.errorType = error.constructor.name;
    // Capture error code if present (Node.js style errors)
    if ('code' in error && typeof (error as { code?: unknown }).code === 'string') {
      ctx.errorCode = (error as { code: string }).code;
    }
  } else if (typeof error === 'string') {
    ctx.errorType = 'StringError';
  }

  return ctx;
}

/**
 * Capture error context for graceful-return failures.
 * These are non-exceptional failures where the code detects invalid data.
 */
function captureGracefulFailure(
  reason: string,
  inputLength: number,
  mode: 'zlib-wrapped' | 'raw-deflate'
): InflateErrorContext {
  return {
    failureMode: 'graceful-return',
    reason,
    inputLength,
    attemptedMode: mode,
    timestamp: Date.now(),
  };
}

function inflateRaw(data: Uint8Array, mode: 'zlib-wrapped' | 'raw-deflate' = 'raw-deflate'): Uint8Array | null {
  try {
    const output: number[] = [];
    let pos = 0;
    let bitBuf = 0;
    let bitCnt = 0;

    // AG-SECURITY-HARDENING-INPUT-01: Output size check helper
    const checkOutputLimit = (): boolean => {
      if (output.length > MAX_INFLATE_OUTPUT_BYTES) {
        lastInflateError = captureGracefulFailure(
          'output-size-exceeded',
          data.length,
          mode
        );
        return false;
      }
      return true;
    };

    const getBits = (n: number): number => {
      while (bitCnt < n) {
        if (pos >= data.length) return -1;
        bitBuf |= data[pos++] << bitCnt;
        bitCnt += 8;
      }
      const val = bitBuf & ((1 << n) - 1);
      bitBuf >>= n;
      bitCnt -= n;
      return val;
    };

    const decodeSymbol = (table: { codes: Int32Array; bits: number }): number => {
      while (bitCnt < table.bits) {
        if (pos >= data.length) {
          if (bitCnt === 0) return -1;
          break;
        }
        bitBuf |= data[pos++] << bitCnt;
        bitCnt += 8;
      }

      const lookup = bitBuf & ((1 << table.bits) - 1);
      const entry = table.codes[lookup];
      if (entry === -1) return -1;

      const sym = entry >> 8;
      const len = entry & 0xFF;
      bitBuf >>= len;
      bitCnt -= len;
      return sym;
    };

    let final = 0;
    while (!final) {
      final = getBits(1);
      const type = getBits(2);

      if (type === 0) {
        // Stored block
        bitBuf = 0;
        bitCnt = 0;
        const len = data[pos] | (data[pos + 1] << 8);
        pos += 4;
        for (let i = 0; i < len; i++) {
          output.push(data[pos++]);
          // AG-SECURITY-HARDENING-INPUT-01: Check limit during stored block copy
          if (i % 10000 === 0 && !checkOutputLimit()) return null;
        }
        if (!checkOutputLimit()) return null;
      } else if (type === 1 || type === 2) {
        let litLenTable: { codes: Int32Array; bits: number };
        let distTable: { codes: Int32Array; bits: number };

        if (type === 1) {
          litLenTable = getFixedLitLenTable();
          distTable = getFixedDistTable();
        } else {
          const hlit = getBits(5) + 257;
          const hdist = getBits(5) + 1;
          const hclen = getBits(4) + 4;

          const codeLenLengths = new Array(19).fill(0);
          for (let i = 0; i < hclen; i++) {
            codeLenLengths[CODE_LENGTH_ORDER[i]] = getBits(3);
          }
          const codeLenTable = buildHuffmanTable(codeLenLengths);

          const allLengths: number[] = [];
          while (allLengths.length < hlit + hdist) {
            const sym = decodeSymbol(codeLenTable);
            if (sym < 0) return null;

            if (sym < 16) {
              allLengths.push(sym);
            } else if (sym === 16) {
              const repeat = getBits(2) + 3;
              const last = allLengths[allLengths.length - 1] || 0;
              for (let i = 0; i < repeat; i++) allLengths.push(last);
            } else if (sym === 17) {
              const repeat = getBits(3) + 3;
              for (let i = 0; i < repeat; i++) allLengths.push(0);
            } else if (sym === 18) {
              const repeat = getBits(7) + 11;
              for (let i = 0; i < repeat; i++) allLengths.push(0);
            }
          }

          litLenTable = buildHuffmanTable(allLengths.slice(0, hlit));
          distTable = buildHuffmanTable(allLengths.slice(hlit, hlit + hdist));
        }

        let symbolCount = 0;
        while (true) {
          const sym = decodeSymbol(litLenTable);
          if (sym < 0) return null;

          if (sym < 256) {
            output.push(sym);
            // AG-SECURITY-HARDENING-INPUT-01: Periodic output limit check
            symbolCount++;
            if (symbolCount % 10000 === 0 && !checkOutputLimit()) return null;
          } else if (sym === 256) {
            break;
          } else {
            const lenIdx = sym - 257;
            const length = LENGTH_BASE[lenIdx] + getBits(LENGTH_EXTRA_BITS[lenIdx]);

            const distSym = decodeSymbol(distTable);
            if (distSym < 0) return null;
            const distance = DIST_BASE[distSym] + getBits(DIST_EXTRA_BITS[distSym]);

            const start = output.length - distance;
            for (let i = 0; i < length; i++) {
              output.push(output[start + i]);
            }
            // AG-SECURITY-HARDENING-INPUT-01: Check after back-reference copy
            if (!checkOutputLimit()) return null;
          }
        }
      } else {
        return null;
      }
    }

    // Final size check before returning
    if (!checkOutputLimit()) return null;

    // Success: clear any previous error context
    lastInflateError = null;
    return new Uint8Array(output);
  } catch (error) {
    // AG-ERROR-DIAGNOSTICS: Capture exception context deterministically
    lastInflateError = captureExceptionContext(error, data.length, mode);
    return null;
  }
}

// ============================================================================
// BROWSER INFLATE ADAPTER
// ============================================================================

/**
 * Browser inflate: handles both zlib-wrapped and raw DEFLATE data.
 * Uses pure JavaScript implementation (no native dependencies).
 *
 * AG-ERROR-DIAGNOSTICS: Error context is preserved deterministically
 * when decompression fails. Use getLastInflateError() to retrieve it.
 */
export const inflateBrowser: InflateFn = (data: Uint8Array): Uint8Array | null => {
  // Clear previous error context before attempting inflate
  lastInflateError = null;

  // Try with zlib header (skip first 2 bytes)
  if (data.length > 2 && (data[0] & 0x0F) === 8) {
    const result = inflateRaw(data.slice(2), 'zlib-wrapped');
    if (result && result.length > 0) return result;
    // Note: lastInflateError may have been set by inflateRaw if it threw
  }

  // Try raw deflate
  const result = inflateRaw(data, 'raw-deflate');
  if (result && result.length > 0) return result;

  // Both attempts failed — ensure error context is set if not already
  // (covers graceful-return failures where no exception was thrown)
  if (lastInflateError === null) {
    lastInflateError = captureGracefulFailure(
      'both-modes-failed',
      data.length,
      'raw-deflate'  // Last attempted mode
    );
  }

  return null;
};
