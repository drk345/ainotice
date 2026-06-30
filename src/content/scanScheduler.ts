/**
 * AgentGuard Scan Scheduler v1.0
 *
 * Non-blocking text scanning with back-pressure handling.
 * Uses requestIdleCallback + chunking for Firefox-safe main thread responsiveness.
 *
 * Features:
 * - Back-pressure: Only ONE active scan at a time (last-write-wins)
 * - Throttle/debounce: Coalesces rapid events (configurable window)
 * - Time-slicing: Yields to main thread between chunks
 * - Deterministic: Same results as synchronous scan
 * - Safe cancellation: Stale scans never update state
 *
 * Privacy: No content logging. Only counts/booleans/timings.
 *
 * RESERVED / DORMANT (AG-PROMPT-211): The async scan mechanics in this module
 * (scheduleTextScan, cancelPendingScans, getSchedulerStats, resetSchedulerStats,
 * generateRequestId) are NOT wired into the live pipeline. src/content/index.ts
 * imports ONLY getEffectiveHostname and isTopFrame from here; detection runs
 * synchronously via runDetection in the content script. Do NOT wire the async
 * scan API without an explicit AG-PROMPT that adds proving tests.
 * See docs/governance/AG-RESERVED-SURFACES.md.
 *
 * @see ADR-017: Non-blocking Scan Scheduler
 */

import type { RiskSignal, SignalSource } from './metadataExtractor';
import { deduplicateSignals } from './signalDedupe';
import { validatePaymentCard } from '../detection/paymentCardValidation';

// ============================================================================
// CONFIGURATION
// ============================================================================

/** Chunk size for text processing (bytes) */
const CHUNK_SIZE = 32 * 1024; // 32KB chunks

/**
 * Overlap between chunks to detect patterns at boundaries (chars)
 *
 * AG-PROMPT-4: Increased from 128 to 200 to handle:
 *   - Spaced extraction artifacts that span chunk boundaries
 *   - Hyphenated words split across chunks
 *   - Multi-word patterns (e.g., "date of birth: DD-MM-YYYY")
 *
 * 200 chars exceeds the longest observed spaced-text artifact in DATA2 corpus.
 */
const CHUNK_OVERLAP = 200;

/** Debounce window for rapid events (ms) */
const DEBOUNCE_MS = 200;

/**
 * Timeout for requestIdleCallback (ms)
 * Ensures scanning doesn't starve during heavy main-thread activity.
 * 100ms balances responsiveness vs starvation prevention.
 */
const IDLE_TIMEOUT_MS = 100;

/** Enable debug logging (counts/timings only) */
const DEBUG_SCHEDULER = false;

// ============================================================================
// TYPES
// ============================================================================

export type ScanSource = 'paste' | 'drop' | 'file' | 'submit';

export interface ScanMeta {
  source: ScanSource;
  requestId: string;
}

export interface ScanResult {
  signals: RiskSignal[];
  source: SignalSource;
  canceled: boolean;
  durationMs: number;
}

interface PendingScan {
  text: string;
  meta: ScanMeta;
  resolve: (result: ScanResult) => void;
  startTime: number;
}

// ============================================================================
// STATE
// ============================================================================

/** Current active scan token (for cancellation) */
let activeRequestId: string | null = null;

/** Pending scan waiting for debounce window */
let pendingScan: PendingScan | null = null;

/** Debounce timer */
let debounceTimer: ReturnType<typeof setTimeout> | null = null;

/** Stats for debugging */
let stats = {
  queued: 0,
  canceled: 0,
  completed: 0,
};

// ============================================================================
// REQUESTIDLECALLBACK POLYFILL
// ============================================================================

type IdleCallback = (deadline: { didTimeout: boolean; timeRemaining: () => number }) => void;

const requestIdleCallbackCompat: (cb: IdleCallback, opts?: { timeout: number }) => number =
  typeof requestIdleCallback !== 'undefined'
    ? requestIdleCallback
    : (cb: IdleCallback, opts?: { timeout: number }) => {
        const start = Date.now();
        // Use setTimeout directly (works in both browser and Node.js)
        return setTimeout(() => {
          cb({
            didTimeout: true,
            timeRemaining: () => Math.max(0, (opts?.timeout ?? 50) - (Date.now() - start)),
          });
        }, 1) as unknown as number;
      };

const cancelIdleCallbackCompat: (id: number) => void =
  typeof cancelIdleCallback !== 'undefined'
    ? cancelIdleCallback
    : (id: number) => clearTimeout(id);

// ============================================================================
// TEXT ANALYSIS (moved from index.ts for chunking)
// ============================================================================

/**
 * Pattern definitions for text content analysis
 * Each pattern has a canonical `id` for stable deduplication (AG-PROMPT-032)
 */
const TEXT_PATTERNS = [
  { id: 'pii.ssn', pattern: /\b\d{3}-\d{2}-\d{4}\b/, type: 'pii' as const, description: 'SSN pattern detected', severity: 'critical' as const, detail: 'File contains text matching Social Security Number format (XXX-XX-XXXX).' },
  { id: 'financial.payment_card', pattern: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/, type: 'financial' as const, description: 'Payment card pattern', severity: 'critical' as const, detail: 'File contains text matching credit/debit card number format.' },
  { id: 'secret.api_key', pattern: /\b(sk-|pk_|api[_-]?key|bearer\s+[a-z0-9]+)/i, type: 'confidential' as const, description: 'API key pattern', severity: 'critical' as const, detail: 'File appears to contain API keys or access tokens.' },
  { id: 'secret.aws_key', pattern: /AKIA[0-9A-Z]{16}/, type: 'confidential' as const, description: 'AWS access key', severity: 'critical' as const, detail: 'File contains an AWS access key ID pattern.' },
  { id: 'secret.password', pattern: /password\s*[:=]\s*\S+/i, type: 'confidential' as const, description: 'Password detected', severity: 'critical' as const, detail: 'File appears to contain a password.' },
  { id: 'marker.confidential', pattern: /\b(confidential|secret|classified|internal\s+only|restricted|proprietary)\b/i, type: 'confidential' as const, description: 'Confidentiality marker in text', severity: 'high' as const, detail: 'Document text contains confidentiality markers.' },
  { id: 'financial.banking', pattern: /\b(bank\s+account|routing\s+number|swift|iban|wire\s+transfer)\b/i, type: 'financial' as const, description: 'Banking information', severity: 'high' as const, detail: 'File contains banking or wire transfer details.' },
  { id: 'legal.contract', pattern: /\b(whereas|hereby|indemnify|liability|jurisdiction|arbitration|governing\s+law)\b/i, type: 'legal' as const, description: 'Legal language detected', severity: 'medium' as const, detail: 'File contains legal contract language.' },
  { id: 'confidential.m_and_a', pattern: /\b(acquisition|merger|due\s+diligence|letter\s+of\s+intent|term\s+sheet|valuation)\b/i, type: 'confidential' as const, description: 'M&A content detected', severity: 'critical' as const, detail: 'File contains merger/acquisition-related content.' },
  { id: 'pii.hr_data', pattern: /\b(salary|compensation|performance\s+review|termination|disciplinary)\b/i, type: 'pii' as const, description: 'HR/Employee data', severity: 'high' as const, detail: 'File contains HR or employee-related information.' },
];

/**
 * Email counting pattern (needs full text for accurate count)
 */
const EMAIL_PATTERN = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;

/**
 * Analyze a chunk of text for patterns
 *
 * AG-PROMPT-SIGNAL-VALIDATION-GATES-024: Payment card patterns are validated
 * through Luhn + issuer prefix + context gates before emitting signals.
 *
 * @param chunk - Text chunk to analyze
 * @param chunkOffset - Absolute offset of this chunk in the original text (for dedupe)
 * @returns Signals with canonical IDs and absolute offsets for stable deduplication
 */
function analyzeChunk(chunk: string, chunkOffset: number): RiskSignal[] {
  const signals: RiskSignal[] = [];

  for (const { id, pattern, type, description, severity, detail } of TEXT_PATTERNS) {
    // Use global regex to find ALL matches, not just the first
    const regex = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');
    let match: RegExpExecArray | null;

    // Find all matches in the chunk
    while ((match = regex.exec(chunk)) !== null) {
      // Calculate absolute offset in original text
      const absoluteOffset = chunkOffset + match.index;

      // AG-PROMPT-SIGNAL-VALIDATION-GATES-024: Payment card validation gates
      // For payment card patterns, validate through Luhn + issuer + context
      if (id === 'financial.payment_card') {
        const validationResult = validatePaymentCard(match[0], chunk, match.index);
        if (!validationResult.isValidCard) {
          // Validation failed - skip this match (not a real card number)
          if (match[0].length === 0) {
            regex.lastIndex++;
          }
          continue;
        }
      }

      signals.push({
        id,  // Canonical pattern ID for stable dedupe (AG-PROMPT-032)
        type,
        description,
        severity,
        detail,
        source: 'content',
        offset: absoluteOffset,
        match: match[0],
        detectedAt: Date.now(),
      });

      // Prevent infinite loop for zero-length matches
      if (match[0].length === 0) {
        regex.lastIndex++;
      }
    }
  }

  return signals;
}

/**
 * Count emails in text (requires full text for accurate count)
 */
function countEmails(text: string): number {
  return (text.match(EMAIL_PATTERN) || []).length;
}

// ============================================================================
// CHUNKED SCANNING
// ============================================================================

/** Chunk info with content and absolute offset */
interface ChunkInfo {
  content: string;
  offset: number;
}

/**
 * Split text into chunks for incremental processing
 *
 * Each chunk extends CHUNK_OVERLAP characters beyond its nominal end
 * to catch patterns that span chunk boundaries.
 *
 * Example with 10-char chunks and 3-char overlap:
 *   Text: "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
 *   Chunk 0: "ABCDEFGHIJKLM" (0-10 + 3 overlap), offset=0
 *   Chunk 1: "KLMNOPQRSTUVW" (10-20 + 3 overlap), offset=10
 *   Chunk 2: "UVWXYZ"        (20-26, final chunk), offset=20
 *
 * @returns Generator yielding ChunkInfo with content and absolute offset
 */
function* chunkText(text: string, chunkSize: number, overlap: number = CHUNK_OVERLAP): Generator<ChunkInfo> {
  for (let i = 0; i < text.length; i += chunkSize) {
    // Each chunk includes overlap beyond its end to catch boundary patterns
    yield {
      content: text.slice(i, i + chunkSize + overlap),
      offset: i,
    };
  }
}

/**
 * Process text in chunks using requestIdleCallback
 * Yields to main thread between chunks for responsiveness
 *
 * Deduplication uses absolute offsets to handle chunk overlap correctly.
 * @see signalDedupe.ts for overlap-safe deduplication logic
 */
async function scanTextChunked(
  text: string,
  requestId: string,
  source: SignalSource
): Promise<ScanResult> {
  const startTime = performance.now();
  const allSignals: RiskSignal[] = [];
  const chunks = Array.from(chunkText(text, CHUNK_SIZE));
  let chunksProcessed = 0;

  return new Promise((resolve) => {
    const processNextChunk = () => {
      // Check if this scan was canceled
      if (activeRequestId !== requestId) {
        if (DEBUG_SCHEDULER) {
          console.log(`[Ai Notice] ScanScheduler: scan ${requestId.slice(0, 8)} canceled mid-processing`);
        }
        resolve({
          signals: [],
          source,
          canceled: true,
          durationMs: performance.now() - startTime,
        });
        return;
      }

      // Process chunks in this idle period
      requestIdleCallbackCompat((deadline) => {
        while (chunksProcessed < chunks.length && (deadline.timeRemaining() > 2 || deadline.didTimeout)) {
          // Check cancellation before each chunk
          if (activeRequestId !== requestId) {
            resolve({
              signals: [],
              source,
              canceled: true,
              durationMs: performance.now() - startTime,
            });
            return;
          }

          // Get chunk with its absolute offset
          const chunkInfo = chunks[chunksProcessed];
          // Pass chunk offset for absolute position tracking (AG-PROMPT-031)
          const chunkSignals = analyzeChunk(chunkInfo.content, chunkInfo.offset);
          allSignals.push(...chunkSignals);
          chunksProcessed++;
        }

        if (chunksProcessed < chunks.length) {
          // More chunks to process - schedule next idle callback
          processNextChunk();
        } else {
          // All chunks processed - finalize
          // Count emails across full text (can't do this in chunks accurately)
          const emailCount = countEmails(text);
          if (emailCount > 5) {
            allSignals.push({
              id: 'pii.email_batch',  // Canonical ID for density-based signal (AG-PROMPT-032)
              type: 'pii',
              description: `${emailCount} email addresses`,
              severity: 'medium',
              detail: 'File contains multiple email addresses which may be personal data.',
              source,
              // No offset for density-based signals (not positional)
              detectedAt: Date.now(),
            });
          }

          // Overlap-safe deduplication using absolute offsets (AG-PROMPT-031)
          // Dedupe logic is in signalDedupe.ts, not here (scheduler stays dumb)
          const uniqueSignals = deduplicateSignals(allSignals);

          const durationMs = performance.now() - startTime;
          if (DEBUG_SCHEDULER) {
            console.log(`[Ai Notice] ScanScheduler: completed ${requestId.slice(0, 8)} chunks=${chunksProcessed} signals=${uniqueSignals.length} durationMs=${durationMs.toFixed(1)}`);
          }

          stats.completed++;
          resolve({
            signals: uniqueSignals,
            source,
            canceled: false,
            durationMs,
          });
        }
      }, { timeout: IDLE_TIMEOUT_MS });
    };

    processNextChunk();
  });
}

// ============================================================================
// PUBLIC API
// ============================================================================

/**
 * Generate a unique request ID
 */
export function generateRequestId(): string {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

/**
 * Schedule a text scan with back-pressure and debouncing
 *
 * - Only ONE active scan at a time (last-write-wins)
 * - Rapid events are debounced (coalesced)
 * - Uses requestIdleCallback + chunking for non-blocking
 *
 * @param text - Text content to scan
 * @param meta - Scan metadata (source, requestId)
 * @returns Promise<ScanResult> with signals or canceled=true
 */
export function scheduleTextScan(text: string, meta: ScanMeta): Promise<ScanResult> {
  return new Promise((resolve) => {
    const startTime = performance.now();

    // Cancel any pending debounced scan
    if (debounceTimer) {
      clearTimeout(debounceTimer);
      debounceTimer = null;
      if (pendingScan) {
        pendingScan.resolve({
          signals: [],
          source: 'content',
          canceled: true,
          durationMs: performance.now() - pendingScan.startTime,
        });
        stats.canceled++;
        if (DEBUG_SCHEDULER) {
          console.log(`[Ai Notice] ScanScheduler: debounce-canceled ${pendingScan.meta.requestId.slice(0, 8)}`);
        }
      }
    }

    // Cancel any active scan (last-write-wins)
    if (activeRequestId) {
      stats.canceled++;
      if (DEBUG_SCHEDULER) {
        console.log(`[Ai Notice] ScanScheduler: superseded ${activeRequestId.slice(0, 8)} with ${meta.requestId.slice(0, 8)}`);
      }
    }

    // Set up pending scan with debounce
    pendingScan = { text, meta, resolve, startTime };
    stats.queued++;

    debounceTimer = setTimeout(async () => {
      debounceTimer = null;
      const scan = pendingScan;
      pendingScan = null;

      if (!scan) return;

      // Mark this scan as active
      activeRequestId = scan.meta.requestId;

      if (DEBUG_SCHEDULER) {
        console.log(`[Ai Notice] ScanScheduler: starting ${scan.meta.requestId.slice(0, 8)} source=${scan.meta.source} length=${scan.text.length}`);
      }

      // Run chunked scan
      const result = await scanTextChunked(scan.text, scan.meta.requestId, 'content');

      // Only clear activeRequestId if this scan is still the active one
      if (activeRequestId === scan.meta.requestId) {
        activeRequestId = null;
      }

      scan.resolve(result);
    }, DEBOUNCE_MS);
  });
}

/**
 * Cancel all pending scans
 *
 * @param reason - Reason for cancellation (for logging)
 */
export function cancelPendingScans(reason: string): void {
  if (DEBUG_SCHEDULER) {
    console.log(`[Ai Notice] ScanScheduler: cancelAll reason="${reason}"`);
  }

  // Cancel debounced pending scan
  if (debounceTimer) {
    clearTimeout(debounceTimer);
    debounceTimer = null;
  }

  if (pendingScan) {
    pendingScan.resolve({
      signals: [],
      source: 'content',
      canceled: true,
      durationMs: performance.now() - pendingScan.startTime,
    });
    stats.canceled++;
    pendingScan = null;
  }

  // Mark active scan as canceled (it will check this and abort)
  if (activeRequestId) {
    stats.canceled++;
    activeRequestId = null;
  }
}

/**
 * Get scheduler stats (for debugging)
 */
export function getSchedulerStats(): { queued: number; canceled: number; completed: number } {
  return { ...stats };
}

/**
 * Reset scheduler stats (for testing)
 */
export function resetSchedulerStats(): void {
  stats = { queued: 0, canceled: 0, completed: 0 };
}

// ============================================================================
// FRAME UTILITIES
// ============================================================================

/**
 * Get the effective destination hostname for destination detection
 *
 * In iframes, window.location.hostname may be misleading.
 * Priority:
 * 1. window.top.location.hostname (if accessible)
 * 2. document.referrer hostname (if present)
 * 3. window.location.hostname (fallback)
 */
export function getEffectiveHostname(): string {
  // 1. Try top-level hostname
  try {
    if (window.top && window.top.location) {
      return window.top.location.hostname;
    }
  } catch {
    // Cross-origin - can't access window.top.location
  }

  // 2. Try document.referrer
  try {
    if (document.referrer) {
      const url = new URL(document.referrer);
      if (url.hostname) {
        return url.hostname;
      }
    }
  } catch {
    // Invalid referrer URL
  }

  // 3. Fallback to current frame
  return window.location.hostname;
}

/**
 * Check if we're in the top frame
 */
export function isTopFrame(): boolean {
  try {
    return window === window.top;
  } catch {
    // Cross-origin - we're definitely not top
    return false;
  }
}
