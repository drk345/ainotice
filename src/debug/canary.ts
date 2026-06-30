/**
 * AgentGuard Canary Signal Detection (AG-PROMPT-044)
 *
 * Debug-only detection pattern that matches a specific canary token.
 * Used to verify the signal pipeline is working end-to-end.
 *
 * The canary:
 * - Only runs when debug mode is enabled
 * - Matches the literal token "DETECTION_CANARY_123"
 * - Produces a harmless signal type that cannot collide with real types
 * - Is clearly labeled for easy identification in logs/UI
 *
 * Usage:
 *   1. Enable debug mode: localStorage.setItem('agentguard.debug', 'true')
 *   2. Create a file containing "DETECTION_CANARY_123"
 *   3. Upload to an AI service
 *   4. Verify canary signal appears in boundary counters
 */

import type { RiskSignal } from '../types/riskSignal';
import {
  CANARY_TOKEN,
  CANARY_SIGNAL_TYPE,
  CANARY_SIGNAL_ID,
  shouldRunCanaryDetection,
  debugLog,
} from './diagnostics';

/**
 * Run canary detection on text content.
 *
 * Only executes when debug mode is enabled.
 * Returns an array of canary signals (usually 0 or 1).
 *
 * @param text - Text content to scan
 * @param source - Signal source ('content' | 'metadata' | 'filename')
 * @returns Array of canary RiskSignals (empty if canary not found or debug mode off)
 */
export function runCanaryDetection(
  text: string,
  source: RiskSignal['source'] = 'content'
): RiskSignal[] {
  // Only run in debug mode
  if (!shouldRunCanaryDetection()) {
    return [];
  }

  const signals: RiskSignal[] = [];

  // Simple literal match (no regex complexity)
  const index = text.indexOf(CANARY_TOKEN);

  if (index !== -1) {
    debugLog('Canary', `Canary token detected at offset=${index}`);

    signals.push({
      id: CANARY_SIGNAL_ID,
      type: CANARY_SIGNAL_TYPE as RiskSignal['type'],
      description: 'Debug canary signal detected',
      severity: 'low',  // Harmless severity
      detail: 'This is a debug-only signal for pipeline verification. It matched the literal token DETECTION_CANARY_123.',
      source,
      offset: index,
      match: CANARY_TOKEN,
      detectedAt: Date.now(),
    });
  }

  return signals;
}

/**
 * Create a test document containing the canary token.
 * Useful for generating test fixtures.
 *
 * @returns Text content containing the canary token with context
 */
export function createCanaryTestContent(): string {
  return `Ai Notice Pipeline Verification Document

This document is used to test that the signal detection pipeline is working.
It contains a debug-only canary token that should trigger a harmless signal.

Canary Token: ${CANARY_TOKEN}

If you see a "debug-canary" signal in the UI or logs, the pipeline is working.
If you do NOT see the signal, check:
1. Is debug mode enabled? (localStorage.setItem('agentguard.debug', 'true'))
2. Check boundary counters in console logs
3. See docs/DEBUGGING.md for troubleshooting

This document also contains some test patterns:
- Email: test@example.com (should trigger email detection if density threshold met)
- Phone: +1-555-123-4567 (may trigger depending on locale confidence)

End of test document.
`;
}
