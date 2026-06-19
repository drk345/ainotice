import type { Message, MessageResponse, MessageType } from '@/types/messages';
import { validateLicense } from './license-validator';
import { StorageManager } from '@/core/storage/storage-manager';

const storageManager = new StorageManager();

// ============================================================================
// AG-SECURITY-HARDENING-SEC-02: MESSAGE HANDLER HARDENING
// ============================================================================

/**
 * Valid message types that the handler accepts.
 * Unknown types are rejected for defense-in-depth.
 */
const VALID_MESSAGE_TYPES: Set<MessageType> = new Set([
  'VALIDATE_LICENSE',
  'DETECT_RISK',
  'GET_SETTINGS',
  'UPDATE_SETTINGS',
]);

/**
 * Validate that a message sender is from this extension.
 *
 * Defense-in-depth: Chrome already isolates extension messaging,
 * but explicit validation guards against future API changes or bugs.
 *
 * @param sender - The message sender info from Chrome
 * @returns true if sender is valid, false otherwise
 */
function isValidSender(sender: chrome.runtime.MessageSender): boolean {
  // Sender must have an ID
  if (!sender.id) {
    console.warn('[AgentGuard:SEC-02] Rejected message: missing sender.id');
    return false;
  }

  // Sender ID must match our extension ID
  // chrome.runtime.id is the extension's own ID
  if (sender.id !== chrome.runtime.id) {
    console.warn('[AgentGuard:SEC-02] Rejected message: sender.id mismatch', {
      expected: chrome.runtime.id,
      received: sender.id,
    });
    return false;
  }

  return true;
}

/**
 * Validate message structure.
 * Ensures message has required fields and known type.
 */
function isValidMessage(message: unknown): message is Message {
  if (typeof message !== 'object' || message === null) {
    console.warn('[AgentGuard:SEC-02] Rejected message: not an object');
    return false;
  }

  const msg = message as Record<string, unknown>;

  // Must have a type field
  if (typeof msg.type !== 'string') {
    console.warn('[AgentGuard:SEC-02] Rejected message: missing type field');
    return false;
  }

  // Type must be known
  if (!VALID_MESSAGE_TYPES.has(msg.type as MessageType)) {
    console.warn('[AgentGuard:SEC-02] Rejected message: unknown type', msg.type);
    return false;
  }

  return true;
}

export async function handleMessage(
  message: unknown,
  sender: chrome.runtime.MessageSender
): Promise<MessageResponse> {
  // AG-SECURITY-HARDENING-SEC-02: Validate sender
  if (!isValidSender(sender)) {
    return {
      success: false,
      error: 'Invalid message sender',
    };
  }

  // AG-SECURITY-HARDENING-SEC-02: Validate message structure
  if (!isValidMessage(message)) {
    return {
      success: false,
      error: 'Invalid message format',
    };
  }

  const requestId = message.requestId;

  try {
    switch (message.type) {
      case 'VALIDATE_LICENSE': {
        const result = await validateLicense();
        return {
          success: true,
          data: result,
          requestId
        };
      }

      case 'DETECT_RISK': {
        // RESERVED / UNUSED (AG-PROMPT-211): No content-script code sends a
        // DETECT_RISK message. Detection runs in the content script via
        // runDetection (src/detection/packRegistry.ts). This case is retained
        // for message-protocol stability only. Do NOT route detection through
        // the background via DETECT_RISK without an explicit AG-PROMPT.
        // See docs/governance/AG-RESERVED-SURFACES.md.
        // Risk detection happens in content script (local-only)
        // Background just coordinates if needed
        return {
          success: true,
          data: { message: 'Detection handled in content script' },
          requestId
        };
      }

      case 'GET_SETTINGS': {
        const settings = await storageManager.getSettings();
        return {
          success: true,
          data: settings,
          requestId
        };
      }

      case 'UPDATE_SETTINGS': {
        await storageManager.updateSettings(message.payload);
        return {
          success: true,
          requestId
        };
      }

      default: {
        return {
          success: false,
          error: 'Unknown message type',
          requestId
        };
      }
    }
  } catch (error) {
    console.error('Message handler error:', error);
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
      requestId
    };
  }
}