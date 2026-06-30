import nacl from 'tweetnacl';
import type {
  LicenseToken,
  LicenseValidationResult,
  LicenseStatus,
  LicenseReason,
  PublicKey
} from '@/types/license';

/**
 * AG-PROMPT-LICENSE-001: Offline-first license validation
 *
 * State machine:
 * - VALID: signature OK + not expired
 * - EXPIRED: signature OK + past expiry (Courtesy Mode - full functionality)
 * - INVALID: signature failed, missing, or error (fail closed)
 */

// Ed25519 public key (embedded in extension)
// AG-PROMPT-078: Production key set for v1.0.0 offline license validation.
// Hex: 7199819a876b6459a98b706810f518a13623d31b8474a58bf624cf50ae17594c
const PUBLIC_KEY: PublicKey = {
  key: new Uint8Array([
    113, 153, 129, 154, 135, 107, 100,  89,
    169, 139, 112, 104,  16, 245,  24, 161,
     54,  35, 211,  27, 132, 116, 165, 139,
    246,  36, 207,  80, 174,  23,  89,  76,
  ]),
  algorithm: 'ed25519'
};

// ============================================================================
// AG-SECURITY-HARDENING-CRYPTO-01: Placeholder Key Detection
// ============================================================================

/**
 * Detect if the public key is a placeholder (all zeros or all same byte).
 *
 * CRITICAL SECURITY INVARIANT:
 * - Placeholder keys MUST fail closed
 * - No signature should EVER validate against a placeholder key
 * - This is defense-in-depth against accidental deployment without real keys
 */
function isPlaceholderKey(key: Uint8Array): boolean {
  if (key.length !== 32) {
    // Invalid key length - treat as placeholder
    return true;
  }

  // Check if all bytes are the same (catches all-zeros, all-0xFF, etc.)
  const firstByte = key[0];
  const allSame = key.every(b => b === firstByte);

  if (allSame) {
    console.warn('[Ai Notice:CRYPTO-01] Placeholder public key detected - license validation will fail closed');
    return true;
  }

  return false;
}

/**
 * Cached result of placeholder key check.
 * Computed once at module load for performance.
 */
const IS_PLACEHOLDER_KEY = isPlaceholderKey(PUBLIC_KEY.key);

/**
 * Compute canonical license status from validation inputs.
 * Pure function for deterministic behavior.
 */
function computeLicenseStatus(
  tokenData: LicenseToken | undefined,
  signatureValid: boolean | null, // null = verification error
  signatureError: boolean,
  now: Date
): LicenseStatus {
  // Case 1: No license token
  if (!tokenData) {
    return {
      state: 'invalid',
      features: [],
      expiresAt: null,
      reason: 'no_license'
    };
  }

  // Case 2: Signature verification error
  if (signatureError) {
    return {
      state: 'invalid',
      features: [],
      expiresAt: tokenData.expiresAt,
      reason: 'signature_error'
    };
  }

  // Case 3: Invalid signature (tampered)
  if (!signatureValid) {
    return {
      state: 'invalid',
      features: [],
      expiresAt: tokenData.expiresAt,
      reason: 'signature_invalid'
    };
  }

  // Signature is valid - check expiration (use UTC for determinism)
  // License is expired when current time is at or past expiry time
  const expiresAt = new Date(tokenData.expiresAt);
  const isExpired = expiresAt.getTime() <= now.getTime();

  // Case 4: Expired but signature-valid (Courtesy Mode)
  if (isExpired) {
    return {
      state: 'expired',
      features: tokenData.features, // Keep features for Courtesy Mode
      expiresAt: tokenData.expiresAt,
      reason: 'expired'
    };
  }

  // Case 5: Valid license
  return {
    state: 'valid',
    features: tokenData.features,
    expiresAt: tokenData.expiresAt
  };
}

export async function validateLicense(): Promise<LicenseValidationResult> {
  const now = new Date();

  try {
    // Retrieve license token from storage
    const result = await chrome.storage.local.get('licenseToken');
    const tokenData = result.licenseToken as LicenseToken | undefined;

    if (!tokenData) {
      const status = computeLicenseStatus(tokenData, null, false, now);
      return {
        valid: false,
        expired: false,
        features: [],
        expiresAt: null,
        error: 'No license token found',
        status
      };
    }

    // Verify signature
    let isValidSignature = false;
    let signatureError = false;

    try {
      isValidSignature = verifySignature(tokenData);
    } catch {
      signatureError = true;
    }

    const status = computeLicenseStatus(tokenData, isValidSignature, signatureError, now);

    // Build backward-compatible result with new status
    if (status.state === 'invalid') {
      const errorMsg = status.reason === 'no_license'
        ? 'No license token found'
        : status.reason === 'signature_invalid'
          ? 'Invalid license signature'
          : 'License validation error';

      return {
        valid: false,
        expired: false,
        features: [],
        expiresAt: tokenData.expiresAt,
        error: errorMsg,
        status
      };
    }

    if (status.state === 'expired') {
      return {
        valid: false,
        expired: true,
        features: tokenData.features,
        expiresAt: tokenData.expiresAt,
        error: 'License expired',
        status
      };
    }

    // Valid license
    return {
      valid: true,
      expired: false,
      features: tokenData.features,
      expiresAt: tokenData.expiresAt,
      status
    };
  } catch (error) {
    // Unexpected validation error - treat as invalid
    const status: LicenseStatus = {
      state: 'invalid',
      features: [],
      expiresAt: null,
      reason: 'validation_error'
    };

    return {
      valid: false,
      expired: false,
      features: [],
      expiresAt: null,
      error: error instanceof Error ? error.message : 'Validation failed',
      status
    };
  }
}

function verifySignature(token: LicenseToken): boolean {
  // AG-SECURITY-HARDENING-CRYPTO-01: Fail closed if placeholder key
  if (IS_PLACEHOLDER_KEY) {
    console.warn('[Ai Notice:CRYPTO-01] Signature verification rejected: placeholder public key');
    return false;
  }

  try {
    // Create message to verify (everything except signature)
    const message = JSON.stringify({
      orgId: token.orgId,
      features: token.features,
      expiresAt: token.expiresAt,
      issuedAt: token.issuedAt
    });

    const messageBytes = new TextEncoder().encode(message);
    const signatureBytes = base64ToUint8Array(token.signature);

    // Verify Ed25519 signature
    return nacl.sign.detached.verify(
      messageBytes,
      signatureBytes,
      PUBLIC_KEY.key
    );
  } catch (error) {
    console.error('Signature verification error:', error);
    return false;
  }
}

function base64ToUint8Array(base64: string): Uint8Array {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

// ============================================================================
// AG-SECURITY-HARDENING-CRYPTO-01: Test Exports
// ============================================================================

/**
 * Test-only exports for verifying placeholder key detection.
 * DO NOT use in production code.
 */
export const _testExports = {
  /** Whether the current public key is a placeholder */
  isPlaceholderKey: IS_PLACEHOLDER_KEY,

  /** Pure function to check if a key is a placeholder (for testing) */
  checkIsPlaceholder: isPlaceholderKey,

  /** The current public key bytes (for inspection) */
  publicKeyBytes: PUBLIC_KEY.key,
};