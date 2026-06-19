/**
 * AG-PROMPT-LICENSE-001: Offline-first licensing types
 *
 * License State Machine:
 * - VALID: signature verified, not expired → normal operation, no banner
 * - EXPIRED: signature verified, past expiry → Courtesy Mode (full function + banner)
 * - INVALID: signature failed, tampered, or missing → fail closed with integrity message
 */

/** Canonical license states */
export type LicenseState = 'valid' | 'expired' | 'invalid';

/** Raw license token stored in chrome.storage.local */
export interface LicenseToken {
  orgId: string;
  features: string[]; // e.g., ['legal', 'finance', 'hr']
  expiresAt: string; // ISO 8601 (UTC)
  issuedAt: string; // ISO 8601 (UTC)
  signature: string; // Ed25519 signature (base64)
}

/**
 * Canonical license status used throughout the application.
 *
 * - `state`: The computed state (valid/expired/invalid)
 * - `features`: Licensed features (populated even when expired for Courtesy Mode)
 * - `expiresAt`: Expiry timestamp (for admin/debug only, NEVER shown to end users)
 * - `reason`: Machine-readable reason code for invalid/expired states
 *
 * Note: expiresAt is intentionally kept for internal decisions and admin tooling,
 * but MUST NOT be displayed to end users or used for countdown UI.
 */
export interface LicenseStatus {
  state: LicenseState;
  features: string[];
  expiresAt: string | null;
  reason?: LicenseReason;
}

/** Machine-readable reasons for license state */
export type LicenseReason =
  | 'no_license'        // No license token found
  | 'signature_invalid' // Signature verification failed (tampered)
  | 'signature_error'   // Error during signature verification
  | 'placeholder_key'   // AG-SECURITY-HARDENING-CRYPTO-01: Placeholder public key detected
  | 'expired'           // License past expiry date
  | 'validation_error'; // Unexpected error during validation

/**
 * @deprecated Use LicenseStatus instead.
 * Kept for backward compatibility during migration.
 */
export interface LicenseValidationResult {
  valid: boolean;
  expired: boolean;
  features: string[];
  expiresAt: string | null;
  error?: string;
  /** New canonical status (prefer this over valid/expired booleans) */
  status?: LicenseStatus;
}

export interface PublicKey {
  key: Uint8Array;
  algorithm: 'ed25519';
}