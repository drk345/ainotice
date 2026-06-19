export type PdfEncryptionReadability =
  | 'NOT_ENCRYPTED'
  | 'ENCRYPTED_READABLE_NO_PROMPT'
  | 'ENCRYPTED_READABLE_BLANK_PASSWORD'
  | 'ENCRYPTED_PASSWORD_REQUIRED';

export function isEncryptedReadableState(state: PdfEncryptionReadability | undefined): boolean {
  return state === 'ENCRYPTED_READABLE_NO_PROMPT' || state === 'ENCRYPTED_READABLE_BLANK_PASSWORD';
}
