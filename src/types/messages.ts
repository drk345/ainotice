export type MessageType =
  | 'VALIDATE_LICENSE'
  | 'DETECT_RISK'
  | 'GET_SETTINGS'
  | 'UPDATE_SETTINGS';

export interface BaseMessage {
  type: MessageType;
  requestId?: string;
}

export interface ValidateLicenseMessage extends BaseMessage {
  type: 'VALIDATE_LICENSE';
}

/**
 * @deprecated AG-PROMPT-100: DO NOT USE - This message type is intentionally unused.
 * Detection MUST happen locally in the content script, NOT via background messaging.
 * Sending file content to background would violate the local-only processing invariant.
 * This type is preserved only for type system completeness and will be removed in future.
 */
export interface DetectRiskMessage extends BaseMessage {
  type: 'DETECT_RISK';
  payload: {
    fileData: ArrayBuffer;
    fileName: string;
    fileType: string;
  };
}

export interface GetSettingsMessage extends BaseMessage {
  type: 'GET_SETTINGS';
}

export interface UpdateSettingsMessage extends BaseMessage {
  type: 'UPDATE_SETTINGS';
  payload: Record<string, unknown>;
}

export type Message =
  | ValidateLicenseMessage
  | DetectRiskMessage
  | GetSettingsMessage
  | UpdateSettingsMessage;

export interface MessageResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
  requestId?: string;
}