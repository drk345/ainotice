import type { Settings } from './settings';
import { DEFAULT_SETTINGS } from './settings';

export class StorageManager {
  async getSettings(): Promise<Settings> {
    try {
      const result = await chrome.storage.local.get('settings');
      return result.settings || DEFAULT_SETTINGS;
    } catch (e) {
      console.warn('[AgentGuard] storage.get(settings) failed:', (e as Error).message);
      return DEFAULT_SETTINGS;
    }
  }

  async updateSettings(updates: Partial<Settings>): Promise<void> {
    try {
      const currentSettings = await this.getSettings();
      const newSettings = { ...currentSettings, ...updates };
      await chrome.storage.local.set({ settings: newSettings });
    } catch (e) {
      console.warn('[AgentGuard] storage.set(settings) failed:', (e as Error).message);
    }
  }

  async getLicenseToken() {
    try {
      const result = await chrome.storage.local.get('licenseToken');
      return result.licenseToken;
    } catch (e) {
      console.warn('[AgentGuard] storage.get(licenseToken) failed:', (e as Error).message);
      return undefined;
    }
  }

  async setLicenseToken(token: unknown): Promise<void> {
    try {
      await chrome.storage.local.set({ licenseToken: token });
    } catch (e) {
      console.warn('[AgentGuard] storage.set(licenseToken) failed:', (e as Error).message);
    }
  }
}
