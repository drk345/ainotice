import type { Pattern } from '@/types/policy';

export interface Settings {
  enabledPacks: string[];
  restrictedMode: boolean;
  customPatterns: Pattern[];
  globalExemptions: string[];
}

export const DEFAULT_SETTINGS: Settings = {
  enabledPacks: [],
  restrictedMode: false,
  customPatterns: [],
  globalExemptions: ['txt', 'jpg', 'png', 'gif']
};