export interface Pattern {
  id: string;
  name: string;
  description: string;
  category: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  regulatoryBasis?: string;
  type: 'regex' | 'keyword' | 'metadata' | 'ml';
  config: {
    regex?: string;
    keywords?: string[];
    metadataFields?: string[];
    caseSensitive?: boolean;
    wholeWord?: boolean;
  };
  enabled: boolean;
}

export interface PatternPack {
  id: string;
  name: string;
  description: string;
  version: string;
  domain: 'legal' | 'finance' | 'hr' | 'ma' | 'engineering' | 'sales';
  patterns: Pattern[];
  requiredLicenseFeature: string;
  lastUpdated: string;
}

export interface PolicyConfig {
  enabledPacks: string[];
  restrictedMode: boolean; // Block on critical, not just warn
  customPatterns: Pattern[];
  globalExemptions: string[]; // File extensions to always allow
}