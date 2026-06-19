export interface FileMetadata {
  name: string;
  size: number;
  type: string;
  lastModified: number;
}

export interface ExtractedMetadata {
  author?: string;
  creator?: string;
  producer?: string;
  creationDate?: string;
  modificationDate?: string;
  title?: string;
  subject?: string;
  keywords?: string[];
  customProperties?: Record<string, string>;
}

export interface PatternMatch {
  patternId: string;
  patternName: string;
  category: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  matchLocation: 'metadata' | 'content';
  matchedValue?: string; // Sanitized, never full content
  regulatoryBasis?: string;
  description: string;
}

export interface RiskAssessment {
  overallSeverity: 'low' | 'medium' | 'high' | 'critical';
  matches: PatternMatch[];
  recommendations: string[];
  regulatoryImplications: string[];
  shouldWarn: boolean;
  shouldBlock: boolean; // Only true if restricted mode + critical
}

export interface DetectionResult {
  fileMetadata: FileMetadata;
  extractedMetadata: ExtractedMetadata | null;
  riskAssessment: RiskAssessment;
  timestamp: string;
  processingTimeMs: number;
}