import type { ExtractedMetadata } from '@/types/detection';

export class PDFParser {
  async extractMetadata(file: File): Promise<ExtractedMetadata | null> {
    try {
      const arrayBuffer = await file.arrayBuffer();
      const text = new TextDecoder('utf-8').decode(arrayBuffer);

      // Simple PDF metadata extraction (not using full WASM parser yet)
      // In production, use pdf.js or similar WASM-based parser
      
      const metadata: ExtractedMetadata = {};

      // Extract /Author
      const authorMatch = text.match(/\/Author\s*\(([^)]+)\)/);
      if (authorMatch) {
        metadata.author = authorMatch[1];
      }

      // Extract /Creator
      const creatorMatch = text.match(/\/Creator\s*\(([^)]+)\)/);
      if (creatorMatch) {
        metadata.creator = creatorMatch[1];
      }

      // Extract /Producer
      const producerMatch = text.match(/\/Producer\s*\(([^)]+)\)/);
      if (producerMatch) {
        metadata.producer = producerMatch[1];
      }

      // Extract /Title
      const titleMatch = text.match(/\/Title\s*\(([^)]+)\)/);
      if (titleMatch) {
        metadata.title = titleMatch[1];
      }

      // Extract /Subject
      const subjectMatch = text.match(/\/Subject\s*\(([^)]+)\)/);
      if (subjectMatch) {
        metadata.subject = subjectMatch[1];
      }

      return metadata;
    } catch (error) {
      console.error('PDF parsing error:', error);
      return null;
    }
  }
}