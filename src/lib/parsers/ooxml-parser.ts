import type { ExtractedMetadata } from '@/types/detection';

export class OOXMLParser {
  async extractMetadata(file: File): Promise<ExtractedMetadata | null> {
    try {
      // OOXML files are ZIP archives
      // In production, use JSZip or similar to extract core.xml, app.xml
      
      // Simplified extraction for now
      const arrayBuffer = await file.arrayBuffer();
      const text = new TextDecoder('utf-8').decode(arrayBuffer);

      const metadata: ExtractedMetadata = {};

      // Extract creator (common in core.xml)
      const creatorMatch = text.match(/<dc:creator>([^<]+)<\/dc:creator>/);
      if (creatorMatch) {
        metadata.creator = creatorMatch[1];
      }

      // Extract lastModifiedBy
      const modifiedByMatch = text.match(/<cp:lastModifiedBy>([^<]+)<\/cp:lastModifiedBy>/);
      if (modifiedByMatch) {
        metadata.author = modifiedByMatch[1];
      }

      // Extract title
      const titleMatch = text.match(/<dc:title>([^<]+)<\/dc:title>/);
      if (titleMatch) {
        metadata.title = titleMatch[1];
      }

      // Extract subject
      const subjectMatch = text.match(/<dc:subject>([^<]+)<\/dc:subject>/);
      if (subjectMatch) {
        metadata.subject = subjectMatch[1];
      }

      return metadata;
    } catch (error) {
      console.error('OOXML parsing error:', error);
      return null;
    }
  }
}