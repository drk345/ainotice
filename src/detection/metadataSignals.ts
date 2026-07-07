/**
 * Metadata-derived risk-signal generation.
 *
 * AG-PROMPT-218: moved verbatim from src/content/metadataExtractor.ts to place
 * metadata detection behind a detection-owned boundary (AG-209 L-1 / AG-215).
 * This is a move-only refactor — signal IDs, severities, types, regexes, and
 * evidence semantics are byte-identical to the prior implementation. In
 * particular the evidence `producer` string is intentionally retained as
 * 'metadataExtractor.analyzeMetadataForRisks' so emitted evidence is unchanged.
 *
 * `DocumentMetadata` is imported type-only from the content extractor; that edge
 * is erased at compile time, so no runtime import cycle is introduced even though
 * metadataExtractor.ts re-exports this function for backward compatibility.
 */
import type { RiskSignal, EvidenceItem } from '../types/riskSignal';
import type { DocumentMetadata } from '../content/metadataExtractor';
import { AG_DEBUG_EVIDENCE, createEvidence } from './evidenceCapture';

export function analyzeMetadataForRisks(metadata: DocumentMetadata): RiskSignal[] {
  const signals: RiskSignal[] = [];

  // AG-PROMPT-379: `author`, `lastModifiedBy`, `creator`, and `producer` are
  // deliberately EXCLUDED from this keyword-matching blend. Root cause
  // (FIELD_BLIND_METADATA_CONFIDENTIAL, found during AG-378): these four
  // fields record WHO/WHAT TOOL touched the file — they are commonly
  // auto-filled by the authoring application (a person's OS username, or a
  // literal tool name like "Microsoft Word") and are not a place a document
  // author deliberately writes a content-classification label. Before this
  // fix, a keyword anywhere in any of these four fields (e.g. an unusual but
  // plausible Author value containing the word "Confidential") could trigger
  // ANY of the checks below at their full severity — including the
  // CRITICAL-severity meta.confidential and meta.ma_deal checks — with no
  // relation to the document's actual visible content or genuine classification.
  // Title/Subject/Company/Manager/Description/Category/Keywords remain in the
  // blend: these ARE fields a document author deliberately fills with
  // descriptive/classification information (e.g. a Title of "Confidential Q4
  // Finance Review" is a genuine, intentional classification signal), so they
  // stay eligible — matching this prompt's explicit "Title/Subject/Keywords
  // metadata may warn only if source-aware and justified" requirement.
  // `author`/`lastModifiedBy` retain their OWN dedicated, separately-gated
  // signal below (meta.author, AG-PROMPT-378) — this change does not affect that.
  const allText = [
    metadata.title,
    metadata.subject,
    metadata.company,
    metadata.manager,
    metadata.description,
    metadata.category,
    ...(metadata.keywords || []),
  ].filter(Boolean).join(' ');

  // AG-PROMPT-379: the previous unconditional `if (!allText) return signals;`
  // early-return was removed. It predates this prompt's change, but became a
  // real bug once author/lastModifiedBy left `allText`: a metadata object
  // with ONLY an author/lastModifiedBy value (no title/subject/etc.) now
  // produces an empty `allText`, and the early return would have skipped the
  // separate, unrelated meta.author name check further below before it ever
  // ran. Safe to remove outright: every check below either tests `allText`
  // with a regex (an empty string simply never matches — no behavior change
  // for genuinely empty metadata) or reads a specific field directly.

  // AG-PROMPT-031: Helper for metadata evidence capture
  function metaEvidence(regex: RegExp, signalId: string, field: string | null): EvidenceItem[] | undefined {
    if (!AG_DEBUG_EVIDENCE) return undefined;
    const execMatch = regex.exec(allText);
    if (execMatch) {
      const ev = createEvidence({
        signal_id: signalId,
        origin_path: 'metadata',
        producer: 'metadataExtractor.analyzeMetadataForRisks',
        rule_id: signalId,
        matched_text: execMatch[0],
        start_index: execMatch.index,
        end_index: execMatch.index + execMatch[0].length,
        full_text: allText,
        location: 'METADATA',
        field,
      });
      return ev ? [ev] : undefined;
    }
    return undefined;
  }

  const confidentialRegex = /confidential|secret|classified|internal.only|restricted/i;
  if (confidentialRegex.test(allText)) {
    signals.push({
      type: 'confidential',
      description: 'Confidentiality marker detected',
      severity: 'critical',
      detail: 'This document appears to be marked as confidential. Uploading to AI may violate data handling policies.',
      source: 'metadata',
      detectedAt: Date.now(),
      evidence: metaEvidence(new RegExp(confidentialRegex.source, 'i'), 'meta.confidential', null),
    });
  }

  if (metadata.company) {
    signals.push({
      type: 'sensitive',
      description: `Corporate document: ${metadata.company}`,
      severity: 'low',
      detail: 'Document metadata reveals company name. This may identify the source organization.',
      source: 'metadata',
      detectedAt: Date.now(),
      evidence: AG_DEBUG_EVIDENCE ? (() => {
        const ev = createEvidence({
          signal_id: 'meta.company',
          origin_path: 'metadata',
          producer: 'metadataExtractor.analyzeMetadataForRisks',
          rule_id: 'meta.company',
          matched_text: metadata.company!,
          start_index: null,
          end_index: null,
          full_text: null,
          location: 'METADATA',
          field: 'company',
        });
        return ev ? [ev] : undefined;
      })() : undefined,
    });
  }

  const deptRegex = /legal|finance|hr|human.resource|accounting|payroll/i;
  if (deptRegex.test(allText)) {
    signals.push({
      type: 'sensitive',
      description: 'Sensitive department document',
      severity: 'high',
      detail: 'Document appears to originate from Legal, Finance, or HR. These typically contain restricted information.',
      source: 'metadata',
      detectedAt: Date.now(),
      evidence: metaEvidence(new RegExp(deptRegex.source, 'i'), 'meta.department', null),
    });
  }

  const maRegex = /merger|acquisition|deal|transaction|due.diligence|valuation|target/i;
  if (maRegex.test(allText)) {
    signals.push({
      type: 'confidential',
      description: 'M&A/Deal information',
      severity: 'critical',
      detail: 'Document may contain merger, acquisition, or deal-related information which is typically material non-public information.',
      source: 'metadata',
      detectedAt: Date.now(),
      evidence: metaEvidence(new RegExp(maRegex.source, 'i'), 'meta.ma_deal', null),
    });
  }

  const hrRegex = /employee|personnel|performance|salary|compensation|benefits/i;
  if (hrRegex.test(allText)) {
    signals.push({
      type: 'pii',
      description: 'Employee/HR data',
      severity: 'high',
      detail: 'Document may contain personal employee information protected under privacy regulations (GDPR, etc.).',
      source: 'metadata',
      detectedAt: Date.now(),
      evidence: metaEvidence(new RegExp(hrRegex.source, 'i'), 'meta.hr_employee', null),
    });
  }

  const legalRegex = /contract|agreement|nda|non.disclosure|terms|license/i;
  if (legalRegex.test(allText)) {
    signals.push({
      type: 'legal',
      description: 'Legal agreement',
      severity: 'high',
      detail: 'Document appears to be a legal agreement. These often contain confidential terms and obligations.',
      source: 'metadata',
      detectedAt: Date.now(),
      evidence: metaEvidence(new RegExp(legalRegex.source, 'i'), 'meta.legal', null),
    });
  }

  const financialRegex = /budget|forecast|revenue|profit|loss|financial|quarterly|annual.report/i;
  if (financialRegex.test(allText)) {
    signals.push({
      type: 'financial',
      description: 'Financial information',
      severity: 'high',
      detail: 'Document contains financial data which may be restricted or material non-public information.',
      source: 'metadata',
      detectedAt: Date.now(),
      evidence: metaEvidence(new RegExp(financialRegex.source, 'i'), 'meta.financial', null),
    });
  }

  const ipRegex = /patent|invention|trademark|copyright|proprietary|trade.secret/i;
  if (ipRegex.test(allText)) {
    signals.push({
      type: 'ip',
      description: 'Intellectual property',
      severity: 'critical',
      detail: 'Document may contain IP, patents, or trade secrets. Sharing externally could harm competitive position.',
      source: 'metadata',
      detectedAt: Date.now(),
      evidence: metaEvidence(new RegExp(ipRegex.source, 'i'), 'meta.ip', null),
    });
  }

  if (metadata.author || metadata.lastModifiedBy) {
    // AG-PROMPT-SIGNAL-PARITY-029: Filter out placeholder/anonymous author values
    // that carry no real PII and just add noise to signals.
    const ANONYMOUS_AUTHORS = new Set([
      'anonymous', 'unknown', 'user', 'admin', 'administrator',
      'author', 'default', 'owner', 'test', 'system',
    ]);
    // AG-PROMPT-378: the blocklist above only excluded a handful of literal
    // placeholder strings — any other value (a bare 2-letter abbreviation, a
    // software/tool name auto-filled by the authoring application) still
    // produced a "personal name" PII signal. Root cause: AUTHOR_ABBREVIATION_
    // FALSE_POSITIVE. Extended with two additional, low-risk checks:
    //  1. Require 2+ whitespace-separated tokens — rejects bare initials/
    //     abbreviations ("AC", "OR") that carry no real name-like structure,
    //     while still accepting "J. Smith" (2 tokens) and normal full names.
    //  2. Reject known, commonly auto-filled document-tool names — these are
    //     not personal names and were previously flagged as if they were.
    const KNOWN_TOOL_AUTHORS = new Set([
      'microsoft word', 'microsoft office', 'adobe acrobat', 'adobe indesign',
      'adobe photoshop', 'libreoffice', 'openoffice', 'apache openoffice',
      'google docs', 'pages', 'pdfcreator', 'pdf24', 'wkhtmltopdf', 'latex',
      'canva', 'wps office', 'foxit', 'nitro pdf',
    ]);
    function looksLikePersonalName(value: string): boolean {
      const trimmed = value.trim();
      const lower = trimmed.toLowerCase();
      if (ANONYMOUS_AUTHORS.has(lower)) return false;
      if (KNOWN_TOOL_AUTHORS.has(lower)) return false;
      const tokens = trimmed.split(/\s+/).filter(Boolean);
      return tokens.length >= 2;
    }
    const names = [metadata.author, metadata.lastModifiedBy]
      .filter(Boolean)
      .filter(name => looksLikePersonalName(name!));
    if (names.length > 0) {
      signals.push({
        type: 'pii',
        description: `Author: ${names.join(', ')}`,
        severity: 'low',
        detail: 'Document metadata contains personal names which will be shared with the AI service.',
        source: 'metadata',
        detectedAt: Date.now(),
        evidence: AG_DEBUG_EVIDENCE ? (() => {
          const ev = createEvidence({
            signal_id: 'meta.author',
            origin_path: 'metadata',
            producer: 'metadataExtractor.analyzeMetadataForRisks',
            rule_id: 'meta.author',
            matched_text: names.join(', '),
            start_index: null,
            end_index: null,
            full_text: null,
            location: 'METADATA',
            field: 'author',
          });
          return ev ? [ev] : undefined;
        })() : undefined,
      });
    }
  }

  return signals;
}
