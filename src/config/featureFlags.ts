/**
 * Feature flags for Sprint N improvements.
 * AG-PROMPT-162: Build-time boolean flags.
 * All flags default ON per council decision.
 * To disable a feature, set the flag to false and rebuild.
 */

export const FF = {
  /** 5C: Self-referential confidentiality bypass */
  ff_confidential_self_bypass_v1: true,

  /** 8B: Extraction-limited notice copy improvement */
  ff_pdf_extraction_limited_copy_v1: true,

  /** 3A: policy_standard archetype */
  ff_archetype_policy_standard_v1: true,

  /** Area 1: clinical_reference archetype with PII guard */
  ff_archetype_clinical_reference_v1: true,

  /** 2A: Aggregate HR/finance severity cap */
  ff_hr_aggregate_cap_v1: true,
} as const;
