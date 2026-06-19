# Contributing

This repository is **generated**, not developed.

Its contents are produced by an allow-list promotion export from the Ai Notice
development repository at a specific, recorded commit (see
`RELEASE_PROVENANCE.json`). It exists to prove exactly what was shipped.

## Rules

- **Do not develop here.** Do not author features, fixes, or experiments in this repo.
- **Fixes go upstream.** Report issues / propose changes in the development repo.
  After they are verified there, a new promotion regenerates this repository.
- **Do not hand-edit promoted files.** They will be overwritten on the next promotion.

## Verifying a release

```bash
npm ci
npx tsx scripts/release-verify.ts
```

All gate steps must pass before packaging or store upload.
