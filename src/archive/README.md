# src/archive — Archived Source Files

Files moved here are no longer part of the active codebase. They are preserved
for historical reference.

## Contents

| File | Archived By | Reason |
|------|-------------|--------|
| `risk-dialog.tsx` | AG-PROMPT-143 | Dead code: never imported, never rendered. Live modal is `buildRiskModal` in `uiComponents.ts`. Documented as OD-06 in AG-PROMPT-139. |

## Context

`risk-dialog.tsx` was an early React-based risk dialog component. The product
moved to a safe-DOM approach (`buildRiskModal` in `src/content/uiComponents.ts`)
with decision-quality cards, focus traps, and friction mechanisms. The React
component was never wired into the extension and lacks all current UX features.
