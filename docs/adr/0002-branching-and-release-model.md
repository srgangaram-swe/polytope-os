# ADR 0002: Branching and sprint promotion model

- Status: Accepted
- Date: 2026-07-19

## Decision

Maintain `main`, `prod`, and `dev` as protected long-lived branches. Feature work begins at
`dev` and merges into it through review. Each completed sprint promotes `dev` to `prod`, then
validated `prod` to `main`. Work branches are deleted after merge.

This model is intentionally requested for project governance. Because three continuously
aligned branches add operational cost, their divergence and promotion latency will be measured
and the model revisited if it produces unsafe manual work or ambiguous release state.
