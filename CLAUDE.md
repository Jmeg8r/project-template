# Project: [PROJECT NAME]

[One or two sentences: what this project does and why it exists. Assume the reader
can see the filesystem — don't restate the tech stack or directory layout here.]

## Workflow

Follows the global **Ironclad Workflow** (`PLAN → EXECUTE → VERIFY → SHIP` — see
`~/.claude/CLAUDE.md`), including its human checkpoints: plan approval before coding,
verification approval before shipping, and a human-approved merge. Scaffold commands:

```bash
npm run verify        # tests, lint, `npm audit --audit-level=high`, then Gemini AI review
npm run ship:pr       # validate the saved verify results and create the PR
```

- **VERIFY requires tests and an AI code review to actually run.** A green `verify` alone
  doesn't prove it: the scaffold's `test`/`lint` scripts are placeholders that always pass,
  and the AI review is skipped (not failed) when `GEMINI_API_KEY` is unset. Replace the
  placeholders and set the key, or say plainly which check didn't run.
- **Run `verify` fresh before shipping.** `ship:pr` reuses the saved results, including the
  audit, and only warns when they're over 4 hours old.
- **Every PR carries the verification evidence.** `ship:pr` adds it automatically; a PR
  created by hand (e.g. without `gh`) must include it too.

## Gotchas

Spend this file's tokens here: non-obvious constraints, incident-derived rules,
conventions that differ from the language's defaults, and edge cases a fresh session
would miss. Genre examples: "types live in `src/types.ts` and nowhere else", "the
staging DB wipes nightly", and for UI work, the specific styles to avoid, by name
("no cream backgrounds, no pill buttons"), not "avoid a generic look". Delete this
explainer once real entries exist.

- [none yet]

## Pointers

Link deep material instead of inlining it — specs, ADRs, mockups, skills:

- [none yet — e.g. `docs/adr/`]

## Maintaining this file

- Keep it under 200 lines, because it loads into every session. Move file-type-specific
  rules to `.claude/rules/<topic>.md` with `paths:` frontmatter so they load only when
  matching files are touched.
- A rule that must fire at a fixed point (before every commit, after each edit) belongs
  in a hook, not here.
- Don't restate rules from the global `~/.claude/CLAUDE.md`. Two copies drift, and
  Claude may follow either one when they conflict.
- Write concrete, checkable rules. Skip generic "be careful / double-check / think
  hard" lines: current Claude models verify their own work, and those lines cause
  over-verification.
