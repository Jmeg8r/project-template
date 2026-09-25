# Project Name

> Brief description of what this project does.

## Quick Start

```bash
# Install dependencies (if any)
npm install

# Run the project
npm start
```

## Ironclad Workflow

This project uses the **Ironclad Workflow** — a structured 4-phase development process:

```
PLAN -> EXECUTE -> VERIFY -> SHIP
```

### Starting New Work

1. **Create a plan:**
   ```bash
   mkdir -p .workflow/sessions/SESSION-$(date +%Y-%m-%d)-feature-name
   cp .workflow/templates/plan-template.md .workflow/sessions/SESSION-$(date +%Y-%m-%d)-feature-name/plan.md
   ```

2. **Get plan approval** before writing code

3. **Execute** the planned tasks

4. **Verify** with AI code review:
   ```bash
   npm run verify
   ```

5. **Ship** when verification passes:
   ```bash
   npm run ship:pr
   ```

### Workflow Commands

| Command | Description |
|---------|-------------|
| `npm run verify` | Full verification with AI review |
| `npm run verify:skip-ai` | Verify without AI review |
| `npm run ai-review` | Run AI review only |
| `npm run ai-review:diff` | Review git changes only |
| `npm run ship` | Validate integrity |
| `npm run ship:pr` | Validate and create PR |

### Environment Setup

Copy `.env.example` to `.env` and add your Gemini API key:

```bash
cp .env.example .env
# Edit .env and add your GEMINI_API_KEY
```

### Forge PR gate

On the Sovereign Forge, `.github/workflows/ai-review.yml` reviews every PR to `main`
through the review broker and posts a verdict comment as `forgejo-actions`.
`forge-pr merge` refuses a PR without that verdict at its current head. The job runs only
when the forge repo variable `AI_REVIEW_ENABLED` is `true` and the repo has a
`BROKER_TOKEN` secret. On GitHub it never runs, so a project generated from this template
on GitHub gets the file with the job switched off.

`bin/review-pr.sh` and `bin/blast-radius.py` are byte-identical copies of sovereign-forge's
`bin/`. Don't edit them here: fix them upstream and re-copy.

## Project Structure

```
.
├── src/                    # Source code
├── bin/                    # Forge review gate kit (vendored; don't edit)
├── scripts/                # Ironclad workflow scripts
├── .workflow/              # Workflow documents
│   ├── templates/          # Plan, session, PR templates
│   ├── checklists/         # Security and verification checklists
│   ├── sessions/           # Active session documents
│   └── state/              # Verification state files
├── .cursor/rules           # Cursor IDE workflow enforcement
├── CLAUDE.md               # AI assistant context
└── package.json
```

## License

MIT
