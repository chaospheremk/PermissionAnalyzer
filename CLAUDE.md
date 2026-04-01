# Code Session — `Permission Analyzer`

## Context

This is the code repository for the `Permission Analyzer` vault project.
Vault memory files are one level up in the parent directory:

- ../bugs.md        — known issues and solutions; check before debugging
- ../decisions.md   — decisions made; check before proposing changes
- ../key-facts.md   — project configuration reference
- ../issues.md      — work log

The vault session that manages planning and note-taking runs from the
vault root. This code session runs from this directory only.

## On Startup

1. Read ../decisions.md
2. Read ../bugs.md
3. Read ../key-facts.md
4. Run `git status` to check for uncommitted vault-session changes

## Memory Protocols

**During the session, watch for:**

- Configuration patterns, parameter conventions, or environment facts worth keeping as reference — prompt to add to ../key-facts.md
- Learnings that are broadly reusable beyond this project — flag them so the vault session can promote them to resource notes
- Decisions being made conversationally that haven't been logged — prompt to add to ../decisions.md before the session ends

Before proposing a technical approach: read ../decisions.md
Before debugging: read ../bugs.md
After fixing a bug: append to ../bugs.md using the standard format
After making a technical decision: append to ../decisions.md as an ADR
After completing a work block: append to ../issues.md
If an entry represents broadly reusable knowledge: add `<!-- promote-candidate -->` so vault:promote finds it

## Memory Boundaries

Vault memory files (../bugs.md, ../decisions.md, ../key-facts.md, ../issues.md):
- Decisions, bugs, key facts, work log entries
- Anything the vault session or future sessions need
- Anything that might be promoted to a resource note

Serena memories (.serena/memories/):
- Code structure discovered via onboarding (module layout, public API surface)
- Build/test commands and environment setup notes
- Session continuity ("in progress" context for multi-session work)
- Code-session-only — the vault session never reads these

## Serena Tools

- Before modifying a public function signature: use `find_referencing_symbols` to identify all callers
- For cross-file renames: use `rename_symbol` instead of manual find-and-replace
- For single-function edits: prefer `replace_symbol_body` over full-file Edit
- For adding adjacent functions: use `insert_after_symbol` or `insert_before_symbol`
- Fallback: if Serena cannot find the symbol (syntax errors, unparseable file), use Edit
- Before writing code after a research phase: use `think_about_collected_information`
- During multi-step implementations: use `think_about_task_adherence` after each step
- Before reporting completion: use `think_about_whether_you_are_done`

## Session Handoff

Before ending a code session:
1. Ensure all bug fixes are logged in ../bugs.md
2. Ensure all decisions are logged in ../decisions.md
3. Ensure work completed is logged in ../issues.md
4. Report a one-paragraph summary of what changed

## Rules

- No real IDs, hostnames, credentials, or org-identifying content — ever
- All parameters use placeholders: `<tenant-id>` `<subscription-id>` etc.
- Never modify files outside this code/ folder except the four memory files
  (../bugs.md, ../decisions.md, ../key-facts.md, ../issues.md)
- The `powershell-standards` and `graph-api-powershell` skills trigger
  automatically when writing relevant code — no manual reads needed
- Read `../../../_meta/security.md` for full sanitization rules when needed

## GitHub

This folder is its own git repository.
Push directly to this project's GitHub remote.
Do not use the vault's 50-Outputs/ for this project's code.
Dev branch + PR workflow — never commit directly to main.
Pre-commit hooks must be installed: `pip install pre-commit && pre-commit install`
