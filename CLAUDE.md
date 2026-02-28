# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

A community mirror of Claude Code documentation from https://docs.anthropic.com/en/docs/claude-code/ (now hosted at https://code.claude.com/docs/en/). Documentation is auto-fetched every 3 hours via GitHub Actions, plus the Claude Code changelog from https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md.

**Not affiliated with Anthropic.** This is an open-source tool by [ericbuess](https://github.com/ericbuess/claude-code-docs).

## Architecture

### Documentation Pipeline

```
Anthropic docs site (code.claude.com/docs/en/*.md)
    ↓ llms.txt discovery + markdown fetch
scripts/fetch_claude_docs.py (Python, runs in GitHub Actions)
    ↓ writes files + manifest
docs/*.md + docs/docs_manifest.json
    ↓ git commit + push (by bot)
GitHub repository (main branch)
    ↓ git pull (triggered by PreToolUse hook or /docs command)
~/.claude-code-docs/ (user's local installation)
    ↓ shell script reads files
claude-docs-helper.sh → Claude Code /docs command output
```

### Key Components

- **`scripts/fetch_claude_docs.py`** - Fetcher that discovers pages from llms.txt index, downloads markdown, validates content, tracks changes via SHA-256 hashes in manifest. Also fetches the changelog from the `anthropics/claude-code` repo and the docs map.
- **`scripts/claude-docs-helper.sh.template`** - Template for the helper script. Copied to `~/.claude-code-docs/claude-docs-helper.sh` during install. Handles `/docs` command routing, auto-update via git fetch/pull, freshness checks, topic search, and "what's new" display.
- **`install.sh`** - Installer/migrator. Clones to `~/.claude-code-docs`, creates `~/.claude/commands/docs.md` (slash command), adds a `PreToolUse` → `Read` hook to `~/.claude/settings.json` for auto-updates, migrates from older versions.
- **`uninstall.sh`** - Removes command, hooks, and installation directory.
- **`docs/docs_manifest.json`** - Git-tracked manifest mapping filenames to original URLs, content hashes, and timestamps. Used by the fetcher to detect changes and avoid unnecessary writes.

### GitHub Actions Workflows

- **`.github/workflows/update-docs.yml`** - Runs `fetch_claude_docs.py` every 3 hours (cron). Commits changed docs to `main`. Creates a GitHub issue on fetch failure.
- **`.github/workflows/release.yml`** - Creates a GitHub release when `scripts/claude-docs-helper.sh.template` changes (version extracted from `SCRIPT_VERSION=` line).

### User Installation Layout

After `install.sh` runs, the user has:
- `~/.claude-code-docs/` - Git clone of this repo
- `~/.claude-code-docs/claude-docs-helper.sh` - Copied from template, gitignored
- `~/.claude/commands/docs.md` - Slash command that calls the helper script
- `~/.claude/settings.json` - PreToolUse hook entry for auto-updates

## Important Details

- **Version** is defined in `scripts/claude-docs-helper.sh.template` as `SCRIPT_VERSION="0.3.3"`. This single value drives release tagging and is referenced by the installer and helper script.
- **`claude-docs-helper.sh` is gitignored** — it's generated from the template during install. Never edit it directly; edit the template instead.
- **The manifest (`docs/docs_manifest.json`) is git-tracked.** Never edit manually — the fetcher manages it.
- **Shell compatibility**: Scripts must work on both macOS (zsh default) and Linux (bash).
- **URL structure changed**: Anthropic moved docs from `docs.anthropic.com/en/docs/claude-code/` to `code.claude.com/docs/en/`. The fetcher handles both patterns.

## Serena Memories

Development commands, style conventions, and task completion checklists are maintained in Serena memories. Read these at session start:
- `suggested_commands` — how to run the fetcher, installer, helper, and uninstaller
- `style_and_conventions` — shell and Python coding patterns for this project
- `task_completion_checklist` — what to verify before considering work done

## For /docs Command

When responding to /docs commands:
1. Follow the instructions in the `~/.claude/commands/docs.md` command file
2. Read documentation files from the `docs/` directory only
3. Use the manifest (`docs/docs_manifest.json`) to know available topics and their source URLs
