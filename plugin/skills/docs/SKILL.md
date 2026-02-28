---
name: docs
description: Search and browse Claude Code documentation offline. Use /magic-claude-docs:docs <topic> to read a specific doc, or just /magic-claude-docs:docs to list all topics.
---

# Claude Code Documentation

Community mirror of Claude Code documentation from https://code.claude.com/docs/en/

**Not affiliated with Anthropic.**

## Instructions

Parse `$ARGUMENTS` to determine what the user wants:

### No arguments (empty or whitespace)
List all available documentation topics. Read the manifest file at `~/.claude-code-docs/docs_manifest.json`. Extract all filenames from the `files` object, strip the `.md` extension, sort alphabetically, and present as a bulleted list grouped by category where possible.

Also mention:
- Use `/magic-claude-docs:docs <topic>` to read a specific document
- Use `/magic-claude-docs:docs what's new` to see recent changes

### "what's new" or "whats new" or "recent" or "changes"
Read the file `~/.claude-code-docs/recent_changes.md` and display its contents.

If the file does not exist, inform the user that change tracking is not yet available and suggest checking the GitHub repository at https://github.com/doublefx/claude-code-docs/commits/main/plugin/docs.

### Specific topic (e.g., "hooks", "mcp", "setup")
1. Strip `.md` extension if present
2. Look for `~/.claude-code-docs/<topic>.md`
3. If found: Read and display the full content. Append the official source link from the manifest's `original_url` field.
4. If not found: Search for partial matches among all filenames in the manifest. Present matching topics as suggestions. If no matches, list all available topics.

### Search query (multi-word or question-like input)
Extract keywords (strip common stop words: "tell", "me", "about", "explain", "what", "is", "how", "do", "to", "show", "the", "for", "in", "are"). Search filenames and manifest titles for matches. Present matching topics with their titles from the manifest.

## File Locations

All documentation files are at `~/.claude-code-docs/`. This directory is populated by a SessionStart hook that syncs docs from the plugin cache. Use the Read tool with the user's actual home directory path (e.g., `/home/<user>/.claude-code-docs/<filename>.md`). Expand `~` to the real home directory path.

The manifest at `~/.claude-code-docs/docs_manifest.json` contains:
- `files` object: keys are filenames, values have `original_url`, `title`, `hash`, `last_updated`
- `fetch_metadata`: `last_fetch_completed`, `total_files`, etc.

## Response Format

Always start responses with:
```
COMMUNITY MIRROR: https://github.com/doublefx/claude-code-docs
OFFICIAL DOCS: https://code.claude.com/docs/en/
```

When displaying a document, append:
```
Source: <original_url from manifest>
```
