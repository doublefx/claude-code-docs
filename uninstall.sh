#!/bin/bash
set -euo pipefail

# Claude Code Documentation Mirror - Smart Uninstaller
# Dynamically finds and removes all installations

# Claude configuration directory (respects CLAUDE_CONFIG_DIR)
CLAUDE_DIR="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"

echo "Claude Code Documentation Mirror - Uninstaller"
echo "=============================================="
echo ""

# Check dependencies
if ! command -v jq &> /dev/null; then
    echo "❌ Error: jq is required but not installed"
    echo "Please install jq and try again"
    exit 1
fi

# Find all installations from configs
find_all_installations() {
    local paths=()
    
    # From command file
    if [[ -f "$CLAUDE_DIR"/commands/docs.md ]]; then
        while IFS= read -r line; do
            if [[ "$line" =~ Execute:.*claude-code-docs ]]; then
                local path=$(echo "$line" | grep -o '[^ "]*claude-code-docs[^ "]*' | head -1)
                path="${path/#\~/$HOME}"
                
                # Get directory part
                if [[ -d "$path" ]]; then
                    paths+=("$path")
                elif [[ -d "$(dirname "$path")" ]] && [[ "$(basename "$(dirname "$path")")" == "claude-code-docs" ]]; then
                    paths+=("$(dirname "$path")")
                fi
            fi
        done < "$CLAUDE_DIR"/commands/docs.md
    fi
    
    # From hooks
    if [[ -f "$CLAUDE_DIR"/settings.json ]]; then
        local hooks=$(jq -r '.hooks.PreToolUse[]?.hooks[]?.command // empty' "$CLAUDE_DIR"/settings.json 2>/dev/null)
        while IFS= read -r cmd; do
            if [[ "$cmd" =~ claude-code-docs ]]; then
                local found=$(echo "$cmd" | grep -o '[^ "]*claude-code-docs[^ "]*' || true)
                while IFS= read -r path; do
                    [[ -z "$path" ]] && continue
                    path="${path/#\~/$HOME}"
                    # Clean up path to get the claude-code-docs directory
                    if [[ "$path" =~ (.*/claude-code-docs)(/.*)?$ ]]; then
                        path="${BASH_REMATCH[1]}"
                    fi
                    [[ -d "$path" ]] && paths+=("$path")
                done <<< "$found"
            fi
        done <<< "$hooks"
    fi
    
    # Always check the default installation path
    if [[ -d "$HOME/.claude-code-docs" ]]; then
        paths+=("$HOME/.claude-code-docs")
    fi

    # Deduplicate - handle empty array case
    if [[ ${#paths[@]} -gt 0 ]]; then
        printf '%s\n' "${paths[@]}" | sort -u
    fi
}

# Main uninstall logic
installations=()
while IFS= read -r line; do
    installations+=("$line")
done < <(find_all_installations)

if [[ ${#installations[@]} -gt 0 ]]; then
    echo "Found installations at:"
    for path in "${installations[@]}"; do
        echo "  📁 $path"
    done
    echo ""
fi

echo "This will remove:"
echo "  • The /docs command from "$CLAUDE_DIR"/commands/docs.md"
echo "  • All claude-code-docs hooks from "$CLAUDE_DIR"/settings.json"
if [[ ${#installations[@]} -gt 0 ]]; then
    echo "  • Installation directories (if safe to remove)"
fi
echo ""

read -p "Continue? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelled."
    exit 0
fi

# Remove command file
if [[ -f "$CLAUDE_DIR"/commands/docs.md ]]; then
    rm -f "$CLAUDE_DIR"/commands/docs.md
    echo "✓ Removed /docs command"
fi

# Remove hooks
if [[ -f "$CLAUDE_DIR"/settings.json ]]; then
    cp "$CLAUDE_DIR"/settings.json "$CLAUDE_DIR"/settings.json.backup
    
    # Remove ALL hooks containing claude-code-docs (atomic writes via mktemp)
    tmp1=$(mktemp "$CLAUDE_DIR"/settings.json.XXXXXX)
    jq '.hooks.PreToolUse = [(.hooks.PreToolUse // [])[] | select(.hooks[0].command | contains("claude-code-docs") | not)]' "$CLAUDE_DIR"/settings.json > "$tmp1"

    # Clean up empty structures
    tmp2=$(mktemp "$CLAUDE_DIR"/settings.json.XXXXXX)
    jq 'if .hooks.PreToolUse == [] then .hooks |= if . == {PreToolUse: []} then {} else del(.PreToolUse) end else . end | if .hooks == {} then del(.hooks) else . end' "$tmp1" > "$tmp2"

    mv "$tmp2" "$CLAUDE_DIR"/settings.json
    rm -f "$tmp1"
    echo "✓ Removed hooks (backup: "$CLAUDE_DIR"/settings.json.backup)"
fi

# Remove directories
if [[ ${#installations[@]} -gt 0 ]]; then
    echo ""
    for path in "${installations[@]}"; do
        if [[ ! -d "$path" ]]; then
            continue
        fi
        
        if [[ -d "$path/.git" ]]; then
            # Save current directory
            current_dir=$(pwd)
            cd "$path"
            
            if [[ -z "$(git status --porcelain 2>/dev/null)" ]]; then
                cd "$current_dir"
                rm -rf "$path"
                echo "✓ Removed $path (clean git repo)"
            else
                cd "$current_dir"
                echo "⚠️  Preserved $path (has uncommitted changes)"
            fi
        else
            echo "⚠️  Preserved $path (not a git repo)"
        fi
    done
fi

echo ""
echo "✅ Uninstall complete!"
echo ""
echo "To reinstall:"
echo "curl -fsSL https://raw.githubusercontent.com/ericbuess/claude-code-docs/main/install.sh | bash"