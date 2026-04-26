#!/usr/bin/env bash
# check-doc-links.sh — validate relative Markdown links under a docs tree
# Usage: bash bin/check-doc-links.sh [DIR]   (default: docs/)
set -euo pipefail

SCAN_DIR="${1:-docs}"
[[ "$SCAN_DIR" != /* ]] && SCAN_DIR="$(pwd)/$SCAN_DIR"

failures=0
link_count=0
file_count=0

# Resolve a path relative to base_dir; fails if the parent directory is absent.
resolve_path() {
    local base="$1" rel="$2"
    local parent file abs_parent
    file="$(basename "$rel")"
    parent="$(dirname "$rel")"
    abs_parent="$(cd "$base" && cd "$parent" 2>/dev/null && pwd)" || return 1
    printf '%s/%s' "$abs_parent" "$file"
}

check_link() {
    local src_file="$1" src_line="$2" raw="$3"
    local path fragment target

    if [[ "$raw" == *#* ]]; then
        path="${raw%%#*}"
        fragment="${raw#*#}"
    else
        path="$raw"
        fragment=""
    fi

    if ! target="$(resolve_path "$(dirname "$src_file")" "$path")"; then
        printf '%s:%s: link to %s is broken (directory not found)\n' "$src_file" "$src_line" "$raw"
        return 1
    fi

    if [[ ! -e "$target" ]]; then
        printf '%s:%s: link to %s is broken (file not found)\n' "$src_file" "$src_line" "$raw"
        return 1
    fi

    # Validate #Lstart-Lend line-range fragments against actual file length.
    if [[ "$fragment" =~ ^L([0-9]+)-L([0-9]+)$ ]]; then
        local end="${BASH_REMATCH[2]}"
        local lines
        lines="$(wc -l < "$target" | tr -d ' ')"
        if [ "$lines" -lt "$end" ]; then
            printf '%s:%s: link to %s is broken (file has %s lines, range ends at L%s)\n' \
                "$src_file" "$src_line" "$raw" "$lines" "$end"
            return 1
        fi
    fi
    return 0
}

while IFS= read -r md_file; do
    file_count=$((file_count + 1))
    line_num=0
    while IFS= read -r line; do
        line_num=$((line_num + 1))

        # Inline links: [text](target)
        while IFS= read -r raw; do
            [[ -z "$raw" ]] && continue
            [[ "$raw" == http://* || "$raw" == https://* || "$raw" == mailto:* || "$raw" == \#* ]] && continue
            link_count=$((link_count + 1))
            if ! check_link "$md_file" "$line_num" "$raw"; then
                failures=$((failures + 1))
            fi
        done < <(printf '%s\n' "$line" | grep -oE '\]\([^)]+\)' | sed 's/^\](//;s/)$//' 2>/dev/null || true)

        # Reference-style links: [label]: target
        if [[ "$line" =~ ^\[[^\]]+\]:[[:space:]]+([^[:space:]]+) ]]; then
            raw="${BASH_REMATCH[1]}"
            [[ "$raw" == http://* || "$raw" == https://* || "$raw" == mailto:* || "$raw" == \#* ]] && continue
            link_count=$((link_count + 1))
            if ! check_link "$md_file" "$line_num" "$raw"; then
                failures=$((failures + 1))
            fi
        fi
    done < "$md_file"
done < <(find "$SCAN_DIR" -name "*.md" -type f | sort)

if [ "$failures" -gt 0 ]; then
    printf 'Found %s broken link(s) across %s files.\n' "$failures" "$file_count" >&2
    exit 1
fi
printf 'Checked %s links across %s files; all OK.\n' "$link_count" "$file_count"
