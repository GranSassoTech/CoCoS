#!/bin/bash
set -e  # Exit immediately if any command fails

# Usage:
#   copyrepos.sh <repo_path> <commit1> [commit2]
#
# Example:
#   copyrepos.sh repos/navigation a91be12 b3d77f9

REPO_PATH=$1
COMMIT1=$2
COMMIT2=$3

if [ -z "$REPO_PATH" ] || [ -z "$COMMIT1" ]; then
  echo "Usage: $0 <repo_path> <commit1> [commit2]"
  exit 1
fi

if [ ! -d "$REPO_PATH/.git" ]; then
  echo "Error: $REPO_PATH is not a Git repository"
  exit 1
fi

REPO_NAME=$(basename "$REPO_PATH")
TMP_ROOT="tmp/$REPO_NAME"

OLD_DIR="$TMP_ROOT/old"
NEW_DIR="$TMP_ROOT/new"

mkdir -p "$OLD_DIR"
mkdir -p "$NEW_DIR"

# Copy files from a given commit
copy_files() {
  local commit=$1
  local target_root=$2

  git ls-tree -r --name-only "$commit" \
    | grep -E '\.(c|h)$' \
    | while read -r file; do
        target_dir="$target_root/$(dirname "$file")"
        mkdir -p "$target_dir"
        git show "$commit:$file" > "$target_root/$file" || {
          echo "Warning: failed to copy $file from $commit"
        }
      done
}

echo "Processing repository: $REPO_NAME"
cd "$REPO_PATH"

echo "Copying files from commit $COMMIT1 → $OLD_DIR"
copy_files "$COMMIT1" "../$OLD_DIR"

if [ -n "$COMMIT2" ]; then
  echo "Copying files from commit $COMMIT2 → $NEW_DIR"
  copy_files "$COMMIT2" "../$NEW_DIR"
fi

echo "Repository $REPO_NAME copied successfully"
