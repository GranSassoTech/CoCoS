#!/bin/bash

set -e  # Exit immediately if any command fails

mkdir -p tmp/old || { echo "Error: Failed to create tmp/old directory"; exit 1; }
mkdir -p tmp/new || { echo "Error: Failed to create tmp/new directory"; exit 1; }

# Function to copy files from a commit to target directory
copy_files() {
  local commit=$1
  local target_root=$2
  
  for file in $(git ls-files "$commit" -- '*.c' '*.h' '**/*.c' '**/*.h'); do
    base=$file
    target_dir="$target_root/$(dirname "$base")"
    target_file="$target_root/$base"

    # Ensure parent directories exist
    mkdir -p "$target_dir" || {
      echo "Error: Failed to create directory $target_dir"
      exit 1
    }

    # Write the committed version
    if ! git show "$commit:$file" > "$target_file"; then
      echo "Error: Failed to write $target_file"
      # Continue despite errors (commented out exit 1)
    fi
  done
}

# Process first commit (always required)
echo "Copying files from commit $1 to tmp/old/"
copy_files "$1" "tmp/old"

# Process second commit if provided
if [ -n "$2" ]; then
  echo "Copying files from commit $2 to tmp/new/"
  copy_files "$2" "tmp/new"
fi