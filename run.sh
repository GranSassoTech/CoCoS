#!/bin/bash
set -e  # Exit immediately if any command fails

# Defaults
TOOL="cocos-only"
DEBUG=0
NEWTAG=""
INCLUDEPATHS="include"
VERBOSITY="4"
REPOS_DIR="repos"
MACROS=""
MACRO_FILE=""

# Parse options
while getopts "t:Dn:I:d:r:m:M:" opt; do
  case $opt in
    t) TOOL=$OPTARG ;;
    D) DEBUG=1 ;;
    n) NEWTAG=$OPTARG ;;
    I) INCLUDEPATHS=$OPTARG ;;
    m) MACROS=$OPTARG ;;
    M) MACRO_FILE=$OPTARG;;
    d) VERBOSITY=$OPTARG ;;
    r) REPOS_DIR=$OPTARG ;;
    *) echo "Usage: $0 [-t TOOL] [-D] [-n NEWTAG] [-m MACRO_INLINE] [-M MACRO_FILE] [-d VERBOSITY_LEVEL] [-r REPOS_DIR] <commit1> [<commit2>]"; exit 1 ;;
  esac
done

# Shift away parsed options; remaining are commits
shift $((OPTIND - 1))
COMMIT1=$1
COMMIT2=$2

# Debug echo function
debug_echo() {
  if [ "$DEBUG" -eq 1 ]; then
    echo "$@"
  fi
}

# Validate input
if [ -z "$COMMIT1" ]; then
  echo "Error: At least one commit must be provided."
  echo "Usage: $0 [-t TOOL] [-D] <commit1> [<commit2>]"
  exit 1
fi

# Iterate over repositories
for repo in "$REPOS_DIR"/*; do
  if [ ! -d "$repo/.git" ]; then
    continue
  fi

  REPO_NAME=$(basename "$repo")
  debug_echo "Processing repository: $REPO_NAME"

  TMP_REPO_DIR="tmp/$REPO_NAME"
  rm -rf "$TMP_REPO_DIR"
  mkdir -p "$TMP_REPO_DIR"

  debug_echo "Copying repository versions"

  if [ -z "$COMMIT2" ]; then
    bash copyrepos.sh "$repo" "$COMMIT1" "$TMP_REPO_DIR"
  else
    bash copyrepos.sh "$repo" "$COMMIT1" "$COMMIT2" "$TMP_REPO_DIR"
  fi

  # External diff (optional)
  if [ "$TOOL" != "cocos-only" ]; then
    if [ -z "$COMMIT2" ]; then
      git -C "$repo" difftool -t "$TOOL" "$COMMIT1" -- '*.c' \
        > "CoCoS/changedlines_${REPO_NAME}.txt"
    else
      git -C "$repo" difftool -t "$TOOL" "$COMMIT1" "$COMMIT2" -- '*.c' \
        > "CoCoS/changedlines_${REPO_NAME}.txt"
    fi
  fi

  # cd CoCoS

  if [ -f "changedlines_${REPO_NAME}.txt" ]; then
    python3 extractlines.py "changedlines_${REPO_NAME}.txt" -t "$TOOL" --repo "$REPO_NAME"
  fi

  MACRO_ARGS=()

  if [ -n "$MACROS" ]; then
    MACRO_ARGS+=("--macros=""$MACROS")
  fi

  if [ -n "$MACROFILE" ]; then
    MACRO_ARGS+=("-M" "$MACROFILE")
  fi

  TAG_ARGS=()

  if [ -n "$NEWTAG" ]; then
    TAG_ARGS+=("-n" "$NEWTAG")
  fi

  if [ -z "$COMMIT2" ]; then
    python3 run.py --repo "$REPO_NAME" "${TAG_ARGS[@]}" -I "$INCLUDEPATHS" -d "$VERBOSITY" "${MACRO_ARGS[@]}" --current
  else
    python3 run.py --repo "$REPO_NAME" "${TAG_ARGS[@]}" -I "$INCLUDEPATHS" -d "$VERBOSITY" "${MACRO_ARGS[@]}"
  fi

  # cd ..
done