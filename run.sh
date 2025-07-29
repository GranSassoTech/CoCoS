#!/bin/bash
set -e  # Exit immediately if any command fails

# Defaults
TOOL="cocos-only"
DEBUG=0
NEWTAG=""
INCLUDEPATHS="include"

# Parse options
while getopts "t:Dn:I:" opt; do
  case $opt in
    t) TOOL=$OPTARG ;;
    D) DEBUG=1 ;;
    n) NEWTAG=$OPTARG ;;
    I) INCLUDEPATHS=$OPTARG ;;
    *) echo "Usage: $0 [-t TOOL] [-D] [-n NEWTAG] <commit1> [<commit2>]"; exit 1 ;;
  esac
done

# Shift away parsed options; remaining are commit hashes
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
  echo "Error: At least one commit hash must be provided."
  echo "Usage: $0 [-t TOOL] [-D] <commit1> [<commit2>]"
  exit 1
fi

# remove data from previous run
debug_echo "data cleanup start"
rm -f CoCoS/changedlines.txt # TODO: remove changed_map.py and file_line_map.py too, but first change run.py script
debug_echo "data cleanup finish"

debug_echo "copying old version of the repository from commit $COMMIT1"
# Modified to conditionally pass COMMIT2
if [ -z "$COMMIT2" ]; then
  bash copyrepos.sh "$COMMIT1"
else
  debug_echo "copying new version of the repository from commit $COMMIT2"
  bash copyrepos.sh "$COMMIT1" "$COMMIT2"
  debug_echo "copy of $COMMIT2 sucessfully stored at tmp/new/"
fi
debug_echo "copy of $COMMIT1 sucessfully stored at tmp/old/"

debug_echo "Tool selected: $TOOL"
debug_echo "Comparing: $COMMIT1 and ${COMMIT2:-(working directory)}"

# Behavior logic
if [ "$TOOL" = "git" ]; then
  if [ -z "$COMMIT2" ]; then
    git diff -U0 "$COMMIT1" -- '*.c' \
      | grep '^@@' \
      | sed -E 's/^@@.*\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(.*/\1/' \
      | uniq
  else
    git diff -U0 "$COMMIT1" "$COMMIT2" -- '*.c' \
      | grep '^@@' \
      | sed -E 's/^@@.*\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(.*/\1/' \
      | uniq
  fi

elif [ "$TOOL" != "cocos-only" ]; then
  if [ -z "$COMMIT2" ]; then
    git difftool -t "$TOOL" "$COMMIT1" -- */*.c *.c > CoCoS/changedlines.txt
  else
    git difftool -t "$TOOL" "$COMMIT1" "$COMMIT2" */*.c *.c > CoCoS/changedlines.txt
  fi
  debug_echo "Semantic diff saved in changedlines.txt"
else
  debug_echo "Skipping external diffs (tool = cocos-only)"
fi

# Change directory to CoCoS
cd CoCoS || { echo "CoCoS directory not found"; exit 1; }

# Extract line changes only if changedlines.txt exists
if [ -f changedlines.txt ]; then
  debug_echo "Mapping changed lines into files"
  python3 extractlines.py changedlines.txt -t $TOOL
  debug_echo "File to changed lines mapping saved"
else
#   python3 extractlines.py changedlines.txt -t skip
  debug_echo "No changedlines.txt file found — skipping line extraction"
fi


# Run the analysis
if [ -z "$COMMIT2" ]; then
  python3 run.py $NEWTAG -I $INCLUDEPATHS --current
else
  python3 run.py $NEWTAG -I $INCLUDEPATHS
fi