#!/usr/bin/env python3

import sys
import re
import pprint
from collections import defaultdict

def extract_file_line_map_diffsitter(diff_file_path, simplify_paths=False):
    file_line_map = defaultdict(set)
    current_file = None

    # Regex to match and remove '/tmp/git-blob-*/' prefix
    tmp_blob_prefix = re.compile(r"^.*/git-blob-[^/]+/")

    file_header_re = re.compile(r"^.+ -> (.+)$")
    line_number_re = re.compile(r"^(\d+)(?:\s*-\s*(\d+))?:")

    with open(diff_file_path, 'r') as f:
        for line in f:
            line = line.rstrip()

            match = file_header_re.match(line)
            if match:
                full_path = match.group(1)

                # remove /tmp/git-blob-*/ prefix
                if simplify_paths:
                    current_file = tmp_blob_prefix.sub('', full_path)
                else:
                    current_file = full_path
                continue

            if line.startswith("===") or line.startswith("---") or line.startswith("+++"):
                continue

            match = line_number_re.match(line)
            if match and current_file:
                start = int(match.group(1))
                end = match.group(2)

                if end:
                    end = int(end)
                    file_line_map[current_file].update(range(start, end + 1))
                else:
                    file_line_map[current_file].add(start)

    return dict(file_line_map)

def extract_file_line_map_git(diff_file_path):
    # Placeholder for git diff parser
    print("Parsing git diff format is not implemented yet.")
    return {}

def extract_file_line_map_difftastic(diff_file_path):
    # Placeholder for difftastic parser
    print("Parsing difftastic output is not implemented yet.")
    return {}

def save_dict_as_python_file(data, output_path):
    with open(output_path, 'w') as f:
        f.write("# Auto-generated file with file-to-lines mapping\n")
        f.write("file_line_map = ")
        pprint.pprint(data, stream=f)

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Extract changed lines from diff output.")
    parser.add_argument("diff_file", help="Path to the diff output file")
    parser.add_argument("-t", "--tool", default="diffsitter", help="Tool used for diffing: diffsitter (default), git, difftastic")

    args = parser.parse_args()
    tool = args.tool.lower()

    if tool == "diffsitter":
        file_changes = extract_file_line_map_diffsitter(args.diff_file)
    elif tool == "git":
        file_changes = extract_file_line_map_git(args.diff_file)
    elif tool == "difftastic":
        file_changes = extract_file_line_map_difftastic(args.diff_file)
    elif tool == "skip":
        file_changes = dict()
    else:
        print(f"Unsupported tool: {tool}")
        sys.exit(1)

    # Pretty-print the result
    for filename, lines in file_changes.items():
        print(f"{filename}: {sorted(lines)}")

    save_dict_as_python_file(file_changes, "file_line_map.py")

if __name__ == "__main__":
    main()
