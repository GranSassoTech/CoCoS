#!/usr/bin/env python3

""" CoCoS - Continuous Compliance Service
    Macro script to run over multiple git repositories
    
Author:
    Emerson Sales

Assumptions:
    - We are relying on the fact that git repositories are all inside the same folder 
      (i.e. each subfolder of --repo option is a git repository)
    - This script is called by run.sh, who is responsible for other preparations before running the analysis,
      therefore this script is not supposed to be called directly by the user
    
ToDos:
    - clean changed_map and file_line_map before (or after) every run
    - add option for graphviz output
"""

import argparse
import os
import subprocess
import sys
from collections import defaultdict


def get_c_files_excluding(root, exclude_dirs):
    """
    Collect all .c files under `root`, excluding any directory listed in exclude_dirs.
    """
    c_files = []
    for dirpath, dirnames, filenames in os.walk(root):
        # prune excluded directories
        dirnames[:] = [
            d for d in dirnames
            if not any(os.path.abspath(os.path.join(dirpath, d)).startswith(
                os.path.abspath(ex))
                for ex in exclude_dirs)
        ]
        for f in filenames:
            if f.endswith(".c"):
                c_files.append(os.path.join(dirpath, f))
    return c_files


def main():
    parser = argparse.ArgumentParser(
        description="Run CoCoS on a repository and collect changed functions"
    )
    parser.add_argument(
        "-n", "--newtag",
        default="",
        help="Release/tag identifier for the new version"
    )
    parser.add_argument(
        "-C", "--current",
        action="store_true",
        help="Compare against the current working tree instead of tmp copies"
    )
    parser.add_argument(
        "--repo",
        required=True,
        help="Repositories folder"
    )
    parser.add_argument(
        "-I", "--include",
        help="Additional include paths (passed through to cocos.py)",
        default=""
    )
    parser.add_argument(
        "-d", "--verbosity",
        help="Verbosity level",
        default="4"
    )
    parser.add_argument(
        "-m", "--macros",
        help="Additional macros (inlined) for gcc precompilation",
        default=""
    )
    parser.add_argument(
        "-M", "--macrofile",
        help="Additional macros (inlined) for gcc precompilation",
        default=""
    )

    args = parser.parse_args()

    repo = args.repo
    repo_root = os.path.join("repos", repo)
    tmp_root = os.path.join("tmp", repo)
    tmp_old_root = os.path.join(tmp_root, "old")
    tmp_new_root = os.path.join(tmp_root, "new")

    if not os.path.isdir(repo_root):
        print(f"Error: repository '{repo_root}' does not exist", file=sys.stderr)
        sys.exit(1)

    # Where we read files from
    if args.current:
        include_root = repo_root
        exclude_dirs = [os.path.abspath("CoCoS"), os.path.abspath(tmp_root)]
    else:
        include_root = tmp_new_root
        exclude_dirs = [os.path.abspath("CoCoS")]

    files = get_c_files_excluding(include_root, exclude_dirs)
    print("C files are:", files)

    # Sort deeper paths first (matches previous behavior)
    files.sort(key=lambda s: s.count(os.sep), reverse=True)

    changed_list = defaultdict(set)

    for file_path in files:
        # Compute path relative to repository root
        if args.current:
            relative_path = os.path.relpath(file_path, repo_root)
        else:
            relative_path = os.path.relpath(file_path, tmp_new_root)

        logical_path = os.path.join(repo_root, relative_path)

        print("\nAnalyzing file:", logical_path)

        cmdline = ["python3", "cocos.py", logical_path]

        # Old file, if it exists
        old_file_path = os.path.join(tmp_old_root, relative_path)
        if os.path.isfile(old_file_path):
            cmdline += ["--old", old_file_path]

        if args.newtag:
            cmdline += ["--new-tag", args.newtag]

        if args.include:
            cmdline += ["-I", args.include]

        if args.macros:
            cmdline += ["--macros="+args.macros]

        if args.macrofile:
            cmdline += ["-M", args.macrofile]

        if args.verbosity:
            cmdline += ["-d", args.verbosity]

        # print("Running:", " ".join(cmdline))

        result = subprocess.run(
            cmdline,
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            print("Error running cocos.py:")
            print(result.stderr)
            continue

        print("Output:\n", result.stdout)



if __name__ == "__main__":
    main()
