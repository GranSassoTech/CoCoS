#!/usr/bin/env python3

""" CoCoS - Continuous Compliance Service
	Macro script to run over a whole git directory
	
Author:
	Emerson Sales

Assumptions:
	- We are relying on the fact that CoCoS is installed in the git root. 
	  This means that all analyzed files start with ../ 
	  and thus, if we want to retrieve a file path, we remove the first three characters of the input name
	- This script is called by run.sh, who is responsible for other preparations before running the analysis,
      therefore this script is not supposed to be called directly by the user
	
ToDos:
	- clean changed_map and file_line_map before (or after) every run
    - add option for graphviz output
"""

import argparse
import glob
from pathlib import Path
from file_line_map import file_line_map
from changed_map import file_func_map
import subprocess
import os


def get_c_files_excluding(root_dir, exclude_dirs):
    c_files = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Modify dirnames in-place to skip excluded directories
        dirnames[:] = [d for d in dirnames if os.path.join(dirpath, d) not in exclude_dirs]
        for file in filenames:
            if file.endswith(".c"):
                c_files.append(os.path.join(dirpath, file))
    return c_files

def main():
    parser = argparse.ArgumentParser(description="Run CoCoS algorithm in multiple files")
    parser.add_argument("newtag", help="release number", default="")
    parser.add_argument("-C", "--current", action='store_true', help="compare to current working directory")
    parser.add_argument("-I", "--include", help="include paths", default="")
    args = parser.parse_args()
    changed_list = {}

    exclude = ["../CoCoS", "../tmp"] if args.current else ["../CoCoS", "../tmp/old"]
    include = ".." if args.current else "../tmp/new"
    files = get_c_files_excluding(include, exclude)
    print("C files are " + str(files))
    # organize files from subfolders to root
    sorted_files = sorted(files, key=lambda s: s.count('/'), reverse=True)
    for file in sorted_files:
        print("\nAnalyzing file: " + file[3:])
        lib_funcs = []
        lines = ""
        # print("line set is "+str(j))
        if file[3:] in file_line_map.keys():
            lines = ",".join(str(lineno) for lineno in sorted(file_line_map[file[3:]]))
        # print("lines are:" + lines)
        # TODO: check .cocos_change_log to populate lib_funcs
        # if changed_list:
        #     # print("running cflow to check dependencies")
        #     lib_files = glob.glob("../lib/*.c")
        #     # TODO: remove cflow dependency
        #     cmd = ["cflow", str(file)] + lib_files
        #     cflowoutput = subprocess.run(cmd, capture_output=True, text=True)
        #     cflowlines = cflowoutput.stdout.splitlines()
        #     # print("cflow output is\n" + cflowoutput.stdout)
        #     for k in cflowlines:
        #         for l in changed_list.keys():
        #             f = k[:k.find("(")].strip() 
        #             # print("checking if "+l+" is in "+k)
        #             # print("f is "+f)
        #             if l in k and f in changed_list[l]:
        #                 lib_funcs.append(f) 
        #                 # print("lib_funcs is now " + str(lib_funcs))
        funcs = ",".join(str(k) for k in sorted(lib_funcs)) if lib_funcs else ""
        cmdline = ["python3", "cocos.py", str(file)]

        # Check if file exists in previous version before adding --old option
        old_file_path = "../tmp/old/" + str(file[3:])
        if os.path.isfile(old_file_path): cmdline += ["--old", old_file_path]
        if lines: cmdline += ["--lines", str(lines)] 
        if funcs: cmdline += ["--functions", funcs]
        if args.newtag: cmdline += ["--new-tag", args.newtag]
        if args.include: cmdline += ["-I", args.include]

        print(f"running command {" ".join(cmdline)}")

        result = subprocess.run(cmdline, capture_output=True, text=True)
        if result.returncode != 0:
            print("Error occurred!")
            print("Error output:", result.stderr)
        else:
            print("Success!")
            print("Output:\n", result.stdout)
        changed_list.update(file_func_map) 


if __name__ == "__main__":
    main()
    file_func_map.clear()

