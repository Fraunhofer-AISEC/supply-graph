#!/usr/bin/env python3
import json
import sys
import shlex
import hashlib
from pathlib import Path

COMPILER_LIKE = ["gcc", "g++", "clang", "clang++", "cc", "cxx"]


def get_files(args, dir: Path):
    files = []
    skip = False
    for arg in args[1:]:
        if skip:
            skip = False
            continue
        if arg in ["-I", "-D", "-o"]:
            skip = True
            continue
        if arg[0] == "-":
            continue
        files.append(str((dir / arg).resolve()))
    return files


def resolve_linked_library(tr):
    cc = []
    if Path(tr["arguments"][0]).name in COMPILER_LIKE:
        # capture -L
        lib_dirs: list[Path] = []
        i = 0
        while i < len(tr["arguments"]):
            arg = tr["arguments"][i]
            lib_dir = None
            if arg == "-L":
                i += 1
                lib_dir = tr["arguments"][i]
            elif arg.startswith("-L"):
                lib_dir = arg[2:]
            if lib_dir:
                lib_dirs.append((Path(tr["directory"]) / lib_dir).resolve())
            i += 1

        # capture -l
        libs = []
        i = 0
        while i < len(tr["arguments"]):
            arg = tr["arguments"][i]
            lib = None
            if arg == "-l":
                i += 1
                lib = tr["arguments"][i]
            elif arg.startswith("-l"):
                lib = arg[2:]
            if lib:
                libs.append(lib)
            i += 1

        for lib in libs:
            for lib_dir in lib_dirs:
                lib_file = lib_dir / f"lib{lib}.so"
                if not lib_file.is_file():
                    lib_file = lib_dir / f"lib{lib}.a"
                if lib_file.is_file():
                    tr_new = {
                        "arguments": tr["arguments"],
                        "directory": tr["directory"],
                        "file": str(lib_file.absolute().resolve()),
                        "output": tr["output"],
                    }
                    cc.append(tr_new)
    return cc


cc = json.load(open(sys.argv[1]))
new_cc = []
known = []
for tr in cc:
    tmp = json.dumps(tr, sort_keys=True)
    tr_hash = hashlib.sha256(tmp.encode()).hexdigest()
    if tr_hash in known:
        continue
    known.append(tr_hash)

    if "command" in tr:
        args = shlex.split(tr["command"])
    else:
        args = tr["arguments"]
    new_tr = {
        "arguments": args,
        "directory": tr["directory"],
        "file": tr["file"],
    }
    if "output" in tr:
        new_tr["output"] = tr["output"]
    else:
        try:
            new_tr["output"] = str(Path(new_tr["directory"]) / args[args.index("-o") + 1])
        except ValueError:
            if "-E" in new_tr["arguments"]:
                new_tr["output"] = ""  # -E produces no output file but only prints on stdout
            elif "-c" in new_tr["arguments"]:
                new_tr["output"] = str(
                    (Path(new_tr["directory"]) / Path(new_tr["file"]).name).with_suffix(".o")
                )
            else:
                new_tr["output"] = str(Path(new_tr["directory"]) / "a.out")

    new_cc.append(new_tr)
    for ln in resolve_linked_library(new_tr):
        new_cc.append(ln)

with open(sys.argv[1], "wt") as f:
    json.dump(new_cc, f, indent=4)
