#!/usr/bin/env python3
import sys
from copy import copy
from pathlib import Path
from functools import partial
import pandas as pd
import numpy as np
from tqdm import tqdm
import kuzu


class BpftraceLogger:
    def __init__(self) -> None:
        self.count_fd = 0
        # Nodes
        self.n_procs = []
        self.n_files = [
            {"path": "stdin", "inode": "tty:0"},
            {"path": "stdout", "inode": "tty:1"},
            {"path": "stderr", "inode": "tty:2"},
        ]
        self.n_fds = []

        # Edges
        self.e_spwan = []
        self.e_write = []
        self.e_read = []
        self.e_open = []
        self.e_pipe = []
        self.e_ipc = []

        # mappings
        self.proc_fd = {}

    def create_fd(self, pid, org_fd):
        fd = self.count_fd
        self.count_fd += 1
        if not pid in self.proc_fd:
            self.proc_fd[pid] = {}
        self.proc_fd[pid][org_fd] = fd
        self.n_fds.append({"fd": fd})
        return fd

    def process_row(self, bar, row):
        match row["action"]:
            case "CLONE":
                proc = [p for p in self.n_procs if p["PID"] == row["PPID"]]
                child = {}
                if proc:
                    assert len(proc) == 1
                    child = copy(proc[0])
                child["PID"] = row["PID"]
                self.n_procs.append(child)
                self.proc_fd[row["PID"]] = {}
                if row["PPID"] in self.proc_fd:
                    self.proc_fd[row["PID"]] = copy(self.proc_fd[row["PPID"]])
                self.e_spwan.append({"parent": row["PPID"], "child": row["PID"]})
            case "EXECV":
                proc = [p for p in self.n_procs if p["PID"] == row["PID"]]
                assert len(proc) == 1
                proc[0]["argv"] = row["argv"]
            case "EXIT":
                if row["PID"] in self.proc_fd:
                    del self.proc_fd[row["PID"]]
            case "OPEN":
                fd = self.create_fd(row["PID"], row["fd"])
                if not [f for f in self.n_files if f["inode"] == row["inode"]]:
                    self.n_files.append({"path": row["filename"], "inode": row["inode"]})
                self.e_open.append({"fd": fd, "inode": row["inode"]})
            case "CLOSE":
                if row["fd"] in self.proc_fd[row["PID"]]:
                    del self.proc_fd[row["PID"]][row["fd"]]
                else:
                    tqdm.write(f"Warning: fd: {row.fd} of proc: {row.PID} not in proc_fd mapping during CLOSE")
            case "READ":
                if not row["fd"] in self.proc_fd[row["PID"]]:
                    match row["fd"]:
                        case 0:
                            ufd = self.create_fd(row["PID"], row["fd"])
                        case _:
                            raise RuntimeError(f"Unknown read to fd: {row.fd} from proc: {row.PID}")
                ufd = self.proc_fd[row["PID"]][row["fd"]]
                self.e_read.append({"fd": ufd, "PID": row["PID"]})
                if not [fd for fd in self.e_open if fd["fd"] == ufd] and not [fd for fd in self.e_pipe if fd["read"] == ufd]:
                    match row["fd"]:
                        case 0:
                            self.e_open.append({"fd": ufd, "inode": "tty:0"})
                        case _:
                            tqdm.write(f"Warning: Read: proc: {row.PID} as no open fd: {row.fd} (unique fd: {ufd})")
            case "WRITE":
                if not row["fd"] in self.proc_fd[row["PID"]]:
                    match row["fd"]:
                        case 1 | 2:
                            ufd = self.create_fd(row["PID"], row["fd"])
                        case _:
                            raise RuntimeError(f"Unknown write to fd: {row.fd} from proc: {row.PID}")
                ufd = self.proc_fd[row["PID"]][row["fd"]]
                self.e_write.append({"fd": ufd, "PID": row["PID"]})
                if not [fd for fd in self.e_open if fd["fd"] == ufd] and not [fd for fd in self.e_pipe if fd["write"] == ufd]:
                    match row["fd"]:
                        case 1:
                            self.e_open.append({"fd": ufd, "inode": "tty:1"})
                        case 2:
                            self.e_open.append({"fd": ufd, "inode": "tty:2"})
                        case _:
                            tqdm.write(f"Warning: Write: proc: {row.PID} as no open fd: {row.fd} (unique fd: {ufd})")
            case "DUP2":
                if row["old_fd"] in self.proc_fd[row["PID"]]:
                    ufd = self.proc_fd[row["PID"]][row["old_fd"]]
                    self.proc_fd[row["PID"]][row["new_fd"]] = ufd
                    self.e_ipc.append({"PID": row["PID"], "fd": ufd})
                else:
                    pass
                    #tqdm.write(f"Warning: DUP2: Could not find fd: {row.old_fd} for proc: {row.PID}")
            case "PIPE":
                fd0 = self.create_fd(row["PID"], row["fd0"])
                fd1 = self.create_fd(row["PID"], row["fd1"])
                self.e_pipe.append({"read": fd0, "write": fd1})
            case "INFO":
                tqdm.write(f"WARNING: {row.message}")
            case _:
                raise NotImplementedError(f"Unknown action: {row.action}")
        bar.update(1)

    def load_bpftrace(self, path):
        df = pd.read_json(path, lines=True)
        #df = df.sort_values(["elapsed"])
        print(df)

        print("Process bpftrace log...")
        bar = tqdm(df.iterrows(), total=df.shape[0])

        df.apply(partial(self.process_row, bar), axis=1)
        bar.close()

        # Create DataFrame
        print("Convert to DataFram...")
        df_procs = pd.DataFrame(self.n_procs)
        df_files = pd.DataFrame(self.n_files)
        df_fds = pd.DataFrame(self.n_fds)

        df_spwan = pd.DataFrame(self.e_spwan)
        df_open = pd.DataFrame(self.e_open)
        df_read = pd.DataFrame(self.e_read)
        df_write = pd.DataFrame(self.e_write)
        df_pipe = pd.DataFrame(self.e_pipe)
        df_ipc = pd.DataFrame(self.e_ipc)

        df_spwan["parent"] = df_spwan["parent"].astype(int)
        df_spwan["child"] = df_spwan["child"].astype(int)

        return df_pipe, df_fds, df_ipc, df_spwan

    def filter_log(self):
        # Pre-process DataFrame
        df_spwan["parent"] = df_spwan["parent"].astype(int)
        df_spwan["child"] = df_spwan["child"].astype(int)

        df_procs["PID"] = df_procs["PID"].astype(int)
        pid_missing = set(df_spwan["parent"]).difference(set(df_procs["PID"]))
        print(f"Missing PIDs: {pid_missing}; add dummy")
        df_procs_missing = pd.DataFrame({"PID": list(pid_missing)})
        df_procs = pd.concat([df_procs, df_procs_missing]).reset_index(drop=True)
        df_procs["argv"] = df_procs["argv"].map(lambda x: x if isinstance(x, list) else [])
        df_procs["name"] = df_procs["argv"].map(lambda x: x[0] if x else "")
        df_procs = df_procs[["name", "PID", "argv"]]

        df_files["name"] = df_files["path"].map(lambda x: x.split("/")[-1])
        df_files['type'] = df_files['name'].map(lambda x: Path(x).suffix)
        df_files['is_upstream'] = False
        df_files = df_files[["inode", "path", "name", "type", "is_upstream"]]

        df_write = df_write[["PID", "fd"]]
        df_write = df_write.drop_duplicates()
        df_read = df_read.drop_duplicates()

        df_pipe = df_pipe[["write", "read"]]

        ## Logging
        print("Processes")
        print(df_procs)
        print("Files")
        print(df_files)
        print("FDs")
        print(df_fds)

        print("Spwan")
        print(df_spwan)
        print("Open")
        print(df_open)
        print("Read")
        print(df_read)
        print("Write")
        print(df_write)
        print("Pipe")
        print(df_pipe)

    def filter_db(self):
        # Clean up graph
        conn.execute("""
            MATCH (f:File)<-[:Open]-(d:FD) WHERE 
            f.path =~ "/usr.*" or
            f.path =~ "/dev.*" or
            f.path =~ "/proc.*" or
            f.path =~ "/sys.*" or
            f.path =~ "/var/log.*" or
            f.path =~ "/etc.*"
            DETACH DELETE f, d
        """)
        conn.execute("""
            match (o:FD) WHERE 
            not EXISTS {match (:Process)-[]-(o)} 
            DETACH DELETE o
        """)
