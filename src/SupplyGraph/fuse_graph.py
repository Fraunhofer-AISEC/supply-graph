#!/usr/bin/env python3
import sys
import json
from pathlib import Path
import pandas as pd
import kuzu


def main():
    base_dir = Path(sys.argv[1])
    if not base_dir.is_dir():
        print(f"Error: base dir not found: {base_dir}")
        sys.exit(1)

    fuse_log = base_dir / 'fuse.json'
    if not fuse_log.is_file():
        print(f"Error: file does not exist: {fuse_log}")
        sys.exit(1)

    bpftrace_log = base_dir / 'bpftrace.json'
    if not bpftrace_log.is_file():
        print(f"Error: file does not exist: {bpftrace_log}")
        sys.exit(1)

    packet_files_log = base_dir / "packet.files.csv"
    if not packet_files_log.is_file():
        print(f"Error: file does not exist: {packet_files_log}")
        sys.exit(1)

    upstream_log = base_dir / "upstream_files.csv"
    if not upstream_log.is_file():
        print(f"Error: file does not exist: {upstream_log}")
        sys.exit(1)

    df = pd.read_json(fuse_log, lines=True)
    df = df.sort_values(["time"])
    print(df)

    df_upstream_files = pd.read_csv(upstream_log, header=None, names=['path', 'inode', 'sha256'], dtype={'path': str, 'inode': int, "sha256": str})
    df_deb = pd.read_csv(packet_files_log, header=None, names=['deb', 'path'])

    df_bpftrace = pd.read_json(bpftrace_log, lines=True)
    df_bpftrace = df_bpftrace.drop_duplicates(["pid", "action", "inode", "fd"])
    assert df_bpftrace.shape[0] == df_bpftrace.drop_duplicates(["pid", "action", "inode"]).shape[0]
    df_bpftrace = df_bpftrace.sort_values(["action"])
    df_bpftrace["action"] = df_bpftrace["action"].str.replace("tracepoint:syscalls:sys_enter_", "")

    df_pipes_read = df_bpftrace[df_bpftrace["action"] == "read"]
    df_pipes_read = df_pipes_read.groupby(["inode"]).agg({"pid": list})
    df_pipes_read = df_pipes_read.rename(columns={"pid": "read"})
    df_pipes_write = df_bpftrace[df_bpftrace["action"] == "write"]
    df_pipes_write = df_pipes_write.groupby(["inode"]).agg({"pid": list})
    df_pipes_write = df_pipes_write.rename(columns={"pid": "write"})
    df_pipes = df_pipes_read.merge(df_pipes_write, left_index=True, right_index=True)
    df_pipes = df_pipes.explode("read")
    df_pipes = df_pipes.explode("write")
    df_pipes = df_pipes.dropna()
    df_pipes = df_pipes[["write", "read"]]
    print("Pipes")
    print(df_pipes)

    df["hash"] = df["sha256"] + df["inode"].astype(str)

    first = lambda x: list(x)[0]
    df_op = df.groupby(['fd']).agg({'PID': first, "inode": first, "path": first, "argv": first, "size": first, "hash": list, "fd": first})
    df_op["hash_pre"] = df_op["hash"].map(lambda x: x[0])
    df_op["hash_post"] = df_op["hash"].map(lambda x: x[1])
    df_op["is_write"] = df_op["hash_pre"] != df_op["hash_post"]
    df_op = df_op.drop(columns=["hash", "argv"])

    # Create DataFrame
    df_procs = df.groupby(['PID']).agg({"argv": lambda x: list(x)[-1]}).reset_index().copy()
    df_files = df.drop_duplicates(['hash']).copy().drop(columns=["argv"])

    df_open = df[df['action'] == 'OPEN'].copy()[["fd", "hash"]]
    df_read = df_op[~df_op["is_write"]].copy()
    df_write = df_op[df_op["is_write"]].copy()


    # Pre-process DataFrame
    df_spwan = df.drop_duplicates(["PID", "PPID"])
    df_spwan = df_spwan.rename(columns={"PID": "child", "PPID": "parent"})
    df_spwan["parent"] = df_spwan["parent"].astype(int)
    df_spwan["child"] = df_spwan["child"].astype(int)
    df_spwan = df_spwan[["parent", "child"]]

    pid_missing = set(df_spwan["parent"]).difference(set(df_procs["PID"]))
    pid_missing |= set(df_spwan["child"]).difference(set(df_procs["PID"]))
    pid_missing |= set(df_pipes["read"]).difference(set(df_procs["PID"]))
    pid_missing |= set(df_pipes["write"]).difference(set(df_procs["PID"]))
    #print(f"Missing PIDs: {pid_missing}; add dummy")
    df_procs_missing = pd.DataFrame({"PID": list(pid_missing)})
    df_procs = pd.concat([df_procs, df_procs_missing]).reset_index(drop=True)
    df_procs["argv"] = df_procs["argv"].map(lambda x: x if isinstance(x, list) else [])
    df_procs["name"] = df_procs["argv"].map(lambda x: x[0].split("/")[-1] if x else "")
    df_procs = df_procs[["name", "PID", "argv"]]

    df_files["name"] = df_files["path"].map(lambda x: x.split("/")[-1])
    df_files['type'] = df_files['name'].map(lambda x: Path(x).suffix)
    df_files['is_upstream'] = df_files['sha256'].isin(df_upstream_files["sha256"])
    df_files = df_files[["hash", "inode", "sha256", "path", "name", "type", "is_upstream"]]

    df_write = df_write[["PID", "hash_post"]]
    df_write = df_write.drop_duplicates()
    df_read = df_read[["hash_post", "PID"]]
    df_read = df_read.drop_duplicates()


    ## Logging
    print("Processes")
    print(df_procs)
    print("Files")
    print(df_files)

    print("Spwan")
    print(df_spwan)
    print("Open")
    print(df_open)
    print("Read")
    print(df_read)
    print("Write")
    print(df_write)

    # Import to Kuzu DB
    print("Import into Kuzu DB...")
    db = kuzu.Database("./db.kuzu")
    conn = kuzu.Connection(db)

    # Create schema
    ## Clear REL
    conn.execute("DROP TABLE IF EXISTS Spawn")
    conn.execute("DROP TABLE IF EXISTS Write")
    conn.execute("DROP TABLE IF EXISTS Read")
    conn.execute("DROP TABLE IF EXISTS Pipe")
    conn.execute("DROP TABLE IF EXISTS Ipc")
    conn.execute("DROP TABLE IF EXISTS Open")
    conn.execute("DROP TABLE IF EXISTS Update")
    ## Clear TABLE
    conn.execute("DROP TABLE IF EXISTS Process")
    conn.execute("DROP TABLE IF EXISTS File")
    conn.execute("DROP TABLE IF EXISTS FD")

    ## Create TABLE
    conn.execute("CREATE NODE TABLE Process(name STRING, PID INT64, argv STRING[], PRIMARY KEY (PID))")
    conn.execute("CREATE NODE TABLE File(hash STRING, inode STRING, sha256 STRING, path STRING, name STRING, type STRING, is_upstream BOOL, PRIMARY KEY (hash))")

    ## Create REL
    conn.execute("CREATE REL TABLE Spawn(FROM Process TO Process)")
    conn.execute("CREATE REL TABLE Write(FROM Process TO File)")
    conn.execute("CREATE REL TABLE Read(FROM File TO Process)")
    conn.execute("CREATE REL TABLE Pipe(FROM Process TO Process)")

    ## Load data from DataFrame
    conn.execute("COPY Process FROM df_procs")
    conn.execute("COPY File FROM df_files")
    conn.execute("COPY Spawn FROM df_spwan")
    conn.execute("COPY Write FROM df_write")
    conn.execute("COPY Read FROM df_read")
    conn.execute("COPY Pipe FROM df_pipes")

    # Analysis
    print("Analyzing Graph...")
    res = {}
    ret = conn.execute('MATCH (p:Process)-[w:Write]->(f:File {type: ".o"}) RETURN DISTINCT p.name')
    res["object-source-proc"] = sorted([row[0] for row in ret])

    ret = conn.execute('''MATCH (p:Process)-[w:Write]->(f:File {type: ".o"})
    where 
    p.name <> "strip" and
    p.name <> "cp" and
    p.name <> "as" and
    p.name <> "ld" and
    p.name <> "x86_64-linux-gnu-as" and
    p.name <> "x86_64-linux-gnu-ld.gold"
    RETURN f, p limit 10''')
    res["bad-object-source"] = [row[0] for row in ret]

    ret = conn.execute('''match (l:File)-[a:Read|:Write|:Pipe* SHORTEST 1..30]->(f:File {type: ".deb"}) where
not exists {match (l)<-[:WRITE]-(p)<-[:Read|:Write|:Pipe]-()}
and l.type <> ".c"
and l.type <> ".h"
and not l.path =~ "/usr/.*"
and not l.path =~ "/var/lib/.*"
and not l.path =~ "/etc/.*"
return DISTINCT l.type''')
    res["top-level-file-types"] = sorted([row[0] for row in ret])

    txt = json.dumps(res, indent=4)
    print(txt)
    with open("result.json", "wt") as f:
        f.write(txt)


if __name__ == '__main__':
    main()
