#!/usr/bin/env python3

from pathlib import Path
import sys
import kuzu
import pandas as pd


def main():
    base_dir = Path(sys.argv[1])
    if not base_dir.is_dir():
        print(f"Error: base dir not found: {base_dir}")
        sys.exit(1)

    fanotify_log = base_dir / 'build.json'
    if not fanotify_log.is_file():
        print(f"Error: file does not exist: {fanotify_log}")
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

    df = pd.read_json(fanotify_log, lines=True)
    df['path'] = df['path'].str.replace(' (deleted)', '')
    df['pid'] = df['pid'].astype(int)

    df_bpf = pd.read_json(bpftrace_log, lines=True)
    df_bpf = df_bpf[df_bpf['action'] != "EXIT"]
    df_bpf['PID'] = df_bpf['PID'].astype(int)
    df_bpf['PPID'] = df_bpf['PPID'].astype(int)

    df_pipe = df_bpf[df_bpf['action'] == 'PIPE'].copy()
    # conn.execute("CREATE NODE TABLE Files(path STRING, name STRING, type STRING, is_upstream BOOL, PRIMARY KEY (path))")
    # {"PID":223029,"PPID":223028,"Program":"autom4te","action":"PIPE"}
    df_pipe = df_pipe[['PID']]
    df_pipe = df_pipe.drop_duplicates(df_pipe.columns)

    # conn.execute("CREATE REL TABLE Read(FROM Files TO Process)")
    # {"PID":223034,"PPID":223033,"Program":"sh","action":"WRITE"}
    df_pipe_write = df_bpf[df_bpf['action'] == "WRITE"].copy()
    df_pipe_write = df_pipe_write[['PID']]
    df_pipe_write = df_pipe_write[df_pipe_write['PID'].isin(df_pipe['PID'])]
    df_pipe_write["pipe"] = df_pipe_write['PID']

    df_pipe_read = df_bpf[df_bpf['action'] == "READ"].copy()
    df_pipe_read = df_pipe_read[['PID']]
    df_pipe_read = df_pipe_read[df_pipe_read['PID'].isin(df_pipe['PID'])]
    df_pipe_read["pipe"] = df_pipe_read['PID']
    # only take pipes in which data is also read
    df_pipe_write = df_pipe_write[df_pipe_write['PID'].isin(df_pipe_read['PID'])]
    df_pipe = df_pipe[df_pipe['PID'].isin(df_pipe_read['PID'])]


    # packet.files.csv
    #df_deb = pd.read_csv(packet_files_log, header=None, names=['deb', 'path'])
    #df_deb['pid'] = -1
    #df_deb = df_deb[['path', 'deb', 'pid']]

    # upstream_files.txt
    upstream_files = pd.read_csv(upstream_log, header=None, names=['path', 'inode', 'sha256'], dtype={'path': str, 'inode': int, 'sha256': str})

    df_open = df[df['access'] == 'OPEN']
    # first process occurance can be just after fork, before replacing image!
    df_progs = df_open.drop_duplicates(['pid'], keep='last').reset_index(drop=True)
    df_progs['name'] = df_progs['argv'].map(lambda x: x[0].split('/')[-1] if x else x)
    df_progs['ppid'] = df_progs['ppid'].astype(int)
    df_progs['pid'] = df_progs['pid'].astype(int)
    df_progs = df_progs[['name', 'pid', 'ppid', 'argv']]

    df_pipe_progs = df_bpf[~df_bpf['PID'].isin(df_progs['pid'])].copy()
    df_pipe_progs['argv'] = '[]'
    df_pipe_progs = df_pipe_progs.rename(columns={'Program': 'name', 'PID': 'pid', 'PPID': 'ppid'})
    df_pipe_progs = df_pipe_progs[['name', 'pid', 'ppid', 'argv']]
    df_pipe_progs = df_pipe_progs.drop_duplicates(['pid'])
    df_progs = pd.concat([df_progs, df_pipe_progs]).reset_index(drop=True)

    df_spawn = df_progs[['ppid', 'pid']]

    df_files = df_open.drop_duplicates(['sha256']).reset_index(drop=True)
    df_files = df_files[['path', 'inode', 'sha256', 'size']]

    df_write = df[df['access'] == "WRITE"].reset_index(drop=True)
    df_write = df_write[['pid', 'sha256']]
    df_write = df_write.drop_duplicates(df_write.columns).reset_index(drop=True)

    df_read = df[df['access'] == "READ"].reset_index(drop=True)
    df_read = df_read[['sha256', 'pid']]
    df_read = df_read.drop_duplicates(df_read.columns).reset_index(drop=True)

    df_delete = df[df['access'] == "DELETE"].reset_index(drop=True)
    df_delete = df_delete[['pid', 'path']]
    df_delete = df_delete.drop_duplicates(df_delete.columns).reset_index(drop=True)

    #df_move = df[df['access'] == 'MOVE'].reset_index(drop=True)
    #df_move = df_move[['old_path', 'path', 'pid']]
    #df_new_files = df_move[['path']].copy()
    #df_files = pd.concat([df_files, df_new_files]).drop_duplicates(df_files.columns).reset_index(drop=True)

    pids = set(df_progs['pid'])
    ppids = set(df_progs['ppid']) | set(df_write['pid']) | set(df_read['pid']) | set(df_delete['pid']) | set(df_pipe_write['PID']) | set(df_pipe_read['PID'])
    missind_pid = ppids - pids
    if missind_pid:
        print(f'missing parent processes: {missind_pid}')
        missind_pid.add(-1)
        # extend df for missing parent processes
        df_extend = pd.DataFrame([{'name': f'pid-{pid}', 'pid': pid, 'ppid': -1} for pid in missind_pid])
        df_progs = pd.concat([df_progs, df_extend]).reset_index(drop=True)

    files = set(df_files['sha256'])
    new_files = set(df_read['sha256']) | set(df_write['sha256'])
    missing_files = new_files - files
    if missing_files:
        print(f'missing files: {missing_files}')
        # extend df for missing files
        df_extend = pd.DataFrame([{'name': path, 'path': path, 'sha256': path, 'size': 0} for path in missing_files])
        df_files = pd.concat([df_files, df_extend]).reset_index(drop=True)

    df_files['is_upstream'] = df_files['sha256'].isin(upstream_files["sha256"])
    df_files['name'] = df_files['path'].map(lambda x: x.split('/')[-1])
    df_files['type'] = df_files['name'].map(lambda x: Path(x).suffix)
    df_files = df_files[['inode', 'path', 'name', 'sha256', 'size', 'type', 'is_upstream']]
    print(df_files[df_files["name"] == "ecdsa_sk1_pw"])
    print(upstream_files)

    # Create an empty on-disk database and connect to it
    db = kuzu.Database("./db/db_fanotify.kuzu")
    conn = kuzu.Connection(db)

    # Create schema
    conn.execute("DROP TABLE IF EXISTS Spawn")
    conn.execute("DROP TABLE IF EXISTS Write")
    conn.execute("DROP TABLE IF EXISTS Read")
    conn.execute("DROP TABLE IF EXISTS WritePipe")
    conn.execute("DROP TABLE IF EXISTS ReadPipe")
    conn.execute("DROP TABLE IF EXISTS Move")
    conn.execute("DROP TABLE IF EXISTS Delete")
    conn.execute("DROP TABLE IF EXISTS Process")
    conn.execute("DROP TABLE IF EXISTS File")
    conn.execute("DROP TABLE IF EXISTS Pipe")

    conn.execute("CREATE NODE TABLE Process(name STRING, pid INT64, ppid INT64, argv STRING[], PRIMARY KEY (pid))")
    conn.execute("CREATE NODE TABLE Pipe(pid INT64, PRIMARY KEY (pid))")
    conn.execute("CREATE NODE TABLE File(inode INT64, path STRING, name STRING, sha256 STRING, size INT64, type STRING, is_upstream BOOL, PRIMARY KEY (sha256))")
    conn.execute("CREATE REL TABLE Spawn(FROM Process TO Process)")
    conn.execute("CREATE REL TABLE Write(FROM Process TO File)")
    conn.execute("CREATE REL TABLE Read(FROM File TO Process)")
    conn.execute("CREATE REL TABLE WritePipe(FROM Process TO Pipe)")
    conn.execute("CREATE REL TABLE ReadPipe(FROM Pipe TO Process)")

    conn.execute("COPY Process FROM df_progs")
    conn.execute("COPY Spawn FROM df_spawn")
    conn.execute("COPY File FROM df_files")
    conn.execute("COPY Pipe FROM df_pipe")
    conn.execute("COPY Write FROM df_write")
    conn.execute("COPY Read FROM df_read")
    conn.execute("COPY ReadPipe FROM df_pipe_read")
    conn.execute("COPY WritePipe FROM df_pipe_write")


if __name__ == '__main__':
    main()
