#!/usr/bin/env python3
import sys
import json
import networkx as nx
import pandas as pd
from pathlib import Path


def load_compile_commands(
    baes_dir: str, cc_path: Path, packet_file: Path
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    cc = json.loads(cc_path.read_text())
    df = pd.DataFrame(cc)
    # exclude system libraries
    df = df[~df["file"].str.startswith("/usr")]
    df = df[~df["file"].str.startswith("/lib")]

    df["cmd"] = df["arguments"].map(lambda x: x[0])
    df["type"] = df["cmd"].map(lambda x: Path(x).name)
    df["file"] = df["file"].map(lambda x: x.replace(baes_dir, ""))
    df["output"] = df["output"].map(lambda x: x.replace(baes_dir, ""))
    df["directory"] = df["directory"].map(lambda x: x.replace(baes_dir, ""))

    df_deb = pd.read_csv(packet_file, names=["target", "source"])
    df_deb["target"] = df_deb["target"].map(lambda x: Path(x).name)
    df_deb["pkg_name"] = df_deb["target"].map(lambda x: x.split("_", 1)[0])
    df_deb["type"] = "deb"
    df_deb = df_deb[df_deb["source"].isin(df["output"])]

    s_nodes = pd.concat([df["file"], df["output"], df_deb["source"], df_deb["target"]])
    df_nodes = pd.DataFrame({"name": s_nodes.unique()})
    df_nodes["type"] = df_nodes["name"].map(lambda x: Path(x).suffix.strip(".") or "exe")

    df_edges = df[["file", "output", "type"]]
    df_edges = df_edges.rename(columns={"file": "source", "output": "target"})
    df_edges = pd.concat([df_edges, df_deb])
    df_edges = df_edges.drop_duplicates().reset_index(drop=True)

    return df, df_nodes, df_edges


def create_suuply_graph(df: pd.DataFrame, df_edges: pd.DataFrame) -> nx.DiGraph:
    DG = nx.DiGraph()

    DG = nx.from_pandas_edgelist(
        df[~df["type"].isin(["install", "cp", "ln", "mv"])],
        "file",
        "output",
        create_using=nx.DiGraph(),
    )
    root_nodes = [n for n, d in DG.in_degree() if d == 0]

    DG = nx.from_pandas_edgelist(df_edges, "source", "target", create_using=nx.DiGraph())
    nodes = root_nodes
    for node in root_nodes:
        nodes += nx.descendants(DG, node)
    return DG.subgraph(nodes)


def main():
    if len(sys.argv) != 2:
        print("Usage: analyze-build-graph <packet-dir>")
        sys.exit(1)

    baes_dir = ""
    packet_dir = Path(sys.argv[1])
    if not packet_dir.is_dir():
        print(f"Error: packet dir does not exist: {packet_dir}")
        sys.exit(1)

    upstream_files = packet_dir / "upstream_files.txt"
    if not upstream_files.is_file():
        print(f"Could not find list of upstream files: {upstream_files}")
        sys.exit(1)
    upstream_files = upstream_files.read_text().strip().split("\n")

    packet_file = packet_dir / "packet.files.csv"
    if not packet_file.is_file():
        print(f"Could not find list of packet files: {packet_file}")
        sys.exit(1)

    cc_path = packet_dir / "compile_commands.json"
    if not cc_path.is_file():
        print(f"Could not find compile commands: {cc_path}")
        sys.exit(1)

    nodes_path = packet_dir / "nodes.csv"
    edges_path = packet_dir / "edges.csv"

    df, df_nodes, df_edges = load_compile_commands(baes_dir, cc_path, packet_file)

    H = create_suuply_graph(df, df_edges)

    RG = H.reverse()
    leaf_nodes = set([n for n, d in RG.in_degree() if d == 0])
    debs = set(filter(lambda x: x.endswith(".deb"), leaf_nodes))
    no_debs = leaf_nodes.difference(debs)
    print(f"None deb leaf nodes: {no_debs}")

    print(f"build deb packets: {debs}")
    for deb in sorted(debs):
        nodes = nx.descendants(RG, deb)
        DD = H.subgraph(nodes)
        source = set([n for n, d in DD.in_degree() if d == 0])
        print(f"{deb} ({len(source)})")
        for s in sorted(source):
            print(f"* {s}")
        print()

    nodes = list(debs)
    for node in debs:
        nodes += nx.descendants(RG, node)

    df_nodes = df_nodes[df_nodes["name"].isin(nodes)]
    df_edges = df_edges[df_edges["source"].isin(nodes)]
    df_nodes.to_csv(nodes_path, header=True, index=False)
    df_edges.to_csv(edges_path, header=True, index=False)

    DG = H.subgraph(nodes)
    root_nodes = [n for n, d in DG.in_degree() if d == 0]

    non_upstream = list(filter(lambda x: x not in upstream_files, root_nodes))
    print("Root files not part of upstream:")
    for node in non_upstream:
        print(f"* {node}")

    non_source_root = list(filter(lambda x: not x.endswith(".c"), root_nodes))
    print("Binary files without corresponding source code:")
    for node in non_source_root:
        print(f"* {node}")


if __name__ == "__main__":
    main()
