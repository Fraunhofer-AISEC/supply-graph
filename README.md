# Supply Graph
In this project, the XZ Upstream Supply Chain Attack (CVE-2024-3094) is used as a case study to demonstrate how supply chain attacks can be detected by tracing the build system by a graph based approach. The increasing prevalence of supply chain attacks on Free/Libre Open Source Software (FLOSS) projects has been highlighted recently by the supply chain attack on the xz project to backdoor SSH servers. The detection of this particular attack was coincidental, raising concerns about potentially undetected threats.

C/C++ build systems, such as GNU autotools, Make, and CMake, have grown highly complex and diverse, exposing a large attack surface to exploit. However, essentially, these build systems all compile the source code to object files and link them together to executables or libraries. For FLOSS projects, we can be even more stringent by postulating that every binary must originate from source code within the upstream project. Technically, this relationship can be modeled by the help of a graph data structure. By traversing this graph, it can be ensured that all distributed binaries originate from upstream source code showcasing the successful detection of the supply chain attack.

Further studies could scale this approach to analyze all Debian packages regularly to detect anomalies early. To prevent attacks (or at least make them harder to conceal), the authors further propose transitioning to a descriptive build system, which reduces complexity and increases transparency, making separate tracing unnecessary.

> [!CAUTION]
> This project contains the CVE-2024-3094 and is only meant for research and demonstration purpose!

> [!WARNING]
> This project is not maintained and only for research purpose!

The current implementation does not support docker environments and is meant to be run in a debian linux and might modify the system (installs packages, creates files and folders).

## Publications
* [FOSDEM 2025](https://fosdem.org/2025/schedule/event/fosdem-2025-5224-finding-anomalies-in-the-debian-packaging-system-to-detect-supply-chain-attacks/) - (git tag)[https://github.com/Fraunhofer-AISEC/supply-graph/releases/tag/v0.1] - (slices)[doc/FOSDEM_2025_Lightning_Talk_Supply_Graph.pdf]
* [ALPSS 2025 -  Detecting Supply Chain Attacks from the Filesystem Level with eBPF, fanotify and others](https://alpss.at/#schedule) - (git - tag)[https://github.com/Fraunhofer-AISEC/supply-graph/releases/tag/v0.2] - (slides)[doc/ALPSS_2025_Talk_File_System_Monitoring.pdf]

## Requirements
* sudo
* python uv
* bpftrace
* debuild
* chroot
* libfuse
* kuzu graph database

## Architecture

The implementation uses a combination of bpftrace and a custom fuse overlay filesystem to capture all filesystem and IPC (pipe) communication during the build process.
Notable:
* build processes (escpecially autotools) do wired stuff like overwrite files with different content, move, copy
* some compilation steps communicatio not only via files, but also via pipe (stdin/stdout)

Main entry point is the (build.sh)[bin/build.sh] script, which orchestrates the package build and monitoring part.

## alternatie build tracing methods
There exist different methods on linux to trace what happs inside a build system.
Some have been also tryied as part of this project:
* llvm compile commands (bear, CodeChecker analyze)
* fanotify

## Docker
Problems with docker:
* bpftrace does currently not work inside docker (https://github.com/bpftrace/bpftrace/issues/4384)
* different views regarding PIN namepsace between eBPF (kernel space) and fuse-fs (userspace/inside container)

Possible solution:
run only build step inside container and monitor from outside

## Analyze build process
With the preparation script, the following Debian packet builds can be downloaded:
* xz-5.6.1 (CVE-2024-3094)
* xz-5.6.2
* openssh-9.2p1
* openssl-3.0.15

```
./preaper.sh
ls data/
openssh-9.2p1/  openssl-3.0.15/  xz-5.6.1/  xz-5.6.2/
make
make install
uv sync
```

Run the analysis:
```
sudo ./bin/build.sh data/xz-5.6.1/xz-utils_5.6.1-1.dsc
uv run analyze-fuse-graph data/xz-5.6.1/
```

Identified anomalies in the supply graph are displayed at the end of the log:
```
[...]
Import into Kuzu DB...
Analyzing Graph...
[...]
```
```json
{
    "object-source-proc": [
        "as",
        "cp",
        "head",
        "ld",
        "strip"
    ],
    "bad-object-source": [
        {
            "_id": {
                "offset": 3763,
                "table": 1
            },
            "_label": "File",
            "hash": "b418bfd34aa246b2e7b5cb5d263a640e5d080810f767370c4d2c24662a2749634735887",
            "inode": "4735887",
            "sha256": "b418bfd34aa246b2e7b5cb5d263a640e5d080810f767370c4d2c24662a274963",
            "path": "/home/tobias/Downloads/supply-graph-github/data/xz-5.6.1/xz-utils-5.6.1/debian/normal-build/src/liblzma/liblzma_la-crc64-fast.o",
            "name": "liblzma_la-crc64-fast.o",
            "type": ".o",
            "is_upstream": false
        }
    ],
    "top-level-file-types": [
        "",
        ".0t",
        ".1",
        ".Debian",
        ".ac",
        ".am",
        ".docs",
        ".gmo",
        ".in",
        ".inc",
        ".lzma",
        ".m4",
        ".map"
    ]
}
```

## Artifacts
The following build artifacts are available:
* bpftrace.json (IPC communication trace)
* fuse.json (filesystem trace)
* build.log (log of packet build)
* db.kuzu (kuzu graph database popolated with supply graph)
* packet.files.csv (list of files per Debian packet)
* upstream_files.txt (list of files in upstream archive)
* result.json (analysis result with any anomalies)

## Visualize supply graph
Use kuzu web ui to brows and vidualize the graph:
```
docker run -p 8000:8000 \
    -v ./data/xz-5.6.1/db:/database:Z \
    -e KUZU_FILE=db.kuzu \
    --rm kuzudb/explorer:latest 
```

# Futur work
* make it compatibel with docker
* try https://tetragon.io/ instead of bpftrace

## Acknowledgments

This work was funded by the German Federal Ministry of Education and Research (BMBF) as part of the [ALPAKA](https://www.forschung-it-sicherheit-kommunikationssysteme.de/projekte/alpaka) project.