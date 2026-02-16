# Supply Graph

Detecting supply chain attacks in Debian package builds through graph-based build system tracing.

> [!CAUTION]
> This project contains the CVE-2024-3094 and is only meant for research and demonstration purposes!

> [!WARNING]
> This project is not maintained and is for research purposes only!

## Overview

This project uses the XZ Upstream Supply Chain Attack ([CVE-2024-3094](https://nvd.nist.gov/vuln/detail/CVE-2024-3094)) as a case study to demonstrate how supply chain attacks can be detected by tracing the build system with a graph-based approach.

C/C++ build systems (GNU autotools, Make, CMake) have grown highly complex, exposing a large attack surface. However, at their core, these build systems all compile source code to object files and link them into executables or libraries. For FLOSS projects, we can postulate that every binary must originate from source code within the upstream project. This relationship is modeled as a directed graph — by traversing it, we can verify that all distributed binaries originate from upstream source code, successfully detecting the supply chain attack.

Further studies could scale this approach to analyze all Debian packages regularly to detect anomalies early. To make attacks harder to conceal, the authors propose transitioning to a descriptive build system, which reduces complexity and increases transparency.

## Publications

* [FOSDEM 2025 — Finding Anomalies in the Debian Packaging System to Detect Supply Chain Attacks](https://fosdem.org/2025/schedule/event/fosdem-2025-5224-finding-anomalies-in-the-debian-packaging-system-to-detect-supply-chain-attacks/) — [git tag](https://github.com/Fraunhofer-AISEC/supply-graph/releases/tag/v0.1) — [slides](doc/FOSDEM_2025_Lightning_Talk_Supply_Graph.pdf)
* [ALPSS 2025 — Detecting Supply Chain Attacks from the Filesystem Level with eBPF, fanotify and others](https://alpss.at/#schedule) — [git tag](https://github.com/Fraunhofer-AISEC/supply-graph/releases/tag/v0.2) — [slides](doc/ALPSS_2025_Talk_File_System_Monitoring.pdf)

## Related Work

* Matthew Suozzo, FOSDEM 2026, [Trust Nothing, Trace Everything: Auditing Package Builds at Scale with OSS Rebuild](https://fosdem.org/2026/schedule/event/EP8AMW-oss-rebuild-observability/)

## Architecture

The implementation uses a combination of **bpftrace** and a custom **FUSE overlay filesystem** to capture all filesystem and IPC (pipe) communication during the build process.

The **supply graph** is a directed graph representing data flow during a Debian package build:

* **Nodes**: Processes (compiler, linker, shell, etc.) and Files (source, object, binary)
* **Edges**: Read, Write, Spawn, and Pipe relationships between nodes

By verifying that all distributed binaries (`.o`, `.a`, executables) are reachable from upstream source files through legitimate compilation processes, anomalies indicating supply chain attacks can be identified.

Notable challenges:
* Build processes (especially autotools) perform unexpected operations like overwriting files with different content, moving, and copying -> content and time relevance
* Some compilation steps communicate not only via files but also via pipes (stdin/stdout) -> just filesystem view is not sufficent

The main entry point is the [build.sh](bin/build.sh) script, which orchestrates the package build and monitoring.

### Alternative Build Tracing Methods

Different methods exist on Linux to trace what happens inside a build system. The following have been explored as part of this project:

* LLVM compile commands ([Bear](https://github.com/rizsotto/Bear), [CodeChecker log](https://github.com/Ericsson/codechecker))
* [fanotify](https://man7.org/linux/man-pages/man7/fanotify.7.html) ([fanotify_logger.c++](src/fanotify_logger.c++))

## Requirements

* Debian Linux (the current implementation does not support Docker and may modify the system)
* sudo access
* [uv](https://docs.astral.sh/uv/) (Python package manager)
* Python 3.12+
* C++ compiler (clang++)
* bpftrace
* debuild / dpkg-source
* chroot
* libfuse3
* [Kuzu](https://kuzudb.com/) graph database

## Getting Started

### 1. Build the C++ tools

```bash
make
sudo make install
```

### 2. Install Python dependencies

```bash
uv sync
```

### 3. Download test packages

The preparation script downloads the following Debian package sources:

* xz-5.6.1 (contains CVE-2024-3094)
* xz-5.6.2
* openssh-9.2p1
* openssl-3.0.15

```bash
./prepare.sh
```

### 4. Run the build analysis

```bash
sudo ./bin/build.sh data/xz-5.6.1/xz-utils_5.6.1-1.dsc
```

### 5. Analyze the supply graph

```bash
uv run analyze-fuse-graph data/xz-5.6.1/
```

Identified anomalies are displayed at the end of the log:

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
            "path": "/data/xz-5.6.1/xz-utils-5.6.1/debian/normal-build/src/liblzma/liblzma_la-crc64-fast.o",
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

The `liblzma_la-crc64-fast.o` object file is flagged as anomalous — it does not originate from upstream source code, which is the injected backdoor from CVE-2024-3094.

## Build Artifacts

Each analysis run produces the following artifacts in the package data directory:

| File | Description |
|------|-------------|
| `bpftrace.json` | IPC communication trace |
| `fuse.json` | Filesystem operation trace |
| `build.log` | Build process log |
| `db.kuzu` | Kuzu graph database populated with the supply graph |
| `packet.files.csv` | List of files per Debian package |
| `upstream_files.txt` | List of files in the upstream archive |
| `result.json` | Analysis result with detected anomalies |

## Visualize the Supply Graph

Use the Kuzu web UI to browse and visualize the graph:

```bash
docker run -p 8000:8000 \
    -v ./data/xz-5.6.1/db:/database:Z \
    -e KUZU_FILE=db.kuzu \
    --rm kuzudb/explorer:latest
```

Then open http://localhost:8000 in your browser.

## Docker Limitations

bpftrace does not currently work inside Docker ([bpftrace#4384](https://github.com/bpftrace/bpftrace/issues/4384)), and there are PID namespace mismatches between eBPF (kernel space) and FUSE (userspace inside the container).

A possible workaround is to run the build step inside the container and monitor from outside.

## Future Work

* Docker compatibility
* Evaluate [Tetragon](https://tetragon.io/) as an alternative to bpftrace

## Acknowledgments

This work was funded by the German Federal Ministry of Education and Research (BMBF) as part of the [ALPAKA](https://www.forschung-it-sicherheit-kommunikationssysteme.de/projekte/alpaka) project.
