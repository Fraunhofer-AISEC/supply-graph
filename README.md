# Supply Graph
In this project, the XZ Upstream Supply Chain Attack (CVE-2024-3094) is used as a case study to demonstrate how supply chain attacks can be detected by tracing the build system by a graph based approach. The increasing prevalence of supply chain attacks on Free/Libre Open Source Software (FLOSS) projects has been highlighted recently by the supply chain attack on the xz project to backdoor SSH servers. The detection of this particular attack was coincidental, raising concerns about potentially undetected threats.

C/C++ build systems, such as GNU autotools, Make, and CMake, have grown highly complex and diverse, exposing a large attack surface to exploit. However, essentially, these build systems all compile the source code to object files and link them together to executables or libraries. For FLOSS projects, we can be even more stringent by postulating that every binary must originate from source code within the upstream project. Technically, this relationship can be modeled by the help of a graph data structure. By traversing this graph, it can be ensured that all distributed binaries originate from upstream source code showcasing the successful detection of the supply chain attack.

Further studies could scale this approach to analyze all Debian packages regularly to detect anomalies early. To prevent attacks (or at least make them harder to conceal), the authors further propose transitioning to a descriptive build system, which reduces complexity and increases transparency, making separate tracing unnecessary.

> [!CAUTION]
> This project contains the CVE-2024-3094 and is only meant for research and demonstration purpose!

> [!WARNING]
> This project is not maintained. It has been published as part of the following conference talk: [FOSDEM 2025](https://fosdem.org/2025/schedule/event/fosdem-2025-5224-finding-anomalies-in-the-debian-packaging-system-to-detect-supply-chain-attacks/)

## Build docker image
Build the docker image local
```
docker build -t supply-graph:main .
```

Or pull from github container registry:
```
docker pull ghcr.io/fraunhofer-aisec/supply-graph:main
```

## Analyze build process
In the docker container, the following Debian packet builds are included:
* xz-5.6.1 (CVE-2024-3094)
* xz-5.6.2
* openssh-9.2p1
* openssl-3.0.15

Run the analysis:
```
docker run --rm -it supply-graph:main
analyze-build-graph xz-5.6.1
```
Identified anomalies in the supply graph are displayed at the end of the log:
```
[...]
Root files not part of upstream:
* /data/xz-5.6.1/xz-utils-5.6.1/debian/normal-build/src/liblzma/liblzma_la-crc64-fast.o
Binary files without corresponding source code:
* /data/xz-5.6.1/xz-utils-5.6.1/debian/normal-build/src/liblzma/liblzma_la-crc64-fast.o
```

## Download artifacts
The following build artifacts are available:
* edges.csv (supply graph edge list)
* nodes.csv (supply graph node list)
* compile_commands.json (trace of build process)
* packet.files.csv (list of files per Debian packet)
* upstream_files.txt (list of files in upstream archive)

Download the artifacts from the container:
```
docker cp <Container-ID>:/data/xz-5.6.1/edges.csv .
docker cp <Container-ID>:/data/xz-5.6.1/nodes.csv .
```

## Visualize supply graph
Use `nodes.csv` and `edges.csv` to visualize the supply graph.
E.g. with: https://cytoscape.org/

## Acknowledgments

This work was funded by the German Federal Ministry of Education and Research (BMBF) as part of the [ALPAKA](https://www.forschung-it-sicherheit-kommunikationssysteme.de/projekte/alpaka) project.