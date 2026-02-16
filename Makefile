all:
	clang++ -std=c++20 -g $(shell pkg-config fuse3 --cflags)  -lcrypto -DBOOST_PROCESS_USE_STD_FS -lboost_filesystem src/supply-graph.c++ src/fanotify_logger.c++ src/common.c++ -o supply-graph $(shell pkg-config fuse3 --libs)
	clang++ -std=c++20 -g $(shell pkg-config fuse3 --cflags) -lcrypto -DFUSE_MAIN src/fuse-hash-fs.c++ src/common.c++ -o fuse-hash-fs $(shell pkg-config fuse3 --libs)
install:
	cp supply-graph /usr/bin/
	cp fuse-hash-fs /usr/bin/
