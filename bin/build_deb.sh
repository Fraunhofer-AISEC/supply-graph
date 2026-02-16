#!/bin/bash
set -e

# install downloaded build dependencies
export DEB_BUILD_OPTIONS="nocheck nodoc parallel=1"
bin_dir=$(dirname $(realpath $0))

# enter source directory
cd $1
bpftrace $bin_dir/trace_pipe_inode.bpftrace -c "make -f debian/rules build binary" -o /tmp/data/bpftrace.json