#!/bin/bash
set -e

if [ $# -lt 1 ]
then
    echo "Usage: build.sh <package.dsc>"
    exit 1
fi

base_dir=$(realpath $(dirname $(realpath $0))/../)
pkt_dsc=$(realpath $1)
data_dir=$(dirname $pkt_dsc)
pkg_name=`basename $pkt_dsc|awk -F_ '{print $1}'`
if [ -z "$pkg_name" ]
then
    echo "Error: no valid packet dir: $source_dir"
    exit 1
fi
echo "packet name: $pkg_name"

build_dir=$data_dir

echo "Extract packet"
cd $build_dir

pkt_dir=$(find  -maxdepth 1 -mindepth 1 -type d)
if [ -d "$pkt_dir" ]
then
    pkt_dir=$(realpath $pkt_dir)
    echo "clean-up old packet dir: $pkt_dir"
    rm -rf $pkt_dir
fi

dpkg-source -x ${pkt_dsc}
pkt_dir=`basename $(find  -maxdepth 1 -mindepth 1 -type d)`
source_dir=`realpath $data_dir/$pkt_dir`


build_dep_dir="$source_dir/build-dep"
if [ ! -d "$source_dir" ]
then
    echo "Error: could not find package dir: $source_dir"
    exit 1
fi

# update package lists
apt-get update

# create package specific directories in workdir
rm -rf "$build_dep_dir"
mkdir "$build_dep_dir" # build dependencies

# download build dependencies to save them (in container cache is cleared after install)
apt-get -d -y build-dep "$pkg_name"

# install downloaded build dependencies
export DEB_BUILD_OPTIONS="nocheck nodoc parallel=1"
apt-get --no-download -y build-dep "$pkg_name"

# enter source directory
cd $source_dir

orig_tar=`ls ../${pkg_name}_*.orig.tar.??`
echo "orig_tar: $orig_tar"
tar tf $orig_tar |while read line
do
    path=$(readlink -m $PWD/$(echo $line | cut -d'/' -f2-))
    inode=-1
    hash=""
    if [ -f $path ]
    then
        inode=$(stat -c '%i' $path)
        hash=$(sha256sum $path|awk '{print $1}')
    fi
    echo $path,$inode,$hash
done > ../upstream_files.csv

deb_tar=`ls ../${pkg_name}_*.debian.tar.??`
echo "deb_tar: $deb_tar"
tar tf $deb_tar |while read line
do
    path=$(readlink -m $PWD/$(echo $line | cut -d'/' -f1-))
    inode=-1
    hash=""
    if [ -f $path ]
    then
        inode=$(stat -c '%i' $path)
        hash=$(sha256sum $path|awk '{print $1}')
    fi
    echo $path,$inode,$hash
done >> ../upstream_files.csv

# create compilation database
debuild -- clean

ulimit -n 512000
mkdir -p /tmp/data
mkdir -p /mnt/proc
mkdir -p /mnt/dev/pts
mkdir -p /mnt/sys/kernel/debug
fuse-hash-fs -f /mnt -o max_idle_threads=100000 2>../fuse.json 1> ../fuse.log &
FUSE_PID=$!
sleep 5
mount -o bind /proc /mnt/proc
mount -o bind /dev /mnt/dev
mount -o bind /dev/pts /mnt/dev/pts
mount -o bind /sys /mnt/sys
mount -o bind /sys/kernel/debug /mnt/sys/kernel/debug
mount -o bind $(realpath ..) /mnt/tmp/data
chroot /mnt $base_dir/bin/build_deb.sh $source_dir 2>&1 |tee ../build.log
umount /mnt/sys/kernel/debug
umount /mnt/sys
umount /mnt/dev/pts
umount /mnt/dev
umount /mnt/proc
umount /mnt/tmp/data
fusermount -u /mnt
wait $FUSE_PID

cd ..
ls *.deb|while read deb
do
    deb=$(realpath $deb)
    deb_=$(basename $deb)
    pkt=$(echo $deb_|awk -F_ '{print $1}')
    dpkg -c "$deb"| grep "^-"|awk -v pwd=$PWD -v pkt=$pkt '{print pwd"/debian/"pkt"/"$6}' | xargs -L1 realpath -m| awk -v deb="$deb" '{print deb","$NF}'
done > packet.files.csv

uv --project $base_dir run analyze-fuse-graph . |tee fuse-graph.log