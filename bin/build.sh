#!/bin/bash
set -e

if [ $# -lt 1 ]
then
    echo "Usage: build.sh <package.dsc>"
    exit 1
fi

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
export DEB_BUILD_OPTIONS='nocheck nodoc'
apt-get --no-download -y build-dep "$pkg_name"

# enter source directory
cd $source_dir

# create compilation database
debuild -- clean
export DEB_BUILD_OPTIONS="parallel=1"

debian/rules configure || true
. /opt/codechecker/venv/bin/activate
CC_LOGGER_ABS_PATH=true CodeChecker log -k --output "/tmp/compile_commands.json" --build "debian/rules build binary"

cp /tmp/compile_commands.json ../compile_commands.json
convert_cc.py ../compile_commands.json

ls ../*.deb|while read deb
do
    deb_=$(basename $deb)
    pkt=$(echo $deb_|awk -F_ '{print $1}')
    dpkg -c "$deb"| grep "^-"|awk -v pwd=$PWD -v pkt=$pkt '{print pwd"/debian/"pkt"/"$6}' | xargs -L1 realpath -m| awk -v deb="$deb_" '{print deb","$NF}'
done > ../packet.files.csv

orig_tar=`ls ../${pkg_name}_*.orig.tar.??`
echo "orig_tar: $orig_tar"
tar tf $orig_tar |while read line
do
    readlink -m $PWD/$(echo $line | cut -d'/' -f2-)
done > ../upstream_files.txt