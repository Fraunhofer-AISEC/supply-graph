#!/bin/bash
mkdir -p data
cd data

mkdir xz-5.6.1 && \
    wget -P xz-5.6.1 http://snapshot.debian.org/archive/debian/20240328T025657Z/pool/main/x/xz-utils/xz-utils_5.6.1-1.debian.tar.xz && \
    wget -P xz-5.6.1 http://snapshot.debian.org/archive/debian/20240328T025657Z/pool/main/x/xz-utils/xz-utils_5.6.1-1.dsc && \
    wget -P xz-5.6.1 http://snapshot.debian.org/archive/debian/20240328T025657Z/pool/main/x/xz-utils/xz-utils_5.6.1.orig.tar.xz && \
    wget -P xz-5.6.1 http://snapshot.debian.org/archive/debian/20240328T025657Z/pool/main/x/xz-utils/xz-utils_5.6.1.orig.tar.xz.asc

mkdir xz-5.6.2 && \
    wget -P xz-5.6.2 http://snapshot.debian.org/archive/debian/20240615T143109Z/pool/main/x/xz-utils/xz-utils_5.6.2-1.debian.tar.xz && \
    wget -P xz-5.6.2 http://snapshot.debian.org/archive/debian/20240615T143109Z/pool/main/x/xz-utils/xz-utils_5.6.2-1.dsc && \
    wget -P xz-5.6.2 http://snapshot.debian.org/archive/debian/20240615T143109Z/pool/main/x/xz-utils/xz-utils_5.6.2.orig.tar.xz && \
    wget -P xz-5.6.2 http://snapshot.debian.org/archive/debian/20240615T143109Z/pool/main/x/xz-utils/xz-utils_5.6.2.orig.tar.xz.asc


mkdir openssl-3.0.15 && \
    wget -P openssl-3.0.15 http://snapshot.debian.org/archive/debian/20241101T025324Z/pool/main/o/openssl/openssl_3.0.15-1~deb12u1.debian.tar.xz && \
    wget -P openssl-3.0.15 http://snapshot.debian.org/archive/debian/20241101T025324Z/pool/main/o/openssl/openssl_3.0.15-1~deb12u1.dsc && \
    wget -P openssl-3.0.15 http://snapshot.debian.org/archive/debian/20241101T025324Z/pool/main/o/openssl/openssl_3.0.15.orig.tar.gz && \
    wget -P openssl-3.0.15 http://snapshot.debian.org/archive/debian/20241101T025324Z/pool/main/o/openssl/openssl_3.0.15.orig.tar.gz.asc

mkdir openssh-9.2p1 && \
    wget -P openssh-9.2p1 http://snapshot.debian.org/archive/debian/20241208T204421Z/pool/main/o/openssh/openssh_9.2p1-2%2Bdeb12u4.debian.tar.xz && \
    wget -P openssh-9.2p1 http://snapshot.debian.org/archive/debian/20241208T204421Z/pool/main/o/openssh/openssh_9.2p1-2%2Bdeb12u4.dsc && \
    wget -P openssh-9.2p1 http://snapshot.debian.org/archive/debian-security/20231222T085454Z/pool/updates/main/o/openssh/openssh_9.2p1.orig.tar.gz && \
    wget -P openssh-9.2p1 http://snapshot.debian.org/archive/debian-security/20231222T085454Z/pool/updates/main/o/openssh/openssh_9.2p1.orig.tar.gz.asc
