ARG DEBIAN_RELEASE=bookworm

FROM debian:${DEBIAN_RELEASE}-slim AS builder
ARG DEBIAN_RELEASE

RUN apt-get update && apt-get install -y --no-install-recommends \
    software-properties-common \
    bear \
    build-essential \
    curl \
    devscripts \
    fakeroot \
    git \
    lsb-release \
    wget \
    netselect-apt \
    clang \
    python3-pip \
    python3-dev \
    python3-setuptools \
    python3-venv \
    debian-keyring

WORKDIR /opt
RUN git clone https://github.com/peckto/codechecker
WORKDIR /opt/codechecker
RUN git checkout ar
RUN make venv && \
    . /opt/codechecker/venv/bin/activate && \
    BUILD_UI_DIST=NO BUILD_LOGGER_64_BIT_ONLY=YES make package
ENV PATH=/opt/codechecker/build/CodeChecker/bin:$PATH
ENV LD_LIBRARY_PATH=/opt/codechecker/build/CodeChecker/ld_logger/lib/x86_64/


RUN apt-add-repository -s -y "deb-src http://deb.debian.org/debian ${DEBIAN_RELEASE} main contrib non-free"
RUN apt-add-repository -s -y "deb-src http://deb.debian.org/debian ${DEBIAN_RELEASE}-updates main contrib non-free"
RUN apt-add-repository -s -y "deb-src https://security.debian.org/debian-security ${DEBIAN_RELEASE}-security main contrib non-free"

RUN apt-add-repository -s -y "deb-src http://deb.debian.org/debian ${DEBIAN_RELEASE} main contrib non-free"
RUN apt-add-repository -s -y "deb-src http://deb.debian.org/debian ${DEBIAN_RELEASE}-updates main contrib non-free"
RUN apt-add-repository -s -y "deb-src https://security.debian.org/debian-security ${DEBIAN_RELEASE}-security main contrib non-free"

RUN mkdir /data
WORKDIR /data

RUN mkdir xz-5.6.1 && \
    wget -P xz-5.6.1 http://snapshot.debian.org/archive/debian/20240328T025657Z/pool/main/x/xz-utils/xz-utils_5.6.1-1.debian.tar.xz && \
    wget -P xz-5.6.1 http://snapshot.debian.org/archive/debian/20240328T025657Z/pool/main/x/xz-utils/xz-utils_5.6.1-1.dsc && \
    wget -P xz-5.6.1 http://snapshot.debian.org/archive/debian/20240328T025657Z/pool/main/x/xz-utils/xz-utils_5.6.1.orig.tar.xz && \
    wget -P xz-5.6.1 http://snapshot.debian.org/archive/debian/20240328T025657Z/pool/main/x/xz-utils/xz-utils_5.6.1.orig.tar.xz.asc

RUN mkdir xz-5.6.2 && \
    wget -P xz-5.6.2 http://snapshot.debian.org/archive/debian/20240615T143109Z/pool/main/x/xz-utils/xz-utils_5.6.2-1.debian.tar.xz && \
    wget -P xz-5.6.2 http://snapshot.debian.org/archive/debian/20240615T143109Z/pool/main/x/xz-utils/xz-utils_5.6.2-1.dsc && \
    wget -P xz-5.6.2 http://snapshot.debian.org/archive/debian/20240615T143109Z/pool/main/x/xz-utils/xz-utils_5.6.2.orig.tar.xz && \
    wget -P xz-5.6.2 http://snapshot.debian.org/archive/debian/20240615T143109Z/pool/main/x/xz-utils/xz-utils_5.6.2.orig.tar.xz.asc


RUN mkdir openssl-3.0.15 && \
    wget -P openssl-3.0.15 http://snapshot.debian.org/archive/debian/20241101T025324Z/pool/main/o/openssl/openssl_3.0.15-1~deb12u1.debian.tar.xz && \
    wget -P openssl-3.0.15 http://snapshot.debian.org/archive/debian/20241101T025324Z/pool/main/o/openssl/openssl_3.0.15-1~deb12u1.dsc && \
    wget -P openssl-3.0.15 http://snapshot.debian.org/archive/debian/20241101T025324Z/pool/main/o/openssl/openssl_3.0.15.orig.tar.gz && \
    wget -P openssl-3.0.15 http://snapshot.debian.org/archive/debian/20241101T025324Z/pool/main/o/openssl/openssl_3.0.15.orig.tar.gz.asc

RUN mkdir openssh-9.2p1 && \
    wget -P openssh-9.2p1 http://snapshot.debian.org/archive/debian/20241208T204421Z/pool/main/o/openssh/openssh_9.2p1-2%2Bdeb12u4.debian.tar.xz && \
    wget -P openssh-9.2p1 http://snapshot.debian.org/archive/debian/20241208T204421Z/pool/main/o/openssh/openssh_9.2p1-2%2Bdeb12u4.dsc && \
    wget -P openssh-9.2p1 http://snapshot.debian.org/archive/debian-security/20231222T085454Z/pool/updates/main/o/openssh/openssh_9.2p1.orig.tar.gz && \
    wget -P openssh-9.2p1 http://snapshot.debian.org/archive/debian-security/20231222T085454Z/pool/updates/main/o/openssh/openssh_9.2p1.orig.tar.gz.asc

COPY bin/ /bin/

RUN build.sh xz-5.6.1/xz-utils_5.6.1-1.dsc && \
    build.sh xz-5.6.2/xz-utils_5.6.2-1.dsc && \
    build.sh openssl-3.0.15/openssl_3.0.15-1~deb12u1.dsc && \
    build.sh openssh-9.2p1/openssh_9.2p1-2+deb12u4.dsc && \
    rm -rf openssl-3.0.15/openssl-3.0.15/build_shared && \
    rm -rf openssl-3.0.15/openssl-3.0.15/build_static && \
    rm -rf */*/debian/tmp

FROM debian:${DEBIAN_RELEASE}-slim
ARG DEBIAN_RELEASE

RUN apt-get update && apt-get install -y --no-install-recommends \
    software-properties-common \
    curl

RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH=/root/.local/bin:/opt/supply-graph/bin/:$PATH
ENV UV_PROJECT_ENVIRONMENT=/opt/supply-graph/venv/
ENV VIRTUAL_ENV=/opt/supply-graph/venv/

COPY --from=builder /data /data/
COPY . /opt/supply-graph

WORKDIR /opt/supply-graph
RUN uv sync && \
    ln -s /opt/supply-graph/venv/bin/analyze-build-graph /opt/supply-graph/bin/analyze-build-graph

WORKDIR /data