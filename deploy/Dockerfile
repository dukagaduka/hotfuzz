FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        cmake \
        coreutils \
        gosu \
        ninja-build \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /workspace /workspace/.hotfuzz-build /workspace/hotfuzz_output \
    && chmod 0777 /workspace /workspace/.hotfuzz-build /workspace/hotfuzz_output

WORKDIR /opt/hotfuzz

COPY CMakeLists.txt README.md main.cpp ./
COPY include ./include
COPY third_party ./third_party

RUN cmake -S . -B /tmp/hotfuzz-smoke -G Ninja -DCMAKE_BUILD_TYPE=Release \
    && cmake --build /tmp/hotfuzz-smoke --target app --parallel \
    && rm -rf /tmp/hotfuzz-smoke

RUN (sha256sum CMakeLists.txt; find include third_party -type f -print0 | sort -z | xargs -0 sha256sum) \
    | sha256sum \
    | cut -d ' ' -f 1 > /opt/hotfuzz/.hotfuzz-source.sha256

COPY deploy/entrypoint.sh /usr/local/bin/hotfuzz-run
RUN chmod +x /usr/local/bin/hotfuzz-run

ENV HOTFUZZ_MAIN_CPP=/workspace/main.cpp
ENV HOTFUZZ_BUILD_DIR=/workspace/.hotfuzz-build
ENV HOTFUZZ_OUTPUT_DIR=/workspace/hotfuzz_output
ENV HOTFUZZ_BUILD_TYPE=Release
ENV HOTFUZZ_RUN_USER=hotfuzz
ENV HOTFUZZ_RUN_UID=1000
ENV HOTFUZZ_RUN_GID=1000
ENV HOTFUZZ_UMASK=000

WORKDIR /workspace

ENTRYPOINT ["/usr/local/bin/hotfuzz-run"]
