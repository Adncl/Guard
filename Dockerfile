ARG BASE_IMAGE=public.ecr.aws/ubuntu/ubuntu:22.04
ARG GLLVM_VERSION=v1.3.1
FROM ${BASE_IMAGE}
ARG GLLVM_VERSION
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build clang-14 llvm-14 llvm-14-dev libclang-14-dev \
    libclang-cpp14-dev libcurl4-openssl-dev libsqlite3-dev nlohmann-json3-dev \
    python3 python3-pip python3-venv golang-go git ca-certificates pkg-config libssl-dev \
    libgraphviz-dev graphviz tshark tcpdump curl zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
RUN apt-get update && apt-get install -y --no-install-recommends file \
    && rm -rf /var/lib/apt/lists/*
RUN pip3 install --no-cache-dir openai==1.109.1 toml==0.10.2 tqdm==4.67.1 \
    scapy==2.6.1 lxml==6.0.2 html2text==2025.4.15 pandas==2.3.2 \
    openpyxl==3.1.5 tenacity==9.1.2 requests==2.32.5 cmake==3.27.9
RUN GOBIN=/usr/local/bin go install github.com/SRI-CSL/gllvm/cmd/...@${GLLVM_VERSION}
RUN ln -sf /usr/lib/x86_64-linux-gnu/libz3.so /usr/local/lib/libz3.so \
    && ln -sf /usr/include/z3++.h /usr/local/include/z3++.h
ENV CC=clang-14 CXX=clang++-14 LLVM_COMPILER_PATH=/usr/lib/llvm-14/bin \
    LLVM_CC_NAME=clang-14 LLVM_CXX_NAME=clang++ LLVM_LINK_NAME=llvm-link \
    LLVM_AR_NAME=llvm-ar WLLVM_BC_STORE=/workspace/output/gllvm-store \
    PYTHONUNBUFFERED=1 PYTHONPATH=/workspace
WORKDIR /workspace
RUN apt-get update && apt-get install -y --no-install-recommends libcap-dev \
    && rm -rf /var/lib/apt/lists/*
