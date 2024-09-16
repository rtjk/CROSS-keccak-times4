# This Dockerfile shows how to build and run the speed test
# Actual tests are run on bare-metal, not in Docker

# Build and run:
# docker build --no-cache -t cross-keccak-times4-image .
# docker run --rm -it cross-keccak-times4-image

FROM ubuntu:22.04

ENV NPROC 4
ENV DEBIAN_FRONTEND noninteractive

# Get all packages
RUN apt update
RUN apt install -y git cmake libssl-dev

# Clone
WORKDIR /my
RUN git clone --depth 1 https://github.com/rtjk/CROSS-keccak-times4

# Alternatively clone the baseline branch (no parallel keccak)
#RUN git clone --depth 1 -b serial-baseline https://github.com/rtjk/CROSS-keccak-times4

# Build
WORKDIR /my/CROSS-keccak-times4/CROSS_submission_package_v1.2/Additional_Implementations/Benchmarking/
RUN rm -rf build; \
    mkdir build && \
    cd build && \
    cmake ../ && \
    make -j ${NPROC} && \
    cd ..

# TODO: set CPU frqeuency to min using cpu-freq to make test more repeatable

# Run speed test and save results to log.txt
RUN ./bench_all.sh

STOPSIGNAL SIGTERM
ENTRYPOINT cat log.txt && /bin/bash
