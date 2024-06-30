FROM ubuntu:22.04

ENV NPROC 4
ENV DEBIAN_FRONTEND noninteractive

# Get all packages
RUN apt update
RUN apt install -y git cmake libssl-dev

# Clone
WORKDIR /my
RUN git clone --depth 1 https://github.com/rtjk/CROSS-keccak-times4

# Build
WORKDIR /my/CROSS-keccak-times4/CROSS_submission_package_v1.2/Additional_Implementations/test_speed/
RUN rm -rf build; \
    mkdir build && \
    cd build && \
    cmake ../ && \
    make -j ${NPROC} && \
    cd ..

    
STOPSIGNAL SIGTERM
WORKDIR /my/CROSS-keccak-times4/CROSS_submission_package_v1.2/Additional_Implementations/test_speed/build/bin
ENTRYPOINT \
    # Open a shell
    /bin/bash && \
    # Run the speed test
    for file in *; do if [[ -x "$file" && ! -d "$file" ]]; then echo "$file"; ./"$file"; fi; done
