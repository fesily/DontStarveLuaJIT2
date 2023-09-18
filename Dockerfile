FROM ubuntu:23.04

RUN apt update
RUN apt install g++-13 cmake git make gdb curl zip unzip tar ninja-build pkg-config linux-libc-dev -y
RUN apt remove cpp -y && apt autoremove -y
RUN ln /usr/bin/gcc-13 /usr/bin/gcc && ln /usr/bin/g++-13 /usr/bin/g++
RUN git clone https://github.com/microsoft/vcpkg /opt/vcpkg
RUN /opt/vcpkg/bootstrap-vcpkg.sh