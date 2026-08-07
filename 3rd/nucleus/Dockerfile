FROM ubuntu
RUN apt-get update
RUN apt-get -y install software-properties-common
RUN add-apt-repository -y ppa:ubuntu-toolchain-r/test
RUN apt-get update
RUN apt-get -y install gcc-4.9 g++-4.9
RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-4.9 60 --slave /usr/bin/g++ g++ /usr/bin/g++-4.9
RUN apt-get -y install build-essential
RUN apt-get -y install libc6-dbg gdb valgrind
RUN apt-get -y install binutils-dev
RUN apt-get -y install strace
RUN apt-get -y install ltrace
RUN apt-get -y install vim-common
RUN apt-get -y install libbfd-dev
RUN apt-get -y install binutils-multiarch-dev
RUN apt-get -y install libcapstone-dev
CMD ["/bin/bash"]
