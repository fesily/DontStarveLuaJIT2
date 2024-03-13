FROM ubuntu:14.04

RUN apt-get update && apt-get install gcc make libreadline-dev libncurses-dev -y
RUN mkdir /home/output
COPY Makefile /home/lua51/
COPY ./src /home/lua51/src
WORKDIR /home/lua51
RUN  make clean  && make linux_so
CMD [ "cp", "/home/lua51/src/liblua.so", "/home/output/liblua51.so" ]
