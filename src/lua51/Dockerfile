FROM ubuntu:14.04

RUN apt-get update && apt-get install g++ cmake -y
RUN mkdir /home/output
COPY CMakeLists.txt /home/lua51/
COPY ./src /home/lua51/src
RUN cd /home/lua51 && cmake -DCMAKE_BUILD_TYPE=Release . && cmake --build .
CMD [ "cp", "/home/lua51/liblua51.so", "/home/output/" ]