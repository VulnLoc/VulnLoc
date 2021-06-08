FROM ubuntu:16.04

RUN apt-get update
RUN apt-get install -y build-essential 
RUN apt-get update
RUN apt-get install -y git vim unzip python-dev python-pip ipython cmake nasm

WORKDIR /root
RUN git clone https://github.com/libjpeg-turbo/libjpeg-turbo.git
RUN mv libjpeg-turbo source
WORKDIR /root/source
RUN git checkout 0fa7850
RUN export CXXFLAGS="-ggdb"
RUN export CFLAGS="-ggdb"
RUN cmake CMakeLists.txt
RUN make

COPY ./exploit /root/exploit

