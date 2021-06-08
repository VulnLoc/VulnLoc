FROM ubuntu:16.04

RUN apt-get update
RUN apt-get install -y build-essential 
RUN apt-get update
RUN apt-get install -y git vim unzip python-dev python-pip ipython autoconf libtool nasm

WORKDIR /root
RUN git clone https://github.com/libjpeg-turbo/libjpeg-turbo.git
RUN mv libjpeg-turbo source
WORKDIR /root/source
RUN git checkout 4f24016
RUN autoreconf -fiv
RUN ./configure
RUN make CFLAGS="-static -ggdb" CXXFLAGS="-static -ggdb"

COPY ./exploit /root/exploit

