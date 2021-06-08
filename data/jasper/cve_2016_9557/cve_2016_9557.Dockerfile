FROM ubuntu:16.04

RUN apt-get update
RUN apt-get install -y build-essential 
RUN apt-get update
RUN apt-get install -y git vim unzip python-dev python-pip ipython autoconf libtool

WORKDIR /root
COPY ./source.zip /root/source.zip
RUN unzip source.zip
WORKDIR /root/source
RUN autoreconf -i
RUN ./configure
RUN make CFLAGS="-static -ggdb" CXXFLAGS="-static -ggdb"

COPY ./exploit /root/exploit
