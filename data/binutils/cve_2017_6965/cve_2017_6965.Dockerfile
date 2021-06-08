FROM ubuntu:16.04

RUN apt-get update
RUN apt-get install -y build-essential 
RUN apt-get update
RUN apt-get install -y git vim unzip python-dev python-pip ipython clang texinfo bison flex

WORKDIR /root
RUN git clone git://sourceware.org/git/binutils-gdb.git
RUN mv binutils-gdb source
WORKDIR /root/source
RUN git checkout 53f7e8ea7fad1fcff1b58f4cbd74e192e0bcbc1d
RUN CC=clang CFLAGS="-DFORTIFY_SOURCE=2 -ggdb -Wno-error" ./configure --disable-shared --disable-gdb --disable-libdecnumber --disable-readline --disable-sim
RUN make

COPY ./exploit /root/exploit
