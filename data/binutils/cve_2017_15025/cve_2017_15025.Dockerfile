FROM ubuntu:16.04

RUN apt-get update
RUN apt-get install -y build-essential 
RUN apt-get update
RUN apt-get install -y git vim unzip python-dev python-pip ipython texinfo bison flex

WORKDIR /root
RUN git clone git://sourceware.org/git/binutils-gdb.git
RUN mv binutils-gdb source
WORKDIR /root/source
RUN git checkout 515f23e63c0074ab531bc954f84ca40c6281a724
RUN CC=gcc CXX=g++ CFLAGS="-DFORTIFY_SOURCE=2 -fno-omit-frame-pointer -ggdb -Wno-error" CXXFLAGS="$CFLAGS" ./configure --disable-shared --disable-gdb --disable-libdecnumber --disable-readline --disable-sim
RUN make

COPY ./exploit /root/exploit
