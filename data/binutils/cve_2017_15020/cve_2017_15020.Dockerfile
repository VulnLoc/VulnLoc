FROM ubuntu:16.04

RUN apt-get update
RUN apt-get install -y build-essential 
RUN apt-get update
RUN apt-get install -y git vim unzip python-dev python-pip ipython zip libtool bison texinfo flex

WORKDIR /root
RUN git clone git://sourceware.org/git/binutils-gdb.git
WORKDIR /root/binutils-gdb
RUN git checkout 11855d8a1f11b102a702ab76e95b22082cccf2f8
RUN mv /root/binutils-gdb /root/source
WORKDIR /root/source
RUN CC=gcc CXX=g++ CFLAGS="-DFORTIFY_SOURCE=2 -ggdb -Wno-error" CXXFLAGS="$CFLAGS" ./configure --disable-shared --disable-gdb --disable-libdecnumber --disable-readline --disable-sim LIBS='-ldl -lutil'
RUN make CFLAGS="-ldl -lutil -static -ggdb" CXXFLAGS="-static -ldl -lutil -ggdb"

COPY ./exploit /root/exploit
