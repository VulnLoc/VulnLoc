FROM ubuntu:16.04

RUN apt-get update
RUN apt-get install -y build-essential 
RUN apt-get update
RUN apt-get install -y git vim unzip python-dev python-pip ipython zip libtool bison texinfo flex

WORKDIR /root
RUN git clone git://sourceware.org/git/binutils-gdb.git
RUN mv binutils-gdb source
WORKDIR /root/source
RUN git checkout 7a31b38ef87d133d8204cae67a97f1989d25fa18
RUN CC=gcc CXX=g++ CFLAGS="-DFORTIFY_SOURCE=2 -ggdb -Wno-error" CXXFLAGS="$CFLAGS" ./configure --disable-shared --disable-gdb --disable-libdecnumber --disable-readline --disable-sim LIBS='-ldl -lutil'
RUN make CFLAGS="-ldl -lutil -ggdb -static" CXXFLAGS="-ldl -lutil -ggdb -static"

COPY ./exploit /root/exploit

