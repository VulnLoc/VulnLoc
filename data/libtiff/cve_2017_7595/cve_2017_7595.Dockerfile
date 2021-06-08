FROM ubuntu:16.04

RUN apt-get update
RUN apt-get -y upgrade
RUN apt-get install -y build-essential git vim unzip python-dev python-pip ipython libjpeg-dev

WORKDIR /root
COPY ./exploit /root/exploit

WORKDIR /root
RUN git clone https://github.com/vadz/libtiff.git
RUN mv libtiff source
WORKDIR /root/source
RUN git checkout 2c00d31
RUN ./configure
RUN make CFLAGS="-static -ggdb" CXXFLAGS="-static -ggdb"
