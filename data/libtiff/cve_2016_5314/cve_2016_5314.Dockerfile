FROM ubuntu:16.04

RUN apt-get update
RUN apt-get -y upgrade
RUN apt-get install -y build-essential git vim unzip python-dev python-pip ipython zlib1g-dev

WORKDIR /root
COPY ./exploit /root/exploit
COPY ./source.zip /root/source.zip

WORKDIR /root
RUN unzip source.zip
WORKDIR /root/source
RUN ./configure
RUN make CFLAGS="-static -ggdb" CXXFLAGS="-static -ggdb"

