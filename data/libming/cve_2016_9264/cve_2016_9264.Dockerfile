FROM ubuntu:16.04

RUN apt-get update
RUN apt-get install -y build-essential 
RUN apt-get update
RUN apt-get install -y git vim unzip python-dev python-pip ipython libtool m4 automake bison flex libfreetype6-dev

WORKDIR /root
RUN git clone https://github.com/libming/libming.git
RUN mv libming source
WORKDIR /root/source
RUN git checkout cc6a386
RUN ./autogen.sh
RUN ./configure
RUN make CFLAGS="-static -ggdb" CXXFLAGS="-static -ggdb"

COPY ./exploit /root/exploit
