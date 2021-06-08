FROM ubuntu:16.04

RUN apt-get update
RUN apt-get install -y build-essential 
RUN apt-get update
RUN apt-get install -y git vim unzip python-dev python-pip ipython autoconf libtool automake pkg-config

WORKDIR /root
RUN git clone https://gitlab.gnome.org/GNOME/libxml2.git
RUN mv libxml2 source
WORKDIR /root/source
RUN git checkout db07dd61
RUN ./autogen.sh
RUN make CFLAGS="-static -ggdb" CXXFLAGS="-static -ggdb"

COPY ./exploit /root/exploit
