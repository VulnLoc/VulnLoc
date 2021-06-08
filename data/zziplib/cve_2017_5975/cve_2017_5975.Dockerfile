FROM ubuntu:16.04

RUN apt-get update
RUN apt-get install -y build-essential 
RUN apt-get update
RUN apt-get install -y git vim unzip python-dev python-pip ipython zlib1g-dev wget

WORKDIR /root
RUN git clone https://github.com/gdraheim/zziplib.git
RUN mv zziplib source
WORKDIR /root/source
RUN git checkout 33d6e9c 
WORKDIR /root/source/docs
RUN wget https://github.com/LuaDist/libzzip/raw/master/docs/zziplib-manpages.tar
WORKDIR /root/source
RUN ./configure
RUN make CFLAGS="-static -ggdb" CXXFLAGS="-static -ggdb"

COPY ./exploit /root/exploit

