FROM ubuntu:16.04

RUN apt-get update
RUN apt-get install -y build-essential 
RUN apt-get update
RUN apt-get install -y git vim unzip python-dev python-pip ipython libjpeg-dev

# asan
WORKDIR /root
COPY ./exploit /root/exploit

# normal
WORKDIR /root
RUN git clone https://github.com/vadz/libtiff.git
RUN mv libtiff source
WORKDIR /root/source
RUN git checkout 9a72a69
RUN ./configure
RUN make CFLAGS="-static -ggdb" CXXFLAGS="-static -ggdb"

