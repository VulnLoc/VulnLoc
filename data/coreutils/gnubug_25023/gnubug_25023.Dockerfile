FROM ubuntu:16.04

RUN apt-get update
RUN apt-get install -y build-essential 
RUN apt-get update
RUN apt-get install -y git vim unzip python-dev python-pip ipython autoconf autopoint bison gettext gperf texinfo wget

WORKDIR /root
RUN git clone https://github.com/coreutils/coreutils.git
RUN mv coreutils source
WORKDIR /root/source
RUN git checkout ca99c52
RUN ./bootstrap
RUN export FORCE_UNSAFE_CONFIGURE=1 && ./configure
RUN make CFLAGS="-ggdb" CXXFLAGS="-ggdb"

