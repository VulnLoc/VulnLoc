FROM ubuntu:16.04

# Dependencies
RUN apt update --fix-missing
RUN apt install -y build-essential 
RUN apt install -y git vim unzip python-dev python-pip ipython wget libssl-dev g++-multilib doxygen transfig imagemagick ghostscript zlib1g-dev

WORKDIR /root
RUN mkdir workspace
WORKDIR /root/workspace
RUN mkdir deps
WORKDIR /root/workspace/deps

# Installing numpy
RUN wget https://github.com/numpy/numpy/releases/download/v1.16.6/numpy-1.16.6.zip
RUN unzip numpy-1.16.6.zip
RUN rm numpy-1.16.6.zip
RUN mv numpy-1.16.6 numpy
WORKDIR /root/workspace/deps/numpy
RUN python setup.py install
WORKDIR /root/workspace/deps

# install pyelftools
RUN pip install pyelftools

# install CMake
RUN wget https://github.com/Kitware/CMake/releases/download/v3.16.2/cmake-3.16.2.tar.gz
RUN tar -xvzf cmake-3.16.2.tar.gz
RUN rm cmake-3.16.2.tar.gz
RUN mv cmake-3.16.2 cmake
WORKDIR /root/workspace/deps/cmake
RUN ./bootstrap
RUN make
RUN make install
WORKDIR /root/workspace/deps

# install dynamorio
RUN git clone https://github.com/DynamoRIO/dynamorio.git
WORKDIR /root/workspace/deps/dynamorio
RUN mkdir build
WORKDIR /root/workspace/deps/dynamorio/build
RUN cmake ../
RUN make
WORKDIR /root/workspace/deps

# set up the tracer
COPY ./code/iftracer.zip /root/workspace/deps/iftracer.zip
RUN unzip iftracer.zip
RUN rm iftracer.zip
WORKDIR /root/workspace/deps/iftracer/iftracer
RUN cmake CMakeLists.txt
RUN make
WORKDIR /root/workspace/deps/iftracer/ifLineTracer
RUN cmake CMakeLists.txt
RUN make
WORKDIR /root/workspace 

# set up CVE-2016-5314
RUN mkdir cves
WORKDIR /root/workspace/cves
RUN mkdir cve_2016_5314
WORKDIR /root/workspace/cves/cve_2016_5314
RUN apt install -y build-essential git vim unzip python-dev python-pip ipython zlib1g-dev
COPY ./data/libtiff/cve_2016_5314/source.zip ./source.zip
RUN unzip source.zip
RUN rm source.zip
WORKDIR /root/workspace/cves/cve_2016_5314/source
RUN ./configure
RUN make CFLAGS="-static -ggdb" CXXFLAGS="-static -ggdb"
# copy exploit
WORKDIR /root/workspace/cves/cve_2016_5314
COPY ./data/libtiff/cve_2016_5314/exploit ./exploit
# setup an exploit detector for cve-2016-5314 --- valgrind
WORKDIR /root/workspace/deps
RUN apt install -y libc6-dbg
RUN wget https://sourceware.org/pub/valgrind/valgrind-3.15.0.tar.bz2
RUN tar xjf valgrind-3.15.0.tar.bz2
RUN mv valgrind-3.15.0 valgrind
WORKDIR /root/workspace/deps/valgrind
RUN ./configure
RUN make
RUN make install

# prepare code
WORKDIR /root/workspace
RUN mkdir code
WORKDIR /root/workspace/code
COPY ./code/fuzz.py ./
COPY ./code/parse_dwarf.py ./
COPY ./code/patchloc.py ./
COPY ./code/tracer.py ./
COPY ./code/utils.py ./
COPY ./code/env.py ./

WORKDIR /root/workspace
