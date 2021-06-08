FROM ubuntu:16.04

# install miscellaneous
RUN apt-get update
RUN apt-get install -y build-essential vim git wget unzip tar clang
RUN apt-get install -y nasm libass-dev libmp3lame-dev dh-autoreconf

# copy setup scripts & exploits
WORKDIR /root
COPY ./CVE_2017_9992-setup.zip /root
RUN unzip CVE_2017_9992-setup.zip
RUN rm CVE_2017_9992-setup.zip

# prepare libs
WORKDIR /root/sources/ffmpeg_deps
RUN ./build_ffmpeg.sh

# prepare main project
WORKDIR /root/sources/ffmpeg
RUN ./project_config.sh

# compile tool
#   w/o ASAN : consider using this to check heap overflow
#              see bugchrom_1404 for of using UBSAN
WORKDIR /root/sources/ffmpeg/project
RUN make tools/target_dec_cavs_fuzzer

# go home
WORKDIR /root
