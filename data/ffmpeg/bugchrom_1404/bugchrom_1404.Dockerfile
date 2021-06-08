FROM ubuntu:16.04

# install miscellaneous
RUN apt-get update
RUN apt-get install -y build-essential vim git wget unzip tar clang
RUN apt-get install -y nasm valgrind libass-dev libmp3lame-dev dh-autoreconf

# copy setup scripts & exploits
WORKDIR /root
COPY ./BUGCHROM_1404-setup.zip /root
RUN unzip BUGCHROM_1404-setup.zip
RUN rm BUGCHROM_1404-setup.zip

# prepare libs
WORKDIR /root/sources/ffmpeg_deps
RUN ./build_ffmpeg.sh

# prepare main project
WORKDIR /root/sources/ffmpeg
RUN ./project_config.sh

# compile tool
#   w/  UBSAN : to check exploit (see project_config.sh)
WORKDIR /root/sources/ffmpeg/project
RUN make tools/target_dec_cavs_fuzzer

# go home
WORKDIR /root
