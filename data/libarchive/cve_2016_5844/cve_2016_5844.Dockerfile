FROM ubuntu:16.04

# install miscellaneous
RUN apt-get update
RUN apt-get install -y build-essential vim wget unzip

# copy exploit
WORKDIR /root/exploit
COPY CVE_2016_5844-setup.zip /root/exploit
RUN unzip CVE_2016_5844-setup.zip
RUN rm CVE_2016_5844-setup.zip

# download libarchive source (v3.2.0)
WORKDIR /root
RUN wget https://libarchive.org/downloads/libarchive-3.2.0.zip
RUN unzip libarchive-3.2.0.zip
RUN rm libarchive-3.2.0.zip
RUN mv libarchive-3.2.0 sources

# compile bsdtar
#   w/o OPENSSL : type inconsistency introduced around v1.1.0
#   w/  UBSAN   : to check exploit
WORKDIR /root/sources
RUN ./configure --without-openssl
RUN make CFLAGS="-ggdb"

# go home
WORKDIR /root
