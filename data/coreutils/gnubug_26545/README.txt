Patch:
https://github.com/coreutils/coreutils/commit/f4570a9e

PoC:


Command:
> cd /root/source/src
> touch abc
# ./shred -n<arg1> -s<arg2> abc
> ./shred -n4 -s7 abc

