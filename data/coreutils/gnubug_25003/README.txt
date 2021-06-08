Patch:
https://github.com/coreutils/coreutils/commit/4954f79

PoC:


Command:
> cd /root/source/src
> touch 7
# ./split -n<arg1>/<arg2> 7
> ./split -n7/75 7

