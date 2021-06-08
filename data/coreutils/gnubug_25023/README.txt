Patch:
https://github.com/coreutils/coreutils/commit/d91aee

PoC:


Command:
> cd /root/source/src/
> echo a > a
> ./pr "-S$(printf "\t\t\t")" a -m a

