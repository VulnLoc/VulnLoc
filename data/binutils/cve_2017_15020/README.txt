Patch:
https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;h=1da5c9a485f3dcac4c45e96ef4b7dae5948314b5

PoC:
https://blogs.gentoo.org/ago/2017/10/03/binutils-heap-based-buffer-overflow-in-parse_die-dwarf1-c/
https://github.com/asarubbo/poc/blob/master/00376-binutils-heapoverflow-parse_die

Command:
> cd /root/source/binutils
> ./nm-new -A -a -l -S -s --special-syms --synthetic --with-symbol-versions -D /root/exploit
