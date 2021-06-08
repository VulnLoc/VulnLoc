Patch:
https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;h=d8010d3e75ec7194a4703774090b27486b742d48

PoC:
https://sourceware.org/bugzilla/show_bug.cgi?id=22186

Command:
> cd /root/source/binutils
> ./nm-new -A -a -l -S -s --special-syms --synthetic --with-symbol-versions /root/exploit

dwarf2.c:2442:34: runtime error: division by zero
Floating point exception (core dumped)

