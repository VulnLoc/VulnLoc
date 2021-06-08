Patch:
https://github.com/vadz/libtiff/commit/5ed9fea523316c2f5cec4d393e4d5d671c2dbc33

PoC:
http://bugzilla.maptools.org/show_bug.cgi?id=2633
https://github.com/asarubbo/poc/blob/master/00107-libtiff-heapoverflow-PSDataColorContig

Command:
> cd /root/source/tools
> ./tiff2ps /root/exploit
