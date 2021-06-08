Patch:
https://github.com/vadz/libtiff/commit/0a76a8c765c7b8327c59646284fa78c3c27e5490

PoC:
https://blogs.gentoo.org/ago/2017/04/01/libtiff-multiple-ubsan-crashes/
https://github.com/asarubbo/poc/blob/master/00119-libtiff-shift-long-tif_jpeg

Command:
> cd /root/source/tools
> ./tiffcp -i /root/exploit foo

