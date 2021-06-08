Patch:
https://github.com/vadz/libtiff/commit/c7153361a4041260719b340f73f2f76b0969235c

PoC:
http://bugzilla.maptools.org/show_bug.cgi?id=2640
https://github.com/asarubbo/poc/blob/master/00112-libtiff-heapoverflow-_TIFFmemcpy

Command: 
> cd /root/source/tools
> ./tiff2pdf ./exploit -o foo

