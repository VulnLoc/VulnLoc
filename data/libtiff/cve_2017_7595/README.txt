Patch:
https://github.com/vadz/libtiff/commit/47f2fb61a3a64667bce1a8398a8fcb1b348ff122

PoC:
https://blogs.gentoo.org/ago/2017/04/01/libtiff-divide-by-zero-in-jpegsetupencode-tiff_jpeg-c/
https://github.com/asarubbo/poc/blob/master/00123-libtiff-fpe-JPEGSetupEncode

Command:
> cd /root/source/tools/
> ./tiffcp -i /root/exploit ./out

tif_jpeg.c:1687:26: runtime error: division by zero
Floating point exception (core dumped)

