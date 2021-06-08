Patch:
https://github.com/libjpeg-turbo/libjpeg-turbo/commit/f8cca819a4fb42aafa5f70df43c45e8c416d716f

PoC:
https://github.com/libjpeg-turbo/libjpeg-turbo/issues/305

Command:
> cd /root/source
> ./djpeg -colors 256 -bmp /root/exploit

=================================================================
==2408==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x610000007ff7 at pc 0x00000040ca25 bp 0x7ffeb6dcd630 sp 0x7ffeb6dcd620
READ of size 1 at 0x610000007ff7 thread T0
    #0 0x40ca24 in put_pixel_rows /root/libjpeg-turbo/wrbmp.c:145
    #1 0x4028b2 in main /root/libjpeg-turbo/djpeg.c:762
    #2 0x7eff2afa182f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2082f)
    #3 0x402da8 in _start (/root/libjpeg-turbo/djpeg+0x402da8)


PS:
The asan part of the dockerfile may not work. Please install it manually follow the instructions
specified in the dockerfile manually.

