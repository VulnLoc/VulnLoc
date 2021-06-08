Patch:
https://github.com/libjpeg-turbo/libjpeg-turbo/commit/1ecd9a5729d78518397889a630e3534bd9d963a8

PoC:
https://github.com/mozilla/mozjpeg/issues/268

Command:
> cd /root/source
> ./djpeg -crop "1x1+16+16" -onepass -dither ordered -dct float -colors 8 -targa -grayscale -outfile o /root/exploit

