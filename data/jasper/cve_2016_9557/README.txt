Patch:
https://github.com/mdadams/jasper/commit/d42b2388f7f8e0332c846675133acea151fc557a

PoC:
https://blogs.gentoo.org/ago/2016/11/19/jasper-signed-integer-overflow-in-jas_image-c/
https://github.com/asarubbo/poc/blob/master/00020-jasper-signedintoverflow-jas_image_c

Command:
> cd /root/source/src/appl
> ./imginfo -f /root/exploit

