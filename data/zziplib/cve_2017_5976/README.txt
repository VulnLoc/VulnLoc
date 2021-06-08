Patch:
https://github.com/gdraheim/zziplib/commit/03de3beabbf570474a9ac05d6dc6b42cdb184cd1

PoC:
https://blogs.gentoo.org/ago/2017/02/09/zziplib-heap-based-buffer-overflow-in-zzip_mem_entry_extra_block-memdisk-c/

Command:
> cd /root/source/Linux_5.0.0-37-generic_x86_64.d/bins
> ./unzzipcat-mem /root/exploit

