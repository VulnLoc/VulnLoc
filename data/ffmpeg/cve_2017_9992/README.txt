Patch:
https://github.com/FFmpeg/FFmpeg/commit/f52fbf4f3ed02a7d872d8a102006f29b4421f360

PoC:
https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=1345

Command:
> cd sources/ffmpeg/project/tools/
> ./target_dec_cavs_fuzzer /root/exploit/test_case
