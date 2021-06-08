Patch:
https://github.com/FFmpeg/FFmpeg/commit/279420b5a63b3f254e4932a4afb91759fb50186a

PoC:
https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=1404

Command:
> cd sources/ffmpeg/project/tools/
> ./target_dec_cavs_fuzzer /root/exploit/test_case