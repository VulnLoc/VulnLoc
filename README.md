# VulnLoc

## Overview


Automatic vulnerability diagnosis can help security analysts identify and, therefore, quickly patch disclosed vulnerabilities. The vulnerability localization problem is to automatically find a program
point at which the “root cause” of the bug can be fixed. This paper
employs a statistical localization approach to analyze a given exploit.
Our main technical contribution is a novel procedure to systematically construct a test-suite which enables high-fidelity localization.
We build our techniques in a tool called VulnLoc (which is originally named with PatchLoc).
VulnLoc automatically pinpoints vulnerability locations, given just one exploit, with
high accuracy. It does not make any assumptions about the
availability of source code, test suites, or specialized knowledge
of the type of vulnerability.

More details about the project can be found at the [paper](https://www.comp.nus.edu.sg/~prateeks/papers/VulnLoc.pdf).

## Installation

1) Install dependencies

VulnLoc requires all the dependencies of Dynamorio, numpy (>=1.16) and pyelftools.
```console
$ sudo apt install -y build-essential git vim unzip python-dev python-pip ipython wget libssl-dev g++-multilib doxygen transfig imagemagick ghostscript git zlib1g-dev  
# install numpy
$ wget https://github.com/numpy/numpy/releases/download/v1.16.6/numpy-1.16.6.zip  
$ unzip numpy-1.16.6.zip  
$ cd ./numpy-1.16.6  
$ python setup.py install  
$ cd ../
# install pyelftools
$ sudo pip install pyelftools
```

2) Install CMake

CMake is required for building dynamorio.
```console
$ wget https://github.com/Kitware/CMake/releases/download/v3.16.2/cmake-3.16.2.tar.gz  
$ tar -xvzf ./cmake-3.16.2.tar.gz  
$ cd ./cmake-3.16.2  
$ ./bootstrap  
$ make  
$ sudo make install  
$ cd ../  
```

3) Install Dynamorio
```console
$ git clone https://github.com/DynamoRIO/dynamorio.git  
$ cd ./dynamorio  
$ mkdir build  
$ cd ./build  
$ cmake ../  
$ make
$ cd ../../  
```

4) Install the Dynamorio-based tracer

We use the tracer to monitor the execution of branches.
```console
$ unzip iftracer.zip  # iftracer.zip can be found in the folder "./code"
```
Users need to replace <path_to_dynamorio> with the path of Dynamorio in the CMakeLists.txt for both iftracer and ifLineTracer. After the modification, please run:
```console
$ cd ./iftracer/iftracer  
$ cmake CMakeLists.txt  
$ make  
$ cd ../ifLineTracer  
$ cmake CMakeLists.txt  
$ make  
$ cd ../../  
```

5) Configure the path to Dynamorio and the tracer

Please fill in the correct path of Dynamorio and the tracer in **./code/env.py**.
```
dynamorio_path = "<path_to_dynamorio>/build/bin64/drrun"  
iftracer_path = "<path_to_tracer>/iftracer/libiftracer.so"  
iflinetracer_path = "<path_to_tracer>/ifLineTracer/libifLineTracer.so"  
libcbr_path = "<path_to_dynamorio>/build/api/bin/libcbr.so"  
```

## Usage
To show the usage of VulnLoc, we take *cve-2016-5314* as an example. Here are the links to the PoC and the developer-generated patch:
- [PoC](http://bugzilla.maptools.org/show_bug.cgi?id=2554)
- [Developer-generated patch](https://github.com/vadz/libtiff/commit/391e77fcd217e78b2c51342ac3ddb7100ecacdd2)

1) (Optional) Compile the target vulnerable program  
VulnLoc takes a vulnerable binary and the corresponding PoC as its input. If you do not have the vulnerable binary, please compile the program first.   
```console
$ sudo apt install -y zlib1g-dev
$ cd cve_2016_5314
$ unzip source.zip # source.zip can be found in the folder "./data/cve_2016_5314"
$ cd source
$ ./configure
$ make CFLAGS="-static -ggdb" CXXFLAGS="-static -ggdb"
```

2) Configure the CVE  
To monitor the execution of the given vulnerable binary, users need to provide the configuration file for each CVE. The template of the configuration file can be found in *./code/config.ini* file. To complete the configuration file, users need to fill in the following info/attributes for each CVE:
- **cve_tag**: The unique ID of each CVE (e.g., cve_2016_5314). A configuration file can include the information for multiple CVE. For extracting the right configuration, users are required to assign a unique ID for each CVE.  
- **trace_cmd**: The command used for executing the vulnerable program with the given PoC. Each argument is separate by ';'. The location of the target argument for fuzzing is replaced with '***'.
- **crash_cmd**: The command used for checking whether the vulnerable program gets exploited or not. crash_cmd follows the same format as trace_cmd.
- **bin_path**: The path to the vulnerable binary.
- **poc**: The path to the PoC
- **poc_fmt**: The type of PoC.
- **mutate_range**: The valid range for mutation.
- **folder**: The output folder for saving the test-suite.
- **crash_tag**: The information which can be utilized to detect whether the program gets exploited or not. The vulnerablity checker is defined in the function *check_exploit* under *./code/fuzz.py*.

**EXAMPLE: cve-2016-5314**

a) Building ane exploit detector.

We utilize Valgrind to detect whether the program gets exploit or not for cve-2016-5314. Valgrind is not the only choice and users can define their own way for detecting the vulnerability. If the binary is compiled with address sanitizer, users can also use ASAN to detect the vulnerability. 
- Building Valgrind
```console
$ sudo apt-get install -y libc6-dbg
$ wget https://sourceware.org/pub/valgrind/valgrind-3.15.0.tar.bz2
$ tar xjf valgrind-3.15.0.tar.bz2
$ cd ./valgrind-3.15.0
$ ./configure
$ make
$ sudo make install
```
- Executing the program with Valgrind
```console
$ cd ./source/tools
$ valgrind ./rgb2ycbcr <exploit_path> tmpout1.tif
```
Here is the output of Valgrind:
```
==48145== Invalid write of size 1
==48145==    at 0x4E43078: ??? (in /lib/x86_64-linux-gnu/libz.so.1.2.8)
==48145==    by 0x4E4638A: inflate (in /lib/x86_64-linux-gnu/libz.so.1.2.8)
==48145==    by 0x443FC4: PixarLogDecode (tif_pixarlog.c:785)
==48145==    by 0x42C3B4: TIFFReadEncodedTile (tif_read.c:668)
==48145==    by 0x42C2A1: TIFFReadTile (tif_read.c:641)
==48145==    by 0x41FEFC: gtTileContig (tif_getimage.c:656)
==48145==    by 0x41F8C0: TIFFRGBAImageGet (tif_getimage.c:495)
==48145==    by 0x41F9C2: TIFFReadRGBAImageOriented (tif_getimage.c:514)
==48145==    by 0x41FA77: TIFFReadRGBAImage (tif_getimage.c:532)
==48145==    by 0x4022A3: tiffcvt (rgb2ycbcr.c:315)
==48145==    by 0x401811: main (rgb2ycbcr.c:127)
==48145==  Address 0x5749c4c is 0 bytes after a block of size 476 alloc'd
==48145==    at 0x4C2DE96: malloc (vg_replace_malloc.c:309)
==48145==    by 0x4313CE: _TIFFmalloc (tif_unix.c:316)
==48145==    by 0x443C80: PixarLogSetupDecode (tif_pixarlog.c:692)
==48145==    by 0x446E12: PredictorSetupDecode (tif_predict.c:111)
==48145==    by 0x42CFB2: TIFFStartTile (tif_read.c:1001)
==48145==    by 0x42CC0E: TIFFFillTile (tif_read.c:901)
==48145==    by 0x42C37C: TIFFReadEncodedTile (tif_read.c:668)
==48145==    by 0x42C2A1: TIFFReadTile (tif_read.c:641)
==48145==    by 0x41FEFC: gtTileContig (tif_getimage.c:656)
==48145==    by 0x41F8C0: TIFFRGBAImageGet (tif_getimage.c:495)
==48145==    by 0x41F9C2: TIFFReadRGBAImageOriented (tif_getimage.c:514)
==48145==    by 0x41FA77: TIFFReadRGBAImage (tif_getimage.c:532)
```

b) Create the configuration file
```
[cve_2016_5314]
trace_cmd=<path_to_source>/tools/rgb2ycbcr;***;tmpout1.tif
crash_cmd=valgrind;<path_to_source>/tools/rgb2ycbcr;***;tmpout2.tif
bin_path=<path_to_source>/tools/rgb2ycbcr
poc=<path_to_poc>
poc_fmt=bfile
mutate_range=default
folder=<path_to_output_folder>
crash_tag=valgrind;3;0x443FC4
```

3) Run ConcFuzz (collect the test-suite)
```console
$ cd ./code
$ python fuzz.py --config_file <path_to_config_file> --tag <cve_tag>
```

4) Rank the location candidates 
```console
$ python patchloc.py --config_file <path_to_config_file> --tag <cve_tag> --func calc --out_folder <path_to_output_folder> --poc_trace_hash <poc_trace_hash> --process_num <process_num> 
```
This script will output a set of candidate branch locations. The basic blocks immediately preceding/succeeding the candidate branch may be modified to fix the bug.

## More Examples
More examples can be found at the folder **./test**. The **README.md** file in
each subfolder under **./test** will tell you how to setup each CVE in our
benchmark. We performed the experiments on a 56-core 2.0GHz 64GB RAM Intel Xeon machine.



