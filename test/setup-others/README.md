## Quick Tour

### Download Configs and Other Files
Please download all the .zip files in the [folder](https://drive.google.com/drive/folders/1B5dKaMfqN_mJSaYIIkeScdvZb9P6_tQh?usp=sharing)
to **./VulnLoc/test** in your localhost and unzip these files.

### Setup Docker Container

```bash
cd ./VulnLoc/test/env_setup
# Build a docker image
docker build -f vulnloc_env.Dockerfile -t vulnloc_env .
# Run a docker container
docker run --privileged -it vulnloc_env bash
cd ../../
docker cp ./code <container_id>:/root/workspace/code
```

### Create CVE folder (in container)

```bash
# Run following commands in the docker container
cd /root/workspace
mkdir <target_cve>
```

### Copy Files From Host to Docker Container

```bash
# Run following commands in your localhost
cd ./VulnLoc/test/scripts
./copy_files.sh <target_cve> <container_id>
```

### Compile Target Programs

```bash
# Run following commands in the docker container
cd /root/workspace/<target_cve>
./compile.sh
```

### Run the Localization Tool

```bash
# Run following commands in the docker container
cd /root/workspace/<target_cve>/code

python fuzz.py  \
    --config_file /root/workspace/<target_cve>/config.ini   \
    --tag <target_cve>

python patchloc.py  \
    --config_file /root/workspace/<target_cve>/config.ini   \
    --tag <target_cve>  
    --func calc \
    --out_folder /root/workspace/<target_cve>/output/output_<timestamp> \
    --poc_trace_hash <poc_trace_hash>   \
    --process_num 10
```

## Example
Let's take cve-2017-5225 as an example. We first create a docker container for running the experiment.
```bash
cd ./VulnLoc/test/env_setup
# Build a docker image
docker build -f vulnloc_env.Dockerfile -t vulnloc_env .
# Run a docker container
docker run --privileged -it vulnloc_env bash
```
To find out the ID of the container, please run (in your localhost):
```bash
docker ps -a | grep "vulnloc_env" | awk '{print $1;}'
```
This command will give you the output such as **88b45068e205**.

The second step is to prepare the environment for cve-2017-5225.
```bash
# Run following commands in the docker container
cd /root/workspace
mkdir cve-2017-5225
```
```bash
# Run following commands in your localhost
cd ./VulnLoc/test/scripts
./copy_files.sh cve-2017-5225 88b45068e205
cd ../../
docker cp ./code 88b45068e205:/root/workspace/code
```
```bash
# Run following commands in the docker container
cd /root/workspace/cve-2017-5225
./compile.sh
```
The third step is to run ConcFuzz with the target program.
```bash
# Run following commands in the docker container
cd /root/workspace/cve-2017-5225/code

python fuzz.py  \
    --config_file /root/workspace/cve-2017-5225/config.ini   \
    --tag cve-2017-5225
```
This step will create an output folder with the name **output_\<timestamp\>** (such as **output_1620642503**) in **/root/workspace/cve-2017-5225/output**. 

The final step is to run the localization tool with the target program.
```bash
# Run following commands in the docker container
cd /root/workspace/cve-2017-5225/code

python patchloc.py  \
    --config_file /root/workspace/cve-2017-5225/config.ini   \
    --tag cve-2017-5225
    --func calc \
    --out_folder /root/workspace/cve-2017-5225/output/output_1620642503 \
    --poc_trace_hash 27a85cdd21788fbf4ce73198609202993a70ba1d2c9153f018e33c88dea4ffef   \
    --process_num 10
```
You can find the hash of the exploit trace by running the following commands:
```bash
cd /root/workspace/cve-2017-5225/output/output_1620642503
head -n 19 fuzz.log | tail -1 | awk '{ print $NF }'
```
Finally, you can find the following localization result in the file **/root/workspace/cve-2017-5225/output/output_1620642503/patchloc.log**
```
Output Folder: /root/workspace/cve-2017-5225/output/output_1620642503
#reports: 5692 (#malicious: 2697; #benign: 2995)
[INSN-0] 0x0000000000404767 -> tiffcp.c:1089 (l2norm: 1.414214; normalized(N): 1.000000; normalized(S): 1.000000)
[INSN-1] 0x0000000000429402 -> tif_write.c:540 (l2norm: 1.412245; normalized(N): 1.000000; normalized(S): 0.997214)
[INSN-2] 0x00000000004293bd -> tif_write.c:537 (l2norm: 1.412245; normalized(N): 1.000000; normalized(S): 0.997214)
[INSN-3] 0x00000000004293b2 -> tif_write.c:538 (l2norm: 1.412245; normalized(N): 1.000000; normalized(S): 0.997214)
[INSN-4] 0x0000000000429360 -> tif_write.c:531 (l2norm: 1.412245; normalized(N): 1.000000; normalized(S): 0.997214)
...
```
