#!/bin/bash

target_cve="cve_2016_5314"
base_folder="/root/workspace"
out_folder="$base_folder/outputs"
code_folder="$base_folder/code"

if [ ! -d "$out_folder" ]; then
        mkdir $out_folder
        echo "Created folder -> $out_folder"
fi

cve_folder="$out_folder/$target_cve"
if [ ! -d "$cve_folder" ]; then
        mkdir $cve_folder
        echo "Created folder -> $cve_folder"
fi

cp ./config.ini $code_folder

echo "The default number of processes is 10. PatchLoc will adjust it according to the number of cpus on the local machines."
echo "The default timeout is 4h. The user can change the timeout in ./code/fuzz.py"
echo "The execution progress can be found at the fuzz.log in the output folder. It will not be printed out in the terminal."
echo "Please do not terminate the execution until PatchLoc timeouts automatically."

cd $code_folder
python fuzz.py --config_file ./config.ini --tag $target_cve
echo "Finish fuzzing ..."

# get the output folder
cve_out_folder=`find $out_folder/$target_cve -maxdepth 1 -name 'output_*' -not -path '*/\.*' -type d | sed 's/^\.\///g'`
echo "Output Folder: $cve_out_folder"
# get the hash of the poc
target_fuzz_path="$cve_out_folder/fuzz.log"
poc_hash=`sed '19q;d' $target_fuzz_path | awk '{print $NF}'`

python patchloc.py --config_file ./config.ini --tag $target_cve --func calc --out_folder $cve_out_folder --poc_trace_hash $poc_hash --process_num 10
