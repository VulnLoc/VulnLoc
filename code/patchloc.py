import parse_dwarf
import numpy as np
import utils
import argparse
import os
import string
import logging
import subprocess
import ConfigParser
import tracer
from copy import deepcopy as dc
from multiprocessing import Pool

NPZTag = False
Assem = ''

def process_poc_trace(poc_trace_path, bin_path, target_src_str):
    if NPZTag:
        tmp = np.load(poc_trace_path)
        poc_trace = tmp['trace']
    else:
        poc_trace = utils.read_pkl(poc_trace_path)
    poc_trace = np.asarray(poc_trace)
    if len(target_src_str) == 0:
        return poc_trace
    else:
        insn_list = parse_dwarf.get_bin_line(bin_path, target_src_str)
        insn_idx_list = []
        for insn in insn_list:
            insn_idx_list += list(np.where(poc_trace == insn)[0])
        if len(insn_idx_list) == 0:
            raise Exception("ERROR: Cannot find the instructions for source -> %s" % target_src_str)
        max_id = max(insn_idx_list)
        return poc_trace[:max_id+1]

def read_single_trace(folder_path, file_name, file_no):
    if file_no % 100 == 0:
        print('Reading %d_th trace' % file_no)
    file_path = os.path.join(folder_path, file_name)
    if NPZTag:
        tmp = np.load(file_path)
        content = tmp['trace']
        trace_hash = file_name.split('.')[0]
    else:
        content = utils.read_pkl(file_path)
        trace_hash = file_name
    unique_insns = np.unique(np.asarray(content))
    temp = [trace_hash, unique_insns]
    return temp

def init_count_dict(valid_insns):
    count_dict = {}
    for insn in valid_insns:
        count_dict[insn] = 0
    return count_dict

def read_all_reports(report_file, trace_folder, process_num):
    file_list = os.listdir(trace_folder)
    file_num = len(file_list)
    trace_collection = []
    pool = Pool(process_num)
    for file_no in range(file_num):
        pool.apply_async(
            read_single_trace,
            args = (trace_folder, file_list[file_no], file_no),
            callback = trace_collection.append
        )
    pool.close()
    pool.join()
    print('Finish reading all the traces')
    trace_dict = {}
    for item in trace_collection:
        trace_dict[item[0]] = item[1]
    # read reports
    reports = utils.read_pkl(report_file)
    # split reports
    report_dict = {
        'm': [], 'b': []
    }
    for item in reports:
        report_dict[item[1]].append(item[0])
    print('Finish splitting the reports into two categories!')
    return trace_dict, report_dict

def count(report_list, dest_dict, trace_dict):
    target_insn_set = set(dest_dict.keys())
    for trace_hash in report_list:
        intersect_set = set(trace_dict[trace_hash]) & target_insn_set
        for insn in intersect_set:
            dest_dict[insn] += 1

def normalize_score(score):
    max_value = np.max(score)
    min_value = np.min(score)
    if max_value == min_value:
        logging.info('max_value == min_value in normalization')
        return score
    else:
        normalized_score = (score - min_value) / (max_value - min_value)
        return normalized_score

def group_scores(scores):
    insn_num = len(scores)
    group_info = []
    group_value = -1
    group_list = []
    for insn_no in range(insn_num):
        if group_value < 0:
            group_value = scores[insn_no]
            group_list.append(insn_no)
        else:
            if group_value == scores[insn_no]:
                group_list.append(insn_no)
            else:
                group_info.append(group_list)
                group_list = [insn_no]
                group_value = scores[insn_no]
    group_info.append(group_list)
    return group_info

def calc_scores(valid_insns, tc_num_dict, t_num_dict, malicious_num, output_path):
    tc_num_list = np.asarray([tc_num_dict[insn] for insn in valid_insns], dtype=np.float)
    t_num_list = np.asarray([t_num_dict[insn] for insn in valid_insns], dtype=np.float)
    n_score = tc_num_list / float(malicious_num)
    s_score = tc_num_list / t_num_list
    normalized_nscore = normalize_score(n_score)
    normalized_sscore = normalize_score(s_score)
    l2_norm = np.sqrt(normalized_nscore ** 2 + normalized_sscore ** 2)
    print('Calculated all the scores!')
    sorted_idx_list = np.argsort(-l2_norm)
    # sorting all the insns
    valid_insns = valid_insns[sorted_idx_list]
    tc_num_list = tc_num_list[sorted_idx_list]
    t_num_list = t_num_list[sorted_idx_list]
    n_score = n_score[sorted_idx_list]
    s_score = s_score[sorted_idx_list]
    normalized_nscore = normalized_nscore[sorted_idx_list]
    normalized_sscore = normalized_sscore[sorted_idx_list]
    l2_norm = l2_norm[sorted_idx_list]
    print('Sorted all the scores')
    # group the insns according to its score
    group_info = group_scores(l2_norm)
    np.savez(output_path,
             insns=valid_insns, tc_num=tc_num_list, t_num=t_num_list, nscore=n_score, sscore=s_score,
             normalized_nscore=normalized_nscore, normalized_sscore=normalized_sscore, l2_norm=l2_norm,
             group_idx=group_info)
    return valid_insns, group_info, l2_norm, normalized_nscore, normalized_sscore

def count_all(valid_insns, report_dict, trace_dict, output_path):
    malicious_num = len(report_dict['m'])
    benign_num = len(report_dict['b'])
    logging.info("#reports: %d (#malicious: %d; #benign: %d)" % (malicious_num + benign_num, malicious_num, benign_num))
    # initialize all the count info
    tc_num_dict = init_count_dict(valid_insns)
    t_num_dict = init_count_dict(valid_insns)
    # count number(t_i & c)
    count(report_dict['m'], tc_num_dict, trace_dict)
    count(report_dict['m'] + report_dict['b'], t_num_dict, trace_dict)
    valid_insns, group_info, l2_norm, normalized_nscore, normalized_sscore = calc_scores(valid_insns, tc_num_dict, t_num_dict, malicious_num, output_path)
    return valid_insns, group_info, l2_norm, normalized_nscore, normalized_sscore

def rank(poc_trace_path, bin_path, target_src_str, report_file, trace_folder, process_num, npz_path):
    # process the poc trace
    poc_trace = process_poc_trace(poc_trace_path, bin_path, target_src_str)
    unique_insn = np.unique(poc_trace)
    # read all the important files
    trace_dict, report_dict = read_all_reports(report_file, trace_folder, process_num)
    # count
    valid_insns, group_info, l2_norm, normalized_nscore, normalized_sscore = count_all(unique_insn, report_dict, trace_dict, npz_path)
    return poc_trace, valid_insns, group_info, l2_norm, normalized_nscore, normalized_sscore

def calc_distance(poc_trace, insns):
    distance_list = []
    for insn in insns:
        distance_list.append(
            np.max(np.where(poc_trace == insn)[0])
        )
    return distance_list

def insn2src(bin_path, insn):
    global Assem
    if len(Assem) == 0:
        cmd_list = ['objdump', '-S', '-l', bin_path]
        p1 = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p1.communicate()
        content = out.split('\n')
        Assem = content
    else:
        content = Assem
    line_num = len(content)
    target_insn = insn[-6:] + ':'
    target_line_no = -1
    for line_no in range(line_num):
        line = content[line_no].split()
        if len(line) > 0 and line[0] == target_insn:
            target_line_no = line_no
            break
    if target_line_no < 0:
        raise Exception("ERROR: Cannot find the instruction -> %s" % insn)
    while(target_line_no >= 0):
        line = content[target_line_no]
        tmp = line.split()
        if len(tmp) >= 1 and ':' in tmp[0]:
            tmp2 = tmp[0].split(':')
            tag = True
            for tmp3 in tmp2[1]:
                if tmp3 not in string.digits:
                    tag = False
                    break
            if os.path.exists(tmp2[0]) and tag:
                return tmp[0].split('/')[-1]
        target_line_no = target_line_no - 1
    logging.info("Cannot find the source code for instruction -> %s" % insn)
    return "UNKNOWN"

def show(bin_path, poc_trace, valid_insns, group_info, l2_norm, normalized_nscore, normalized_sscore, show_num):
    group_num = len(group_info)
    show_no = 0
    for group_no in range(group_num):
        insn_id_list = np.asarray(group_info[group_no])
        insns = valid_insns[insn_id_list]
        distance_list = calc_distance(poc_trace, insns)
        sorted_idx_list = np.argsort(-np.asarray(distance_list))
        sorted_insn_id_list = insn_id_list[sorted_idx_list]

        for insn_id in sorted_insn_id_list:
            logging.info("[INSN-%d] %s -> %s (l2norm: %f; normalized(N): %f; normalized(S): %f)" % (
                show_no, valid_insns[insn_id], insn2src(bin_path, valid_insns[insn_id]), l2_norm[insn_id], normalized_nscore[insn_id], normalized_sscore[insn_id]
            ))
            show_no += 1
            if show_no >= show_num:
                break
        if show_no >= show_num:
            break

def parse_args():
    parser = argparse.ArgumentParser(description="PatchLoc")
    parser.add_argument("--config_file", dest="config_file", type=str, required=True,
                        help="The path of config file")
    parser.add_argument("--tag", dest="tag", type=str, required=True,
                        help="The cve tag")
    parser.add_argument("--func", dest="func", type=str, required=True,
                        help="The function for execution (calc/show)")
    parser.add_argument("--out_folder", dest="out_folder", type=str, required=True,
                        help="The path of output folder which is named according to the timestamp")
    parser.add_argument("--poc_trace_hash", dest="poc_trace_hash", type=str, required=True,
                        help="The hash of executing trace of poc")
    parser.add_argument("--target_src_str", dest="target_src_str", type=str, default="",
                        help="The source line at the crash location")
    parser.add_argument("--process_num", dest="process_num", type=int, default=10,
                        help="The number of processes")
    parser.add_argument("--show_num", dest="show_num", type=int, default=10, help="The number of instructions to show")
    args = parser.parse_args()

    config = ConfigParser.ConfigParser()
    config.read(args.config_file)
    if args.tag not in config.sections():
        raise Exception("ERROR: Please provide the configuration file for %s" % args.tag)

    detailed_config = {}
    for item in config.items(args.tag):
        if item[0] == 'folder':
            if not os.path.exists(item[1]):
                raise Exception("ERROR: The folder does not exist -> %s" % item[1])
            detailed_config[item[0]] = item[1]
        else:
            detailed_config[item[0]] = item[1].split(';')

    if 'bin_path' in detailed_config:
        bin_path = detailed_config['bin_path'][0]
        if not os.path.exists(bin_path):
            raise Exception("ERROR: Binary file does not exist -> %s" % bin_path)
        detailed_config['bin_path'] = bin_path
    else:
        raise Exception("ERROR: Please specify the binary file in config.ini")

    trace_folder = os.path.join(args.out_folder, 'traces')
    if not os.path.exists(trace_folder):
        raise Exception("ERROR: Unknown folder -> %s" % trace_folder)
    detailed_config['trace_folder'] = trace_folder

    poc_trace_path = os.path.join(trace_folder, args.poc_trace_hash)
    if not os.path.exists(poc_trace_path):
        poc_trace_path = poc_trace_path + '.npz'
        if not os.path.exists(poc_trace_path):
            raise Exception("ERROR: Unknown file path -> %s" % poc_trace_path)
        else:
            global NPZTag
            NPZTag = True
    detailed_config['poc_trace_path'] = poc_trace_path

    report_file = os.path.join(args.out_folder, 'reports.pkl')
    if not os.path.exists(report_file):
        raise Exception("ERROR: Unknown file path -> %s" % report_file)
    detailed_config['report_file'] = report_file

    npz_path = os.path.join(args.out_folder, 'var_ranking.npz')
    detailed_config['npz_path'] = npz_path

    return args.func, args.target_src_str, detailed_config, args.process_num, args.show_num, args.out_folder

def init_log(out_folder):
    log_path = os.path.join(out_folder, 'patchloc.log')
    logging.basicConfig(filename=log_path, filemode='a+', level=logging.DEBUG,
                        format="[%(asctime)s-%(funcName)s-%(levelname)s]: %(message)s",
                        datefmt="%d-%b-%y %H:%M:%S")
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console_fmt = logging.Formatter(fmt="[%(asctime)s-%(funcName)s-%(levelname)s]: %(message)s",
                                    datefmt="%d-%b-%y %H:%M:%S")
    console.setFormatter(console_fmt)
    logging.getLogger().addHandler(console)
    logging.info("Output Folder: %s" % out_folder)

def controller(tag, target_src_str, config_info, process_num, show_num):
    if tag == 'calc':
        poc_trace, valid_insns, group_info, l2_norm, normalized_nscore, normalized_sscore = rank(
            config_info['poc_trace_path'], config_info['bin_path'], target_src_str,
            config_info['report_file'], config_info['trace_folder'], process_num, config_info['npz_path'])
        # get_src_trace(config_info, out_folder)
        show(config_info['bin_path'], poc_trace, valid_insns, group_info, l2_norm, normalized_nscore, normalized_sscore, show_num)
    elif tag == 'show':
        # process the poc trace
        poc_trace = process_poc_trace(config_info['poc_trace_path'], config_info['bin_path'], target_src_str)

        if not os.path.exists(config_info['npz_path']):
            raise Exception("ERROR: The .npz file does not exist -> %s" % config_info['npz_path'])
        info = np.load(config_info['npz_path'], allow_pickle=True)

        show(config_info['bin_path'], poc_trace, info['insns'], info['group_idx'], info['l2_norm'],
             info['normalized_nscore'], info['normalized_sscore'], show_num)
    else:
        raise Exception("ERROR: Function tag does not exist -> %s" % tag)

def get_src_trace(detailed_config, out_folder):
    # process the cmd
    trace_cmd = detailed_config['trace_cmd']
    poc = detailed_config['poc']
    replace_idx = np.where(np.asarray(trace_cmd) == '***')[0]
    cmd = dc(trace_cmd)
    replace_num = len(replace_idx)
    for id in range(replace_num):
        cmd[replace_idx[id]] = poc[id]
    # write the cmd
    cmd_path = os.path.join(out_folder, 'cmd.txt')
    utils.write_txt(cmd_path, [' '.join(cmd)])
    # get binary path
    bin_path = detailed_config['bin_path']
    # get the source trace
    tmp_folder = './tempDr'
    if not os.path.exists(tmp_folder):
        os.mkdir(tmp_folder)
    my_parser = parse_dwarf.DwarfParser(bin_path)
    flineNumberDict, fileBoundRangesList, fileBoundIndexList, src_filepath = my_parser.get_main_addr()
    ifSrcList = tracer.findIfSrcInOrderDyn(bin_path, src_filepath, flineNumberDict, fileBoundRangesList, fileBoundIndexList, cmdFile=cmd_path)
    logging.info("Got the source trace!")
    # process the source trace
    insn2src = {}
    src2insn = {}
    for item in ifSrcList:
        insn = item[0]
        src = '-'.join(item[1:3])
        if insn not in insn2src:
            insn2src[insn] = src
        if src in src2insn:
            src2insn[src].add(insn)
        else:
            src2insn[src] = {insn}
    info = {
        'raw': ifSrcList,
        'insn2src': insn2src,
        'src2insn': src2insn
    }
    # write the source trace
    output_path = os.path.join(out_folder, 'poc_source_trace.pkl')
    utils.write_pkl(output_path, info)
    logging.info("Recorded the source trace -> %s" % output_path)
    return insn2src, src2insn

if __name__ == '__main__':
    tag, target_src_str, config_info, process_num, show_num, out_folder = parse_args()
    init_log(out_folder)
    controller(tag, target_src_str, config_info, process_num, show_num)