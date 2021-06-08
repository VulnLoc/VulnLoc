import argparse
import ConfigParser
import logging
import os
import utils
import numpy as np
from time import time
import string
from copy import deepcopy as dc
import hashlib
import shutil
import tracer
import itertools
from multiprocessing import Pool

DefaultItems = ['trace_cmd', 'crash_cmd', 'poc', 'poc_fmt', 'folder', 'mutate_range', 'crash_tag']
OutFolder = ''
TmpFolder = ''
TraceFolder = ''

SeedPool = [] # Each element is in the fmt of [<process_tag>, <seed_content>]. <process_tag>: True (selected) / False (not selected)
SeedTraceHashList = []
ReportCollection = [] # Each element if in the fmt of [<trace_hash>, <tag>]. <tag>: m - malicious / b - benign
TraceHashCollection = []
GlobalTimeout = 4 * 60 * 60 # 2 hours
LocalTimeout = 4 * 60 * 60 # 2 hours
DefaultRandSeed = 3
DefaultMutateNum = 200
DefaultMaxCombination = 2
MaxCombineNum = 10**20

def parse_args():
	parser = argparse.ArgumentParser(description="ConcFuzz")
	parser.add_argument('--config_file', dest='config_file', type=str, required=True,
						help="The path of config file")
	parser.add_argument('--tag', dest='tag', type=str, required=True,
						help="The corresponding CVE id")
	parser.add_argument('--verbose', dest='verbose', type=str, default='True',
						help="Whether print out the debugging info")
	args = parser.parse_args()

	# check the validity of args
	config = ConfigParser.ConfigParser()
	config.read(args.config_file)
	if args.tag not in config.sections():
		raise Exception("ERROR: Please provide the configuration file for %s" % args.tag)
	# read & processing config file
	detailed_config = {}
	for item in config.items(args.tag):
		if item[0] == 'folder':
			if not os.path.exists(item[1]):
				raise Exception("ERROR: The folder does not exist -> %s" % item[1])
			detailed_config[item[0]] = item[1]
		else:
			detailed_config[item[0]] = item[1].split(';')
	# check whether it contains all the required attributes
	if len(set(detailed_config.keys()) & set(DefaultItems)) != len(DefaultItems):
		raise Exception("ERROR: Missing required attributes in config.ini -> Required attributes: %s" % str(DefaultItems))
	# check poc & poc_fmt & mutate_range
	arg_num = len(detailed_config['poc'])
	if arg_num != len(detailed_config['poc_fmt']) and arg_num != len(detailed_config['mutate_range']):
		raise Exception("ERROR: Your defined poc is not matched with poc_fmt/mutate_range")
	processed_arg = []
	processed_fmt = [] # each element is in the fmt of [<type>, <start_idx>, <size>, <mutate_range>]
	for arg_no in range(arg_num):
		if detailed_config['poc_fmt'][arg_no] == 'bfile':
			if not os.path.exists(detailed_config['poc'][arg_no]):
				raise Exception("ERROR: Exploit file does not exist -> %s" % detailed_config['poc'][arg_no])
			content = utils.read_bin(detailed_config['poc'][arg_no])

			processed_fmt.append(['bfile', len(processed_arg), len(content), range(256)])
			processed_arg += content
		elif detailed_config['poc_fmt'][arg_no] == 'int':
			try:
				tmp = detailed_config['mutate_range'][arg_no].split('~')
				mutate_range = range(int(tmp[0]), int(tmp[1]))
			except:
				raise Exception('ERROR: Please check the value of mutate_range in your config file.')
			processed_fmt.append(['int', len(processed_arg), 1, mutate_range])
			processed_arg.append(int(detailed_config['poc'][arg_no]))
		elif detailed_config['poc_fmt'][arg_no] == 'float':
			try:
				tmp = detailed_config['mutate_range'][arg_no].split('~')
				mutate_range = list(np.arange(float(tmp[0]), float(tmp[1]), float(tmp[2])))
			except:
				raise Exception('ERROR: Please check the value of mutate_range in your config file.')
			processed_fmt.append(['float', len(processed_arg), 1, mutate_range])
			processed_arg.append(float(detailed_config['poc'][arg_no]))
		elif detailed_config['poc_fmt'][arg_no] == 'str':
			processed_fmt.append(['str', len(processed_arg), len(detailed_config['poc'][arg_no]), list(string.printable)])
			processed_arg += list(detailed_config['poc'][arg_no])
		else:
			raise Exception("ERROR: Unknown type of arguments -> %s" % detailed_config['poc_fmt'][arg_no])
	detailed_config['poc'] = processed_arg
	detailed_config['poc_fmt'] = processed_fmt
	detailed_config.pop('mutate_range')
	# process the optional args
	if 'global_timeout' not in detailed_config: # read the global timeout (overall)
		global GlobalTimeout
		detailed_config['global_timeout'] = GlobalTimeout
	else:
		detailed_config['global_timeout'] = int(detailed_config['global_timeout'][0])
	if 'local_timeout' not in detailed_config: # read the local timeout for each seed
		global LocalTimeout
		detailed_config['local_timeout'] = LocalTimeout
	else:
		detailed_config['local_timeout'] = int(detailed_config['local_timeout'][0])
	if 'rand_seed' not in detailed_config: # read the randomization seed
		global DefaultRandSeed
		detailed_config['rand_seed'] = DefaultRandSeed
	else:
		detailed_config['rand_seed'] = int(detailed_config['rand_seed'][0])
	if 'mutation_num' not in detailed_config: # read the number of mutation for each byte
		global DefaultMutateNum
		detailed_config['#mutation'] = DefaultMutateNum
	else:
		detailed_config['#mutation'] = int(detailed_config['mutation_num'][0])
		detailed_config.pop('mutation_num')
	if 'combination_num' not in detailed_config:
		global DefaultMaxCombination
		detailed_config['#combination'] = DefaultMaxCombination
	else:
		detailed_config['#combination'] = int(detailed_config['combination_num'][0])
		detailed_config.pop('combination_num')
	if 'max_combine_num' in detailed_config:
		global MaxCombineNum
		MaxCombineNum = int(detailed_config['max_combine_num'][0])
	if 'tmp_filename_len' in detailed_config: # read the length of temperol filename
		utils.FileNameLen = int(detailed_config['tmp_filename_len'][0])
	# get all the replace idx in the cmd
	tmp = ';'.join(detailed_config['trace_cmd']).split('***')
	detailed_config['trace_cmd'] = []
	detailed_config['trace_replace_idx'] = []
	for id in range(len(tmp)):
		detailed_config['trace_cmd'].append(tmp[id])
		detailed_config['trace_cmd'].append('')
		detailed_config['trace_replace_idx'].append(2*id + 1)
	detailed_config['trace_cmd'] = detailed_config['trace_cmd'][:-1]
	detailed_config['trace_replace_idx'] = detailed_config['trace_replace_idx'][:-1]

	tmp = ';'.join(detailed_config['crash_cmd']).split('***')
	detailed_config['crash_cmd'] = []
	detailed_config['crash_replace_idx'] = []
	for id in range(len(tmp)):
		detailed_config['crash_cmd'].append(tmp[id])
		detailed_config['crash_cmd'].append('')
		detailed_config['crash_replace_idx'].append(2 * id + 1)
	detailed_config['crash_cmd'] = detailed_config['crash_cmd'][:-1]
	detailed_config['crash_replace_idx'] = detailed_config['crash_replace_idx'][:-1]
	# detailed_config['trace_replace_idx'] = np.where(np.asarray(detailed_config['trace_cmd']) == '***')[0]
	# detailed_config['crash_replace_idx'] = np.where(np.asarray(detailed_config['crash_cmd']) == '***')[0]
	return args.tag, detailed_config, args.verbose

def init_log(tag, verbose, folder):
	global OutFolder, TmpFolder, TraceFolder
	OutFolder = os.path.join(folder, 'output_%d' % int(time()))
	if os.path.exists(OutFolder):
		raise Exception("ERROR: Output folder already exists! -> %s" % OutFolder)
	else:
		os.mkdir(OutFolder)
	TmpFolder = os.path.join(OutFolder, 'tmp')
	if not os.path.exists(TmpFolder):
		os.mkdir(TmpFolder)
	TraceFolder = os.path.join(OutFolder, 'traces')
	if not os.path.exists(TraceFolder):
		os.mkdir(TraceFolder)
	log_path = os.path.join(OutFolder, 'fuzz.log')
	if verbose == 'True':
		logging.basicConfig(filename=log_path, filemode='a+', level=logging.DEBUG,
							format="[%(asctime)s-%(funcName)s-%(levelname)s]: %(message)s",
							datefmt="%d-%b-%y %H:%M:%S")
	else:
		pass
	console = logging.StreamHandler()
	console.setLevel(logging.INFO)
	console_fmt = logging.Formatter(fmt="[%(asctime)s-%(funcName)s-%(levelname)s]: %(message)s", datefmt="%d-%b-%y %H:%M:%S")
	console.setFormatter(console_fmt)
	logging.getLogger().addHandler(console)
	logging.info('Output Folder: %s' % OutFolder)
	logging.debug("CVE: %s" % tag)
	logging.debug("Config Info: \n%s" % '\n'.join(['\t%s : %s' % (key, config_info[key]) for key in config_info]))

def choose_seed():
	global SeedPool
	# get all the seeds which have not been selected
	seed_num = len(SeedPool)
	ns_idx = []
	for seed_no in range(seed_num):
		if SeedPool[seed_no][0] == False:
			ns_idx.append(seed_no)
	if len(ns_idx) == 0:
		return []
	else:
		selected_id = np.random.choice(ns_idx)
		SeedPool[selected_id][0] = True
		return [SeedTraceHashList[selected_id], SeedPool[selected_id][1]]

def prepare_args(input_no, poc, poc_fmt):
	global TmpFolder
	# prepare the arguments
	arg_num = len(poc_fmt)
	arg_list = []
	for arg_no in range(arg_num):
		if poc_fmt[arg_no][0] == 'bfile': # write the list into binary file
			content = np.asarray(poc[poc_fmt[arg_no][1]: poc_fmt[arg_no][1]+poc_fmt[arg_no][2]]).astype(np.int)
			tmp_filepath = os.path.join(TmpFolder, 'tmp_%d' % input_no)
			utils.write_bin(tmp_filepath, content)
			arg_list.append(tmp_filepath)
		elif poc_fmt[arg_no][0] == 'int':
			arg_list.append(int(poc[poc_fmt[arg_no][1]]))
		elif poc_fmt[arg_no][0] == 'float':
			arg_list.append(float(poc[poc_fmt[arg_no][1]]))
		elif poc_fmt[arg_no][0] == 'str': # concatenate all the chars together
			arg_list.append(''.join(poc[poc_fmt[arg_no][1]: poc_fmt[arg_no][1]+poc_fmt[arg_no][2]]))
		else:
			raise Exception("ERROR: Unknown poc_fmt -> %s" % poc_fmt[arg_no][0])
	return arg_list

def prepare_cmd(cmd_list, replace_idx, arg_list):
	replaced_cmd = dc(cmd_list)
	arg_num = len(replace_idx)
	for arg_no in range(arg_num):
		replaced_cmd[replace_idx[arg_no]] = str(arg_list[arg_no])
	replaced_cmd = ''.join(replaced_cmd)
	replaced_cmd = replaced_cmd.split(';')
	return replaced_cmd

def calc_trace_hash(trace):
	trace_str = '\n'.join(trace)
	return hashlib.sha256(trace_str).hexdigest()

def just_trace(input_no, raw_args, poc_fmt, trace_cmd, trace_replace_idx):
	processed_args = prepare_args(input_no, raw_args, poc_fmt)
	cmd = prepare_cmd(trace_cmd, trace_replace_idx, processed_args)
	trace = tracer.ifTracer(cmd)
	trace_hash = calc_trace_hash(trace)
	return trace, trace_hash

def check_exploit(err, crash_info):
	tmp = err.split('\n')
	if crash_info[0] == 'valgrind':
		line_num = len(tmp)
		distance = int(crash_info[1])
		for line_no in range(line_num):
			item = tmp[line_no]
			tmp2 = item.split()
			if len(tmp2) >=2 and len(tmp2[0])>=2 and tmp2[0][:2] == '==' and tmp2[1] == 'Invalid':
				target_line_no = line_no + 3
				if target_line_no < line_num:
					if crash_info[2] in tmp[target_line_no]:
						return 'm'
		return 'b'
	elif crash_info[0] == 'asan':
		tag = '#'+ crash_info[1]
		for item in tmp:
			tmp2 = item.split()
			if len(tmp2) == 0:
				break
			if item.split()[0] == tag:
				if crash_info[2] in item:
					return 'm'
		return 'b'
	elif crash_info[0] == "assert":
		if crash_info[1] in err:
			return "m"
		else:
			return "b"
	else:
		raise Exception('ERROR: Unknown crash info -> %s' % crash_info)

def trace_cmp(seed_trace, trace):
	min_len = min(len(seed_trace), len(trace))
	for id in range(min_len):
		if seed_trace[id] != trace[id]:
			return id
	return min_len

def gen_report(input_no, raw_args, poc_fmt, trace_cmd, trace_replace_idx, crash_cmd, crash_replace_idx, crash_info, seed_trace):
	processed_args = prepare_args(input_no, raw_args, poc_fmt)
	trace_cmd = prepare_cmd(trace_cmd, trace_replace_idx, processed_args)
	trace = tracer.ifTracer(trace_cmd)
	trace_diff_id = trace_cmp(seed_trace, trace)
	trace_hash = calc_trace_hash(trace)
	crash_cmd = prepare_cmd(crash_cmd, crash_replace_idx, processed_args)
	_, err = tracer.exe_bin(crash_cmd)
	crash_result = check_exploit(err, crash_info)
	return [input_no, trace, trace_hash, crash_result, trace_diff_id]

def init_sensitivity_map(seed_len, seed_trace_len, max_combination):
	global MaxCombineNum
	idx_list = []
	for comb_id in range(1, max_combination+1):
		tmp = list(itertools.combinations(range(seed_len), comb_id))
		if len(tmp) > (MaxCombineNum-len(idx_list)):
			np.random.shuffle(tmp)
			idx_list += tmp[:MaxCombineNum-len(idx_list)]
			break
		else:
			idx_list += tmp
	crash_sens_map = {
		'idx': idx_list,
		'value': np.zeros(len(idx_list))
	}
	loc_sens_map = {
		'idx': idx_list,
		'tag': np.zeros(len(idx_list)),
		'value': [[] for _ in range(seed_trace_len)]
		# 'value': np.zeros((seed_trace_len, len(idx_list)))
	}
	logging.debug("Max Combinations: %d" % max_combination)
	logging.debug("Number of Mutation Idxes: %d" % len(idx_list))
	logging.debug("#Loc: %d" % seed_trace_len)
	logging.debug("Size(seed): %d" % seed_len)
	return crash_sens_map, loc_sens_map

def select_mutate_idx(loc_sens_map, seed_len, max_combination):
	# select the non-mutated bytes
	non_mutated_idx = np.where(loc_sens_map['tag'] == 0)[0]
	# find out which loc has not been explored
	# unexplore_list = np.where(np.sum(loc_sens_map['value'], axis=-1)==0)[0]
	unexplore_list = np.where(np.asarray([len(item) for item in loc_sens_map['value']]) == 0)[0]
	logging.debug("#(unexplored loc): %d" % len(unexplore_list))
	if len(unexplore_list) == 0:
		return None
	unexplore_loc_id = np.min(unexplore_list)
	logging.debug("Unexplored Loc ID: %d" % unexplore_loc_id)
	tmp = []
	for item in loc_sens_map['value'][:unexplore_loc_id]:
		tmp += item
	fixed_idx = np.asarray(list(set(tmp)))
	# fixed_idx = np.where(np.sum(loc_sens_map['value'][:unexplore_loc_id], axis=0)>0)[0]
	logging.debug("Fixed IDs: %s" % str(fixed_idx))
	# find out the bytes that can be mutated
	non_mutated_idx = np.asarray(list(set(non_mutated_idx) - set(fixed_idx)))
	logging.debug("#(potential idxes): %d" % len(non_mutated_idx))
	# randomly select one idx from non_mutated_idx
	min_idx = 0
	idx_range = []
	for comb_id in range(1, max_combination + 1):
		max_idx = min_idx + len(list(itertools.combinations(range(seed_len), comb_id)))
		idx_range += list(non_mutated_idx[np.where(np.logical_and(non_mutated_idx >= min_idx, non_mutated_idx<max_idx))[0]])
		min_idx = max_idx
		if len(idx_range) > 0:
			logging.debug("Select the mutation idx from %d-combination" % comb_id)
			np.random.shuffle(idx_range)
			return idx_range[0]
	return None

def update_loc_sens_map(mutate_idx, diff_collection, loc_sens_map):
	loc_num = len(loc_sens_map['value'])
	for diff_id in diff_collection:
		if diff_id < loc_num:
			logging.debug("Update location sensitivity map! loc: %d; mutate id: %d" % (diff_id, mutate_idx))
			loc_sens_map['value'][diff_id].append(mutate_idx)
			# loc_sens_map['value'][diff_id][mutate_idx] = 1
	return loc_sens_map

def update_crash_sens_map(mutate_idx, crash_collection, crash_sens_map):
	if len(crash_collection) == 2:
		logging.debug("Update crash location sensitivity map! mutate id: %d" % mutate_idx)
		crash_sens_map['value'][mutate_idx] = 1
	return crash_sens_map

def update_sens_map(mutate_idx, diff_collection, crash_collection, loc_sens_map, crash_sens_map):
	loc_sens_map = update_loc_sens_map(mutate_idx, diff_collection, loc_sens_map)
	crash_sens_map = update_crash_sens_map(mutate_idx, crash_collection, crash_sens_map)
	return loc_sens_map, crash_sens_map

def mutate_inputs(seed, poc_fmt, mutation_num, mutate_idx):
	redundant_mutations = mutation_num*2
	inputs = np.tile(seed, (redundant_mutations, 1))
	# get the mutate range for the specific mutate_idx
	for idx in mutate_idx:
		mutate_range = None
		for arg_fmt in poc_fmt:
			if idx >= arg_fmt[1] and idx < (arg_fmt[1] + arg_fmt[2]):
				mutate_range = arg_fmt[3]
		if mutate_range == None:
			raise Exception("ERROR: Cannot find the corresponding fmt -> mutate_idx: %s" % str(idx))
		mutate_values = np.random.choice(mutate_range, redundant_mutations)
		inputs[:, idx] = mutate_values
	inputs = np.unique(inputs, axis = 0)[: mutation_num]
	return inputs

def concentrate_fuzz(config_info):
	global TraceHashCollection, ReportCollection, SeedPool, SeedTraceHashList, TraceFolder, TmpFolder
	# init the randomization function
	np.random.seed(config_info['rand_seed'])
	logging.info("Initialized the random seed -> %d" % config_info['rand_seed'])

	'''Process the PoC'''
	# generate the trace for the poc
	trace, trace_hash = just_trace(0, config_info['poc'], config_info['poc_fmt'], config_info['trace_cmd'], config_info['trace_replace_idx'])
	logging.debug('PoC Hash: %s' % trace_hash)
	seed_len = len(config_info['poc'])
	# save the trace
	TraceHashCollection.append(trace_hash)
	path = os.path.join(TraceFolder, trace_hash)
	# utils.write_pkl(path, trace)
	np.savez(path, trace=trace)
	# add the report
	ReportCollection.append([trace_hash, 'm'])
	# add into seed pool
	SeedPool.append([False, config_info['poc']])
	SeedTraceHashList.append(trace_hash)
	logging.info('Finish processing the poc!')

	stime = time() # starting time
	round_no = 0
	while(True):
		round_no += 1
		# choose seed & load seed_trace
		result = choose_seed()
		if len(result) == 0:
			logging.debug("[R-%d] Finish processing all the seeds!" % round_no)
			break
		selected_seed = result[1]
		selected_seed_trace_hash = result[0]
		logging.debug("[R-%d] Select seed -> %s" % (round_no, selected_seed_trace_hash))
		logging.debug("The status of current seed pool:\n%s" % '\n'.join(
			['%s: %s' % (SeedTraceHashList[id], str(SeedPool[id][0])) for id in range(len(SeedPool))]))
		trace_path = os.path.join(TraceFolder, selected_seed_trace_hash) + '.npz'
		if round_no == 1:
			selected_seed_trace = trace
		else:
			selected_seed_trace = np.load(trace_path)
			# selected_seed_trace = utils.read_pkl(trace_path)
		logging.info('len(Seed Trace): %d' %  len(selected_seed_trace))
		# initialize sensitivity map
		crash_sensitivity_map, loc_sensitivity_map = init_sensitivity_map(seed_len, len(selected_seed_trace), config_info['#combination'])

		# check each selected seed
		subround_no = 0
		while(True):
			subround_no += 1
			# select mutate byte
			mutate_idx = select_mutate_idx(loc_sensitivity_map, seed_len, config_info['#combination'])
			if mutate_idx == None: # exist if all the bytes get mutated
				break
			logging.debug('[R-%d-%d] Select the mutate idx -> %s: %s' % (round_no, subround_no, str(mutate_idx), str(loc_sensitivity_map['idx'][mutate_idx])))
			loc_sensitivity_map['tag'][mutate_idx] = 1
			# mutate inputs
			inputs = mutate_inputs(selected_seed, config_info['poc_fmt'], config_info['#mutation'], loc_sensitivity_map['idx'][mutate_idx])
			logging.debug("Shape(mutated_inputs): %s" % str(inputs.shape))
			# execute all the mutated inputs
			result_collection = [] # each element is in the fmt of [id, trace, trace_hash, crash_result, trace_diff_id]
			input_num = len(inputs)
			pool = Pool(utils.ProcessNum)
			for input_no in range(input_num):
				pool.apply_async(
					gen_report,
					args = (input_no, inputs[input_no], config_info['poc_fmt'], config_info['trace_cmd'], config_info['trace_replace_idx'],
						   config_info['crash_cmd'], config_info['crash_replace_idx'], config_info['crash_tag'], selected_seed_trace),
					callback = result_collection.append
				)
			pool.close()
			pool.join()
			logging.debug("#(Missed): %d" % (input_num-len(result_collection)))
			# Delete all the tmp files
			shutil.rmtree(TmpFolder)
			os.mkdir(TmpFolder)
			# if input_num != len(result_collection):
			# 	missed_ids = set(range(input_num)) - set([item[0] for item in result_collection])
			# 	missed_inputs = [inputs[id] for id in missed_ids]
			# 	output_path = os.path.join(OutFolder, 'missed_inputs.pkl')
			# 	utils.write_pkl(output_path, missed_inputs)
			# 	raise Exception("ERROR: #execution does not match with #input. -> Missed inputs can be found in %s" % output_path)
			# collect all the trace
			diff_collection = set()
			crash_collection = {'m'}
			for item in result_collection:
				diff_collection.add(item[4])
				crash_collection.add(item[3])
				# save the trace
				if item[2] not in TraceHashCollection:
					TraceHashCollection.append(item[2])
					trace_path = os.path.join(TraceFolder, item[2])
					# utils.write_pkl(trace_path, item[1])
					np.savez(trace_path, trace=item[1])
				# check whether to add it into the seed pool
				if item[3] == 'm' and item[2] not in SeedTraceHashList:
					SeedPool.append([False, inputs[item[0]]])
					SeedTraceHashList.append(item[2])
				# Update reports
				if [item[2], item[3]] not in ReportCollection:
					ReportCollection.append([item[2], item[3]])
			logging.debug("#Diff: %d; #ExeResult: %d; #seed: %d" % (len(diff_collection), len(crash_collection), len(SeedPool)))
			# update sensitivity map
			loc_sensitivity_map, crash_sensitivity_map = update_sens_map(mutate_idx, diff_collection, crash_collection, loc_sensitivity_map, crash_sensitivity_map)
			# check whether it timeouts or not
			ctime = time()
			duration = ctime-stime
			if(duration >= config_info['local_timeout']): # exist if it timeouts
				logging.debug("[R-%d-%d] Timeout locally! -> Duration: %f (%f - %f) in seconds" % (round_no, subround_no, duration, ctime, stime))
				break
			# check whether all the locations get explored or not.
			unexplore_loc_idx_list = np.where(np.asarray([len(item) for item in loc_sensitivity_map['value']]) == 0)[0]
			logging.debug("[R-%d-%d] #(Unexplored Locs): %d" % (round_no, subround_no, len(unexplore_loc_idx_list)))
			if len(unexplore_loc_idx_list) == 0:
				logging.debug("[R-%d-%d] Finish exploring all the locs!" % (round_no, subround_no))
				break
			# loc_tag = np.where(np.sum(loc_sensitivity_map['value'], axis = 1) > 0)[0]
			# if len(loc_tag) >= len(selected_seed_trace):
			# 	logging.debug("[R-%d-%d] Finish exploring all the locs!" % (round_no, subround_no))
			# 	break
		# processing the local sensitivity (for saving the hard disk)
		loc_sens = []
		loc_idxes = []
		loc_num = len(loc_sensitivity_map['value'])
		for loc_id in range(loc_num):
			if len(loc_sensitivity_map['value'][loc_id]) > 0:
				loc_idxes.append(loc_id)
				loc_sens.append(loc_sensitivity_map['value'][loc_id])
		# loc_sens = []
		# loc_idxes = []
		# loc_num = len(loc_sensitivity_map['value'])
		# for loc_id in range(loc_num):
		# 	tmp = np.where(loc_sensitivity_map['value'][loc_id]>0)[0]
		# 	if len(tmp) > 0:
		# 		loc_idxes.append(loc_id)
		# 		loc_sens.append(tmp)
		# save the sensitivity map
		sensitivity_filepath = os.path.join(OutFolder, 'sensitivity_%s.pkl' % selected_seed_trace_hash)
		logging.debug("Start saving the sensitivity map -> %s" % sensitivity_filepath)
		info = {
			'idx': loc_sensitivity_map['idx'],
			'loc_idx': loc_idxes,
			'loc_sens': loc_sens,
			'crash_sens': list(crash_sensitivity_map['value']),
			'loc_tag': list(loc_sensitivity_map['tag'])
		}
		utils.write_pkl(sensitivity_filepath, info)
		logging.debug("Finish writing the sensitivity map -> %s" % sensitivity_filepath)
		# check whether it timeouts
		ctime = time()
		duration = ctime - stime
		if (duration >= config_info['global_timeout']):
			logging.debug("[R-%d] Timeout! -> Duration: %f (%f - %f) in seconds" % (round_no, duration, ctime, stime))
			break

	# save all the remaining info
	report_filepath = os.path.join(OutFolder, 'reports.pkl')
	utils.write_pkl(report_filepath, ReportCollection)
	logging.debug("Finish writing all the reports!")

	seed_filepath = os.path.join(OutFolder, 'seeds.pkl')
	utils.write_pkl(seed_filepath, SeedPool)
	logging.debug("Finish writing all the seeds!")

	seed_hash_filepath = os.path.join(OutFolder, 'seed_hashes.pkl')
	utils.write_pkl(seed_hash_filepath, SeedTraceHashList)
	logging.debug("Finish writing all the hash of seeds!")
	logging.debug('Done!')

if __name__ == '__main__':
	tag, config_info, verbose = parse_args()
	init_log(tag, verbose, config_info['folder'])
	concentrate_fuzz(config_info)
