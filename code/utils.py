import pickle
import string
import numpy as np
import multiprocessing

# system setup
ProcessNum=np.min((10, multiprocessing.cpu_count()))

# Used for generating the random filename
FileNameChars = list(string.letters + string.digits)
FileNameLen = 30

'''
Process the binary file
'''
def read_bin(path):
	with open(path, 'rb') as f:
		temp = f.readlines()
	temp = ''.join(temp)
	content = [ord(i) for i in temp]
	return content

def write_bin(path, inputs):
	with open(path, 'wb') as f:
		f.write(bytearray(list(inputs)))


'''
Process the normal text file
'''
def read_txt(path):
	with open(path, 'r') as f:
		content = f.readlines()
	return content

def write_txt(path, content):
	with open(path, 'w') as f:
		f.writelines(content)

'''
Process the pickle file
'''
def write_pkl(path, info):
	with open(path, 'w') as f:
		pickle.dump(info, f)

def read_pkl(path):
	with open(path) as f:
		info = pickle.load(f)
	return info


'''
Generating the temp filename
'''
def gen_temp_filename():
	return ''.join(np.random.choice(FileNameChars, FileNameLen))
