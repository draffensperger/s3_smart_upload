# Amazon S3 Helper functions

import sys
import http.client
import time
import hashlib
from pprint import pprint
import string
import random
import re
import hmac
import mimetypes
import base64
import urllib.parse
import os
import types
import traceback
from stat import *
from xml.etree import ElementTree
from getpass import getpass

REMOTE_ENC = 'utf-8'
SEND_CHUNK_SIZE = 8192
LOG_FILE = ''
STORAGE_CLASS = 'REDUCED_REDUNDANCY'

class FileInfo:
	def __init__(self):
		self.base_path = ""
		self.path = ""
		self.md5 = ""
		self.size = 0
		self.mod_time = 0
		self.storage_class = ""		
		self.placeholder_file = None

	def __str__(self):
		try:
			return "\"" + self.path + "\" [" + str(self.size) + " bytes]"
		except:
			return "(Error preparing file info string)"

	def get_full_path(self):
		return os.path.join(self.base_path, self.path)
	
	def calc_md5(self, dir):
		full_path = os.path.join(dir, self.path)
		try:			
			log("Calculating MD5 for " + full_path)			
			out = get_file_md5(full_path)
		except:
			log("Error calculating MD5 for :" + full_path + " " + str(sys.exc_info()[0]))
			out = ""
		return out 

class FileInfoMap:
	def __init__(self):
		self.by_path = {}
		self.by_md5 = {}
		self.by_size = {}

	def add_file(self, info):
		self.by_path[info.path] = info

		if info.size > 0:
			if info.size in self.by_size:
				self.by_size[info.size].append(info)
			else:
				self.by_size[info.size] = [info]

		if info.md5 != "":
			self.by_md5[info.md5] = info

outfile = None

def close_log_file():
	global outfile
	if LOG_FILE != "":
		outfile.close()

def log(str):
	global outfile
	if LOG_FILE != "":
		if outfile == None:
			outfile = open(LOG_FILE, "w")
	try:
		print(str)
		if LOG_FILE != "":
			outfile. write(str + "\n")
	except:
		print("Error printing or writing log file line.")

def save_remote_map(remote_map, cache_file):
	paths = list(remote_map.by_path.keys())
	paths.sort()

	log("Saving remote map ...")

	fh = open(cache_file, 'w+')
	dir_stack = []

	for path in paths:
		line = ""
		dir_parts = path.split("/")
		file_part = dir_parts[-1]
		dir_parts = dir_parts[0:-1]
		#log("Saving map, dir parts: " + dir_parts)
		i = 0
		while i < len(dir_stack) and i < len(dir_parts) and dir_parts[i] == dir_stack[i]:
			line += "\t"
			i += 1

		j = i
		while j < len(dir_stack):
			dir_stack.pop()

		while i < len(dir_parts):
			line += dir_parts[i] + "/"
			dir_stack.append(dir_parts[i])
			i += 1

		info = remote_map.by_path[path]
		line += file_part + "\t" + str(info.size) + "\t" + info.md5 + "\t" + str(info.mod_time) + "\n"		
		#log("Writing line:" + line)
		try:
			fh.write(line)
		except:
			log("Error writing line of remote map.")

	fh.close()

	log("Saved remote map.")

def load_remote_map(cache_file):
	log("Reading remote cache file...")
	fh = open(cache_file, "r+")

	map = FileInfoMap()


	lines = fh.readlines()
	fh.close()

	log("Read remote cache file.")
	log("Creating remote map...")

	dir_stack = []
	indent = 0
	j = 0

	for line in lines:
		path = ""
		i = 0
		while line[i] == '\t':
			path += dir_stack[i] + "/"
			i += 1
		line = line[i:]

		while indent > i:
			dir_stack.pop()
			indent -= 1

		record = line.split("\t")
		#log("Record split: " + record

		dir_parts = record[0].split("/")
		file_part = dir_parts[-1]
		dir_parts = dir_parts[:-1]

		for part in dir_parts:
			dir_stack.append(part)
			indent += 1
			path += part + "/"
	  
		info = FileInfo()
		info.path = path + file_part
		info.size = int(record[1])
		info.md5 = record[2]
		info.mod_time = int(record[3])

		#if j < 50:
		#   log("File in map: " + info
		#   log("File MD5: " + info.md5
		#   log("File mod time: " + info.mod_time
		map.add_file(info)

		j+= 1

	log("Created remote map")

	return map

# From: http://www.joelverhagen.com/blog/2011/02/md5-hash-of-file-in-python/

def execute_operations(access_key, secret_key, local_dir, bucket, prefix, to_upload, to_copy, to_delete, 
	remote_map, storage_class, access_level):
	
	remote_dir_base = "/" + bucket + "/" + prefix

	# Next thing to do: update the remote map accordingly to the things that change.

	total_ops = len(to_copy) + len(to_upload) + len(to_delete)
	op_num = 1

	for copy_op in to_copy:
		copy_local_dst = copy_op[0]
		copy_remote_src = copy_op[1]

		amz_headers = {}
		amz_headers['x-amz-storage-class'] = storage_class		
		amz_headers['x-amz-acl'] = access_level		
		amz_headers['x-amz-copy-source'] = remote_dir_base + copy_remote_src.path

		try:
			status = s3_operation(access_key, secret_key, "PUT", remote_dir_base + copy_local_dst.path, "", amz_headers)		
	
			if status == 200:
				remote_map.add_file(copy_local_dst)
				log("Copied to: " + str(copy_local_dst) + " from " + str(copy_remote_src) \
					  + " (" + str(op_num) + "/" + str(total_ops) + ")")
			else:
				log("Tried to copy, source not found, status: " + str(status))
			
		except:
			log("Error copying file: " + str(copy_local_dst) + " from " + str(copy_remote_src) + ": " + str(sys.exc_info()[0]))

		op_num += 1

	for local in to_upload:
		amz_headers = {}
		amz_headers['x-amz-storage-class'] = storage_class
		amz_headers['x-amz-acl'] = access_level
		
		try:
			s3_operation(access_key, secret_key, "PUT", remote_dir_base + local.path, "", amz_headers, local)
			remote_map.add_file(local)
			log("Uploaded: " + str(local) + " (" + str(op_num) + "/" + str(total_ops) + ")")
		except:
			log("Error uploading file: " + str(local) + ": " + str(sys.exc_info()[0]) + ": " + str(sys.exc_info()[1]))			
			traceback.print_exc(file=sys.stdout)

		op_num += 1

	for remote_to_delete in to_delete:
		try:			
			s3_operation(access_key, secret_key, "DELETE", remote_dir_base + remote_to_delete.path, "", {})
	
			# Note: I just delete it in the by_path category because only that is used for saving the map.
			del remote_map.by_path[remote_to_delete.path]
	
			log("Deleted: " + str(remote_to_delete) + " (" + str(op_num) + "/" + str(total_ops) + ")")
		except:
			log("Error deleting file: " + str(remote_to_delete) + ": " + str(sys.exc_info()[0]))

		op_num += 1

def determine_operations(local_dir, local_map, remote_map):
	log("Comparing local and remote files...")

	to_upload = []
	to_copy = []
	to_delete = remote_map.by_path.copy()

	# eliminate duplicates in local files, replace with placeholders	
	#size_cutoff = 1024		
	# log("Checking for duplicate local files...")
	# local_sizes = list(local_map.by_size.keys())
	# for local_size in local_sizes:
		# if local_size > size_cutoff and len(local_map.by_size[local_size]) > 1:
			# same_size_files = local_map.by_size[local_size]
			
			#Calc MD5's, use from remote if matches
			# for local in same_size_files:
				# remote_by_path = remote_map.by_path.get(local.path)
				# if remote_by_path.size == local.size and remote_by_path.mod_time == local.mod_time:
					# local.md5 = remote_by_path.md5
				# else:
					# local.md5 = local.calc_md5(local_dir)
			
			#Find duplicates by MD5's
			# by_md5 = {}
			# for local in same_size_files:
				# if local.md5 in by_md5:
					# matching_file = by_md5[local.md5]
					# log("Duplicate local file: " + str(local) + " same as " + str(matching_file))
					# local.placeholder_file = matching_file
				# else:
					# by_md5[local.md5] = local
	
	file_list = local_map.by_path.values()	
	for local in file_list:
		try:
			str(local)
		except UnicodeEncodeError:
			print("Unable to convert filename to unicode: " + local.encode(REMOTE_ENC))
			continue
			
		remote_by_path = remote_map.by_path.get(local.path)
		if remote_by_path != None:
			if local.size != remote_by_path.size:
				to_upload.append(local)
			elif local.mod_time != remote_by_path.mod_time or local.mod_time == 0 or remote_by_path.mod_time == 0:
				#log("Local mod time: " + local.mod_time
				#log("Remote mod time: " + remote_by_path.mod_time

				if local.md5 == "":
					local.md5 = local.calc_md5(local_dir)
					
				if local.md5 == remote_by_path.md5:
					remote_by_path.mod_time = local.mod_time
				else:
					to_upload.append(local)

			del to_delete[local.path]
		else:
			if local.size > 0:
				remote_by_size_bucket = remote_map.by_size.get(local.size)

				if remote_by_size_bucket == None:
					to_upload.append(local)
				else:
					#log("File not in remote map: " + local.path
					if local.md5 == "":
						local.md5 = local.calc_md5(local_dir)

					remote_by_md5 = remote_map.by_md5.get(local.md5)
					if remote_by_md5 == None or remote_by_md5.size != local.size:
						to_upload.append(local)
					else:
						to_copy.append([local, remote_by_md5])
			else:
				#log("Should upload blank file: " + local.path
				to_upload.append(local)


	to_delete = to_delete.values()

	for file in to_upload:
		log("About to upload: " + str(file))
	for dst_src in to_copy:
		log("About to copy to: " + str(dst_src[0]) + " from " + str(dst_src[1]))
	for file in to_delete:
		log("About to delete: " + str(file))

	log("Done comparing local and remote files...")

	return to_upload, to_copy, to_delete


def get_local_file_map(local_dir, exclude):
	local_files = []
	local_dir_len = len(local_dir)

	map = FileInfoMap()

	log("Walking directory tree...")
	
	log("Excluding: " + str(exclude))
	
	paths = []
	for root, dirs, files in os.walk(local_dir):
		for name in files:
			full_path = os.path.join(root, name)
			if re.match(exclude, full_path) != None:
				#log("Excluded: " + str(full_path))
				pass
			else:
				paths.append(full_path)
	
	log("Loaded local files")

	log("Getting local file attributes and building map...")
	for full_path in paths:			
		#try:
		stats = os.stat(full_path)		
		info = FileInfo()
		info.base_path = local_dir
		info.path = (full_path[local_dir_len:]).replace("\\", "/")		
		info.size = int(stats[ST_SIZE])
		info.mod_time = int(stats[ST_MTIME])
		map.add_file(info)
		#except:
		#	log("Error getting stats for :" + full_path, sys.exc_info()[0])

	log("Built map of local files.")

	return map

def get_remote_file_map(access_key, secret_key, bucket, prefix):
	map = FileInfoMap()

	marker = ""

	prefix_len = len(prefix)

	while True:
		url = "/" + bucket + "/"

		if marker != "" or prefix != "":
			query_str = "?"
		else:
			query_str = ""

		if marker != "":
			quoted_marker = urllib.parse.quote(marker)
			query_str += "marker=" + quoted_marker
			if prefix != "":
				query_str += "&"

		if prefix != "":
			prefix_str = "prefix=" + urllib.parse.quote(prefix)
			query_str += prefix_str

		result_dict = s3_operation(access_key, secret_key, "GET", url, query_str, {}, None)
		
		try:
			result_dict = result_dict['ListBucketResult']
		except:
			# In this case the bucket may not exist, just return an empty map			
			return map

		if 'Contents' in result_dict:
			contents = result_dict['Contents']
			
			# If just one item, we need to put it in a list for the for loop
			if isinstance(contents, dict):				
				contents = [contents]
			
			for file in contents:
				path_in_bucket = file['Key']
				if path_in_bucket.endswith("/"):
					# Skip the directory listings
					continue

				info = FileInfo()
				info.base_path = url + prefix
				info.path = path_in_bucket[prefix_len:]
				info.path = info.path
				info.storage_class = file['StorageClass']
				info.md5 = file['ETag'][1:-1]
				info.size = int(file['Size'])
				map.add_file(info)
		else:
			contents = []

		if result_dict['IsTruncated'] != 'true':
			break;
		else:
			marker = contents[-1]['Key']
			log("Loaded remote to: " + marker)

	return map

def s3_operation(access_key, secret_key, method, path, query_str="", amz_headers={}, body_file=None):
	server = 's3.amazonaws.com'
	conn = http.client.HTTPConnection(server)

	#Perhaps I could get this from the body_file.md5 if it is specified.
	content_md5 = ""

	content_type = mimetypes.guess_type(path)[0]
	if content_type == None:
		content_type = ""
	
	resource_str = urllib.parse.quote(path)
	resource_str = resource_str
	date_str = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())

	amz_headers_str = ""	
		
	sorted_keys = list(amz_headers.keys())
	sorted_keys.sort()
	for key in sorted_keys:
		if key == 'x-amz-copy-source':
			amz_headers[key] = urllib.parse.quote(amz_headers[key])
		amz_headers_str += key + ":" + amz_headers[key] + "\n"

	# From: http://mashupguide.net/1.0/html/ch16s05.xhtml
	string_to_sign = method + "\n" + content_md5 + "\n" + content_type + "\n" + date_str + "\n" + amz_headers_str + resource_str	
	
	signature = base64.b64encode(hmac.new(secret_key.encode(REMOTE_ENC), string_to_sign.encode(REMOTE_ENC), hashlib.sha1).digest())	
	
	#log("String to sign"
	#log("========================"
	#log string_to_sign
	#log("========================"

	headers = amz_headers

	headers['Date'] = date_str

	# Doesn't hurt to query it again here, so that in case it changed, we have it up-to-date
	if body_file != None:
		body_file.size = os.stat(body_file.get_full_path())[ST_SIZE]
		headers['Content-Length'] = body_file.size
	
	headers['Content-Type'] = content_type
	headers['Authorization'] = "AWS " + access_key + ":" + signature.decode(REMOTE_ENC)

	conn.connect()

	url = resource_str + query_str
	if method == "PUT":
		conn.putrequest(method, url)
		# Took from S3.py		
		
		header_keys = headers.keys()
		for header in header_keys:
			conn.putheader(header, headers[header])			

		conn.endheaders()
	else:
		conn.request(method, url, "", headers)

	if body_file != None:
		fh = open(body_file.get_full_path(), 'rb')
		fh.seek(0)

		md5_hash = hashlib.md5()
		size_left = body_file.size
		while size_left > 0:
			data = fh.read(SEND_CHUNK_SIZE)
			md5_hash.update(data)
			conn.send(data)
			size_left -= len(data)

		body_file.md5 = md5_hash.hexdigest()

		fh.close()
	else:
		md5_hash = ""

	response = conn.getresponse()
	headers = tuple_list_to_dict(response.getheaders())
	data = response.read()
	conn.close()

	if (response.status != 200 and method != "DELETE") or (response.reason == 204 and method != "DELETE"):
		#if (response.status == 404 and amz_headers_str)
		msg = 'Error response: ' + str(response.status) + "||reason: " + response.reason + "||data: " + data.decode(REMOTE_ENC)
		log(msg)
		#raise Exception(msg)	

	if body_file != None:
		if body_file.md5 != headers["ETag"][1:-1]:
			msg = "MD5 Differs for file: " + body_file.path
			log >> sys.stderr, msg
			raise Exception(msg)
	elif method == "GET":
		#log(data)
	
		return xml_to_dict(data)
	
	return response.status

# ------------------------------------------------------------------------
# Misc Helpers
# ------------------------------------------------------------------------

def tuple_list_to_dict(tuple_list):
	dict = {}
	for tuple in tuple_list:
		dict[tuple[0]] = tuple[1]
	return dict

def get_file_md5(path):	
	fh = open(path, 'rb')
	m = hashlib.md5()
	while True:
		data = fh.read(8192)
		if not data:
			break
		m.update(data)

	fh.close()
	return m.hexdigest()

# ------------------------------------------------------------------------
# XML Helpers
# ------------------------------------------------------------------------

def strip_tag_braces_part(tag):
	index = tag.find("}")
	if index == -1:
		return tag
	else:
		return tag[index + 1:]

## From: http://code.activestate.com/recipes/573463-converting-xml-to-dictionary-and-back/
def xml_to_dict_recurse(node):
	nodedict = {}

	if len(node.items()) > 0:
		# if we have attributes, set them
		nodedict.update(dict(node.items()))

	for child in node:
		# recursively add the element's children
		newitem = xml_to_dict_recurse(child)
		tag = strip_tag_braces_part(child.tag)
		if tag in nodedict:
			# found duplicate tag, force a list
			if type(nodedict[tag]) is type([]):
				# append to existing list
				nodedict[tag].append(newitem)
			else:
				# convert to list
				nodedict[tag] = [nodedict[tag], newitem]
		else:
			# only one, directly set the dictionary
			nodedict[tag] = newitem

	if node.text is None:
		text = ''
	else:
		text = node.text.strip()

	if len(nodedict) > 0:
		# if we have a dictionary add the text as a dictionary value (if there is any)
		if len(text) > 0:
			nodedict['_text'] = text
	else:
		# if we don't have child nodes or attributes, just set the text
		nodedict = text

	return nodedict

def xml_to_dict(str):
	root = ElementTree.fromstring(str)
	dict = {}
	tag = strip_tag_braces_part(root.tag)
	dict[tag] = xml_to_dict_recurse(root)
	return dict

# ------------------------------------------------------------------------
# AES Password Helpers
# ------------------------------------------------------------------------
def get_key_from_pw(password):
	random.seed(9284)
	round = 0
	num_rounds = 10000
	rand_salt_len = 20
	initial_salt = "asjkenvien732xe;'/~124*asdfze".encode(REMOTE_ENC)
	key = hashlib.sha256(password.encode(REMOTE_ENC) + initial_salt).digest()

	char_set = string.ascii_uppercase + string.digits

	while round < num_rounds:
		rand_bytes = "".join(random.sample(char_set,rand_salt_len)).encode(REMOTE_ENC)
		key = hashlib.sha256(key + rand_bytes).digest()
		round += 1

	return key

# Taken from: http://www.codekoala.com/blog/2009/aes-encryption-python-using-pycrypto/
# Requires PyCrypto
def encrypt_decrypt_aes(should_encrypt, password, data):
	from Crypto.Cipher import AES

	data = data.encode(REMOTE_ENC)

	key = get_key_from_pw(password)

	PADDING = b'{'
	BLOCK_SIZE = 32

	# create a cipher object using the random secret
	cipher = AES.new(key)

	if should_encrypt:
		data += (BLOCK_SIZE - len(data) % BLOCK_SIZE) * PADDING
		data = cipher.encrypt(data)
		data = base64.b64encode(data)		
	else:
		data = base64.b64decode(data)
		data = cipher.decrypt(data)
		data = data.rstrip(PADDING)		
	
	return data.decode(REMOTE_ENC)

def encrypt_secret_key(password, secret_key):
	return encrypt_decrypt_aes(True, password, secret_key)

def decrypt_secret_key(password, secret_key):
	return encrypt_decrypt_aes(False, password, secret_key)
