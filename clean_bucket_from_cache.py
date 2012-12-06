#
# Copyright (C) 2012 David Raffensperger
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
# and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS 
# IN THE SOFTWARE.
#
#
#
#
# Program to Syncronize a local directory with an S3 directory/bucket
# David Raffensperger
# Created May 2011

# Part of it requires PyCrypto
# To install PyCrypto on Windows, go to: http://www.voidspace.org.uk/python/modules.shtml#pycrypto
# Ideas:
#	Run it every day but partition the files to upload many only once per month (would need to save date of last file,
#		   could hash names mod frequency)
#	Check the modified times for whole directories and traverse down to find the changed files - don't think that really works in Vista/NTFS
#	Compress large files
#	Try to optimize big files that change a lot into archived vs. current
#	Only upload files that have changed a lot (a big size change)
#	Ignore files over a certain size unless they are in a specified list
# 
# More ideas:
#	Make it not use os.walk, and make it use stat to do a walk, and get the modified times of files
#	Add better exception handling
#	 Use multi-delete S3 operation
#	 Have multiple TCP connections and upload multiple files at a time?
#	 Do disk operations in parallel with network operations?
#	Consider cases of files that get modified in the midst of running the script
#	Make it so that it doesn't need to store the local map, just process each local file as it goes
#	Make it update the cache file after every file is updated, or maybe every 10 or something, so that it can keep info if it crashes
#	Make a way to sort of uses a hybrid of getting server info and using local cache, so MD5's don't need to be corrected, but file can get back in sync.
#	Make a GUI with wxPython
#	Make it an Open Source project on SourceForge
#	Make it check that things were deleted and copied successfully
#	Work to have it have better error handling and check more things against S3 and with the local file system, make it more fault-tolerant
#	More advanced status stuff that shows total amount of stuff to upload

import sys
from pprint import pprint
from s3_helpers import *

def main(args):
	if len(args) < 4:
		log("Expected parametes: access_key [secret_key|decrypt:encypted_key|encrypt:secret_key] remote_bucket_and_prefix cache_file")
		exit(-1)
	
	access_key = args[0]
	secret_key = args[1]

	dec_prefix = 'decrypt:'
	enc_prefix = 'encrypt:'
	if secret_key.startswith(dec_prefix):
		log('Password to access AWS:')
		password = getpass('')			
		secret_key = decrypt_secret_key(password, secret_key[len(dec_prefix):])
	elif secret_key.startswith(enc_prefix):
		log('Password to encrypt AWS secret key:')
		password = getpass('')			
		secret_key = encrypt_secret_key(password, secret_key[len(enc_prefix):])
		log('Key Encrypted as: ' + secret_key)
		log('Run again with decrypt:[encrypted secret key (above)] to sync to S3.')
		exit(-1)

	remote = args[2]
	cache_file = args[3]
	
	remote_separator = remote.find("/")

	if remote_separator == -1:
		remote_bucket = remote
		remote_prefix = ""
	else: 
		remote_bucket = remote[0:remote_separator]
		remote_prefix = remote[remote_separator+1:]	
	
	remote_map = get_remote_file_map(access_key, secret_key, remote_bucket, remote_prefix)
	
	local_cache = load_remote_map(cache_file)

	remote_files = list(remote_map.by_path.values())
	
	for remote_file in remote_files:
		if remote_file.path not in local_cache.by_path:
			full_path = "/" + remote_bucket + "/" + remote_prefix + remote_file.path
			try:			
				s3_operation(access_key, secret_key, "DELETE", full_path, "", {})
		
				log("Cleaned: " + str(full_path))
			except:
				log("Error deleting file: " + str(full_path))
			
	close_log_file()

if __name__ == "__main__":
	main(sys.argv[1:])
