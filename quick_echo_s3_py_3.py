import sys
from pprint import pprint
from s3_helpers import *

def main(args):
	if len(args) < 6:
		log("Expected parametes: access_key [secret_key|decrypt:encypted_key|encrypt:secret_key] local_dir remote_bucket_and_prefix exclude cache_file [storage class] [access level acl]")
		exit(-1)
	else:
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
			log('Run again with dcrypted:[encrypted secret key (above)] to sync to S3.')
			exit(-1)

		local_dir = args[2]
		remote = args[3]
		exclude = args[4]
		cache_file = args[5]
		
	storage_class = 'REDUCED_REDUNDANCY'
	try:
		storage_class = args[6]
	except:
		pass
		
	access_level = 'private'
	try:
		access_level = args[7]
	except:
		pass

	remote_separator = remote.find("/")

	if remote_separator == -1:
		remote_bucket = remote
		remote_prefix = ""
	else: 
		remote_bucket = remote[0:remote_separator]
		remote_prefix = remote[remote_separator+1:]	

	if cache_file != "" and os.path.exists(cache_file):
		remote_map = load_remote_map(cache_file)
	else:
		remote_map = get_remote_file_map(access_key, secret_key, remote_bucket, remote_prefix)

	local_map = get_local_file_map(local_dir, exclude)

	to_upload, to_copy, to_delete = determine_operations(local_dir, local_map, remote_map)
	
	execute_operations(access_key, secret_key, local_dir, remote_bucket, remote_prefix, 
		to_upload, to_copy, to_delete, remote_map, storage_class, access_level)

	if cache_file != "":
		save_remote_map(remote_map, cache_file)

	close_log_file()

if __name__ == "__main__":
	main(sys.argv[1:])
