This small Python script that will echo the contents of a directory to an Amazon S3 bucket. It utilizes a local cache file so that assuming the S3 contents are not modified at all, it will only do an incremental echo of files from the local cache. It current requires Python 3.

If a local cache file is not specified (or to build one during the first run), the script will pull the meta data from the S3 bucket.

When a local file is deleted, it deletes the file in the S3 bucket. If a file is modified or deleted in S3 however, those changes are not reflected locally. This is useful for backup but not file sharing because it assumes that the remote files are never changed except by the script.

Here's how to uses it:

python access_key [secret_key|decrypt:encypted_key|encrypt:secret_key] local_dir remote_bucket_and_prefix exclude_reg_exp cache_file [storage class] [access level acl]

Examples:

	python quick_echo_s3_py_3.py 44CF9590006BF252F707 encrypt:OtxrzxIsfpFjA7SwPzILwy8Bw21TLhquhboDYROV

This will output an encrypted version of your secret key based on a password you enter (in this example). Supposed you give password "test", then the encrypted key would now be /tUAqeXWSZEb6r5IeX8BRuD/5UB177auoAfPKm64btRUJvaUxFJpF2XbfiAc0wfPaBMBGSFRIRzvJP+dzANuBA==

Say you want to syncronize the C:\ToSync with your Amazon S3 bucket ToSyncDestBucket. You would enter this command:

	python quick_echo_s3_py_3.py 44CF9590006BF252F707 decrypt:/tUAqeXWSZEb6r5IeX8BRuD/5UB177auoAfPKm64btRUJvaUxFJpF2XbfiAc0wfPaBMBGSFRIRzvJP+dzANuBA== C:/ToSync/ ToSyncDestBucket/ .*\$RECYCLE\.BIN.* C:\backup_cache.txt STANDARD public-read
	
That would echo the contents of ToSync to ToSyncDestBucket and give them public read access and STANDARD S3 storage. It would store the modified times, MD5 hashes and file sizes in the C:\backup_cache.txt file. That way next time you ran it with the same parameters, it would only upload the changed files, and it would only execute S3 copy commands for renamed or moved files.