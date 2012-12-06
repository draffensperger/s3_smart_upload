This small Python script that will echo the contents of a directory to an Amazon S3 bucket. It utilizes a local cache file so that assuming the S3 contents are not modified at all, it will only do an incremental echo of files from the local cache.

If a local cache file is not specified (or to build one during the first run), the script will pull the meta data from the S3 bucket.

When a local file is deleted, it deletes the file in the S3 bucket. If a file is modified or deleted in S3 however, those changes are not reflected locally. This is useful for backup but not file sharing because it assumes that the remote files are never changed except by the script.