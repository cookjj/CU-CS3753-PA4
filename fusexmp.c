/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  Minor modifications and note by Andy Sayler (2012) <www.andysayler.com>

  Source: fuse-2.8.7.tar.gz examples directory
  http://sourceforge.net/projects/fuse/files/fuse-2.X/

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall `pkg-config fuse --cflags` fusexmp.c -o fusexmp `pkg-config fuse --libs`

  Note: This implementation is largely stateless and does not maintain
        open file handels between open and release calls (fi->fh).
        Instead, files are opened and closed as necessary inside read(), write(),
        etc calls. As such, the functions that rely on maintaining file handles are
        not implmented (fgetattr(), etc). Those seeking a more efficient and
        more complete implementation may wish to add fi->fh support to minimize
        open() and close() calls and support fh dependent functions.

*/

#define FUSE_USE_VERSION 28
#define HAVE_SETXATTR

/* Define crypt_do actions */
#define ENCRYPT 1
#define DECRYPT 0
#define PASS_THROUGH -1

/* Definitions of extended attribute name and values */
#define XATRR_ENCRYPTED_FLAG "user.pa4-encfs.encrypted"
#define ENCRYPTED "true"
#define UNENCRYPTED "false"

/* Size of encrypted values 4 characters = 4 bytes */
#define XATRR_VALUE_SIZE 4

#define TMPSUFFIX ".really_awesome"


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() and open_memstream */
#define _XOPEN_SOURCE 700
#endif

//#define HAVE_SETXATTR
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <stddef.h>
#include <sys/types.h>
#include <limits.h>


#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include "aes-crypt.h"

//#define USAGE "Usage:\n\t./pa4-encfs KEY ENC_DIR MOUNT_POINT\n"
#define USAGE "Usage:\n\t./fusexmp <passphrase> <mirror_directory> <mount_point>\n"

#define XMP_DATA ((struct xmp_state *) fuse_get_context()->private_data)

struct xmp_state {
    char *mirror_dir;
    char *key_phrase;
};

char* tmp_path(const char* old_path){
    char* new_path;
    int len=0;
    len=strlen(old_path) + strlen(TMPSUFFIX) + 1;
    new_path = malloc(sizeof(char)*len);
    if(new_path == NULL){
        return NULL;
    }
    new_path[0] = '\0';
    strcat(new_path, old_path);
    strcat(new_path, TMPSUFFIX);
    return new_path;
}

/* Function for changing paths of all the functions to the specific mirror directory instead of root */
static void xmp_fullpath(char fpath[PATH_MAX], const char *path)
{
    strcpy(fpath, XMP_DATA->mirror_dir);
    strncat(fpath, path, PATH_MAX); 
}


static int xmp_getattr(const char *path, struct stat *stbuf)
{
	int res;
	

	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);


	res = lstat(fpath, stbuf);

	if (S_ISREG(stbuf->st_mode)){

		FILE *tmpFile = tmpfile();
		FILE *f = fopen(fpath, "wb+");

		fseek(f, 0, SEEK_END);
		long fsize = ftell(f);
		fseek(f, 0, SEEK_SET);

		char *buffer = malloc(fsize+1);
		fread(buffer, fsize, 1, f);
		fwrite(buffer, 1, fsize, tmpFile);

		do_crypt(tmpFile, f, DECRYPT, XMP_DATA->key_phrase);

		fclose(f);
		fclose(tmpFile);
		free(buffer);

		res = lstat(fpath, stbuf);
		if (res == -1){
			return -errno;
		}
	}



	
	/*
	res = lstat(fpath, stbuf);
    if (res == -1){
        return -errno;
    }

if(S_ISREG(stbuf->st_mode)){
        atime = stbuf->st_atime;
        mtime = stbuf->st_mtime;
        ctime = stbuf->st_ctime;
        mode = stbuf->st_mode;

        const char* tmpPath = tmp_path(fpath);
        FILE *f = fopen(fpath, "rb");
		FILE *tmpFile = fopen(tmpPath, "wb");
        do_crypt(f, tmpFile, DECRYPT, XMP_DATA->key_phrase);
        fclose(f);
		fclose(tmpFile);
        res = lstat(tmpPath, stbuf);
        if (res == -1){
            return -errno;
        }

        stbuf->st_atime = atime;
        stbuf->st_mtime = mtime;
        stbuf->st_ctime = ctime;
        stbuf->st_mode= mode;

        remove(tmpPath);
    }
*/
	return 0;
}

static int xmp_access(const char *path, int mask)
{
	int res;
	/* change path to specific mirror directory instead of root */
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	res = access(fpath, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
	int res;
	/* change path to specific mirror directory instead of root */
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	res = readlink(fpath, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}


static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	DIR *dp;
	struct dirent *de;

	(void) offset;
	(void) fi;

	/* change path to specific mirror directory instead of root */
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	dp = opendir(fpath);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0))
			break;
	}

	closedir(dp);
	return 0;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;

	/* change path to specific mirror directory instead of root */
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	/* On Linux this could just be 'mknod(path, mode, rdev)' but this
	   is more portable */
	if (S_ISREG(mode)) {
		res = open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(fpath, mode);
	else
		res = mknod(fpath, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
	int res;

	/* change path to specific mirror directory instead of root */
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	res = mkdir(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_unlink(const char *path)
{
	int res;
	/* change path to specific mirror directory instead of root */
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	res = unlink(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rmdir(const char *path)
{
	int res;

	/* change path to specific mirror directory instead of root */
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	res = rmdir(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_symlink(const char *from, const char *to)
{
	int res;
	/* change path to specific mirror directory instead of root */
	char fto[PATH_MAX];
	xmp_fullpath(fto, to);
	res = symlink(from, fto);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rename(const char *from, const char *to)
{
	int res;
	/* change path to specific mirror directory instead of root */
	char ffrom[PATH_MAX];
	char fto[PATH_MAX];
	xmp_fullpath(ffrom, from);
	xmp_fullpath(fto, to);
	res = rename(ffrom, fto);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_link(const char *from, const char *to)
{
	int res;
	char ffrom[PATH_MAX];
	char fto[PATH_MAX];
	xmp_fullpath(ffrom, from);
	xmp_fullpath(fto, to);
	res = link(ffrom, fto);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chmod(const char *path, mode_t mode)
{
	int res;
	/* change path to specific mirror directory instead of root */
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	res = chmod(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;
	/* change path to specific mirror directory instead of root */
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	res = lchown(fpath, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_truncate(const char *path, off_t size)
{
	int res;
	/* change path to specific mirror directory instead of root */
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	res = truncate(fpath, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_utimens(const char *path, const struct timespec ts[2])
{
	int res;
	struct timeval tv[2];
	/* change path to specific mirror directory instead of root */
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	res = utimes(fpath, tv);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
	int res;
	/* change path to specific mirror directory instead of root */
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	res = open(fpath, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	/*
	(void) fi;
    int res;
    int fd;
    int action = PASS_THROUGH;

    char* tmpval = NULL;
	ssize_t valsize = 0;

    char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	
	FILE *memstream;
	char *membuf;
	size_t memlen;
	memstream = open_memstream(&membuf, &memlen);

	FILE *f = fopen(fpath, "rb");

	do_crypt(f, memstream, action, XMP_DATA->key_phrase);

	fflush(memstream);
	fseek(memstream, 0, SEEK_SET);

	res = fread(buf, 1, memlen, memstream);
	fclose(memstream);
	free(membuf);
	fclose(f);

	return res;
*/
	int fd;
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	(void) fi;
	fd = open(fpath, O_RDONLY);
	if (fd == -1)
		return -errno;

	res = pread(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);
	return res;

}

static int xmp_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	/*
	int fd;
	int res;
	char *membuf;
    size_t memlen;

	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	(void) fi;
	FILE *tmpFile = open_memstream(&membuf, &memlen);
	FILE *f = fopen(fpath, "wb+");
	
	res = fwrite(buf, 1, size, tmpFile);

	fflush(tmpFile);
	fseek(tmpFile, 0, SEEK_SET);
	
	do_crypt(tmpFile, f, -1, XMP_DATA->key_phrase);
	fclose(tmpFile);
	fclose(f);
	free(membuf);
	
	return res;
	*/
	int fd;
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	(void) fi;
	fd = open(fpath, O_WRONLY);
	if (fd == -1)
		return -errno;

	res = pwrite(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);
	return res;
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
	int res;
	/* change path to specific mirror directory instead of root */
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	res = statvfs(fpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

/* Set file attribute to encrypted */
static int xmp_create(const char* path, mode_t mode, struct fuse_file_info* fi) {

/*
	(void) fi;
	(void) mode;

	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

    char *membuf;
    size_t memlen;
    FILE *stream = open_memstream(&membuf, &memlen);
    FILE *f = fopen(fpath, "wb");

    if(f == NULL || stream == NULL)
		return -errno;
	
    if(!do_crypt(stream, f, ENCRYPT, XMP_DATA->key_phrase)){
	fprintf(stderr, "do_crypt failed for creating a file\n");
    }

    fclose(stream);
    fclose(f);
    free(membuf);

    return 0;
*/
    char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

    (void) fi;

    int res;
    res = creat(fpath, mode);
    if(res == -1)
	return -errno;

    close(res);

    return 0;
}


static int xmp_release(const char *path, struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) fi;
	return 0;
}

static int xmp_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) isdatasync;
	(void) fi;
	return 0;
}

#ifdef HAVE_SETXATTR
static int xmp_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	/* change path to specific mirror directory instead of root */
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	int res = lsetxattr(fpath, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	/* change path to specific mirror directory instead of root */
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	int res = lgetxattr(fpath, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
	/* change path to specific mirror directory instead of root */
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	int res = llistxattr(fpath, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
	/* change path to specific mirror directory instead of root */
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	int res = lremovexattr(fpath, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations xmp_oper = {
	.getattr	= xmp_getattr,
	.access		= xmp_access,
	.readlink	= xmp_readlink,
	.readdir	= xmp_readdir,
	.mknod		= xmp_mknod,
	.mkdir		= xmp_mkdir,
	.symlink	= xmp_symlink,
	.unlink		= xmp_unlink,
	.rmdir		= xmp_rmdir,
	.rename		= xmp_rename,
	.link		= xmp_link,
	.chmod		= xmp_chmod,
	.chown		= xmp_chown,
	.truncate	= xmp_truncate,
	.utimens	= xmp_utimens,
	.open		= xmp_open,
	.read		= xmp_read,
	.write		= xmp_write,
	.statfs		= xmp_statfs,
	.create         = xmp_create,
	.release	= xmp_release,
	.fsync		= xmp_fsync,
#ifdef HAVE_SETXATTR
	.setxattr	= xmp_setxattr,
	.getxattr	= xmp_getxattr,
	.listxattr	= xmp_listxattr,
	.removexattr	= xmp_removexattr,
#endif
};

int main(int argc, char *argv[])
{
	
	umask(0);

	/* Making sure there is the proper number of arguments */
	if(argc < 4){
        fprintf(stderr, "ERROR: Not enough arguments.\n");
        fprintf(stderr, USAGE);
        exit(EXIT_FAILURE);
    }

    /* From the tutorial Pfeiffer, Joseph. Writing a FUSE Filesystem: a Tutorial 
    * http: //www.cs.nmsu.edu/~pfeiffer/fuse-tutorial/.
    *
    * Allows Fuse to mirror a specific directory instead of the default root 
    */

    /* Initializing a struct to hold mirror directory and key phrase */
    struct xmp_state *xmp_data;
    xmp_data = malloc(sizeof(struct xmp_state));
    if(xmp_data == NULL){
        fprintf(stderr, "There was an error allocating memory for the state struct. Exiting.\n");
        exit(EXIT_FAILURE);
    }

    /* Pulling out mirror dirctory for VFS functions */
    xmp_data->mirror_dir = realpath(argv[2], NULL);

    /* Pulling out key phrase for encryption/decryption in write, read, create in fuse_operations */
    xmp_data->key_phrase = argv[1];
    fprintf(stdout, "key_phrase = %s\n", xmp_data->key_phrase);
    fprintf(stdout, "mirror_dir = %s\n", xmp_data->mirror_dir);

    /* Passing only 3 arguments, this includes any flags such as -d, from argv to fuse_main because fuse main will
    * use these in other fuse functions: program name and mount point and optional flags
    */
    argv[1] = argv[3];
    argv[2] = argv[4];
    argv[3] = NULL;
    argv[4] = NULL;
    argc = argc - 2;

	return fuse_main(argc, argv, &xmp_oper, xmp_data);
}