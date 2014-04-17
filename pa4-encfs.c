/* This file is a FUSE executable. It creates a mounted directory of a mirror directory found 
*	in the command arguments.  It also uses a passphrase to encrypt a decrypt files using 
*	AES encryption with OpenSSL libcrypto EVP API and FUSE filesystem.
*	Command Line Usage: "Usage: ./pa4-encfs <passphrase> <mirror_directory> <mount_point>
*/
  


#define FUSE_USE_VERSION 28
#define HAVE_SETXATTR

/* Define do_crypt actions */
#define ENCRYPT 1
#define DECRYPT 0
#define PASS_THROUGH -1

/* Definitions of extended attribute name and values */
#define XATRR_ENCRYPTED_FLAG "user.pa4-encfs.encrypted"
#define ENCRYPTED "true"
#define UNENCRYPTED "false"

/* File suffixes for the tmp_path function to distinguish which function is calling it*/
#define SUFFIXGETATTR ".getattr"
#define SUFFIXREAD ".read"
#define SUFFIXWRITE ".write"
#define SUFFIXCREATE ".create"

#ifdef linux
/* Linux is missing ENOATTR error, using ENODATA instead */
#define ENOATTR ENODATA
#endif


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

/* This if for the do_crypt function */
#include "aes-crypt.h"

/* Define command line usage of file */
#define USAGE "Usage:\n\t./fusexmp <passphrase> <mirror_directory> <mount_point>\n"

#define XMP_DATA ((struct xmp_state *) fuse_get_context()->private_data)

struct xmp_state {
    char *mirror_dir;
    char *key_phrase;
};

/* This is function that creates physical temporary file
*	Credit to Alex Beal for this function
 */
char* tmp_path(const char* old_path, const char *suffix){
    char* new_path;
    int len=0;
    len=strlen(old_path) + strlen(suffix) + 1;
    new_path = malloc(sizeof(char)*len);
    if(new_path == NULL){
        return NULL;
    }
    new_path[0] = '\0';
    strcat(new_path, old_path);
    strcat(new_path, suffix);
    return new_path;
}

/* Function for changing paths of all the functions to the specific mirror directory instead of root */
static void xmp_fullpath(char fpath[PATH_MAX], const char *path)
{
    strcpy(fpath, XMP_DATA->mirror_dir);
    strncat(fpath, path, PATH_MAX); 
}

/* This function gets certain characteristics of a file like size and stores them in a struct called stat */
static int xmp_getattr(const char *path, struct stat *stbuf)
{
	int res;
	int crypt_action = PASS_THROUGH;
	ssize_t valsize = 0;
	char *tmpval = NULL;


	time_t    atime;   /* time of last access */
    time_t    mtime;   /* time of last modification */
    time_t    tctime;   /* time of last status change */
    dev_t     t_dev;     /* ID of device containing file */
    ino_t     t_ino;     /* inode number */
    mode_t    mode;    /* protection */
    nlink_t   t_nlink;   /* number of hard links */
    uid_t     t_uid;     /* user ID of owner */
    gid_t     t_gid;     /* group ID of owner */
    dev_t     t_rdev;    /* device ID (if special file) */
	

	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	res = lstat(fpath, stbuf);
	if (res == -1){
			return -errno;
	}
	
	/* is it a regular file? */
	if (S_ISREG(stbuf->st_mode)){

		/* These file characteristics don't change after decryption so just storing them */
		atime = stbuf->st_atime;
		mtime = stbuf->st_mtime;
		tctime = stbuf->st_ctime;
		t_dev = stbuf->st_dev;
		t_ino = stbuf->st_ino;
		mode = stbuf->st_mode;
		t_nlink = stbuf->st_nlink;
		t_uid = stbuf->st_uid;
		t_gid = stbuf->st_gid;
		t_rdev = stbuf->st_rdev;


		/* Get size of flag value and value itself */
		valsize = getxattr(fpath, XATRR_ENCRYPTED_FLAG, NULL, 0);
		tmpval = malloc(sizeof(*tmpval)*(valsize));
		valsize = getxattr(fpath, XATRR_ENCRYPTED_FLAG, tmpval, valsize);
		
		//fprintf(stderr, "Xattr Value: %s\nXattr size: %zu\n", tmpval, sizeof(*tmpval)*(valsize));
		fprintf(stderr, "Xattr Value: %s\n", tmpval);

		/* If the specified attribute doesn't exist or it's set to false */
		if (valsize < 0 || memcmp(tmpval, "false", 5) == 0){
			if(errno == ENOATTR){
				fprintf(stderr, "No %s attribute set\n", XATRR_ENCRYPTED_FLAG);
			}
			//fprintf(stderr, "file is unencrypted, leaving crypt_action as pass-through\n valsize is %zu\n", valsize);
			fprintf(stderr, "file is unencrypted, leaving crypt_action as pass-through\n");

		} /* If the attribute exists and is true then we need to get size of decrypted file */
		else if (memcmp(tmpval, "true", 4) == 0){
			//fprintf(stderr, "file is encrypted, need to decrypt\nvalsize is %zu\n", valsize);
			fprintf(stderr, "file is encrypted, need to decrypt\n");
			crypt_action = DECRYPT;
		}

		const char *tmpPath = tmp_path(fpath, SUFFIXGETATTR);
		FILE *tmpFile = fopen(tmpPath, "wb+");
		FILE *f = fopen(fpath, "rb");

		fprintf(stderr, "fpath: %s\ntmpPath: %s\n", fpath, tmpPath);

		if(!do_crypt(f, tmpFile, crypt_action, XMP_DATA->key_phrase)){
		fprintf(stderr, "getattr do_crypt failed\n");
    	}

		fclose(f);
		fclose(tmpFile);

		/* Get size of decrypted file and store in stat struct */
		res = lstat(tmpPath, stbuf);
		if (res == -1){
			return -errno;
		}

		/* Put info about file we did not want to change back into stat struct*/
		stbuf->st_atime = atime;
		stbuf->st_mtime = mtime;
		stbuf->st_ctime = tctime;
		stbuf->st_dev = t_dev;
		stbuf->st_ino = t_ino;
		stbuf->st_mode = mode;
		stbuf->st_nlink = t_nlink;
		stbuf->st_uid = t_uid;
		stbuf->st_gid = t_gid;
		stbuf->st_rdev = t_rdev;

		free(tmpval);
		remove(tmpPath);
	}

		

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

/* This function reads file contents into application window */
static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{

	(void)fi;
	int res;
	int crypt_action = PASS_THROUGH;
	ssize_t valsize = 0;
	char *tmpval = NULL;

	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	valsize = getxattr(fpath, XATRR_ENCRYPTED_FLAG, NULL, 0);
	tmpval = malloc(sizeof(*tmpval)*(valsize));
	valsize = getxattr(fpath, XATRR_ENCRYPTED_FLAG, tmpval, valsize);
		
	fprintf(stderr, " Read: Xattr Value: %s\n", tmpval);

	/* If the specified attribute doesn't exist or it's set to false */
	if (valsize < 0 || memcmp(tmpval, "false", 5) == 0){
		if(errno == ENOATTR){
			fprintf(stderr, "Read: No %s attribute set\n", XATRR_ENCRYPTED_FLAG);
		}
		fprintf(stderr, "Read: file is unencrypted, leaving crypt_action as pass-through\n");
	}/* If the attribute exists and is true then we need to get size of decrypted file */
	else if (memcmp(tmpval, "true", 4) == 0){
		fprintf(stderr, "Read: file is encrypted, need to decrypt\n");
		crypt_action = DECRYPT;
	}

	const char *tmpPath = tmp_path(fpath, SUFFIXREAD);
	FILE *tmpFile = fopen(tmpPath, "wb+");
	FILE *f = fopen(fpath, "rb");

	fprintf(stderr, "Read: fpath: %s\ntmpPath: %s\n", fpath, tmpPath);

	if(!do_crypt(f, tmpFile, crypt_action, XMP_DATA->key_phrase)){
	fprintf(stderr, "Read: do_crypt failed\n");
    }

    fseek(tmpFile, 0, SEEK_END);
    size_t tmpFilelen = ftell(tmpFile);
    fseek(tmpFile, 0, SEEK_SET);

    fprintf(stderr, "Read: size given by read: %zu\nsize of tmpFile: %zu\nsize of offset: %zu\n", size, tmpFilelen, offset);

    /* Read the decrypted contents of original file to the application widow */
    res = fread(buf, 1, tmpFilelen, tmpFile);
    if (res == -1)
    	res = -errno;

	fclose(f);
	fclose(tmpFile);
	remove(tmpPath);
	free(tmpval);

	return res;
	
	
}

/* Write contents to encrypted or unencrypted file
*	Echo was used to write to files.  See bottom of README, IMPORTANT NOTES.
*/
static int xmp_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	(void) fi;
	(void) offset;
	int res;
	int fd;
	int crypt_action = PASS_THROUGH;
	ssize_t valsize = 0;
	char *tmpval = NULL;

	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);


	valsize = getxattr(fpath, XATRR_ENCRYPTED_FLAG, NULL, 0);
	tmpval = malloc(sizeof(*tmpval)*(valsize));
	valsize = getxattr(fpath, XATRR_ENCRYPTED_FLAG, tmpval, valsize);
		
	fprintf(stderr, " WRITE: Xattr Value: %s\n", tmpval);

	if (valsize < 0 || memcmp(tmpval, "false", 5) == 0){
		if(errno == ENOATTR){
			fprintf(stderr, "WRITE: No %s attribute set\n", XATRR_ENCRYPTED_FLAG);
		}
		fprintf(stderr, "WRITE: file is unencrypted, leaving crypt_action as pass-through\n");
	}/* If the attribute exists and is true then we need to get size of decrypted file */
	else if (memcmp(tmpval, "true", 4) == 0){
		fprintf(stderr, "WRITE: file is encrypted, need to decrypt\n");
		crypt_action = DECRYPT;
	}

	fprintf(stderr, "crypt_action is set to %d\n", crypt_action);

	/* If the file to be written to is encrypted */
	if (crypt_action == DECRYPT){
		fprintf(stderr, "WRITE: File to be written is encrypted\n");
		
		FILE *f = fopen(fpath, "rb+");
		const char *tmpPath = tmp_path(fpath, SUFFIXWRITE);
		FILE *tmpFile = fopen(tmpPath, "wb+");

		fprintf(stderr, "path of original file %s\n", fpath);

		fseek(f, 0, SEEK_END);
		size_t original = ftell(f);
		fseek(f, 0, SEEK_SET);
		fprintf(stderr, "Size of original file %zu\n", original);

		fprintf(stderr, "Decrypting contents of original file to tmpFile for writing\n");
		if(!do_crypt(f, tmpFile, DECRYPT, XMP_DATA->key_phrase)){
		fprintf(stderr, "WRITE: do_crypt failed\n");
    	}

    	fseek(f, 0, SEEK_SET);

    	size_t tmpFilelen = ftell(tmpFile);
    	fprintf(stderr, "Size to be written to tmpFile %zu\n", size);
    	fprintf(stderr, "size of tmpFile %zu\n", tmpFilelen);
    	fprintf(stderr, "Writing to tmpFile\n");

    	res = fwrite(buf, 1, size, tmpFile);
    	if (res == -1)
			res = -errno;

		tmpFilelen = ftell(tmpFile);
		fprintf(stderr, "Size of tmpFile after write %zu\n", tmpFilelen);

		fseek(tmpFile, 0, SEEK_SET);

		fprintf(stderr, "Encrypting new contents of tmpFile into original file\n");
		if(!do_crypt(tmpFile, f, ENCRYPT, XMP_DATA->key_phrase)){
		fprintf(stderr, "WRITE: do_crypt failed\n");
		}

		fclose(f);
		fclose(tmpFile);
		remove(tmpPath);
    	
	}/* If the file to be written to is unencrypted */
	else if (crypt_action == PASS_THROUGH){
		fprintf(stderr, "File to be written is unencrypted");

		fd = open(fpath, O_WRONLY);
		if (fd == -1)
			return -errno;

		res = pwrite(fd, buf, size, offset);
		if (res == -1)
			res = -errno;

		close(fd);
   	}
   	
	free(tmpval);
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

/* Create a file with encrypted contents and encrypted flag
* An empty file is encrypted so that you can't tell if it is empty or not
*/

static int xmp_create(const char* path, mode_t mode, struct fuse_file_info* fi) {

	
    char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	

    (void) fi;
    (void) mode;

	FILE *f = fopen(fpath, "wb+");

	fprintf(stderr, "CREATE: fpath: %s\n", fpath);

	/* It is okay to encrypt a file into itself as long as it's empty
	*	otherwise the contents of the file would be erased.
	*/

	if(!do_crypt(f, f, ENCRYPT, XMP_DATA->key_phrase)){
		fprintf(stderr, "Create: do_crypt failed\n");
    	}

	fprintf(stderr, "Create: encryption done correctly\n");

	fclose(f);

	if(setxattr(fpath, XATRR_ENCRYPTED_FLAG, ENCRYPTED, 4, 0)){
    	fprintf(stderr, "error setting xattr of file %s\n", fpath);
    	return -errno;
   	}
   	fprintf(stderr, "Create: file xatrr correctly set %s\n", fpath);
    

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

    /* Displaying key_phrase and mirror path */
    fprintf(stdout, "key_phrase = %s\n", xmp_data->key_phrase);
    fprintf(stdout, "mirror_dir = %s\n", xmp_data->mirror_dir);

    /* Passing only 3 arguments, this includes any flags such as -d, from argv to fuse_main because fuse main will
    * use these in other fuse functions: program name and mount point and optional flags
    */
    argv[1] = argv[3];//Moving mount directory to second argument
    argv[2] = argv[4];//Moving flag to third argument
    argv[3] = NULL;
    argv[4] = NULL;
    argc = argc - 2; // making sure number of arguments matches up with size of argv

	return fuse_main(argc, argv, &xmp_oper, xmp_data);
}
