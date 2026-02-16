// based on: https://github.com/libfuse/libfuse/blob/63579dffce8ab079a1a1eab047e63dc1211185d2/example/passthrough.c

#include <chrono>
#define FUSE_USE_VERSION 31

#ifdef linux
/* For pread()/pwrite()/utimensat() */
#define _XOPEN_SOURCE 700
#endif

#include <fuse3/fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif
#include <iostream>
#include <nlohmann/json.hpp>
#include <boost/process.hpp>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "fuse_helpers.h"
#include "common.hpp"

#define HAVE_UTIMENSAT

using json = nlohmann::json;

static int fill_dir_plus = 0;
static int count_fd = 100;

std::string rewrite_path(const char *path) {
	return path;
	//return std::string("/mnt") + path;
}

static void *xmp_init(struct fuse_conn_info *conn,
		      struct fuse_config *cfg)
{
	(void) conn;
	cfg->use_ino = 1;

#if FUSE_MINOR_VERSION > 14
	/* parallel_direct_writes feature depends on direct_io features.
	   To make parallel_direct_writes valid, need either set cfg->direct_io
	   in current function (recommended in high level API) or set fi->direct_io
	   in xmp_create() or xmp_open(). */
	// cfg->direct_io = 1;
	   cfg->parallel_direct_writes = 1;
#endif

	/* Pick up changes from lower filesystem right away. This is
	   also necessary for better hardlink support. When the kernel
	   calls the unlink() handler, it does not know the inode of
	   the to-be-removed entry and can therefore not invalidate
	   the cache of the associated inode - resulting in an
	   incorrect st_nlink value being reported for any remaining
	   hardlinks to this inode. */
	if (!cfg->auto_cache) {
		cfg->entry_timeout = 0;
		cfg->attr_timeout = 0;
		cfg->negative_timeout = 0;
	}

	return NULL;
}

static int xmp_getattr(const char *path, struct stat *stbuf,
		       struct fuse_file_info *fi)
{
	(void) fi;
	int res;

	auto path_s = rewrite_path(path);
	path = path_s.c_str();

	res = lstat(path, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_access(const char *path, int mask)
{
	int res;

	auto path_s = rewrite_path(path);
	path = path_s.c_str();

	res = access(path, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
	int res;

	auto path_s = rewrite_path(path);
	path = path_s.c_str();

	res = readlink(path, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}


static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi,
		       enum fuse_readdir_flags flags)
{
	DIR *dp;
	struct dirent *de;

	(void) offset;
	(void) fi;
	(void) flags;

	auto path_s = rewrite_path(path);
	path = path_s.c_str();

	dp = opendir(path);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		if (fill_dir_plus) {
			fstatat(dirfd(dp), de->d_name, &st,
				AT_SYMLINK_NOFOLLOW);
		} else {
			memset(&st, 0, sizeof(st));
			st.st_ino = de->d_ino;
			st.st_mode = de->d_type << 12;
		}
		if (filler(buf, de->d_name, &st, 0, (enum fuse_fill_dir_flags)fill_dir_plus))
			break;
	}

	closedir(dp);
	return 0;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;

	auto path_s = rewrite_path(path);
	path = path_s.c_str();

	res = mknod_wrapper(AT_FDCWD, path, NULL, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
	int res;

	auto path_s = rewrite_path(path);
	path = path_s.c_str();

	res = mkdir(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_unlink(const char *path)
{
	int res;

	auto path_s = rewrite_path(path);
	path = path_s.c_str();

	res = unlink(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rmdir(const char *path)
{
	int res;

	auto path_s = rewrite_path(path);
	path = path_s.c_str();

	res = rmdir(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_symlink(const char *from, const char *to)
{
	int res;

	auto from_s = rewrite_path(from);
	from = from_s.c_str();
	//auto to_s = rewrite_path(to);
	//to = to_s.c_str();

	res = symlink(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rename(const char *from, const char *to, unsigned int flags)
{
	int res;

	auto from_s = rewrite_path(from);
	from = from_s.c_str();
	auto to_s = rewrite_path(to);
	to = to_s.c_str();

	if (flags)
		return -EINVAL;

	res = rename(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_link(const char *from, const char *to)
{
	int res;

	auto from_s = rewrite_path(from);
	from = from_s.c_str();
	//auto to_s = rewrite_path(to);
	//to = to_s.c_str();

	res = link(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chmod(const char *path, mode_t mode,
		     struct fuse_file_info *fi)
{
	(void) fi;
	int res;

	auto path_s = rewrite_path(path);
	path = path_s.c_str();

	res = chmod(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid,
		     struct fuse_file_info *fi)
{
	(void) fi;
	int res;

	auto path_s = rewrite_path(path);
	path = path_s.c_str();

	res = lchown(path, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_truncate(const char *path, off_t size,
			struct fuse_file_info *fi)
{
	int res;

	auto path_s = rewrite_path(path);
	path = path_s.c_str();

	if (fi != NULL)
		res = ftruncate(fi->fh, size);
	else
		res = truncate(path, size);
	if (res == -1)
		return -errno;

	return 0;
}

#ifdef HAVE_UTIMENSAT
static int xmp_utimens(const char *path, const struct timespec ts[2],
		       struct fuse_file_info *fi)
{
	(void) fi;
	int res;

	auto path_s = rewrite_path(path);
	path = path_s.c_str();

	/* don't use utime/utimes since they follow symlinks */
	res = utimensat(0, path, ts, AT_SYMLINK_NOFOLLOW);
	if (res == -1)
		return -errno;

	return 0;
}
#endif

static void log_file_info(const char *path, int fd, std::string action) {
	auto ctx = fuse_get_context();

	auto hash = sha256_file_hex(path);
	auto size = fd_size(fd);
	auto t = duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
	auto argv = get_program_args_from_pid(ctx->pid);
	auto inode = get_inode(fd);
	auto ppid = get_parent_pid(ctx->pid);

	json event = {
		{"action", action},
		{"PID", ctx->pid},
		{"PPID", ppid},
		{"fd", fd},
		{"path", path},
		{"sha256", hash},
		{"argv", argv},
		{"inode", inode},
		{"size", size},
		{"time", t},
	};
	static std::mutex m;
	{
		std::lock_guard<std::mutex> lk(m);
		std::cerr << event.dump() << std::endl;
	}

}

static int create_unique_fd(const char *path, int fd) {
	static std::mutex m;
	{
		for (int i=0;i<100;i++) {
			if (count_fd == std::numeric_limits<int>::max()) {
				std::cout << "PID: " << fuse_get_context()->pid << " Error: unique file counter reached max: " << count_fd << "; re-init" << std::endl;
				count_fd = 100;
			}
			/*int fd = fcntl(STDIN_FILENO, F_DUPFD_CLOEXEC, count_fd);
			if (fd == -1) {
				std::cout << "Error on fcntl: " << errno << std::endl;
				return -errno;
			}
			count_fd = fd+1;
			close(fd);*/
			if (fcntl(count_fd, F_GETFD) != -1) {
				std::cout << "PID: " << fuse_get_context()->pid << " Warning: opening file " << path << " unique fd (" << count_fd << ") from counter already taken; retry: " << i << std::endl;
				count_fd++;
				continue;
			}
			int ufd = dup2(fd, count_fd++);
			if (ufd == -1) {
				return -errno;
			}
			close(fd);
			return ufd;
		}
		std::cout << "PID: " << fuse_get_context()->pid << " Error: opening file " << path << " unique fd (" << count_fd << ") from counter already taken; retry exceeded: " << std::endl;
		return -1;
	}
}

static int xmp_create(const char *path, mode_t mode,
		      struct fuse_file_info *fi)
{
	int res;

	auto path_s = rewrite_path(path);
	path = path_s.c_str();

	res = open(path, fi->flags, mode);
	if (res == -1)
		return -errno;

	int ufd = create_unique_fd(path, res);
	if (ufd < 0) {
		std::cout << "PID: " << fuse_get_context()->pid << " Error on create when create unique fd: " << res << " -> " << ufd << std::endl;
		return ufd;
	}
	log_file_info(path, ufd, "OPEN");

	fi->fh = ufd;
	return 0;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
	int res;
	std::string path_org(path);
	auto path_s = rewrite_path(path);
	path = path_s.c_str();

	res = open(path, fi->flags);
	if (res == -1)
		return -errno;

#if FUSE_MINOR_VERSION > 14
	/* Enable direct_io when open has flags O_DIRECT to enjoy the feature
	parallel_direct_writes (i.e., to get a shared lock, not exclusive lock,
	for writes to the same file). */
	if (fi->flags & O_DIRECT) {
		fi->direct_io = 1;
		fi->parallel_direct_writes = 1;
	}
#endif

	int ufd = create_unique_fd(path, res);
	if (ufd < 0) {
		std::cout << "PID: " << fuse_get_context()->pid << " Error on create when create unique fd: " << res << " -> " << ufd << std::endl;
		return ufd;
	}
	log_file_info(path, ufd, "OPEN");

	fi->fh = ufd;

	return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	int fd;
	int res;

	auto path_s = rewrite_path(path);
	path = path_s.c_str();

	if(fi == NULL)
		fd = open(path, O_RDONLY);
	else
		fd = fi->fh;
	
	if (fd == -1)
		return -errno;

	res = pread(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	if(fi == NULL)
		close(fd);
	return res;
}

static int xmp_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	int fd;
	int res;

	auto path_s = rewrite_path(path);
	path = path_s.c_str();

	(void) fi;
	if(fi == NULL)
		fd = open(path, O_WRONLY);
	else
		fd = fi->fh;
	
	if (fd == -1)
		return -errno;

	res = pwrite(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	if(fi == NULL)
		close(fd);
	return res;
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
	int res;

	auto path_s = rewrite_path(path);
	path = path_s.c_str();

	res = statvfs(path, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_release(const char *path, struct fuse_file_info *fi)
{
	(void) path;

	auto path_s = rewrite_path(path);
	path = path_s.c_str();

	log_file_info(path, fi->fh, "CLOSE");

	close(fi->fh);

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

static int xmp_fallocate(const char *path, int mode,
			off_t offset, off_t length, struct fuse_file_info *fi)
{
	int fd;
	int res;

	(void) fi;

	auto path_s = rewrite_path(path);
	path = path_s.c_str();

	if(fi == NULL)
		fd = open(path, O_WRONLY);
	else
		fd = fi->fh;
	
	if (fd == -1)
		return -errno;

	res = do_fallocate(fd, mode, offset, length);

	if(fi == NULL)
		close(fd);
	return res;
}

#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
static int xmp_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	auto path_s = rewrite_path(path);
	path = path_s.c_str();

	int res = lsetxattr(path, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	auto path_s = rewrite_path(path);
	path = path_s.c_str();

	int res = lgetxattr(path, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
	auto path_s = rewrite_path(path);
	path = path_s.c_str();

	int res = llistxattr(path, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
	auto path_s = rewrite_path(path);
	path = path_s.c_str();

	int res = lremovexattr(path, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

#ifdef HAVE_COPY_FILE_RANGE
static ssize_t xmp_copy_file_range(const char *path_in,
				   struct fuse_file_info *fi_in,
				   off_t offset_in, const char *path_out,
				   struct fuse_file_info *fi_out,
				   off_t offset_out, size_t len, int flags)
{
	int fd_in, fd_out;
	ssize_t res;

	if(fi_in == NULL)
		fd_in = open(path_in, O_RDONLY);
	else
		fd_in = fi_in->fh;

	if (fd_in == -1)
		return -errno;

	if(fi_out == NULL)
		fd_out = open(path_out, O_WRONLY);
	else
		fd_out = fi_out->fh;

	if (fd_out == -1) {
		close(fd_in);
		return -errno;
	}

	res = copy_file_range(fd_in, &offset_in, fd_out, &offset_out, len,
			      flags);
	if (res == -1)
		res = -errno;

	if (fi_out == NULL)
		close(fd_out);
	if (fi_in == NULL)
		close(fd_in);

	return res;
}
#endif

static off_t xmp_lseek(const char *path, off_t off, int whence, struct fuse_file_info *fi)
{
	int fd;
	off_t res;

	auto path_s = rewrite_path(path);
	path = path_s.c_str();

	if (fi == NULL)
		fd = open(path, O_RDONLY);
	else
		fd = fi->fh;

	if (fd == -1)
		return -errno;

	res = lseek(fd, off, whence);
	if (res == -1)
		res = -errno;

	if (fi == NULL)
		close(fd);
	return res;
}

#ifdef HAVE_STATX
static int xmp_statx(const char *path, int flags, int mask, struct statx *stxbuf,
		     struct fuse_file_info *fi)
{
	int fd = -1;
	int res;

	auto path_s = rewrite_path(path);
	path = path_s.c_str();

	if (fi)
		fd = fi->fh;

	res = statx(fd, path, flags | AT_SYMLINK_NOFOLLOW, mask, stxbuf);
	if (res == -1)
		return -errno;

	return 0;
}
#endif

void create_fuse_context(struct fuse_operations *xmp_oper) {
	*xmp_oper = {
	.getattr	= xmp_getattr,
	.readlink	= xmp_readlink,
	.mknod		= xmp_mknod,
	.mkdir		= xmp_mkdir,
	.unlink		= xmp_unlink,
	.rmdir		= xmp_rmdir,
	.symlink	= xmp_symlink,
	.rename		= xmp_rename,
	.link		= xmp_link,
	.chmod		= xmp_chmod,
	.chown		= xmp_chown,
	.truncate	= xmp_truncate,
	.open		= xmp_open,
	.read		= xmp_read,
	.write		= xmp_write,
	.statfs		= xmp_statfs,
	.release	= xmp_release,
	.fsync		= xmp_fsync,
	.readdir	= xmp_readdir,
	.init           = xmp_init,
	.access		= xmp_access,
	.create 	= xmp_create,
#ifdef HAVE_UTIMENSAT
	.utimens	= xmp_utimens,
#endif
#ifdef HAVE_POSIX_FALLOCATE
	.fallocate	= xmp_fallocate,
#endif
#ifdef HAVE_SETXATTR
	.setxattr	= xmp_setxattr,
	.getxattr	= xmp_getxattr,
	.listxattr	= xmp_listxattr,
	.removexattr	= xmp_removexattr,
#endif
#ifdef HAVE_COPY_FILE_RANGE
	.copy_file_range = xmp_copy_file_range,
#endif
	.lseek		= xmp_lseek,
};
}

int fuse_fs_run(int argc, const char **argv, int pipe_fanotify_to_child, int pipe_child_to_fanotify) {
	struct fuse_operations xmp_oper;
	create_fuse_context(&xmp_oper);
	char *fuse_args[] = {"foo", "/tmp"};
	int ret = fuse_main(0, fuse_args, &xmp_oper, NULL);
	if (ret !=0) {
		std::cout << "Error on mounting fuse fs: " << ret << std::endl;
		return ret;
	}
	std::this_thread::sleep_for(std::chrono::seconds(5));  // wait for fuse mount to be ready

	int tmp = 0;
    write(pipe_fanotify_to_child, &tmp, sizeof(tmp)); // Signal to child process, that fanotify is set up
	read(pipe_child_to_fanotify, &tmp, sizeof(tmp));  // wait for buiold process to be done
	// TODO: umount
    return 0;
}

#ifdef FUSE_MAIN
int main(int argc, char *argv[])
{
	enum { MAX_ARGS = 10 };
	int i,new_argc;
	char *new_argv[MAX_ARGS];
	struct fuse_operations xmp_oper;

	umask(0);
			/* Process the "--plus" option apart */
	for (i=0, new_argc=0; (i<argc) && (new_argc<MAX_ARGS); i++) {
		if (!strcmp(argv[i], "--plus")) {
			fill_dir_plus = FUSE_FILL_DIR_PLUS;
		} else {
			new_argv[new_argc++] = argv[i];
		}
	}
	create_fuse_context(&xmp_oper);
	return fuse_main(new_argc, new_argv, &xmp_oper, NULL);
}
#endif