#include "common.hpp"
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <unistd.h>
#include <sys/stat.h>

/*
 * Computes SHA-256 of the file referred to by fd using the EVP API.
 * - If fd is seekable: hashes the whole file (from start) and restores the offset.
 * - If fd is not seekable: hashes from the current offset to EOF.
 * out_hex must have space for at least 65 bytes (64 hex chars + NUL).
 * Returns 0 on success, -1 on error (errno set).
 */
std::string sha256_fd_hex(int fd) {
    char out_hex[65];
    memset(out_hex, '0', sizeof(out_hex));
    unsigned char buf[32768];
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    EVP_MD_CTX *ctx = NULL;

    try {
        ctx = EVP_MD_CTX_new();
        if (!ctx) {
            errno = ENOMEM;
            std::cout << "SHA256 error: EVP_MD_CTX_new" << std::endl;
            return "";
        }
        if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
            errno = EFAULT;
            throw "EVP_DigestInit_ex failed";
        }

        for (;;) {
            ssize_t r = read(fd, buf, sizeof buf);
            if (r > 0) {
                if (EVP_DigestUpdate(ctx, buf, (size_t)r) != 1) {
                    errno = EFAULT;
                    throw "EVP_DigestUpdate failed";
                }
            } else if (r == 0) {
                break; // EOF
            } else {
                if (errno == EINTR) continue;
                throw "read failed";
            }
        }

        if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1) {
            errno = EFAULT;
            throw "EVP_DigestFinal_ex failed";
        }
        if (digest_len != 32) { // SHA-256 should be 32 bytes
            errno = EFAULT;
            throw "Wrong hash size";
        }

        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            sprintf(out_hex + (i * 2), "%02x", digest[i]);
        }
    } catch (std::string err) {
        std::cout << "Error in SHA256: " << err << std::endl;
    }
    EVP_MD_CTX_free(ctx);
    out_hex[sizeof(out_hex)-1] = '\0';
    return out_hex;
}


/*
 * Computes SHA-256 of the file referred to by fd using the EVP API.
 * - If fd is seekable: hashes the whole file (from start) and restores the offset.
 * - If fd is not seekable: hashes from the current offset to EOF.
 * out_hex must have space for at least 65 bytes (64 hex chars + NUL).
 * Returns 0 on success, -1 on error (errno set).
 */
std::string sha256_file_hex(const char *path) {
    unsigned char buf[32768];
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    EVP_MD_CTX *ctx = NULL;
	int fd = open(path, O_RDONLY);
	if (fd == -1) {
		std::cout << "SHA256 error: could not open file: " << path << std::endl;
		return "";
	}
    auto out_hex = sha256_fd_hex(fd);
	close(fd);
    return out_hex;
}

/*
 * Returns the size of the object referenced by fd as an off_t.
 * - For regular files: uses fstat().
 * - For other seekable fds: uses lseek(SEEK_END) and restores the offset.
 * - For non-seekable fds (pipes/sockets): returns -1 with errno set (ESPIPE).
 *
 * Note: On 32-bit systems, compile with -D_FILE_OFFSET_BITS=64 for large files.
 */
off_t fd_size(int fd) {
    struct stat st;
    if (fstat(fd, &st) == -1) {
        return (off_t)-1;
    }
    if (S_ISREG(st.st_mode)) {
        return st.st_size;
    }

    off_t orig = lseek(fd, 0, SEEK_CUR);
    if (orig == (off_t)-1) {
        // Not seekable (e.g., pipe, socket)
        errno = ESPIPE;
        return (off_t)-1;
    }

    off_t end = lseek(fd, 0, SEEK_END);
    int saved_errno = errno;
    (void)lseek(fd, orig, SEEK_SET); // best-effort restore
    if (end == (off_t)-1) {
        errno = saved_errno;
    }
    return end;
}

int get_parent_pid(int pid) {
    if (pid == 0) {
        return -1;
    }
    fs::path status_path = fs::path("/proc") / std::to_string(pid) / "status";
    std::ifstream status_file(status_path);
    if (!status_file.is_open()) {
        std::cerr << "Unable to open status file for PID " << pid << std::endl;
        return -1;  // Return -1 to indicate an error
    }

    std::string line;
    while (std::getline(status_file, line)) {
        if (line.rfind("PPid:", 0) == 0) {  // Check if line starts with "PPid:"
            std::istringstream line_stream(line);
            std::string label;
            int ppid;
            line_stream >> label >> ppid;
            return ppid;
        }
    }

    return -1;  // Return -1 if PPid line is not found
}

std::vector<std::string> get_program_args_from_pid(int pid) {
    std::vector<std::string> args;
    if (pid < 1) {
        return args;
    }
    fs::path cmdline_path = fs::path("/proc") / std::to_string(pid) / "cmdline";
    
    std::ifstream cmdline_file(cmdline_path);
    if (!cmdline_file.is_open()) {
        //std::cout << "Unable to open cmdline file for PID " << pid << ": " << cmdline_path << std::endl;
        return args;
    }

    std::string arg;
    while (std::getline(cmdline_file, arg, '\0')) {
        if (!arg.empty()) {
            args.push_back(arg);
        }
    }

    return args;
}

fs::path get_file_path_from_fd(int fd) {
    fs::path fd_path = fs::path("/proc/self/fd") / std::to_string(fd);

    if (!fs::exists(fd_path)) {
        return "";
    }

    try {
        return fs::read_symlink(fd_path);  // Read the symlink target
    } catch (const fs::filesystem_error&) {
        return "";
    }
}

unsigned int get_inode(int fd) {
    /*int fd = open(path.c_str(), O_PATH);

    if (fd < 0) {
        return -1;
    }*/

    struct stat file_stat;
    int ret;
    ret = fstat (fd, &file_stat);
    if (ret < 0) {
        return -1;
    }

    return file_stat.st_ino;
}
