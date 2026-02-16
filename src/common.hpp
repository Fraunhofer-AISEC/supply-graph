#include <string>
#include <vector>
#include <filesystem>

namespace fs = std::filesystem;

/*
 * Computes SHA-256 of the file referred to by fd using the EVP API.
 * - If fd is seekable: hashes the whole file (from start) and restores the offset.
 * - If fd is not seekable: hashes from the current offset to EOF.
 * out_hex must have space for at least 65 bytes (64 hex chars + NUL).
 * Returns 0 on success, -1 on error (errno set).
 */
std::string sha256_fd_hex(int fd);
std::string sha256_file_hex(const char *path);

/*
 * Returns the size of the object referenced by fd as an off_t.
 * - For regular files: uses fstat().
 * - For other seekable fds: uses lseek(SEEK_END) and restores the offset.
 * - For non-seekable fds (pipes/sockets): returns -1 with errno set (ESPIPE).
 *
 * Note: On 32-bit systems, compile with -D_FILE_OFFSET_BITS=64 for large files.
 */
off_t fd_size(int fd);
int get_parent_pid(int pid);
std::vector<std::string> get_program_args_from_pid(int pid);
fs::path get_file_path_from_fd(int fd);
unsigned int get_inode(int fd);