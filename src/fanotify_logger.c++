// based on https://github.com/jrelo/fs_monitoring/blob/master/fanotify-example-access-control.c

#include <iostream>
#include <fstream>
#include <filesystem>
#include <sched.h>
#include <signal.h>
#include <string>
#include <unistd.h>
#include <stdlib.h>
#include <poll.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/signalfd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <nlohmann/json.hpp>
#include <boost/process.hpp>


#include <sys/fanotify.h>
#include <linux/fanotify.h>
#include <vector>
#include <cstring>

#include "common.hpp"
#include "fanotify_logger.hpp"


using json = nlohmann::json;
namespace fs = std::filesystem;

static std::vector<Monitored> monitors;

bool is_in_scope(std::string &file_path) {
    bool in_scope = false;
        for (const auto &monitor : monitors) {
            if (file_path.starts_with(monitor.path)) {
                in_scope = true;
            }
        }
        return in_scope;
}

void event_process(struct fanotify_event_metadata *event, int fanotify_fd, std::ofstream &json_log) {
    std::string file_path  = get_file_path_from_fd(event->fd);

    if (event->mask & FAN_OPEN_PERM) {
        struct fanotify_response access;
        access.fd = event->fd;
        access.response = FAN_ALLOW;
        int ppid = get_parent_pid(event->pid);
        
        if (is_in_scope(file_path)) {
            auto program_path = get_program_args_from_pid(event->pid);
            auto hash = sha256_fd_hex(access.fd);
            auto size = fd_size(access.fd);
            json ex3 = {
            {"pid", event->pid},
            {"path", file_path},
            {"argv", program_path},
            {"access", "OPEN"},
            {"ppid", ppid},
            {"sha256", hash},
            {"size", size},
            {"inode", get_inode(event->fd)}
            };
            json_log << ex3.dump() << std::endl;
        }

        write(fanotify_fd, &access, sizeof(access));
    }
    if (event->mask & FAN_CLOSE_NOWRITE) {
        if (is_in_scope(file_path)) {
            auto hash = sha256_fd_hex(event->fd);
            auto size = fd_size(event->fd);
            json ex3 = {
            {"pid", event->pid},
            {"path", file_path},
            {"access", "READ"},
            {"sha256", hash},
            {"size", size},
            {"inode", get_inode(event->fd)}
            };
            json_log << ex3.dump() << std::endl;
        }
    }

    if (event->mask & FAN_CLOSE_WRITE) {
        if (is_in_scope(file_path)) {
            auto hash = sha256_fd_hex(event->fd);
            auto size = fd_size(event->fd);
            json ex3 = {
            {"pid", event->pid},
            {"path", file_path},
            {"access", "WRITE"},
            {"sha256", hash},
            {"size", size},
            {"inode", get_inode(event->fd)}
            };
            json_log << ex3.dump() << std::endl;
        }
    }
    std::fflush(stdout);
    close(event->fd);
}

fs::path get_fd_path(int mount_fd, struct file_handle *file_handle) {
    char fdpath[32];
    char path[PATH_MAX + 1];

    auto event_fd = open_by_handle_at(mount_fd, file_handle, O_RDONLY);
    if (event_fd == -1) {
        if (errno == ESTALE) {
            std::cout << "File handle is no longer valid. File has been deleted" << std::endl;
            return "";
        } else if (errno == EMFILE) {
            std::cout << "Error: Too many open files; Exit"  << std::endl;
            exit(EXIT_FAILURE);
        } else {
            std::cout << "Unknown error on open_by_handle_at: " << errno << std::endl;
            return "";
        }
    }

    sprintf(fdpath, "/proc/self/fd/%d", event_fd);
    auto linklen = readlink(fdpath, path, sizeof(path) - 1);
    if (linklen == -1) {
        std::cout << "readlink error" << std::endl;
        return "";
    }
    path[linklen] = '\0';
    return std::string(path);
}

class Event {
public:
    std::string fid;
    std::string dfid;
    std::string dfid_name;
    std::string old_dfid_name;
    std::string new_dfid_name;
    int inode = -1;

    int info_record_process(struct fanotify_event_info_header * info_header, int mount_fd) {
        if (info_header->info_type == FAN_EVENT_INFO_TYPE_FID) {
            auto record = (struct fanotify_event_info_fid *) (info_header);
            auto file_handle = (struct file_handle *) record->handle;
            // TODO: What is going wrong here? Why does does cause system hang?
            //fid = get_fd_path(mount_fd, file_handle);
            // std::cout << "FAN_EVENT_INFO_TYPE_FID: " << fid << std::endl;
        } else if (info_header->info_type == FAN_EVENT_INFO_TYPE_DFID) {
            auto record = (struct fanotify_event_info_fid *) (info_header);
            auto file_handle = (struct file_handle *) record->handle;
            dfid = get_fd_path(mount_fd, file_handle);
            // std::cout << "FAN_EVENT_INFO_TYPE_DFID: " << dfid << std::endl;
        } else if (info_header->info_type == FAN_EVENT_INFO_TYPE_DFID_NAME) {            
            auto record = (struct fanotify_event_info_fid *) (info_header);
            auto file_handle = (struct file_handle *) record->handle;
            auto file_name = file_handle->f_handle + file_handle->handle_bytes;
            dfid_name = get_fd_path(mount_fd, file_handle) / (char *)file_name;
            // std::cout << "FAN_EVENT_INFO_TYPE_DFID_NAME: " << dfid_name << std::endl;
        } else if (info_header->info_type == FAN_EVENT_INFO_TYPE_OLD_DFID_NAME) {
            auto record = (struct fanotify_event_info_fid *) (info_header);
            auto file_handle = (struct file_handle *) record->handle;
            auto file_name = file_handle->f_handle + file_handle->handle_bytes;
            old_dfid_name = get_fd_path(mount_fd, file_handle) / (char *)file_name;
            // std::cout << "FAN_EVENT_INFO_TYPE_OLD_DFID_NAME: " << old_dfid_name << std::endl;
        } else if (info_header->info_type == FAN_EVENT_INFO_TYPE_NEW_DFID_NAME) {
            auto record = (struct fanotify_event_info_fid *) (info_header);
            auto file_handle = (struct file_handle *) record->handle;
            auto file_name = file_handle->f_handle + file_handle->handle_bytes;
            new_dfid_name = get_fd_path(mount_fd, file_handle) / (char *)file_name;
            // std::cout << "FAN_EVENT_INFO_TYPE_NEW_DFID_NAME: " << new_dfid_name << std::endl;
        } else if (info_header->info_type == FAN_EVENT_INFO_TYPE_PIDFD) {
            // std::cout << "FAN_EVENT_INFO_TYPE_PIDFD" << std::endl;
            auto record = (struct fanotify_event_info_pidfd *) (info_header);
        } else if (info_header->info_type == FAN_EVENT_INFO_TYPE_ERROR) {
            // std::cout << "FAN_EVENT_INFO_TYPE_ERROR" << std::endl;
            auto record = (struct fanotify_event_info_error *) (info_header);
        } else {
            std::cout << "Received unexpected event info type: " << (int)info_header->info_type << std::endl;
            exit(EXIT_FAILURE);
        }
        return info_header->len;
    }

    void event_process_2(struct fanotify_event_metadata *event, int mount_fd, std::ofstream &json_log) {
        int offset = sizeof(*event);
        inode = get_inode(event->fd);
        while (offset < event->event_len - event->metadata_len) {
            auto info_header = (struct fanotify_event_info_header*)(((char *)event) + offset);
            offset += info_record_process(info_header, mount_fd);
        }

        if (event->mask & FAN_RENAME) {
            if (is_in_scope(new_dfid_name)) {
                json ex3 = {
                    {"pid", event->pid},
                    {"path", new_dfid_name},
                    {"old_path", old_dfid_name},
                    {"access", "MOVE"},
                    {"inode", inode},
                };
                json_log << ex3.dump() << std::endl;
            }
        }

        if (event->mask & FAN_DELETE) {
            if (is_in_scope(dfid_name)) {
                json ex3 = {
                    {"pid", event->pid},
                    {"path", dfid_name},
                    {"access", "DELETE"},
                    {"inode", inode},
                };
                json_log << ex3.dump() << std::endl;
            }
        }

        std::fflush(stdout);
        close(event->fd);
    }
};

void shutdown_fanotify(int fanotify_fd, int event_mask) {
    for (const auto &monitor : monitors) {
        fanotify_mark(fanotify_fd, FAN_MARK_REMOVE, event_mask, AT_FDCWD, monitor.path.c_str());
    }
    close(fanotify_fd);
}

int initialize_fanotify(int argc, const char **argv, int init_flags, int f_flags, int event_mask) {
    int fanotify_fd;

    if ((fanotify_fd = fanotify_init(init_flags, f_flags)) < 0) {
        std::cout << "Couldn't setup new fanotify device: " << strerror(errno) << std::endl;
        return -1;
    }

    for (int i = 1; i < argc; ++i) {
        monitors.push_back({std::string(argv[i])});
        if (fanotify_mark(fanotify_fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, event_mask, AT_FDCWD, argv[i]) < 0) {
            std::cout << "Couldn't add monitor in mount '" << argv[i] << "': '" << strerror(errno) << "'" << std::endl;
            return -1;
        }

        std::cout << "Started monitoring mount '" << argv[i] << "'..." << std::endl;
    }

    return fanotify_fd;
}

void shutdown_signals(int signal_fd) {
    close(signal_fd);
}

int initialize_signals() {
    int signal_fd;
    sigset_t sigmask;

    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGINT);
    sigaddset(&sigmask, SIGTERM);

    /*if (sigprocmask(SIG_BLOCK, &sigmask, nullptr) < 0) {
        std::cout << "Couldn't block signals: '" << strerror(errno) << "'" << std::endl;
        return -1;
    }*/

    if ((signal_fd = signalfd(-1, &sigmask, 0)) < 0) {
        std::cout << "Couldn't setup signal FD: '" << strerror(errno) << "'" << std::endl;
        return -1;
    }

    return signal_fd;
}

int capture_fanotify(int argc, const char **argv, int pipe_fanotify_to_child, int pipe_child_to_fanotify) {
    int signal_fd;
    int fanotify_fd;
    int fanotify_fd_2;
    struct pollfd fds[FD_POLL_MAX];

    /* Setup fanotify notifications (FAN) mask. All these defined in fanotify.h. */
    uint64_t event_mask = FAN_OPEN_PERM | FAN_CLOSE; /* Open permission control */
    uint64_t event_mask_2 = FAN_RENAME | FAN_DELETE; 

    auto mount_fd = open(argv[3], O_DIRECTORY | O_RDONLY);
    if (mount_fd == -1) {
        perror(argv[3]);
        return EXIT_FAILURE;
    }

    std::ofstream json_log;
    json_log.open (argv[1]);

    if ((signal_fd = initialize_signals()) < 0) {
        std::cout << "Couldn't initialize signals" << std::endl;
        return EXIT_FAILURE;
    }

    // sync events
    if ((fanotify_fd = initialize_fanotify(argc-2, argv+2, FAN_CLOEXEC | FAN_CLASS_CONTENT, O_RDONLY | O_CLOEXEC | O_LARGEFILE | O_NOATIME, event_mask)) < 0) {
        std::cout << "Couldn't initialize fanotify 1" << std::endl;
        return EXIT_FAILURE;
    }
    // async events
    if ((fanotify_fd_2 = initialize_fanotify(argc-2, argv+2, FAN_CLASS_NOTIF | FAN_REPORT_FID | FAN_REPORT_TARGET_FID | FAN_REPORT_DIR_FID | FAN_REPORT_NAME, O_RDWR, event_mask_2)) < 0) {
        std::cout << "Couldn't initialize fanotify 2" << std::endl;
        return EXIT_FAILURE;
    }

    int tmp = 0;
    write(pipe_fanotify_to_child, &tmp, sizeof(tmp)); // Signal to child process, that fanotify is set up

    fds[FD_POLL_SIGNAL].fd = signal_fd;
    fds[FD_POLL_SIGNAL].events = POLLIN;
    fds[FD_POLL_FANOTIFY].fd = fanotify_fd;
    fds[FD_POLL_FANOTIFY].events = POLLIN;
    fds[FD_POLL_FANOTIFY_2].fd = fanotify_fd_2;
    fds[FD_POLL_FANOTIFY_2].events = POLLIN;
    fds[FD_POLL_PIPE].fd = pipe_child_to_fanotify;
    fds[FD_POLL_PIPE].events = POLLIN;

    while (true) {
        if (poll(fds, FD_POLL_MAX, -1) < 0) {
            std::cout << "Couldn't poll(): '" << strerror(errno) << "'" << std::endl;
            return EXIT_FAILURE;
        }

        if (fds[FD_POLL_PIPE].revents & POLLIN) {
            std::cout << "Child process finished; Exit" << std::endl;
            break;
        }

        if (fds[FD_POLL_SIGNAL].revents & POLLIN) {
            struct signalfd_siginfo fdsi;

            if (read(fds[FD_POLL_SIGNAL].fd, &fdsi, sizeof(fdsi)) != sizeof(fdsi)) {
                std::cout << "Couldn't read signal, wrong size read" << std::endl;
                return EXIT_FAILURE;
            }

            if (fdsi.ssi_signo == SIGINT || fdsi.ssi_signo == SIGTERM) {
                break;
            }

            std::cout << "Received unexpected signal" << std::endl;
        }

        if (fds[FD_POLL_FANOTIFY].revents & POLLIN) {
            char buffer[FANOTIFY_BUFFER_SIZE];
            ssize_t length;

            if ((length = read(fds[FD_POLL_FANOTIFY].fd, buffer, FANOTIFY_BUFFER_SIZE)) > 0) {
                struct fanotify_event_metadata *metadata;

                metadata = (struct fanotify_event_metadata *)buffer;
                while (FAN_EVENT_OK(metadata, length)) {
                    try {
                        event_process(metadata, fanotify_fd, json_log);
                    } catch (...) {
                        std::cout << "Error during event_process" << std::endl;
                    }
                    
                    if (metadata->fd > 0)
                        close(metadata->fd);
                    metadata = FAN_EVENT_NEXT(metadata, length);
                }
            }
        }
        if (fds[FD_POLL_FANOTIFY_2].revents & POLLIN) {
            char buffer[FANOTIFY_BUFFER_SIZE];
            ssize_t length;

            if ((length = read(fds[FD_POLL_FANOTIFY_2].fd, buffer, FANOTIFY_BUFFER_SIZE)) > 0) {
                struct fanotify_event_metadata *metadata;

                metadata = (struct fanotify_event_metadata *)buffer;
                while (FAN_EVENT_OK(metadata, length)) {
                    Event ev;
                    ev.event_process_2(metadata, mount_fd, json_log);
                    if (metadata->fd > 0)
                        close(metadata->fd);
                    metadata = FAN_EVENT_NEXT(metadata, length);
                }
            }
        }
    }

    std::cout << "shutdown_fanotify..." << std::endl;
    shutdown_fanotify(fanotify_fd, event_mask);
    shutdown_fanotify(fanotify_fd_2, event_mask_2);
    std::cout << "shutdown_signals..." << std::endl;
    shutdown_signals(signal_fd);
    std::cout << "json_log.close..." << std::endl;
    json_log.close();

    return EXIT_SUCCESS;
}