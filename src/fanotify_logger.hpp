#include <string>

/* Structure to keep track of monitored directories */
struct Monitored {
    std::string path;
};

/* Size of buffer to use when reading fanotify events */
#define FANOTIFY_BUFFER_SIZE 8192

/* Enumerate list of FDs to poll */
enum {
    FD_POLL_SIGNAL = 0,
    FD_POLL_FANOTIFY,
    FD_POLL_FANOTIFY_2,
    FD_POLL_PIPE,
    FD_POLL_MAX
};

int capture_fanotify(int argc, const char **argv, int pipe_fanotify_to_child, int pipe_child_to_fanotify);