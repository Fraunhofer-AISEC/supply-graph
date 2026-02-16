// based on https://github.com/jrelo/fs_monitoring/blob/master/fanotify-example-access-control.c

#include <chrono>
#include <future>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <barrier>
#include <sched.h>
#include <signal.h>
#include <sstream>
#include <string>
#include <unistd.h>
#include <stdlib.h>
#include <poll.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/signalfd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <nlohmann/json.hpp>
#include <boost/process.hpp>


#include <sys/fanotify.h>
#include <vector>
#include <cstring>
#include <thread>

#include "common.hpp"
#include "fanotify_logger.hpp"
#include "fuse-hash-fs.c++"

namespace bp = boost::process;
using json = nlohmann::json;


int exec_watch_command(int argc, const char **argv, int pipe_child_to_fanotify) {
    std::vector<std::string> args = {"-c"};
    std::vector<std::string> args_tmp;
    for (int i=0;i<argc;i++) {
        std::string tmp(argv[i]);
        args_tmp.push_back(tmp);
    }
    args.push_back(boost::algorithm::join(args_tmp, " "));
    int ret = 0;

    std::cout << "start subprocess" << std::endl;
    bp::system(bp::search_path("sh"), args);
    std::cout << "subprocess finished" << std::endl;

    write(pipe_child_to_fanotify, &ret, sizeof(ret)); // Write to child that fanotify finished

    return EXIT_SUCCESS;
}

std::barrier br_bpftrace{2};

int run_bpftrace(std::string trace_log, pid_t child_pid, std::promise<int> &&p) {
    bp::opstream in;
    std::stringstream ss;
    ss << (R"(
        tracepoint:syscalls:sys_enter_write
        /@writes[pid] == 0 && args->fd == 1/ {
            printf("{\"action\": \"WRITE\", \"PID\": %d, \"Program\": \"%s\", \"PPID\": %d}\n", pid, comm, curtask->real_parent->tgid);
            @writes[pid] = 1;
        }

        tracepoint:syscalls:sys_enter_read
        /@reads[pid] == 0 && args->fd == 0/ {
            printf("{\"action\": \"READ\", \"PID\": %d, \"Program\": \"%s\", \"PPID\": %d}\n", pid, comm, curtask->real_parent->tgid);
            @reads[pid] = 1;
        }

        tracepoint:syscalls:sys_enter_pipe2
        {
            printf("{\"action\": \"PIPE\", \"PID\": %d, \"Program\": \"%s\", \"PPID\": %d}\n", pid, comm, curtask->real_parent->tgid);
        }

        tracepoint:sched:sched_process_exit
        {
            printf("{\"action\": \"EXIT\", \"PID\": %d, \"Program\": \"%s\"}\n", pid, comm);
        }
    )");
    std::string prog = ss.str();

    std::future<std::string> data;
    bp::ipstream out;
    std::string line;

    std::cout << "Start bpftrace with target PID: " << child_pid << std::endl;
    bp::child c(bp::search_path("bpftrace"), "-", (bp::std_out & bp::std_err) > out, bp::std_in < in);
    in << prog << std::endl;
    in.pipe().close();
    std::cout << "Waiting for bpftrace to attache probes..." << std::endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(10000));
    if (!c.running()) {
        std::cout << "Error: bpftrace process terminated unexpectedly" << std::endl;
        while (out && std::getline(out, line) && !line.empty()) {
            std::cout << line << std::endl;
        }
        p.set_value(1);
        br_bpftrace.arrive_and_wait();
        return 1;
    }
    std::ofstream json_log;
    json_log.open(trace_log);
    while (out && std::getline(out, line) && !line.empty()) {
        if (line.starts_with("Attached ") || line.starts_with("Attaching ")) {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            p.set_value(0);
            br_bpftrace.arrive_and_wait();
        }
        else if (line.starts_with("{")) {
            auto event = json::parse(line);
            auto action = event["action"].template get<std::string>();
            auto pid = event["PID"].template get<int>();
            json_log << event.dump() << std::endl;
            if (action == "EXIT") {
                if (pid == child_pid) {
                    break;
                }
            }
        } else {
            std::cout << line << std::endl;
        }
    }

    ::kill(c.id(), SIGTERM);
    if (!c.wait_for(std::chrono::seconds(5))) {
        ::kill(c.id(), SIGTERM);
        if (!c.wait_for(std::chrono::seconds(5))) {
            ::kill(c.id(), SIGKILL);
        }
    }
    c.wait();
    json_log.close();
    while (std::getline(out, line)) {
            std::cout << line << std::endl;
    }
    return 0;
}

int main(int argc, const char **argv) {
    int ret = EXIT_FAILURE;
    int pipe_fanotify_to_child[2];
    int pipe_child_to_fanotify[2];
    pipe(pipe_fanotify_to_child);
    pipe(pipe_child_to_fanotify);

    int next_args;
    for (next_args=0; next_args<argc;next_args++) {
        if (std::string("--") == argv[next_args]) {
            break;
        }
    }
    if (next_args == argc) {
        std::cout << "Usage error: please specify -- <command>" << std::endl;
        return EXIT_FAILURE;
    }

    if (next_args < 4) {
        std::cout << "Usage: " << argv[0] << " <fanotify-log.json> <bpftrace-log.json> <monitor dir>" << std::endl;
        return 1;
    }

    pid_t pid = fork();

    if (pid == 0) { // Child process
        next_args++; // skip -- arg
        int fanotify_ret = -1;
        close(pipe_fanotify_to_child[1]); // Close write end
        read(pipe_fanotify_to_child[0], &fanotify_ret, sizeof(fanotify_ret)); // wait for fanotify to be started...
        close(pipe_fanotify_to_child[0]); // Close read end

        close(pipe_child_to_fanotify[0]); // Close read end

        if (fanotify_ret == 0) {
            ret = exec_watch_command(argc-next_args, &argv[next_args], pipe_child_to_fanotify[1]);
        } else {
            std::cout << "Error on setup fanotify; Exit" << std::endl;
        }
        close(pipe_child_to_fanotify[1]); // Close write end
    } else { // Parent process
        close(pipe_fanotify_to_child[0]); // Close read end
        close(pipe_child_to_fanotify[1]); // Close write end

        // start eBPF trace
        std::promise<int> p;
        auto f = p.get_future();
        auto bpftrace_thread = std::thread(run_bpftrace, argv[2], pid, std::move(p));
        br_bpftrace.arrive_and_wait();
        ret = f.get();
        if (ret != 0) {
            write(pipe_fanotify_to_child[1], &ret, sizeof(ret));
            close(pipe_fanotify_to_child[1]); // Close write end
            close(pipe_child_to_fanotify[0]); // Close read end
            wait(NULL); // Wait for child to finish
            bpftrace_thread.join();
            std::cout << "Error: bftrace termianted; exit" << std::endl;
            return ret;
        }

        // start fanotify trace
        //ret = fuse_fs_run(argc, argv, pipe_fanotify_to_child[1], pipe_child_to_fanotify[0]);
        //std::cout << "capture_fanotify done: " << ret << std::endl;
        //std::this_thread::sleep_for(std::chrono::seconds(2));  // make sure, all file operations of the child have been locked
        //if (ret != 0) {
        //    write(pipe_fanotify_to_child[1], &ret, sizeof(ret)); // Write to child that fanotify finished
        //}
        int tmp;
        write(pipe_fanotify_to_child[1], &tmp, sizeof(tmp));
        close(pipe_fanotify_to_child[1]); // Close write end
        close(pipe_child_to_fanotify[0]); // Close read end

        std::cout << "Wait for child to finish" << std::endl;
        wait(NULL); // Wait for child to finish
        std::cout << "bpftrace_thread.join" << std::endl;
        bpftrace_thread.join();
    }

    return ret;
}
