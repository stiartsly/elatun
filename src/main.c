#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <sys/resource.h>

#include <vlog.h>

#include "config.h"
#include "tunnel.h"
#include "cmd.h"

const char *prog_dir  = ".secure_tunnel";
const char *prog_name = "tunnel";
const char *prog_version = "0.1";

static void daemonize(const char *pid_file_path, int need_daemonize)
{
   // Check if the PID file exists
    FILE *fp;
    pid_t pid;

    if (!need_daemonize)
        return;

    if ((fp = fopen(pid_file_path, "r"))) {
        vlogW("Another instance of tunnel daemon is already running,"
              "PID file %s exists. Exiting.\n", pid_file_path);
        fclose(fp);
        exit(1);
    }

    // Open the PID file for writing
    fp = fopen(pid_file_path, "w+");
    if (!fp) {
        vlogE("Couldn't open the PID file for writing: %s. Exiting.\n",
              pid_file_path);
        exit(1);
    }

    pid = fork();

    if (pid > 0) {
        fprintf(fp, "%d", pid);
        fclose(fp);
        vlogD("Forking succeeded: PID: %d.\n", pid);
        exit(0);
    } else {
        fclose(fp);
    }

    if (pid < 0) {
        vlogE("Forking failed. Exiting");
        exit(1);
    }

    if (setsid() < 0) {
        vlogE("SID creation failed. Exiting.\n");
        exit(1);
    }
}

static void signal_handler(int signum)
{
    tunnel_kill();
}

int sys_coredump_set(bool enable)
{
    const struct rlimit rlim = {
        enable ? RLIM_INFINITY : 0,
        enable ? RLIM_INFINITY : 0
    };

    return setrlimit(RLIMIT_CORE, &rlim);
}

static void show_version(void)
{
    fprintf(stdout, "%s version: %s\n\n", prog_name, prog_version);
}

static void show_usage(void)
{
    fprintf(stdout,
           "Usage: %s [OPTIONS | COMMAND] \n"
           "A secure tunnel program to forward services over carrier network\n"
           "Options:\n"
           "      --config=string      Location of config file (default \'%s/%s\')\n"
           "  -D, --daemon             Run as a background daemon\n"
           "  -h, --help               Print this help usage and quit\n"
           "  -v, --version            Print version information and quit\n"
           "\n"
           "Commands:\n"
           "  bind        Bind a service with specific nodeId, binding address and port\n"
           "  unbind      Unbind a specific service or all services\n"
           "  services    List services\n"
           "  open        Open a service forwarding to specific nodeid and service\n"
           "  close       Close a specific service forwarding\n"
           "  ps          List service forwarding list\n"
           "  info        Display system-wide information\n"
           "\n"
           "Use \'%s [COMMAND] -h\' for more information about command\n"
           "\n",
           prog_name,
           getenv("HOME"), prog_dir,
           prog_name);
}

void show_hint(const char *cmd_name)
{
    fprintf(stdout, "See \'%s %s -h\'\n", prog_name, cmd_name);
}

void wait_for_debug(void)
{
    fprintf(stdout, "Wait for debugger attaching, process id is: %d.\n",
            getpid());
    fprintf(stdout, "After debugger attached, press any key to continue...");
    getchar();
}

int main(int argc, char *argv[])
{

    char buffer[2048] = { 0 };
    int need_daemonize = 0;
    int opt;
    int idx;

    sys_coredump_set(true);

    signal(SIGINT, signal_handler);
    signal(SIGHUP, signal_handler);
    signal(SIGTERM, signal_handler);

    struct option options[] = {
        { "config",         required_argument,  NULL, 'c' },
        { "daemon",         no_argument,        NULL, 'D' },
        { "debug",          no_argument,        NULL,  1  },
        { "help",           no_argument,        NULL, 'h' },
        { "version",        no_argument,        NULL, 'v' },
        { NULL,             0,                  NULL,  0  }
    };

    if (isalpha(argv[1][0]))
        exit(run_cmd(--argc, ++argv));

    while ((opt = getopt_long(argc, argv, "c:Dh?v", options, &idx)) != -1) {
        switch (opt) {
        case 'c':
            strcpy(buffer, optarg);
            break;
        case 'D':
            need_daemonize = 1;
            break;
        case 1:
            wait_for_debug();
            break;
        case 'v':
            show_version();
            exit(0);
            break;
        case 'h':
        case '?':
        default:
            show_usage();
            exit(0);
            break;
        }
    }

    if (!*buffer) {
        realpath(argv[0], buffer);
        strcat(buffer, ".conf");
    }

    return tunnel_main(buffer, need_daemonize, daemonize);
}
