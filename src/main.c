#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/resource.h>

#include "tunnel.h"
#include "cmd.h"

const char *prog_name = "elatun";
const char *prog_version  = "0.1";

static int sys_coredump_set(bool enable)
{
    const struct rlimit rlim = {
        enable ? RLIM_INFINITY : 0,
        enable ? RLIM_INFINITY : 0
    };

    return setrlimit(RLIMIT_CORE, &rlim);
}

static void show_version(void)
{
    fprintf(stdout, "Elastos tunnel version: %s\n\n", prog_version);
}

static void show_usage(void)
{
    fprintf(stdout,
            "A secure tunnel program to forward services over carrier network\n"
            "\n"
            "Usage: %s [OPTIONS | COMMAND] \n"
            "\n"
            "Options:\n"
            "      --config=string  Location of config file.\n"
            "                       Default: ./tunnel.conf\n"
            "                                ~/.elatun/tunnel.conf\n"
            "                                /etc/elatun/tunnel.conf\n"
            "                                /usr/local/etc/elatun/tunnel.conf\n"
            "  -D, --daemon         Run as a background daemon\n"
            "  -h, --help           Print this help usage and quit\n"
            "  -v, --version        Print version information and quit\n"
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
            prog_name, prog_name);
}

static void wait_for_debug(void)
{
    fprintf(stdout, "Wait for debugger attaching, process id is: %d.\n",
            getpid());
    fprintf(stdout, "After debugger attached, press any key to continue...");
    getchar();
}

int main(int argc, char *argv[])
{
    int debug = 0;
    int rc;
    
    sys_coredump_set(true);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            show_version();
            exit(0);
        }

        // Only show program usage without command context
        if ((strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) &&
                *argv[1] == '-') {
            show_usage();
            exit(0);
        }

        if (strcmp(argv[i], "--debug") == 0) {
            debug = 1;

            // remove debug option from argv
            for (int j = i; j < (argc - 1); j++)
                argv[j] = argv[j+1];

            argc--;
        }
    }

    if (debug)
        wait_for_debug();

    if (argc <=1 || *argv[1] == '-') {
        rc = tunnel_main(argc, argv);
    } else {
        rc = cmd_main(--argc, ++argv);
    }

    return rc;
}
