#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <getopt.h>

#include "cmd.h"

static int display_info(bool show_user_address, bool show_userid,
                        bool show_user_info, bool show_friends)
{
    fprintf(stderr, "Comamand Unsupported yet.\n");
    return -1;
}

static void show_usage(void)
{
    fprintf(stdout,
            "Usage: %s info\n"
            "       %s info [OPTIONS]\n"
            "\n"
            "Display system information\n"
            "\n"
            "Options:\n"
            "      --all                Show carrier information\n"
            "  -r, --address            Tunnel carrier user address\n"
            "  -u, --userid             Tunnel carrier userid\n"
            "      --info               Tunnel carrier user information\n"
            "      --friends            Friends of tunnel carrier\n"
            "  -h, --help               Display command usage\n"
            "\n",
            prog_name, prog_name);
}

static void show_hint(void)
{
    fprintf(stdout,
            "See \'%s info -h\'\n",
            prog_name);
}

int info_cmd(int argc, char **argv)
{
    int show_user_address = 0;
    int show_userid = 0;
    int show_user_info = 0;
    int show_friends = 0;
    int opt;
    int idx;

    struct option options[] = {
        { "all",            no_argument,        NULL,   'a' },
        { "address",        no_argument,        NULL,   'r' },
        { "userid",         no_argument,        NULL,   'u' },
        { "info",           no_argument,        NULL,   'I' },
        { "friends",        no_argument,        NULL,   'f' },
        { "help",           no_argument,        NULL,   'h' },
        { NULL,             0,                  NULL,    0  }
    };

    while ((opt = getopt_long(argc, argv, "aruIfh", options, &idx)) != -1) {
        switch (opt) {
        case 'a':
            show_user_address = 1;
            show_userid = 1;
            show_user_info = 1;
            show_friends = 1;
            break;

        case 'r':
            show_user_address = 1;
            break;

        case 'u':
            show_userid = 1;
            break;

        case 'I':
            show_user_info = 1;
            break;

        case 'f':
            show_friends = 1;
            break;
            
        case 'h':
            show_usage();
            return 0;

        default:
            show_hint();
            return 1;
        }
    }

    return display_info(show_user_address, show_userid, show_user_info,
                        show_friends);
}
