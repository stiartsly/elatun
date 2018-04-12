#include <stdio.h>
#include <string.h>
#include <getopt.h>

#include <ela_carrier.h>

#include "packet.h"
#include "status.h"

extern const char *prog_name;
extern void wait_for_debug(void);

static int ps_service_forwardings(const char *service, const char *userid,
                                  bool ps_all)
{
    //TODO:
    fprintf(stderr, "Comamand Unsupported yet.\n");
    return -1;
}

static int check_arguments(int index, int argc, char **argv, int *no_options)
{
    if (index == 1 && argc == 2) {
        *no_options = true;
        return true;
    }
    else if (index < argc) {
        int i;

        fprintf(stdout, "Invalid options: '%s ", argv[index]);
        for (i = index + 1; i < argc; i++) {
            fprintf(stdout, " %s", argv[i]);
        }
        fprintf(stdout, "'\n");
        fprintf(stdout, "See \'%s bind -h\'\n", prog_name);
        return false;
    }
    else {
        return true;
    }
}

static void parse_arguments(const char *args, char *userid, size_t userid_buflen,
                            char *service, size_t service_buflen)
{
    const char *prev = args;
    char *pos;

    pos = strchr(prev, ':');  // find userid option
    if (!pos) {
        if (strlen(args) >= userid_buflen) {
            strncpy(userid, prev, userid_buflen - 1);
            userid[userid_buflen - 1] = '\0';
        } else {
            strcpy(userid, prev);
        }
        return;
    }

    if (pos - prev >= userid_buflen) {
        strncpy(userid, prev, userid_buflen - 1);
        userid[userid_buflen - 1] = '\0';
    } else {
        strncpy(userid, prev, pos - prev);
        userid[pos - prev ] = '\0';
    }

    prev = pos + 1;

    if (strlen(prev) >= service_buflen) {
        strncpy(service, prev, service_buflen - 1);
        service[service_buflen - 1] = '\0';
    } else {
        strcpy(service, prev);
    }
}

static void show_usage(void)
{
    fprintf(stdout,
           "Usage: %s ps\n"
           "       %s ps [OPTIONS]\n"
           "\n"
           "List service forwardings\n"
           "\n"
           "Options:\n"
           "      --all                List all service forwardings\n"
           "  -u, --userid=string      List forwrdings connected to specific user\n"
           "  -s, --service=string     List forwrdings of specific service\n"
           "  -h, --help               Display usage about this command\n"
           "\n",
           prog_name, prog_name);
}

static void show_hint(void)
{
    fprintf(stdout,
            "See \'%s ps -h\'\n",
            prog_name);
}

int ps_cmd(int argc, char **argv)
{
    char userid[ELA_MAX_ID_LEN + 1] = {0};
    char service[128] = {0};
    int  no_options = 0;
    int  ps_all = 0;
    int  opt;
    int  idx;

    struct option options[] = {
        { "all",            no_argument,        NULL, 'a' },
        { "quiet",          no_argument,        NULL, 'q' },
        { "debug",          no_argument,        NULL,  1  },
        { "help",           no_argument,        NULL, 'h' },
        { NULL,             0,                  NULL,  0  }
    };

    while ((opt = getopt_long(argc, argv, "au:s:h", options, &idx)) != -1) {
        switch (opt) {
        case 'a':
            ps_all = 1;
            break;

        case 'u':
            if (strlen(optarg) >= sizeof(userid))
                strncpy(userid, optarg, sizeof(userid) - 1);
            else
                strcpy(userid, optarg);
            break;

        case 's':
            if (strlen(optarg) >= sizeof(service))
                strncpy(service, optarg, sizeof(service) - 1);
            else
                strcpy(service, optarg);
            break;

        case 1:
            wait_for_debug();
            break;
        
        case 'h':
            show_usage();
            return 0;

        default:
            show_hint();
            return -1;
        }
    }

    if (!check_arguments(optind, argc, argv, &no_options))
        return 1;

    if (no_options)
        parse_arguments(argv[1], userid, sizeof(userid), service, sizeof(service));

    if (!*userid) {
        fprintf(stderr, "Missing command options\n");
        show_hint();
        return 1;
    }

    if (!*service) {
        fprintf(stderr, "Missing command options\n");
        show_hint();
        return 1;
    }

    if (!ela_id_is_valid(userid)) {
        fprintf(stderr, "Userid \'%s\' invalid\n", userid);
        return 1;
    }

    fprintf(stdout, "userid:%s\n", userid);
    fprintf(stdout, "service:%s\n", service);

    return ps_service_forwardings(service, userid, ps_all);
}
