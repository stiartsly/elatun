#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include <rc_mem.h>

#include "config.h"
#include "cmd.h"

extern int bind_cmd(int, char **);
extern int unbind_cmd(int, char **);
extern int services_cmd(int, char **);
extern int open_cmd(int, char **);
extern int close_cmd(int, char **);
extern int ps_cmd(int, char **);
extern int info_cmd(int, char **);

static struct control_command {
    const char *name;
    int (*routine)(int argc, char *argv[]);
} commands[] = {
    { "bind",       bind_cmd    },
    { "unbind",     unbind_cmd  },
    { "services",   services_cmd},
    { "open",       open_cmd    },
    { "close",      close_cmd   },
    { "ps",         ps_cmd      },
    { "info",       info_cmd    },
    { NULL,         NULL        }
};

const char *control_uri;

void show_hint(const char *cmd_name)
{
    fprintf(stdout, "See \'%s %s -h\'\n", prog_name, cmd_name);
}

int cmd_main(int argc, char **argv)
{
    struct control_command *cmd;
    const char *config_file = NULL;
    Config *config;
    int opt;

    struct option options[] = {
        { "config",         required_argument,  NULL, 'c' },
        { NULL,             0,                  NULL,  0  }
    };

    opterr = 0;
    while ((opt = getopt_long(argc, argv, "", options, NULL)) != -1) {
        if (opt == 'c') {
            int cfg_argc = 1;
            config_file = optarg;
            
            if (strcmp(argv[optind-1], config_file) == 0)
                cfg_argc = 2;

            for (int i = optind; i < argc; i++)
                argv[i-cfg_argc] = argv[i];

            argc -= cfg_argc;
            break;
        }
    }

    config = load_config(config_file);
    if (!config) {
        printf("Cannot open config file.");
        exit(-1);
    }

    control_uri = strdup(config->ctrl_uri);
    deref(config);

    // Reset getopt routines for sub commands
    optind = 1;
    opterr = 1;
    optopt = '?';

    for (cmd = &commands[0]; cmd->routine != NULL; cmd++) {
        if (strcmp(argv[0], cmd->name) != 0)
            continue;
        else {
            int rc = cmd->routine(argc, argv);
            free((void *)control_uri);
            return rc;
        }
    }

    fprintf(stdout,
            "%s: \'%s\' is not a tunnel command\n"
            "See \'%s -h\'\n"
            "\n",
            prog_name, argv[0], prog_name);

    free((void *)control_uri);
    return -1;
}
