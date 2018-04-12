#include <stdio.h>
#include <string.h>

typedef struct {
    const char *name;
    int (*routine)(int argc, char *argv[]);
} Command;

extern const char *prog_name;

extern int bind_cmd(int, char **);
extern int unbind_cmd(int, char **);
extern int services_cmd(int, char **);
extern int open_cmd(int, char **);
extern int close_cmd(int, char **);
extern int ps_cmd(int, char **);
extern int info_cmd(int, char **);

static Command commands[] = {
    { "bind",       bind_cmd    },
    { "unbind",     unbind_cmd  },
    { "services",   services_cmd},
    { "open",       open_cmd    },
    { "close",      close_cmd   },
    { "ps",         ps_cmd      },
    { "info",       info_cmd    },
    { NULL,         NULL        }
};

int run_cmd(int argc, char **argv)
{
    Command *cmd;

    for (cmd = &commands[0]; cmd->routine != NULL; cmd++) {
        if (strcmp(argv[0], cmd->name) != 0)
            continue;
        else
            return cmd->routine(argc, argv);
    }

    fprintf(stdout,
            "%s: \'%s\' is not a tunnel command\n"
            "See \'%s -h\'\n"
            "\n",
            prog_name, argv[0], prog_name);

    return -1;
}
