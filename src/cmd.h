#ifndef __COMMAND_H__
#define __COMMAND_H__

#ifdef __cplusplus
extern "C" {
#endif

extern const char *prog_name;
extern const char *control_uri;

int cmd_main(int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif
