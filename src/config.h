#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <linkedlist.h>
#include <ela_carrier.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct BootstrapItem {
    ListEntry le;
    BootstrapNode node;
} BootstrapItem;

typedef struct {
    bool udp_enabled;

    int loglevel;
    char *logfile;

    char *datadir;
    char *pidfile;

    char *ctrl_uri;

    List *bootstraps;
} Config;

Config *load_config(const char *config_file);

#ifdef __cplusplus
}
#endif

#endif
