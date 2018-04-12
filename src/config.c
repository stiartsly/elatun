#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <assert.h>

#include <confuse.h>
#include <rc_mem.h>
#include <ela_carrier.h>

#include "config.h"

static const char *def_ctrl_addr = "udp://localhost:33568";

static void config_error(cfg_t *cfg, const char *fmt, va_list ap)
{
    fprintf(stderr, "Config file error, line %d: ", cfg->line);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
}

static int not_null_validator(cfg_t *cfg, cfg_opt_t *opt)
{
    if (cfg_getstr(cfg, opt->name) == NULL) {
        cfg_error(cfg, "option '%s' missing.", opt->name);
        return -1;
    }
    return 0;
}

static void bootstrap_item_destroy(void *p)
{
    BootstrapItem *item = (BootstrapItem *)p;
    assert(item);

#define FIELD_FREE(field) \
    if (item->node.field) \
        free((void *)item->node.field)

    FIELD_FREE(ipv4);
    FIELD_FREE(ipv6);
    FIELD_FREE(port);
    FIELD_FREE(public_key);
}

static void config_destroy(void *p)
{
    Config *config = (Config *)p;
    assert(config);

    if (config->bootstraps)
        deref(config->bootstraps);

    if (config->logfile)
        free(config->logfile);

    if (config->datadir)
        free(config->datadir);

    if (config->pidfile)
        free(config->pidfile);

    if (config->ctrl_addr)
        free(config->ctrl_addr);
}

Config *load_config(const char *config_file)
{
    Config *config;
    cfg_t *cfg, *sec;
    cfg_t *bootstraps;
    const char *stropt;
    int nsecs;
    int i;
    int rc;
    char buffer[PATH_MAX];

    cfg_opt_t bootstrap_opts[] = {
        CFG_STR("ipv4", NULL, CFGF_NONE),
        CFG_STR("ipv6", NULL, CFGF_NONE),
        CFG_STR("port", "33445", CFGF_NONE),
        CFG_STR("public_key", NULL, CFGF_NONE),
        CFG_END()
    };

    cfg_opt_t bootstraps_opts[] = {
        CFG_SEC("bootstrap", bootstrap_opts, CFGF_MULTI | CFGF_NO_TITLE_DUPES),
    };

    cfg_opt_t cfg_opts[] = {
        CFG_BOOL("udp_enabled", true, CFGF_NONE),
        CFG_SEC("bootstraps", bootstraps_opts, CFGF_NONE),
        CFG_INT("loglevel", 3, CFGF_NONE),
        CFG_STR("logfile", NULL, CFGF_NONE),
        CFG_STR("datadir", NULL, CFGF_NONE),
        CFG_STR("pidfile", NULL, CFGF_NONE),
        CFG_STR("ctrlpath", NULL, CFGF_NONE),
        CFG_END()
    };

    cfg = cfg_init(cfg_opts, CFGF_NONE);
    cfg_set_error_function(cfg, config_error);
    cfg_set_validate_func(cfg, NULL, not_null_validator);

    rc = cfg_parse(cfg, config_file);
    if (rc != CFG_SUCCESS) {
        cfg_error(cfg, "can not parse config file: %s.", config_file);
        cfg_free(cfg);
        return NULL;
    }

    config = (Config *)rc_zalloc(sizeof(Config), config_destroy);
    if (!config) {
        cfg_error(cfg, "out of memory.");
        cfg_free(cfg);
        return NULL;
    }

    config->udp_enabled = cfg_getbool(cfg, "udp_enabled");

    bootstraps = cfg_getsec(cfg, "bootstraps");
    if (!bootstraps) {
        cfg_error(cfg, "missing services section.");
        cfg_free(cfg);
        deref(config);
        return NULL;
    }

    config->bootstraps = list_create(1, NULL);
    if (!config->bootstraps) {
        cfg_error(cfg, "Out of memory.");
        cfg_free(cfg);
        deref(config);
        return NULL;
    }

    nsecs = cfg_size(bootstraps, "bootstrap");

    for (i = 0; i < nsecs; i++) {
        BootstrapItem *item;

        item = rc_zalloc(sizeof(BootstrapItem), bootstrap_item_destroy);
        if (!item) {
            cfg_error(cfg, "out of memory.");
            cfg_free(cfg);
            deref(config);
            return NULL;
        }

        sec = cfg_getnsec(bootstraps, "bootstrap", i);

        stropt = cfg_getstr(sec, "ipv4");
        if (stropt)
            item->node.ipv4 = (const char *)strdup(stropt);
        else
            item->node.ipv4 = NULL;

        stropt = cfg_getstr(sec, "ipv6");
        if (stropt)
            item->node.ipv6 = (const char *)strdup(stropt);
        else
            item->node.ipv6 = NULL;

        stropt = cfg_getstr(sec, "port");
        if (stropt)
            item->node.port = (const char *)strdup(stropt);
        else
            item->node.port = NULL;

        stropt = cfg_getstr(sec, "public_key");
        if (stropt)
            item->node.public_key = (const char *)strdup(stropt);
        else
            item->node.public_key = NULL;

        item->le.data = item;
        list_add(config->bootstraps, &item->le);
    }

    config->loglevel = (int)cfg_getint(cfg, "loglevel");
    stropt = cfg_getstr(cfg, "logfile");
    if (stropt)
        config->logfile = strdup(stropt);
    else {
        sprintf(buffer, "%s/%s/%s.log", getenv("HOME"), prog_dir, prog_name);
        config->logfile = strdup(buffer);
    }

    stropt = cfg_getstr(cfg, "datadir");
    if (stropt)
        config->datadir = strdup(stropt);
    else {
        sprintf(buffer, "%s/%s/data", getenv("HOME"), prog_dir);
        config->datadir = strdup(buffer);
    }

    stropt = cfg_getstr(cfg, "pidfile");
    if (stropt) {
        config->pidfile = strdup(stropt);
    } else {
        sprintf(buffer, "%s/%s/%s.pid", getenv("HOME"), prog_dir, prog_name);
        config->pidfile = strdup(buffer);
    }

    config->ctrl_addr = strdup(def_ctrl_addr);
    return config;
}
