#ifndef __TUNNEL_H__
#define __TUNNEL_H__

#ifdef __cplusplus
extern "C" {
#endif

int tunnel_main(const char *config_path,
                int need_daemonize,
                void (*daemonize)(const char *, int));

void tunnel_kill(void);

#ifdef __cplusplus
}
#endif

#endif
