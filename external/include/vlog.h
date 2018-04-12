#ifndef __VLOG_H__
#define __VLOG_H__

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VLOG_NONE       0
#define VLOG_FATAL      1
#define VLOG_ERROR      2
#define VLOG_WARN       3
#define VLOG_INFO       4
#define VLOG_DEBUG      5
#define VLOG_TRACE      6
#define VLOG_VERBOSE    7

extern int log_level;

#define vlogF(format, ...) \
    do { \
        if (log_level >= VLOG_FATAL) \
            vlog(VLOG_FATAL, format, ##__VA_ARGS__); \
    } while(0)

#define vlogE(format, ...) \
    do { \
        if (log_level >= VLOG_ERROR) \
            vlog(VLOG_ERROR, format, ##__VA_ARGS__); \
    } while(0)

#define vlogW(format, ...) \
    do { \
        if (log_level >= VLOG_WARN) \
            vlog(VLOG_WARN, format, ##__VA_ARGS__); \
    } while(0)

#define vlogI(format, ...) \
    do { \
        if (log_level >= VLOG_INFO) \
            vlog(VLOG_INFO, format, ##__VA_ARGS__); \
    } while(0)

#define vlogD(format, ...) \
    do { \
        if (log_level >= VLOG_DEBUG) \
            vlog(VLOG_DEBUG, format, ##__VA_ARGS__); \
    } while(0)

#define vlogT(format, ...) \
    do { \
        if (log_level >= VLOG_TRACE) \
            vlog(VLOG_TRACE, format, ##__VA_ARGS__); \
    } while(0)

#define vlogV(format, ...) \
    do { \
        if (log_level >= VLOG_VERBOSE) \
            vlog(VLOG_VERBOSE, format, ##__VA_ARGS__); \
    } while(0)

typedef void log_printer(const char *format, va_list args);

void vlog_init(int level, const char *logfile, log_printer *printer);

void vlog_set_level(int level);

void vlog(int level, const char *format, ...);

void vlogv(int level, const char *format, va_list args);

#ifdef __cplusplus
}
#endif

#endif
