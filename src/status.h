#ifndef __STATUS_H__
#define __STATUS_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    STATUS_OK               = 0,
    STATUS_ERR              = 1,
    STATUS_OUT_OF_MEMORY    = 2,
    STATUS_ALREADY_EXIST    = 3,
    STATUS_NOT_EXIST        = 4,
} Status;

#ifdef __cplusplus
}
#endif

#endif
