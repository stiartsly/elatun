#ifndef __SCOKET_H__
#define __SCOKET_H__

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int SOCKET;

#define INVALID_SOCKET ((SOCKET)-1)

SOCKET socket_create(const char *uri_address);

void socket_close(SOCKET sock);

int socket_errno(void);

ssize_t socket_ahead_read_length(SOCKET socket);

int socket_address(const char *uri_address,
                   struct sockaddr *sockaddr, socklen_t *socklen);

#ifdef __cplusplus
}
#endif

#endif
