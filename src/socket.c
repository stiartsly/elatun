#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include <fcntl.h>

#include <vlog.h>

#include "socket.h"

#define MAX_ADDRESS_LEN   (1024)

//static const char *unx_prefix = "unix://";
static const char *udp_prefix = "udp://";

/*
static inline bool is_unix_addr(const char *addr)
{
    return strncmp(addr, unx_prefix, strlen(unx_prefix)) == 0;
}

static inline bool is_udp_addr(const char *addr)
{
    return strncmp(addr, udp_prefix, strlen(udp_prefix)) == 0;
}
*/

static void socket_error(bool log_output, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    log_output ? vlogv(VLOG_ERROR, fmt, ap) : (void)vfprintf(stdout, fmt, ap);
    va_end(ap);
}

int socket_errno(void)
{
#if defined(_WIN32) || defined(_WIN64)
    return WSAGetLastError();
#else
    return errno;
#endif
}

int socket_set_nonblock(SOCKET socket)
{
#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
    u_long mode = 1;
    return (ioctlsocket(socket, FIONBIO, &mode) == 0);
#else
    return (fcntl(socket, F_SETFL, O_NONBLOCK, 1) == 0);
#endif
}

ssize_t socket_ahead_read_length(SOCKET socket)
{
#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
    unsigned long count = 0;
    ioctlsocket(socket, FIONREAD, &count);
#else
    int count = 0;
    ioctl(socket, FIONREAD, &count);
#endif

    return (ssize_t)count;
}

SOCKET socket_create(const char *uri_address)
{
    const char *addr;
    char host[128] = {0};
    char *port;
    struct addrinfo hints;
    struct addrinfo *ai;
    struct addrinfo *p;
    SOCKET sock = INVALID_SOCKET;
    int rc;

    if (!uri_address) {
        sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0) {
            socket_error(0, "socket erro (%d)\n", socket_errno());
            return INVALID_SOCKET;
        }
        return sock;
    }

    addr = uri_address;
    if (strncmp(addr, udp_prefix, strlen(udp_prefix)) != 0) {
        socket_error(1, "not udp protocol\n");
        return INVALID_SOCKET;
    }

    addr += strlen(udp_prefix);
    port = strchr(addr, ':');
    if (!port) {
        socket_error(1, "missing port of %s\n", addr);
        return INVALID_SOCKET;
    }
    strncpy(host, addr, port - addr);
    host[port - addr] = '\0';
    port += 1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = AI_PASSIVE;

    rc = getaddrinfo(host, port, &hints, &ai);
    if (rc != 0){
        socket_error(1, "getaddrinfo error (%s)\n", gai_strerror(rc));
            return INVALID_SOCKET;
        return INVALID_SOCKET;
    }

    for (p = ai; p; p = p->ai_next) {
        int set = 1;

        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock == INVALID_SOCKET)
            continue;

        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void*)&set, sizeof(set));
        if (bind(sock, p->ai_addr, p->ai_addrlen) != 0) {
            socket_close(sock);
            sock = INVALID_SOCKET;
            continue;
        }
        break;
    }
    freeaddrinfo(ai);

    socket_set_nonblock(sock);
    return sock;
}

void socket_close(SOCKET sock)
{
    if (sock < 0)
        return;

#if !defined(_WIN32) && !defined(_WIN64)
    close(sock);
#else
    closesocket(sock);
#endif
}

int socket_address(const char *uri_address,
                   struct sockaddr *sockaddr, socklen_t *socklen)
{
    const char *addr;
    char host[128] = {0};
    char *port;
    struct addrinfo hints;
    struct addrinfo *ai;
    struct addrinfo *p;
    int rc;

    if (!uri_address || !sockaddr || !socklen)
        return -1;

    addr = uri_address;
    if (strncmp(addr, udp_prefix, strlen(udp_prefix)) != 0) {
        fprintf(stderr, "not udp protocol\n");
        return -1;
    }

    addr += strlen(udp_prefix);
    port = strchr(addr, ':');
    if (!port) {
        fprintf(stderr, "missing port of %s\n", addr);
        return -1;
    }
    strncpy(host, addr, port - addr);
    host[port - addr] = '\0';
    port += 1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = AI_PASSIVE;

    rc = getaddrinfo(host, port, &hints, &ai);
    if (rc < 0) {
        fprintf(stderr, "getaddrinfo error (%s)\n", gai_strerror(rc));
        return -1;
    }
    for (p = ai; p; p = p->ai_next) {
        if (p->ai_family == AF_INET) {
            if (p->ai_addrlen > *socklen)
                continue;

            memcpy(sockaddr, p->ai_addr, p->ai_addrlen);
            *socklen = p->ai_addrlen;
            freeaddrinfo(ai);
            return 0;
        }
    }

    freeaddrinfo(ai);
    return -1;
}

