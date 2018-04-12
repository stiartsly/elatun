#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/socket.h>

#include <ela_carrier.h>

#include "socket.h"
#include "packet.h"
#include "status.h"

extern const char *prog_name;
extern void wait_for_debug(void);

static int close_service_forwarding(SOCKET fd, const char *userid, const char *service)
{
    Packet *packet;
    int64_t tid;
    uint8_t *data;
    size_t data_len;
    int status = 0;
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    ssize_t rc;

    BEGIN_ENCODE(CLOSE_SERVICE) {
        packet_set_userid(packet, userid);
        packet_set_service(packet, service);
    } END_ENCODE();

    socket_address("udp://127.0.0.1:33568", (struct sockaddr *)&addr, &addrlen);
    rc = sendto(fd, data, data_len, 0, (const struct sockaddr *)&addr, addrlen);
    free(data);
    if (rc != (ssize_t)data_len) {
        fprintf(stderr, "sendto error (%d)\n", socket_errno());
        return -1;
    }

    data_len = 1024;
    data = calloc(1, data_len);
    if (!data) {
        fprintf(stderr, "Out of memory\n");
        return -1;
    }

    rc = recvfrom(fd, data, data_len, 0, (struct sockaddr *)&addr,
                  &addrlen);
    if (rc < 0) {
        fprintf(stderr, "recvfrom error (%d)\n", socket_errno());
        free(data);
        return -1;
    }
    data_len = (size_t)rc;

    BEGIN_DECODE_RC(CLOSE_SERVICE) {
        status = packet_get_status(packet);
    } END_DECODE_RC();

    if (status == STATUS_OK) {
        fprintf(stdout, "Command executed succeeded.\n");
    } else {
        fprintf(stderr, "Command excecuted error with reason: %d\n", status);
    }

    return 0;
}

static int check_arguments(int index, int argc, char **argv, int *no_options)
{
    if (index == 1 && argc == 2) {
        *no_options = true;
        return true;
    }
    else if (index < argc) {
        int i;

        fprintf(stdout, "Invalid options: '%s ", argv[index]);
        for (i = index + 1; i < argc; i++) {
            fprintf(stdout, " %s", argv[i]);
        }
        fprintf(stdout, "'\n");
        fprintf(stdout, "See \'%s bind -h\'\n", prog_name);
        return false;
    }
    else {
        return true;
    }
}

static void parse_arguments(const char *args, char *userid, size_t userid_buflen,
                            char *service, size_t service_buflen)
{
    const char *prev = args;
    char *pos;

    pos = strchr(prev, ':');  // find userid option
    if (!pos) {
        if (strlen(args) >= userid_buflen) {
            strncpy(userid, prev, userid_buflen - 1);
            userid[userid_buflen - 1] = '\0';
        } else {
            strcpy(userid, prev);
        }
        return;
    }

    if (pos - prev >= userid_buflen) {
        strncpy(userid, prev, userid_buflen - 1);
        userid[userid_buflen - 1] = '\0';
    } else {
        strncpy(userid, prev, pos - prev);
        userid[pos - prev ] = '\0';
    }

    prev = pos + 1;

    if (strlen(prev) >= service_buflen) {
        strncpy(service, prev, service_buflen - 1);
        service[service_buflen - 1] = '\0';
    } else {
        strcpy(service, prev);
    }
}

static void show_usage(void)
{
    fprintf(stdout,
            "Usage: %s close userid:service\n"
            "       %s close [OPTIONS]\n"
            "\n"
            "Close service\n"
            "\n"
            "Options:\n"
            "  -u, --userid=string      Userid to close service forwarding to\n"
            "  -s, --service=string     Service name to close for forwarding\n"
            "  -h, --help               Display command usage\n"
            "\n",
            prog_name, prog_name);
}

static void show_hint(void)
{
    fprintf(stdout,
            "See \'%s close -h\'\n",
            prog_name);
}

static SOCKET socket_fd = INVALID_SOCKET;
static void reclaim_socket(void)
{
    socket_close(socket_fd);
}

int close_cmd(int argc, char **argv)
{
    char userid[ELA_MAX_ID_LEN + 1] = { 0 };
    char service[128] = { 0 };
    int no_options = 0;
    int opt;
    int idx;

    struct option options[] = {
        { "userid",         required_argument,  NULL,   'u' },
        { "service",        required_argument,  NULL,   's' },
        { "debug",          no_argument,        NULL,    1  },
        { "help",           no_argument,        NULL,   'h' },
        { NULL,             0,                  NULL,    0  }
    };

    while ((opt = getopt_long(argc, argv, "n:qh", options, &idx)) != -1) {
        switch (opt) {
        case 'u':
            if (strlen(optarg) >= sizeof(userid))
                strncpy(userid, optarg, sizeof(userid) - 1);
            else
                strcpy(userid, optarg);
            break;

        case 's':
            if (strlen(optarg) >= sizeof(service))
                strncpy(service, optarg, sizeof(service) - 1);
            else
                strcpy(service, optarg);
            break;

        case 1:
            wait_for_debug();
            break;

        case 'h':
            show_usage();
            return 0;
            
        default:
            show_hint();
            return -1;
        }
    }

    if (!check_arguments(optind, argc, argv, &no_options))
        return 1;

    if (no_options)
        parse_arguments(argv[1], userid, sizeof(userid), service, sizeof(service));

    if (!*userid) {
        fprintf(stderr, "Missing command options\n");
        show_hint();
        return 1;
    }

    if (!*service) {
        fprintf(stderr, "Missing command options\n");
        show_hint();
        return 1;
    }

    if (!ela_id_is_valid(userid)) {
        fprintf(stderr, "Userid \'%s\' invalid\n", userid);
        return 1;
    }

    socket_fd = socket_create(0);
    if (socket_fd < 0)
        return -1;
    else
        atexit(reclaim_socket);

    return close_service_forwarding(socket_fd, userid, service);
}
