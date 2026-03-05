
/* NETWORKING HEADER */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "udp.h"
#include "color.h"

typedef struct sockaddr_in sockaddr_in ;
const uint8_t DNS_PORT = 53;

static const char *ipBuffer[] = {
    "1.0.0.1",
    "1.1.1.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9"
};
const uint8_t ipCount = sizeof(ipBuffer) / sizeof(ipBuffer[0]);

static uint8_t get_Random_Id(void) {
    return rand() % ipCount;
}

typedef struct {
    int fd;
    sockaddr_in socket_addr;
} connection_details_t;

connection_details_t get_udp_server_socket(const char* ip) {

    connection_details_t data = {
        .fd = -1,
        .socket_addr = {0}
    };

    int s_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (s_fd < 0) {
        perror("socket failed");
        return data;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DNS_PORT);
    inet_pton(AF_INET, ip, &server_addr.sin_addr);

    data.fd = s_fd;
    data.socket_addr = server_addr;
    return data;
}

uint8_t* getData(const uint8_t* message, const uint8_t length, int *buf_len) {

    uint8_t  ip_id = get_Random_Id();
    const char *ip = ipBuffer[ip_id];

    connection_details_t serv_data = get_udp_server_socket(ip);
    printf("\n%sSending data to IP: %s[%s%s%s]", FG_CYAN, RESET, FG_RED, ip, RESET);
    
    // Send data
    ssize_t sent = sendto(
        serv_data.fd,
        message,
        length,
        0,
        (struct sockaddr*)&(serv_data.socket_addr),
        sizeof(serv_data.socket_addr)
    );
    if (sent < 0) {
        perror("sendto failed");
        close(serv_data.fd);
        return NULL;
    }

    uint8_t* buffer = malloc(_1KB_);
    if (!buffer) {
        perror("Buffer Allcocation failed!");
        close(serv_data.fd);
        return NULL;
    }

    uint server_addr_len = sizeof(serv_data.socket_addr);
    ssize_t received = recvfrom(serv_data.fd, buffer, _1KB_, 0,
                        (struct sockaddr*)&(serv_data.socket_addr), &server_addr_len);
    if (received < 0) {
        free(buffer);
        perror("recvfrom failed");
        close(serv_data.fd);
        return NULL;
    }
    *buf_len = received;
    return buffer;
}

