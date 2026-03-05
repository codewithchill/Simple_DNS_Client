#pragma once

typedef enum {
    DNS_SUCCESS = 0,

    /* Validation & System Errors */
    DNS_ERR_NULL_POINTER = 1,
    DNS_ERR_INVALID_ARGS = 2,
    DNS_ERR_MEM_ALLOC = 3,

    /* Network Errors */
    DNS_ERR_SOCKET_CREATE = 10,
    DNS_ERR_SEND = 11,
    DNS_ERR_RECV = 12,
    DNS_ERR_TIMEOUT = 13,

    /* Protocol & Parsing Errors */
    DNS_ERR_INVALID_DOMAIN = 20,
    DNS_ERR_MALFORMED_PACKET = 21,
    DNS_ERR_TRUNCATED = 22,
    DNS_ERR_UNSUPPORTED_TYPE = 23
} dns_status_t;

const char* dns_strerror(dns_status_t status);

