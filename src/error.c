#include "error.h"

const char* dns_strerror(dns_status_t status) {
    switch (status) {
        case DNS_SUCCESS:              return "Success";
        case DNS_ERR_NULL_POINTER:     return "Null pointer provided";
        case DNS_ERR_INVALID_ARGS:     return "Invalid arguments";
        case DNS_ERR_MEM_ALLOC:        return "Memory allocation failed";
        case DNS_ERR_SOCKET_CREATE:    return "Failed to create UDP socket";
        case DNS_ERR_SEND:             return "Failed to send data";
        case DNS_ERR_RECV:             return "Failed to receive data";
        case DNS_ERR_TIMEOUT:          return "Network connection timed out";
        case DNS_ERR_INVALID_DOMAIN:   return "Domain name is invalid or too long";
        case DNS_ERR_MALFORMED_PACKET: return "Received a malformed DNS packet";
        case DNS_ERR_TRUNCATED:        return "DNS response was truncated";
        case DNS_ERR_UNSUPPORTED_TYPE: return "Unsupported DNS record type";
        default:                       return "Unknown error";
    }
}
