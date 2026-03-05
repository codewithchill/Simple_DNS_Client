#pragma once

#include <stdint.h>
#include <stdio.h>

#define  RCODE_CHECK ( (1 << 3) | (1 << 2) | (1 << 1) | ( 1 << 0 ) )
#define      Z_CHECK ( (1 << 6) | (1 << 5) | (1 << 4) )
#define     RA_CHECK ( (1 << 7) )
#define     RD_CHECK ( (1 << 8) )
#define     TC_CHECK ( (1 << 9) )
#define     AA_CHECK ( (1 << 10) )
#define OPCODE_CHECK ( (1 << 14) | (1 << 13) | (1 << 12) | (1 << 11) )
#define     QR_CHECK ( (1 << 15) )

#define SIZE_IN_BYTES(x) ( sizeof(x) / sizeof(x[0]) )
#define MIN_RESOURCE_SIZE 13

uint8_t *dns_str_conv(const uint8_t* str_buffer);
void parse_dns_response(const uint8_t* query, const uint8_t* buffer, size_t buf_len);

