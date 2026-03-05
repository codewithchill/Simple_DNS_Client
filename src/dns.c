#include "dns.h"
#include "udp.h"
#include "dns_parse.h"
#include "color.h"

#include <arpa/inet.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>

unsigned char* parse_str_to_dns(const char *domain, size_t* dns_string_len);

uint16_t id_gen() {
    return (rand() % UINT16_MAX);
}

void parse_arguments(int argc,char **argv) {
    if ( argc != 2 ) {
        printf("\nUsage: %s <website>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
}

dns_header_t generate_header() {
    dns_header_t head;
    memset(&head, 0, sizeof(head));

    head.id      = id_gen();
    head.flags   = RD;
    head.anCount = 0;
    head.arCount = 0;
    head.nsCount = 0;
    head.qdCount = 1;

    head.id      = htons(head.id);
    head.flags   = htons(head.flags);
    head.qdCount = htons(head.qdCount);
    head.anCount = htons(head.anCount);
    head.nsCount = htons(head.nsCount);
    head.arCount = htons(head.arCount);

    return head;
}

static inline uint16_t get_valid_len(const int i, const int start, int limit) {
    int len = i - start;
    if (len > limit || len < 1) exit(EXIT_FAILURE);
    return len;
}

unsigned char* parse_str_to_dns(const char *domain, size_t* dns_string_len) {
    if (!domain || !dns_string_len) return NULL;

    *dns_string_len = 0;
    uint16_t total_len = 0;
    uint16_t next_start_count = 0;
    int i = 0;
    for (i = 0; domain[i] != '\0' ; i++) {
        if ( '.' == domain[i] ) {
            total_len += ( get_valid_len(i, next_start_count, 63) + 1 );
            next_start_count = i + 1;
        }
    }
    total_len += (get_valid_len( i, next_start_count, 63) + 1);
    total_len++; // Zero byte

    unsigned char *dns_str = malloc(total_len);
    if (!dns_str) return NULL;
    int offset = 0;
    int start_ptr = 0;
    for ( i = 0; domain[i] != '\0'; i++) {
        if ('.' == domain[i]) {
            int n = i - start_ptr;
            dns_str[offset++] = n;
            memcpy(dns_str + offset, domain + start_ptr, n);
            start_ptr = i + 1;
            offset += n;
        }
    }
    int len = i - start_ptr;
    dns_str[offset++] = len;
    memcpy(dns_str + offset, domain + start_ptr, len);
    offset += len;
    dns_str[offset++] = 0;
    *dns_string_len = offset;
    return dns_str;
}

uint8_t* craft_query(char *url, size_t *packet_size) {
    if (packet_size == NULL) exit(EXIT_FAILURE);
    dns_header_t head = generate_header();

    printf("\n%sID sent: %s%X%s", FG_CYAN, FG_RED, ntohs(head.id), RESET);
    printf("\n%sInput string: %s[%s%s%s]", FG_CYAN, RESET, FG_RED, url, RESET);

    size_t dns_string_len = 0;
    unsigned char *dns_string = parse_str_to_dns( url, &dns_string_len);
    if (!dns_string || dns_string_len < 1) exit(EXIT_FAILURE);

//    printf("\n%sDNS format string: %s[%s%s%s]", FG_CYAN, RESET, FG_RED, dns_string, RESET);

    dns_question_no_name_t q = {
        .qtype = htons(TYPE_A),
        .qclass = htons(CLASS_IN)
    };

    size_t q_size = dns_string_len + sizeof(dns_question_no_name_t);
    uint8_t *question = malloc( q_size );
    if (!question) {
        free(dns_string);
        exit(EXIT_FAILURE);
    }

    memcpy(question, dns_string, dns_string_len);
    memcpy(question + dns_string_len, &q, sizeof(q));
    
    uint16_t p_size = sizeof(head) + q_size;
    uint8_t *packet = malloc( p_size );
    if (!packet) {
        free(question);
        free(dns_string);
        exit(EXIT_FAILURE);
    }

    memcpy(packet, &head, sizeof(head));
    memcpy(packet + sizeof(head), question, q_size);

    free(question);
    free(dns_string);

    *packet_size = p_size;
    return packet;
}

void dns_query(char *website) {

    size_t query_len = 0;
    uint8_t *query_packet = craft_query(website, &query_len);

    printf("\n%sQuery packet created: %s", FG_CYAN, RESET);
    for (size_t i = 0; i < query_len; i++)
        printf("%02X", query_packet[i]);

    int buf_len = 0;
    uint8_t *buffer = getData( query_packet, query_len, &buf_len);

    printf("\n%sResponse recieved: %s", FG_CYAN, RESET);
    for (int i = 0; i < buf_len; i++)
        printf("%02X", buffer[i]);

    parse_dns_response( query_packet, buffer, buf_len);

    free(query_packet);
    free(buffer);
}

