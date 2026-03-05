
#include "dns_parse.h"
#include "color.h"
#include "dns.h"

#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>

void dns_parse_header(dns_header_t *head) {
    (*head).id      = ntohs((*head).id);
    (*head).flags   = ntohs((*head).flags);
    (*head).qdCount = ntohs((*head).qdCount);
    (*head).anCount = ntohs((*head).anCount);
    (*head).arCount = ntohs((*head).arCount);
    (*head).nsCount = ntohs((*head).nsCount);
}

void dns_parse_print_header_flags(const uint16_t flags) {
    printf("\n---------HEADER_FLAGS------------------");

    /*
       Skipping the Z flag because not necessary according to RFC 1035
       Skipping the RD because is it set by the client
    */

    // RCODE Checking
    if ((flags & RCODE_CHECK) == 0)
        printf("\nNo Error Found!");
    else
        printf("\nSome error occured!");

    // RA Checking
    if ((flags & RA_CHECK) == 0)
        printf("\nRecursive query support is not available in the name server!");
    else
        printf("\nRecursive query support is available in the name server!");
 
    // TC Checking
    if ((flags & RCODE_CHECK) == 0)
        printf("\nMessage was not Truncated!");
    else
        printf("\nMessage was Truncated!");

    // AA Checking
    if ((flags & AA_CHECK) == 0)
        printf("\nResponding NS is not an authority for the domain name!");
    else
        printf("\nResponding NS is the authority for the domain name!");

    // OPCODE Checking
    if ((flags & OPCODE_CHECK) == 0)
        printf("\nA standard query (QUERY) was sent!");
    else
        printf("\nNot a standard query!");

    // QR Checking
    if ((flags & QR_CHECK) == 0)
        printf("\nA query was made!");
    else
        printf("\nA response was recieved!");

    printf("\n---------HEADER_FLAGS------------------");
}

void dns_print_header(const dns_header_t head) {
    printf("\n%s----HEADER----%s", FG_YELLOW, RESET);
    printf("\nHeader                      ID: %X", head.id);
    dns_parse_print_header_flags(head.flags);
    printf("\nHeader   Question Record Count: %d", head.qdCount);
    printf("\nHeader     Answer Record Count: %d", head.anCount);
    printf("\nHeader  Authority Record Count: %d", head.nsCount);
    printf("\nHeader Additional Record Count: %d", head.arCount);
    printf("\n%s----HEADER----%s", FG_YELLOW, RESET);
}

void dns_parse_print_question_no_name(dns_question_no_name_t qt) {
    printf("\n---------------Q-----------------");
    printf("\n QTYPE: [%d]", ntohs(qt.qtype));
    printf("\nQCLASS: [%d]", ntohs(qt.qclass));
    printf("\n---------------Q-----------------");
}

uint8_t *dns_str_conv(const uint8_t* str_buffer) {
    uint8_t* str = NULL;
    uint16_t total_len = 0;
    uint16_t offset = 0;
    while ( *(str_buffer + offset) != 0) {
        int temp_size = *(str_buffer + offset);
        total_len += temp_size + 1;
        str = realloc( str, total_len);
        memcpy( str + offset, str_buffer + offset + 1, temp_size);
        *(str + total_len - 1) = '.';
        offset = total_len;
    }
    *(str + offset - 1) = '\0';
    return str;
}

uint8_t* dns_parse_dns_str(const uint8_t* buffer_head, const uint8_t *buffer_start, bool *is_Offset) {
    uint16_t value = ( (buffer_start[0] << 8) | buffer_start[1] );
    uint16_t offset = 0;
    
    if ( ( value & DNS_POINTER_MASK ) == DNS_POINTER_VALUE ) {
        offset = value & DNS_POINTER_OFFSET_MASK;
        *is_Offset = true;
        return dns_str_conv(buffer_head + offset);
    } else
        return dns_str_conv(buffer_start);
}

void print_resource(resourse_rec_no_name_rdata_t rr) {
    printf("\n________Resource_Record________");
    printf("\nResource  type: [%s]", dns_type_to_string(rr.qtype));
    printf("\nResource class: [%s]", dns_class_to_string(rr.qclass));
    printf("\nResource   TTL: [%d]", rr.qTTL);
    printf("\nResource RDLen: [%d]", rr.q_rd_len);
    printf("\n________Resource_Record________");
}

#define MAX_IPV4_STR_LEN (15 + 1)

char* dns_parse_ipv4(const uint8_t *buffer_start) {
    const unsigned char *p = (const unsigned char *)buffer_start;
    char *ip = malloc(MAX_IPV4_STR_LEN);
    snprintf(ip, MAX_IPV4_STR_LEN, "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
    return ip;
}

char* dns_parse_rdata(resourse_rec_no_name_rdata_t rr, const uint8_t* buffer_start) {
    if (buffer_start == NULL) return NULL;
    switch (rr.qclass) {
        case CLASS_IN:
            switch (rr.qclass) {
                case TYPE_A:
                    if (rr.q_rd_len == 4) return dns_parse_ipv4(buffer_start);
                    else return NULL;
                default:
                    return NULL;
            }
            break;
        default: return NULL;
    }
}

void dns_parse_ans_auth_add(
        dns_header_t head, const uint8_t* response_buffer,
        const uint8_t* buff_start, const size_t /*buf_len*/
        ) {
    uint32_t total_count = head.anCount + head.arCount + head.nsCount;
    
    resourse_rec_no_name_rdata_t rr = {0};
    const uint8_t* rr_buf = NULL;
    uint8_t offset = 0;

    for (uint32_t i = 0; i < total_count; i++) {

        bool is_Offset = false;
        uint8_t* url_str = dns_parse_dns_str(response_buffer,
               buff_start + offset, &is_Offset);
        printf("\n The web URL returned is: [%s]", url_str);
        char *ip_str = NULL;

        if (is_Offset) {
            rr_buf = buff_start + 2;
         
            rr.qtype  = ( ( rr_buf[0] <<  8 ) | rr_buf[1] );
            rr.qclass = ( ( rr_buf[2] <<  8 ) | rr_buf[3] );
            
            rr.qTTL = ntohl(*(uint32_t *)(rr_buf + 4));
            rr.q_rd_len = ntohs( *( (uint16_t*)(rr_buf + 8) ) );

            print_resource(rr);
            
            ip_str = dns_parse_rdata(rr, buff_start + offset + 2 + 10);
            printf("\n IP returned: [%s]", ip_str);
            
            offset = 2 + 10 + rr.q_rd_len;

            free(ip_str);
        }
        free(url_str);
    }

}


void parse_dns_response(const uint8_t* query_buf, const uint8_t* buffer, size_t buf_len) {

    if (buf_len < MIN_RESOURCE_SIZE) exit(EXIT_FAILURE);

    dns_header_t head;
    memcpy( &head, buffer, sizeof(head));

    dns_parse_header(&head);
    dns_print_header(head);

    // Parse Question
    if (strcmp( (const char*)buffer + sizeof(head), (const char*)query_buf + sizeof(head) ) == 0)
        printf("\nDNS String returned!");

    uint8_t* ques = buffer + sizeof(head);
    while (*ques != 0)
        ques += (*ques) + 1;
    ques++;

    dns_question_no_name_t qt;
    memcpy(&qt, ques, sizeof(qt));

    dns_parse_print_question_no_name(qt);

    dns_parse_ans_auth_add(
            head, buffer, ques + sizeof(qt),
            ( buf_len - ( sizeof(head) + strlen(buffer + sizeof(head) ) + 1 + sizeof(qt) ) )
            );


}

