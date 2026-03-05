#include "dns.h"

static const DNS_TypeName dns_type_table[] = {
    {1, "A"},      {2, "NS"},          {5, "CNAME"},  {6, "SOA"},    {12, "PTR"},
    {15, "MX"},    {16, "TXT"},        {28, "AAAA"},  {33, "SRV"},   {41, "OPT"},
    {43, "DS"},    {44, "SSHFP"},      {46, "RRSIG"}, {47, "NSEC"},  {48, "DNSKEY"},
    {50, "NSEC3"}, {51, "NSEC3PARAM"}, {52, "TLSA"},  {64, "SVCB"},  {65, "HTTPS"},
    {99, "SPF"},   {250, "TSIG"},      {251, "IXFR"}, {252, "AXFR"}, {255, "ANY"}};

static size_t t_count = sizeof(dns_type_table) / sizeof(dns_type_table[0]);

const char *dns_type_to_string(uint16_t dns_type) {
    for (size_t i = 0; i < t_count; i++)
        if (dns_type_table[i].type == dns_type)
            return dns_type_table[i].name;
    return "UNKNOWN";
}

const char *dns_class_to_string(uint16_t dns_class) {
    switch(dns_class)
    {
        case 1:   return "IN";
        case 2:   return "CS";
        case 3:   return "CH";
        case 4:   return "HS";
        case 255: return "ANY";
        default:  return "UNKNOWN";
    }
}

