#pragma once

#include <stdint.h>
#include <stdio.h>

#define RD (1 << 8)

typedef enum {
    TYPE_A = 1,      /* IPv4 address */
    TYPE_NS = 2,     /* Authoritative name server */
    TYPE_MD = 3,     /* Mail destination (obsolete) */
    TYPE_MF = 4,     /* Mail forwarder (obsolete) */
    TYPE_CNAME = 5,  /* Canonical name */
    TYPE_SOA = 6,    /* Start of authority */
    TYPE_MB = 7,     /* Mailbox domain name (experimental) */
    TYPE_MG = 8,     /* Mail group member (experimental) */
    TYPE_MR = 9,     /* Mail rename domain name (experimental) */
    TYPE_NULL = 10,  /* Null RR */
    TYPE_WKS = 11,   /* Well known service */
    TYPE_PTR = 12,   /* Domain name pointer */
    TYPE_HINFO = 13, /* Host info */
    TYPE_MINFO = 14, /* Mailbox info */
    TYPE_MX = 15,    /* Mail exchange */
    TYPE_TXT = 16,   /* Text record */

    TYPE_RP = 17,    /* Responsible person */
    TYPE_AFSDB = 18, /* AFS database */
    TYPE_X25 = 19,
    TYPE_ISDN = 20,
    TYPE_RT = 21,
    TYPE_NSAP = 22,
    TYPE_NSAP_PTR = 23,
    TYPE_SIG = 24, /* DNSSEC (obsolete) */
    TYPE_KEY = 25, /* DNSSEC key (obsolete) */
    TYPE_PX = 26,
    TYPE_GPOS = 27,
    TYPE_AAAA = 28, /* IPv6 address */
    TYPE_LOC = 29,
    TYPE_NXT = 30, /* DNSSEC (obsolete) */
    TYPE_EID = 31,
    TYPE_NIMLOC = 32,
    TYPE_SRV = 33, /* Service locator */
    TYPE_ATMA = 34,
    TYPE_NAPTR = 35,
    TYPE_KX = 36,
    TYPE_CERT = 37,
    TYPE_A6 = 38, /* Deprecated IPv6 */
    TYPE_DNAME = 39,
    TYPE_SINK = 40,
    TYPE_OPT = 41, /* EDNS */
    TYPE_APL = 42,
    TYPE_DS = 43, /* DNSSEC Delegation Signer */
    TYPE_SSHFP = 44,
    TYPE_IPSECKEY = 45,
    TYPE_RRSIG = 46,
    TYPE_NSEC = 47,
    TYPE_DNSKEY = 48,
    TYPE_DHCID = 49,
    TYPE_NSEC3 = 50,
    TYPE_NSEC3PARAM = 51,
    TYPE_TLSA = 52,
    TYPE_SMIMEA = 53,
    TYPE_HIP = 55,
    TYPE_NINFO = 56,
    TYPE_RKEY = 57,
    TYPE_TALINK = 58,
    TYPE_CDS = 59,
    TYPE_CDNSKEY = 60,
    TYPE_OPENPGPKEY = 61,
    TYPE_CSYNC = 62,
    TYPE_ZONEMD = 63,
    TYPE_SVCB = 64,
    TYPE_HTTPS = 65,

    TYPE_SPF = 99,
    TYPE_UINFO = 100,
    TYPE_UID = 101,
    TYPE_GID = 102,
    TYPE_UNSPEC = 103,

    TYPE_NID = 104,
    TYPE_L32 = 105,
    TYPE_L64 = 106,
    TYPE_LP = 107,
    TYPE_EUI48 = 108,
    TYPE_EUI64 = 109,

    TYPE_TKEY = 249,
    TYPE_TSIG = 250,
    TYPE_IXFR = 251,

    /* Query types */
    QTYPE_AXFR = 252,
    QTYPE_MAILB = 253,
    QTYPE_MAILA = 254,
    QTYPE_ANY = 255
} DNS_Type;

typedef struct {
    uint16_t type;
    const char *name;
} DNS_TypeName;

const char *dns_type_to_string(uint16_t dns_type);

typedef enum {
    CLASS_IN = 1, /* Internet */
    CLASS_CS = 2, /* CSNET (obsolete) */
    CLASS_CH = 3, /* CHAOS */
    CLASS_HS = 4, /* Hesiod */

    /* Query-only class */
    QCLASS_ANY = 255 /* Any class */
} DNS_Class;

const char *dns_class_to_string(uint16_t dns_class);

#define DNS_POINTER_MASK 0xC000
#define DNS_POINTER_VALUE 0xC000
#define DNS_POINTER_OFFSET_MASK 0x3FFF
/*
 ** These are the types inside flags
qr: 1;  // Query/Response Indicator [0 for query]
opcode: 4;  // Operation Code [0 for standard query]
aa: 1;  // Authoritative Answer [0 for query]
tc: 1;  // Truncation: 1 if the message is larger than 512 bytes. Always 0 in UDP responses.
rd: 1;  // Recursion Desired [1 prefered for query]
ra: 1;  // Recursion Available [0 for query]
z: 3;  // Reserved [used by DNSSEC]
rcode: 4;  // Response code [0 for query]
*/
typedef struct {
    uint16_t id;      // Random ID
    uint16_t flags;   // FLAGS
    uint16_t qdCount; // number of entries in the question section.
    uint16_t anCount; // number of resource records in the answer section
    uint16_t nsCount; // number of name server resource records in the authority records section.
    uint16_t arCount; // number of resource records in the additional records section.
} dns_header_t;

typedef struct {
    uint16_t qtype;
    uint16_t qclass;
} dns_question_no_name_t;

typedef struct __attribute__((packed)) {
    uint16_t qtype;
    uint16_t qclass;
    uint32_t qTTL;
    uint16_t q_rd_len;
} resourse_rec_no_name_rdata_t;

void parse_arguments(int argc, char **argv);
void dns_query(char *website);
