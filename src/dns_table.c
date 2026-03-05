#include "dns.h"

static const DNS_TypeName dns_type_table[] = {{TYPE_A, "A"},
                                              {TYPE_NS, "NS"},
                                              {TYPE_MD, "MD"},
                                              {TYPE_MF, "MF"},
                                              {TYPE_CNAME, "CNAME"},
                                              {TYPE_SOA, "SOA"},
                                              {TYPE_MB, "MB"},
                                              {TYPE_MG, "MG"},
                                              {TYPE_MR, "MR"},
                                              {TYPE_NULL, "NULL"},
                                              {TYPE_WKS, "WKS"},
                                              {TYPE_PTR, "PTR"},
                                              {TYPE_HINFO, "HINFO"},
                                              {TYPE_MINFO, "MINFO"},
                                              {TYPE_MX, "MX"},
                                              {TYPE_TXT, "TXT"},
                                              {TYPE_RP, "RP"},
                                              {TYPE_AFSDB, "AFSDB"},
                                              {TYPE_X25, "X25"},
                                              {TYPE_ISDN, "ISDN"},
                                              {TYPE_RT, "RT"},
                                              {TYPE_NSAP, "NSAP"},
                                              {TYPE_NSAP_PTR, "NSAP_PTR"},
                                              {TYPE_SIG, "SIG"},
                                              {TYPE_KEY, "KEY"},
                                              {TYPE_PX, "PX"},
                                              {TYPE_GPOS, "GPOS"},
                                              {TYPE_AAAA, "AAAA"},
                                              {TYPE_LOC, "LOC"},
                                              {TYPE_NXT, "NXT"},
                                              {TYPE_EID, "EID"},
                                              {TYPE_NIMLOC, "NIMLOC"},
                                              {TYPE_SRV, "SRV"},
                                              {TYPE_ATMA, "ATMA"},
                                              {TYPE_NAPTR, "NAPTR"},
                                              {TYPE_KX, "KX"},
                                              {TYPE_CERT, "CERT"},
                                              {TYPE_A6, "A6"},
                                              {TYPE_DNAME, "DNAME"},
                                              {TYPE_SINK, "SINK"},
                                              {TYPE_OPT, "OPT"},
                                              {TYPE_APL, "APL"},
                                              {TYPE_DS, "DS"},
                                              {TYPE_SSHFP, "SSHFP"},
                                              {TYPE_IPSECKEY, "IPSECKEY"},
                                              {TYPE_RRSIG, "RRSIG"},
                                              {TYPE_NSEC, "NSEC"},
                                              {TYPE_DNSKEY, "DNSKEY"},
                                              {TYPE_DHCID, "DHCID"},
                                              {TYPE_NSEC3, "NSEC3"},
                                              {TYPE_NSEC3PARAM, "NSEC3PARAM"},
                                              {TYPE_TLSA, "TLSA"},
                                              {TYPE_SMIMEA, "SMIMEA"},
                                              {TYPE_HIP, "HIP"},
                                              {TYPE_NINFO, "NINFO"},
                                              {TYPE_RKEY, "RKEY"},
                                              {TYPE_TALINK, "TALINK"},
                                              {TYPE_CDS, "CDS"},
                                              {TYPE_CDNSKEY, "CDNSKEY"},
                                              {TYPE_OPENPGPKEY, "OPENPGPKEY"},
                                              {TYPE_CSYNC, "CSYNC"},
                                              {TYPE_ZONEMD, "ZONEMD"},
                                              {TYPE_SVCB, "SVCB"},
                                              {TYPE_HTTPS, "HTTPS"},
                                              {TYPE_SPF, "SPF"},
                                              {TYPE_UINFO, "UINFO"},
                                              {TYPE_UID, "UID"},
                                              {TYPE_GID, "GID"},
                                              {TYPE_UNSPEC, "UNSPEC"},
                                              {TYPE_NID, "NID"},
                                              {TYPE_L32, "L32"},
                                              {TYPE_L64, "L64"},
                                              {TYPE_LP, "LP"},
                                              {TYPE_EUI48, "EUI48"},
                                              {TYPE_EUI64, "EUI64"},
                                              {TYPE_TKEY, "TKEY"},
                                              {TYPE_TSIG, "TSIG"},
                                              {TYPE_IXFR, "IXFR"},
                                              {QTYPE_AXFR, "AXFR"},
                                              {QTYPE_MAILB, "MAILB"},
                                              {QTYPE_MAILA, "MAILA"},
                                              {QTYPE_ANY, "ANY"}};
static size_t t_count = sizeof(dns_type_table) / sizeof(dns_type_table[0]);

const char *dns_type_to_string(uint16_t dns_type) {
    for (size_t i = 0; i < t_count; i++)
        if (dns_type_table[i].type == dns_type)
            return dns_type_table[i].name;
    return "UNKNOWN";
}

const char *dns_class_to_string(uint16_t dns_class) {
    switch (dns_class) {
    case 1:
        return "IN";
    case 2:
        return "CS";
    case 3:
        return "CH";
    case 4:
        return "HS";
    case 255:
        return "ANY";
    default:
        return "UNKNOWN";
    }
}
