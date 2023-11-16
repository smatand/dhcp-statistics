#ifndef DHCPMONITOR_H
#define DHCPMONITOR_H

#include <pcap/pcap.h>
#include <string.h>

#define MAX_DHCP_CHADDR_LENGTH           16
#define MAX_DHCP_SNAME_LENGTH            64
#define MAX_DHCP_FILE_LENGTH             128
#define MAX_DHCP_OPTIONS_LENGTH          312

#define DHCPDISCOVER    1
#define DHCPOFFER       2
#define DHCPREQUEST     3
#define DHCPDECLINE     4
#define DHCPACK         5
#define DHCPNACK        6
#define DHCPRELEASE     7

struct dhcp_packet {
        u_int8_t  op;                   /* packet type */
        u_int8_t  htype;                /* type of hardware address for this machine (Ethernet, etc) */
        u_int8_t  hlen;                 /* length of hardware address (of this machine) */
        u_int8_t  hops;                 /* hops */
        u_int32_t xid;                  /* random transaction id number - chosen by this machine */
        u_int16_t secs;                 /* seconds used in timing */
        u_int16_t flags;                /* flags */
        struct in_addr ciaddr;          /* IP address of this machine (if we already have one) */
        struct in_addr yiaddr;          /* IP address of this machine (offered by the DHCP server) */
        struct in_addr siaddr;          /* IP address of DHCP server */
        struct in_addr giaddr;          /* IP address of DHCP relay */
        unsigned char chaddr [MAX_DHCP_CHADDR_LENGTH];      /* hardware address of this machine */
        char sname [MAX_DHCP_SNAME_LENGTH];    /* name of DHCP server */
        char file [MAX_DHCP_FILE_LENGTH];      /* boot file name (used for diskless booting?) */
	    char options[MAX_DHCP_OPTIONS_LENGTH];  /* options */
};

/** Subnet */
typedef struct Subnet {
    std::string to_print;
    struct in_addr network_address;
    struct in_addr broadcast_address;
    struct in_addr mask_address;

    uint32_t allocated;
    uint32_t max_hosts;
    float utilization;

    std::vector<std::string> hosts;
} subnet_t;

/**
 * Options
 * -r <filename> - statistics will be created from pcap files
 * -i <interface-name> - listen on interface
 * <ip-prefix> - print stats for this prefix
*/
typedef struct Options {
    // may be optional
    std::string filename;
    // may be optional
    std::string interface;
    // whether it's a pcap file or interface
    uint8_t mode;
} options_t;

#endif