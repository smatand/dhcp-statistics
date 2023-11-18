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

#define ETHER_H_SIZE 14
#define IP_H_SIZE 20
#define UDP_H_SIZE 8

#define DHCP_MAGIC_COOKIE 0x63825363
#define DHCP_OP_REPLY 2

#define DHCP_OPTION_MESSAGE_TYPE 53
#define DHCP_OPTION_END 255


#define Q_UNUSED(x) (void)x;

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
        uint32_t magic_cookie;          /* fixed first four option bytes for DHCP, not BOOTP */
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

    bool warning_printed;
    bool critical_warning_printed;

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

/**
 * Exit with error message
 * 
 * @param message Error message
*/
void exitWithError(std::string message);


/**
 * Get maximum count of hosts in subnet
 * 
 * @param s_addr subent mask in 0-32 format
*/
uint32_t getHostsCount(uint32_t mask);

/**
 * @brief Signal handler.
 *  
 * @param sig signal 
*/
void handleExit(int sig);

/**
 * Parse network prefix
 * 
 * @param prefix Network prefix X.X.X.X/Y
 * 
 * @return subnet_t subnet structure 
*/
subnet_t parseNetworkPrefix(std::string prefix);

/**
 * Compare two subnets for std::find function used in parseOptions()
 * 
 * @param lhs Left hand side
 * @param rhs Right hand side
 * 
 * @return true if the addresses and masks are equal, false otherwise
*/
bool operator==(const subnet_t &lhs, const subnet_t &rhs);

/** Print help */
void printHelp();

/**
 * Parse command line options
 * 
 * @param argc Count of args
 * @param argv Args
*/
options_t parseOptions(int argc, char * argv[]);

/** Initialize ncurses */
void initNcurses();

/** Print header of ncurses win */
void ncurseHeaderPrint();

/** Ncurses dynamic window */
void ncurseWindowPrint();

/** Print statistics to stdout without using ncurses lib (offline reading of pcap)*/
void offlineStatsPrint();

/**
 * Check whether the address is in the subnet
 * 
 * @param address address to be checked
 * @param subnet subnet 
 * 
 * @return true if address is in subnet, false otherwise 
*/
bool isIpInSubnet(struct in_addr address, subnet_t subnet);

/**
 * Print warning to syslog and stdout if 50 % of the prefix is allocated
 * 
 * @param prefix Prefix to be printed
 * 
 * @return true if the warning has been printed
*/
bool printWarning(std::string prefix);

/**
 * Print critical warning to syslog and stdout if 80 % of the prefix is allocated
 * 
 * @param prefix Prefix to be printed
 * 
 * @return true if the warning has been printed
*/
bool printCritical(std::string prefix);

/**
 * Print information about 100 % of the prefix is allocated
 * 
 * @param prefix Prefix to be printed
 * 
 * @return true if the warning has been printed
*/
bool printFullUtilization(std::string prefix);

/**
 * Add address to the prefix
 * 
 * @param address Address to be added
*/
void addAddress(struct in_addr address);

/**
 * Callback function for pcap_loop
 * 
 * @param handle Handle to the opened file
 * @param header Header of the packet
 * @param packet packet
*/
void packetCallback(u_char * handle, const struct pcap_pkthdr * header, const u_char * packet);

/** 
 * Open pcap file from the specified -f option
 * 
 * @param filename path to the pcap file
 * 
 * @return pcap_t * handle
*/
pcap_t * openPcapFile(std::string filename);

/**
 * Open pcap file from the specified --interface option
 * 
 * @param interface name of the interface
 * @param net network address
 * 
 * @return pcap_t * handle
*/
pcap_t * openPcapLive(std::string interface);

#endif