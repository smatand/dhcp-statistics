#include <iostream>
#include <vector>
#include <string>
#include <unistd.h>
#include <algorithm>

#include <syslog.h>

// for inet_pton (convert to IPv4)
#include <arpa/inet.h>
#include <pcap/pcap.h>

#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

// terminal output
#include <ncurses.h>

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
    struct in_addr address;
    uint32_t mask;

    uint32_t allocated;
    uint32_t max_hosts;

    std::vector<std::string> hosts;
} subnet_t;

std::vector<subnet_t> subnets{};
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
void exitWithError(std::string message) {
    std::cerr << "ERROR: " << message << std::endl;
    std::exit(1);
}

/**
 * Get maximum count of hosts in subnet
 * 
 * @param mask Subnet mask 
*/
uint32_t getHostsCount(uint32_t mask) {
    if (mask == 32) {
        return 1;
    } else if (mask == 31) {
        return 2;
    }

    return (1 << (32 - mask)) - 2;
}

/**
 * Parse network prefix
 * 
 * @param prefix Network prefix X.X.X.X/Y
 * 
 * @return subnet_t subnet structure 
*/
subnet_t parseNetworkPrefix(std::string prefix) {
    subnet_t subnet;

    // split by '/'
    std::size_t pos = prefix.find('/');
    if (pos == std::string::npos) {
        exitWithError("Invalid prefix: " + prefix);
    }

    // 0.0.0.0 - 255.255.255.255
    // store converted address in subnet.address (in_addr)
    std::string address = prefix.substr(0, pos);
    if (inet_pton(AF_INET, address.c_str(), &subnet.address) != 1) {
        exitWithError("This address is not in IPv4 format: " + address);
    }

    std::string mask = prefix.substr(pos + 1);
    subnet.mask = std::stoi(mask);

    subnet.to_print = prefix;
    subnet.max_hosts = getHostsCount(subnet.mask);

    return subnet;
}

/**
 * Parse command line options
 * 
 * @param argc Count of args
 * @param argv Args
*/
options_t parseOptions(int argc, char * argv[]) {
    options_t options;

    int opt{};

    while ((opt = getopt(argc, argv, "-r:-i:")) != -1) {
        switch (opt) {
            case 'r':
                options.filename = optarg;
                options.mode = 1;
                break;
            case 'i':
                options.interface = optarg;
                options.mode = 2;
                break;
            default:
                if (optarg[0] == '-') {
                    exitWithError("Unknown option: " + std::string{optarg});
                } else {
                    subnets.push_back(parseNetworkPrefix(optarg));
                }
        }
    }

    if (subnets.empty()) {
        exitWithError("No prefixes specified");
    }

    if (options.mode == 0) {
        exitWithError("Specify either -r or -i option.");
    }

    return options;
}

/** Initialize ncurses */
void initNcurses() {
    initscr();
    erase();
    //cbreak(); // handle the CTRL+C key, but do not buffer input
    //noecho();
}

/** Print header of ncurses win */
void ncurseHeaderPrint() {
    printw("IP-Prefix\t\tMax-hosts\tAllocated addresses\tUtilization\t\n");
}

/** 
 * Ncurses dynamic window 
 * 
 * @param options Options for printing prefixes
 * */
void ncurseWindowPrint() {
    initNcurses();

    start_color();
    init_pair(1, COLOR_BLACK, COLOR_WHITE);

    attron(COLOR_PAIR(1));
    ncurseHeaderPrint();
    attroff(COLOR_PAIR(1));

    for (const subnet_t &prefix : subnets) {
        printw("%-18s\t%-10d\t%-10d\t\t%-4f\n", 
            prefix.to_print.c_str(),
            prefix.max_hosts,
            prefix.allocated,
            (float) prefix.allocated / prefix.max_hosts * 100
        );
    }

    refresh();
    timeout(1000);
}

/**
 * Check whether the address is in the subnet
 * 
 * @param address address to be checked
 * @param subnet subnet 
 * 
 * @return true if address is in subnet, false otherwise 
*/
bool isIpInSubnet(struct in_addr address, subnet_t subnet) {
    uint32_t addr = ntohl(address.s_addr);
    uint32_t net = ntohl(subnet.address.s_addr); 
    uint32_t mask = ntohl(subnet.mask);

    return (addr & mask) == (net & mask);
}

/**
 * Add address to the prefix
 * 
 * @param address Address to be added
*/
void addAddress(struct in_addr address) {
    for (subnet_t &prefix : subnets) {
        if (isIpInSubnet(address, prefix)) {
            std::string address_str = inet_ntoa(address);
            // FOR DEBUGGING PURPOSES TODO: REMOVE
            // check whether the address is already in the vector
            if (std::find(prefix.hosts.begin(), prefix.hosts.end(), address_str) != prefix.hosts.end()) {
                return;
            }

            prefix.allocated++;


            prefix.hosts.push_back(inet_ntoa(address));

            return;
        }
    }
}

/**
 * Callback function for pcap_loop
 * 
 * @param handle Handle to the opened file
 * @param header Header of the packet
 * @param packet packet
*/
void packetCallback(u_char * handle, const struct pcap_pkthdr * header, const u_char * packet) {
    struct ether_header * ethernet = (struct ether_header *) packet;

    (void) handle;
    (void) header;

    if (ntohs(ethernet->ether_type) == ETHERTYPE_IP) {
        struct dhcp_packet * dhcp = (struct dhcp_packet *) (packet + sizeof(struct udphdr) + sizeof(struct ip) + sizeof(struct ether_header));

        // https://cs.uwaterloo.ca/twiki/pub/CF/DhcpDebug/dhcp.c
        if (dhcp->options[6] == DHCPACK) {
            // ciaddr : will be filled by client and is used only in BOUND,RENEW and REBINDING state
            // yiaddr :Filled by server and sent to client in DHCPOFFER and DHCPACK.
            addAddress(dhcp->yiaddr);
        } else if (dhcp->options[6] == DHCPDECLINE) {
            std::cout << "DHCP DECLINE" << std::endl;
        }
    }

    ncurseWindowPrint();
}

/** 
 * Open pcap file from the specified -f option
 * 
 * @param filename path to the pcap file
 * 
 * @return pcap_t * handle
*/
pcap_t * openPcapFile(std::string filename) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * handle;

    handle = pcap_open_offline(filename.c_str(), errbuf);
    if (handle == nullptr) {
        exitWithError("pcap_open_offline: " + std::string{errbuf});
    }

    return handle;
}

/**
 * Open pcap file from the specified --interface option
 * 
 * @param interface name of the interface
 * @param net network address
 * 
 * @return pcap_t * handle
*/
pcap_t * openPcapLive(std::string interface) {
    // https://www.tcpdump.org/pcap.html
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t * handle;

    // opens the selected network interface for packet capture
    // the term live is used because the packets will be read from an active network
    // the term offline is the exact opposite (.pcap file)
    // BUFSIZ is defined in /usr/include/stdio.h
    // as it is expected that the monitor will be running from dhcp server, the promiscuous mode is not needed
    handle = pcap_open_live(interface.c_str(), BUFSIZ, 0, 1000, errbuf);
    if (handle == nullptr) {
        exitWithError("pcap_open_live: " + std::string{errbuf});
    }

    return handle;
}

int main(int argc, char * argv[]) {
    options_t options = parseOptions(argc, argv);
    pcap_t * handle;

    switch (options.mode) {
        case 1:
            handle = openPcapFile(options.filename);
            break;
        case 2:
            handle = openPcapLive(options.interface);
            break;
        default:
            exitWithError("Invalid mode");
    }

    // ports used by DHCP server and DHCP client
    std::string filter = "port 67 or port 68";
    bpf_program fp;

    if (pcap_compile(handle, &fp, filter.c_str(), 0, 0) == -1) {
        exitWithError("pcap_compile: " + std::string{pcap_geterr(handle)});
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        exitWithError("Unable to install filter.");
    }

    if (options.mode == 2) {
        initscr(); 
        ncurseWindowPrint();
    }

    pcap_loop(handle, 0, packetCallback, nullptr);

    #ifdef DEBUG
    while (n < 10) {
        ncurseWindowPrint(&options);
        printw("%d", n);
        sleep(1);
        refresh();
        erase();

        n++; // tbd
    }

    endwin();

    setlogmask(LOG_UPTO (LOG_NOTICE));

    openlog("exampleprog", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

    if (!options.filename.empty()) {
        syslog(LOG_NOTICE, "File: %s", options.filename.c_str());
    }
    if (!options.interface.empty()) {
        syslog(LOG_NOTICE, "Interface: %s", options.interface.c_str());
    }
    for (auto prefix : options.prefixes) {
        syslog(LOG_NOTICE, "Prefix: %s/%d", inet_ntoa(prefix.address), prefix.mask);
    }

    closelog();
    #endif // DEBUG
}