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

#include <csignal>

#include "dhcpmonitor.h"

std::vector<subnet_t> subnets{};

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
 * @param s_addr subent mask in 0-32 format
*/
uint32_t getHostsCount(uint32_t mask) {
    if (mask == 32) {
        return 0;
    }

    return (1 << (32 - mask)) - 2;
}

/**
 * @brief Signal handler.
 *  
 * @param sig signal 
*/
void handle_exit(int sig) {
    Q_UNUSED(sig);
    exit(0);
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

    // only 0.0.0.0 - 255.255.255.255
    std::string address = prefix.substr(0, pos);
    if (inet_pton(AF_INET, address.c_str(), &subnet.network_address) != 1) {
        exitWithError("This address is not in IPv4 format: " + address);
    }

    uint32_t mask = std::stoi(prefix.substr(pos + 1));
    if (mask == 0) {
        exitWithError("Prefix X.X.X.X/0 is not allowed.");
    }
    
    // if mask is 24, then 1 << (32 - mask) is 0x1000000
    // 1 << (32 - mask) - 1 is 0x00FFFFFF
    // NOT (~) flips it to 0xFF000000
    // htonl converts it to network byte order (big endian), so it's 0x000000FF
    subnet.mask_address.s_addr = htonl(~((1 << (32 - mask)) - 1));

    subnet.broadcast_address.s_addr = subnet.network_address.s_addr | ~subnet.mask_address.s_addr;

    subnet.to_print = prefix;
    subnet.max_hosts = getHostsCount(mask);
    subnet.allocated = 0;
    subnet.utilization = 0.0;
    subnet.critical_warning_printed = false;
    subnet.warning_printed = false;

    return subnet;
}

/**
 * Compare two subnets for std::find function used in parseOptions()
 * 
 * @param lhs Left hand side
 * @param rhs Right hand side
 * 
 * @return true if the addresses and masks are equal, false otherwise
*/
bool operator==(const subnet_t &lhs, const subnet_t &rhs) {
    return lhs.network_address.s_addr == rhs.network_address.s_addr && lhs.mask_address.s_addr == rhs.mask_address.s_addr;
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
                    subnet_t subnet_to_add = parseNetworkPrefix(optarg);

                    if (std::find(subnets.begin(), subnets.end(), subnet_to_add) != subnets.end()) {
                        std::cerr << "Duplicate prefix in an argument: " << optarg << std::endl;
                    } else {
                        subnets.push_back(subnet_to_add);
                    }
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
        printw("%-18s\t%-10u\t%-10d\t\t%.2f %%\n", 
            prefix.to_print.c_str(),
            prefix.max_hosts,
            prefix.allocated,
            prefix.utilization
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
    if (subnet.max_hosts == 0) {
        return false;
    } else if (address.s_addr == subnet.network_address.s_addr) {
        return false;
    } else if (address.s_addr == subnet.broadcast_address.s_addr) {
        return false;
    }

    if ((address.s_addr & subnet.mask_address.s_addr) == (subnet.network_address.s_addr & subnet.mask_address.s_addr)) {
        return true;
    }

    return false;
}

/**
 * Print warning to syslog and stdout if 50 % of the prefix is allocated
 * 
 * @param prefix Prefix to be printed
 * 
 * @return true if the warning has been printed
*/
bool printWarning(std::string prefix) {
    syslog(LOG_NOTICE, "prefix %s exceeded 50%% of allocations", prefix.c_str());
    std::cout << "prefix " << prefix << " exceeded 50% of allocations" << std::endl;

    return true;
}

/**
 * Print critical warning to syslog and stdout if 80 % of the prefix is allocated
 * 
 * @param prefix Prefix to be printed
 * 
 * @return true if the warning has been printed
*/
bool printCritical(std::string prefix) {
    syslog(LOG_NOTICE, "prefix %s exceeded 80%% of allocations (critical)", prefix.c_str());

    return true;
}

/**
 * Print information about 100 % of the prefix is allocated
 * 
 * @param prefix Prefix to be printed
 * 
 * @return true if the warning has been printed
*/
bool printFullUtilization(std::string prefix) {
    syslog(LOG_NOTICE, "no more addresses in prefix %s", prefix.c_str());

    return true;
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

            // check whether the address is already counted in monitoring of the prefix
            if (std::find(prefix.hosts.begin(), prefix.hosts.end(), address_str) != prefix.hosts.end()) {
                return;
            }
            prefix.allocated++;
            prefix.utilization = static_cast<float>(prefix.allocated) / prefix.max_hosts * 100;

            if (prefix.utilization >= 50.0 && !prefix.warning_printed) {
                prefix.warning_printed = printWarning(prefix.to_print);
            } 
            
            if (prefix.utilization >= 80.0 && !prefix.critical_warning_printed) {
                prefix.critical_warning_printed = printCritical(prefix.to_print);
            }

            if (prefix.utilization == 100.0) {
                printFullUtilization(prefix.to_print);
            }

            prefix.hosts.push_back(inet_ntoa(address));
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
    #ifndef __linux__
        std::cerr << "ERROR: This program is only supported on Linux." << std::endl;
        exit(2);
    #endif

    options_t options = parseOptions(argc, argv);
    pcap_t * handle;
    setlogmask(LOG_UPTO (LOG_NOTICE));
    openlog("dhcp-stats", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
    std::signal(SIGINT, handle_exit);

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

    closelog();
}