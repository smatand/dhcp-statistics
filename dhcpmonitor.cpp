/**
 * @file dhcpmonitor.cpp
 * @author Andrej Smatana <xsmata03>
*/

#include <iostream>
#include <vector>
#include <string>
#include <getopt.h>
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


std::vector<subnet_t> subnets_g{};

void exitWithError(std::string message) {
    std::cerr << "ERROR: " << message << std::endl;
    std::exit(1);
}

uint32_t getHostsCount(uint32_t mask) {
    if (mask == 32) {
        return 0;
    }

    return (1 << (32 - mask)) - 2;
}

void handleExit(int sig) {
    Q_UNUSED(sig);
    closelog();
    exit(0);
}

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
        // if it's not 0.0.0.0/0, then it's invalid
        if (subnet.network_address.s_addr != 0) {
            exitWithError("Prefix X.X.X.X/0 is not allowed.");
        }

        subnet.mask_address.s_addr = 0;
    } else {
        // if mask is 24, then 1 << (32 - mask) is 0x1000000
        // 1 << (32 - mask) - 1 is 0x00FFFFFF
        // NOT (~) flips it to 0xFF000000
        // htonl converts it to network byte order (big endian), so it's 0x000000FF
        subnet.mask_address.s_addr = htonl(~((1 << (32 - mask)) - 1));
    }

    subnet.broadcast_address.s_addr = subnet.network_address.s_addr | ~subnet.mask_address.s_addr;

    subnet.to_print = prefix;
    subnet.max_hosts = getHostsCount(mask);
    subnet.allocated = 0;
    subnet.utilization = 0.0;
    subnet.critical_warning_printed = false;
    subnet.warning_printed = false;

    return subnet;
}

bool operator==(const subnet_t &lhs, const subnet_t &rhs) {
    return lhs.network_address.s_addr == rhs.network_address.s_addr && lhs.mask_address.s_addr == rhs.mask_address.s_addr;
}

void printHelp() {
    std::cout << "Usage: ./dhcp-stats [-h] [-r <filename>] [-i <interface-name>] <ip-prefix> [ <ip-prefix> [ ... ] ]" << std::endl;
}

options_t parseOptions(int argc, char * argv[]) {
    options_t options;
    options.mode = 0;

    struct option long_options[] = {
        {"read", required_argument, nullptr, 'r'},
        {"interface", required_argument, nullptr, 'i'},
        {"help", no_argument, nullptr, 'h'},
        { NULL, 0, NULL, 0 }
    };

    int opt{};

    while ((opt = getopt_long(argc, argv, "r:i:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'r':
                if (options.mode == 2) {
                    exitWithError("Specify either -r or -i option.");
                }

                options.filename = optarg;
                options.mode = 1;
                break;
            case 'i':
                if (options.mode == 1) {
                    exitWithError("Specify either -r or -i option.");
                }

                options.interface = optarg;
                options.mode = 2;
                break;
            case 'h':
                printHelp();
                exit(0);
                break;
            default:
                exitWithError("Unknown option: " + std::string{optarg});
        }

    }

    if (optind >= argc) {
        exitWithError("No prefixes specified");
    }

    for (int i = optind; i < argc; i++) {
        subnet_t subnet_to_add = parseNetworkPrefix(argv[i]);

        if (std::find(subnets_g.begin(), subnets_g.end(), subnet_to_add) != subnets_g.end()) {
            std::cerr << "Duplicate prefix in an argument: " << argv[i] << std::endl;
        } else {
            subnets_g.push_back(subnet_to_add);
        }
    }

    if (subnets_g.empty()) {
        exitWithError("No prefixes specified");
    }

    if (options.mode == 0) {
        exitWithError("Specify either -r or -i option.");
    }

    return options;
}

void initNcurses() {
    initscr();
    erase();
    cbreak(); // handle the CTRL+C key, but do not buffer input
    noecho();
}

void ncurseHeaderPrint() {
    printw("IP-Prefix\t\tMax-hosts\tAllocated addresses\tUtilization\t\n");
}

void ncurseWindowPrint() {
    initNcurses();

    start_color();
    init_pair(1, COLOR_BLACK, COLOR_WHITE);

    attron(COLOR_PAIR(1));
    ncurseHeaderPrint();
    attroff(COLOR_PAIR(1));

    for (const subnet_t &prefix : subnets_g) {
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

void offlineStatsPrint() {
    std::cout << std::endl << "IP-Prefix\t\tMax-hosts\tAllocated addresses\tUtilization\t" << std::endl;

    for (const subnet_t &prefix : subnets_g) {
        printf("%-18s\t%-10u\t%-10d\t\t%.2f %%\n", 
            prefix.to_print.c_str(),
            prefix.max_hosts,
            prefix.allocated,
            prefix.utilization
        );
    }
}

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

bool printWarning(std::string prefix) {
    syslog(LOG_NOTICE, "prefix %s exceeded 50%% of allocations", prefix.c_str());
    std::cout << "prefix " << prefix << " exceeded 50% of allocations" << std::endl;

    return true;
}

bool printCritical(std::string prefix) {
    syslog(LOG_NOTICE, "prefix %s exceeded 80%% of allocations (critical)", prefix.c_str());

    return true;
}

bool printFullUtilization(std::string prefix) {
    syslog(LOG_NOTICE, "no more addresses in prefix %s", prefix.c_str());

    return true;
}

void checkToPrintWarning(subnet_t &prefix) {
    if (prefix.utilization >= 50.0 && !prefix.warning_printed) {
        prefix.warning_printed = printWarning(prefix.to_print);
        prefix.warning_printed = true;
    } 

    if (prefix.utilization >= 80.0 && !prefix.critical_warning_printed) {
        prefix.critical_warning_printed = printCritical(prefix.to_print);
        prefix.critical_warning_printed = true;
    }

    if (prefix.utilization == 100.0) {
        printFullUtilization(prefix.to_print);
    }
}

void addAddress(struct in_addr address) {
    for (subnet_t &prefix : subnets_g) {
        if (isIpInSubnet(address, prefix)) {
            std::string address_str = inet_ntoa(address);

            // check whether the address is already counted in monitoring of the prefix
            if (std::find(prefix.hosts.begin(), prefix.hosts.end(), address_str) != prefix.hosts.end()) {
                return;
            }
            prefix.allocated++;
            prefix.utilization = static_cast<float>(prefix.allocated) / prefix.max_hosts * 100;

            checkToPrintWarning(prefix);

            prefix.hosts.push_back(inet_ntoa(address));

            // sort prefixes by utilization
            std::sort(subnets_g.begin(), subnets_g.end(), [](const subnet_t &lhs, const subnet_t &rhs) {
                return lhs.utilization > rhs.utilization;
            });
        }
    }
}

void packetCallback(u_char * handle, const struct pcap_pkthdr * header, const u_char * packet) {
    Q_UNUSED(handle);
    Q_UNUSED(header);

    struct ether_header * ethernet = (struct ether_header *) packet;
    struct ip * ip = (struct ip *) (packet + sizeof(struct ether_header));

    // packet should be large enough to contain eth, ip and dhcp headers
    if (ntohs(ip->ip_len) < (ETHER_H_SIZE + IP_H_SIZE + UDP_H_SIZE + sizeof(struct dhcp_packet))) {
        return;
    }

    if (ntohs(ethernet->ether_type) == ETHERTYPE_IP) {
        struct dhcp_packet * dhcp = (struct dhcp_packet *) (packet + ETHER_H_SIZE + IP_H_SIZE + UDP_H_SIZE);

        if (dhcp->magic_cookie != htonl(DHCP_MAGIC_COOKIE)) {
            return;
        }

        // the options are right after the magic cookie set
        const u_char * dhcp_options = packet + ETHER_H_SIZE + IP_H_SIZE + UDP_H_SIZE + sizeof(struct dhcp_packet);
        int16_t dhcp_options_len = (ip->ip_len + ETHER_H_SIZE) - IP_H_SIZE - UDP_H_SIZE - sizeof(struct dhcp_packet);

        for (u_char options_code = dhcp_options[0]; options_code != DHCP_OPTION_END && dhcp_options_len > 0; options_code = dhcp_options[0]) {
            char option_len = dhcp_options[1];

            if (dhcp->op == DHCP_OP_REPLY && option_len == 1 && dhcp_options[2] == DHCPACK && options_code == DHCP_OPTION_MESSAGE_TYPE) {
                addAddress(dhcp->yiaddr);
            }

            dhcp_options += option_len + 2;
            dhcp_options_len -= option_len + 2;
        }
    }

    if (stdscr != nullptr) {
        ncurseWindowPrint();
    }
}

pcap_t * openPcapFile(std::string filename) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * handle;

    handle = pcap_open_offline(filename.c_str(), errbuf);
    if (handle == nullptr) {
        exitWithError("pcap_open_offline: " + std::string{errbuf});
    }

    return handle;
}

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
    std::signal(SIGINT, handleExit);

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

    // live mode, '-i' argument (interface)
    if (options.mode == 2) {
        initscr(); 
        ncurseWindowPrint();
    }

    pcap_loop(handle, 0, packetCallback, nullptr);

    pcap_close(handle);
    closelog();

    // offline mode, '-r' argument 
    if (options.mode == 1) {
        offlineStatsPrint();
    }
}