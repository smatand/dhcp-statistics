#include <iostream>
#include <vector>
#include <string>
#include <unistd.h>

#include <syslog.h>

// for inet_pton (convert to IPv4)
#include <arpa/inet.h>

// terminal output
#include <ncurses.h>


/** Subnet */
typedef struct Subnet {
    std::string to_print;
    struct in_addr address;
    uint32_t mask;
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
    // a set of prefixes to be monitored
    std::vector<subnet_t> prefixes;
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
                break;
            case 'i':
                options.interface = optarg;
                break;
            default:
                if (optarg[0] == '-') {
                    exitWithError("Unknown option: " + std::string{optarg});
                } else {
                    options.prefixes.push_back(parseNetworkPrefix(optarg));
                }
        }
    }

    if (options.prefixes.empty()) {
        exitWithError("No prefixes specified");
    }

    return options;
}

/** Initialize ncurses */
void initNcurses() {
    initscr();
    cbreak(); // handle the CTRL+C key, but do not buffer input
    noecho(); // do not show any user input
}

/** Print header of ncurses win */
void ncurseHeaderPrint() {
    printw("IP-Prefix\t\tMax-hosts\tAllocated addresses\tUtilization\t\n");
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
 * Ncurses dynamic window 
 * 
 * @param options Options for printing prefixes
 * */
void ncurseWindowPrint(const options_t * options) {
    initNcurses();

    start_color();
    init_pair(1, COLOR_BLACK, COLOR_WHITE);

    attron(COLOR_PAIR(1));
    ncurseHeaderPrint();
    attroff(COLOR_PAIR(1));

    for (const subnet_t &prefix : options->prefixes) {
        printw("%-18s\t%-10d\n", 
            prefix.to_print.c_str(),
            getHostsCount(prefix.mask)
        );
    }
}

int main(int argc, char * argv[]) {
    options_t options = parseOptions(argc, argv);

    int n = 0; // tbd
    while (true) {
        ncurseWindowPrint(&options);
        printw("%d", n);

        sleep(1);
        refresh();
        erase();

        n++; // tbd
    }

    endwin();

    #ifdef DEBUG
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