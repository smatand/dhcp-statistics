#include <iostream>
#include <vector>
#include <string>
#include <unistd.h>

#include <arpa/inet.h>

/** Subnet */
typedef struct Subnet {
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
                // todo: check for its existence
                // todo: check what is it for?
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

int main(int argc, char * argv[]) {
    options_t options = parseOptions(argc, argv);

    if (!options.filename.empty()) {
        std::cout << "File: " << options.filename << std::endl;
    }
    if (!options.interface.empty()) {
        std::cerr << "Interface: " << options.interface << std::endl;
    }
    for (auto prefix : options.prefixes) {
        std::cout << "Prefix: " << inet_ntoa(prefix.address) << "/" << prefix.mask << std::endl;
    }

}