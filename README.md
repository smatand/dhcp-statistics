Andrej Smatana xsmata03

19th November 2023

The **dhcp-stats** command displays utilization for each given `IP-PREFIX` of DHCP server. Peacefully exits on `SIGINT` signal. Has a logging mechanism of writing into syslog if 50 %, 80 %, or 100 % of utilization of a prefix exceeded.

Example of sniffing on a network interface for DHCP traffic:
```
./dhcp-stats -i eth0 192.168.0.0/24
```
Example of reading a pcap file:
```
./dhcp-stats -r stats.pcap 192.168.0.0/24
```

Files uploaded:
```
README.md
Makefile
dhcpmonitor.cpp
dhcpmonitor.h
manual.pdf
dhcp-stats.1
```