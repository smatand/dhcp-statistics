# Makefile
CXX := g++

CXXFLAGS := -std=c++20 -Wall -Wextra -Werror

OBJECTS := dhcpmonitor.o

.PHONY: clean pack

all: dhcp-stats

dhcp-stats: $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ -lncurses -lpcap

%.o: %.cpp %.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f *.o dhcp_stats

pack: 
	tar -cvf xsmata03.tar *.cpp *.h Makefile manual.pdf dhcp-stats.1