CXX = g++
CXXFLAGS = -O2 -Wall -g
LDLIBS = -lpcap

TARGET = tcp-block
OBJS = main.o ethhdr.o ip.o iphdr.o mac.o tcp.o boyer_moore_search.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $<

clean:
	rm -f $(TARGET) $(OBJS)
