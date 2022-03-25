
# File names
EXENAME = nfqueue
SOURCES = $(wildcard *.cpp)
OBJECTS = $(SOURCES:.cpp=.o)
LDLIBS+= -pthread -latomic -lnfnetlink -lmnl -lnetfilter_queue -levent
CXXFLAGS+= -O2 -Wall -D_GNU_SOURCE -D_DEFAULT_SOURCE -std=c++11

# Main target
$(EXENAME): $(OBJECTS)
	$(CXX) -o $(EXENAME) $(OBJECTS) $(LDLIBS)

# Object files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# To remove generated files
clean:
	rm -f $(EXENAME) $(OBJECTS)
