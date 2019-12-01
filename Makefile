LDLIBS=z -l ssl -lcrypto -lresolv

nfcsnoop: main.o
	$(CXX) $(CXXFLAGS) -o nfcsnoop main.o -l $(LDLIBS)

main.o: pcapng.h
