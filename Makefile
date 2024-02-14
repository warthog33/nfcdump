LDLIBS=z  -lresolv -lcrypto 

nfcdump: main.o
	$(CXX) $(CXXFLAGS) -o nfcdump main.o -l $(LDLIBS)

main.o: pcapng.h
