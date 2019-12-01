LDLIBS=z -l ssl -lcrypto -lresolv

nfcdump: main.o
	$(CXX) $(CXXFLAGS) -o nfcdump main.o -l $(LDLIBS)

main.o: pcapng.h
