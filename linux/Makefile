CC=g++-8
CFLAGS=-g --std=c++17
LFLAGS=-lstdc++fs

all: manumap manumap32

manumap: entry.cpp manumap.cpp
	$(CC) $(CFLAGS) $^ -o $@ $(LFLAGS)

manumap32: entry.cpp manumap.cpp
	$(CC) -m32 $(CFLAGS) $^ -o $@ $(LFLAGS)
clean:
	rm manumap manumap32
