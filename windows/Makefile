CC=x86_64-w64-mingw32-g++
AS=x86_64-w64-mingw32-g++
AS32=i686-w64-mingw32-g++
RES=x86_64-w64-mingw32-windres
OBJCOPY=x86_64-w64-mingw32-objcopy
OBJCOPY32=i686-w64-mingw32-objcopy

CFLAGS=-static -std=c++17 -I.
LFLAGS=-lstdc++fs

manumap.exe: entry.o manumap.o load.o
	$(CC) $(CFLAGS) $^ -o $@ $(LFLAGS)

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@ $(LFLAGS)

load.o: load32.bin load64.bin
	$(RES) resource.rc $@

load32.bin: load32.S
	$(AS32) -c -m32 -o load32.o $<
	$(OBJCOPY32) -O binary load32.o $@

load64.bin: load64.S
	$(AS) -c -o load64.o $<
	$(OBJCOPY) -O binary load64.o $@

clean:
	rm manumap.exe *.o *.bin
