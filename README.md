# manumap

Simple tool that helps you inject library in process (win + linux)

## compilation

make

## usage 

### linux 

Usage: `./manumap dl_open_addr PID path_so_to_inject`, where `dl_open_addr` is 
the address of `dl_open` in the running process, `PID` the pid of target
process and `path_so_to_inject` the path of the library to be injected.
Obviously it does not work for static binaries as `dl_open` will not be 
accessible in the process.

### windows

Usage: `./manumap.exe pid path_dll_to_inject` where `pid` is the pid of 
target process and `path_dll_to_inject` the path of the dll to be injected.
