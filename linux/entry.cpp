#include <iostream>
#include <string.h>

#include "manumap.hpp"

int main(int argc, char** argv)
{
    bool do_stop = 0;

    if (argc != 4)
    {
        std::throw_with_nested(
            std::runtime_error(
                "Error: wrong usage.\n"
                "Usage: ./manumap dl_open_addr PID path_exe_to_inject\n"
                //"Where STOP is 0 or 1 ( 1 means the target process is "
                //"SIG_STOPPED).\n"
                "dl_open_addr is the address of dl_open in target process.\n"
                "PID is the target process PID.\n"
                "path_exe_to_inject is a path of a STATIC PIE binary.\n"
            )
        );
    }

    /*if ( !strcmp(argv[1], "1") )
    {
        do_stop = 1; 
    }
    else if ( strcmp(argv[1], "0") )
    {
        std::throw_with_nested(
            std::runtime_error(
                "STOP is not 1 nor 0\n"
            )
        );
    }*/

    
    Manumap m(argv[1], argv[2], argv[3]);
    m.inject();

    return 0;
}
