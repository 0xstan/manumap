#include <iostream>
#include <experimental/filesystem>
#include <windows.h>

#include "manumap.hpp"

int main( int argc, char** argv )
{
    if ( argc != 3 )
    {
        std::throw_with_nested(
            std::runtime_error(
                "Error: wrong usage."
                "Usage: ./manumap.exe <pid> <path_dll_to_inject>\n"
            )
        );
    }

    manumap m(argv[1], argv[2]);
    m.inject();

    return 0;
}
