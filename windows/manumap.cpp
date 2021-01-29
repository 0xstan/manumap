#include <exception>
#include <fstream>
#include <stdexcept>
#include <experimental/filesystem>
#include <experimental/bits/fs_ops.h>
#include <windows.h>
#include <tlhelp32.h>
#include <winnt.h>

#include "manumap.hpp"
#include "resource.h"

manumap::manumap(
    char* pid, 
    char* path
)
{
    this->pid = strtol(pid, nullptr, 10);
    this->path = std::experimental::filesystem::path(path); 
    this->c.clear();
    this->alloc = nullptr;
    this->loader = nullptr;
    this->is_64 = 1;
    this->offset_orig_rcx.clear();
    this->offset_orig_rip.clear();
    this->offset_alloc_rcx.clear();
}

void manumap::inject()
{
    this->find_processes();
    this->find_file();
    this->alloc_in_target();
    this->map_loader();
    this->map_file();
    this->find_thread_in_target();
    if ( this->is_64 )
    {
        this->launch_loader64();
    }
    else
    {
        this->launch_loader32();
    }
}

void
manumap::find_processes()
{
    auto snap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );

    if ( snap == INVALID_HANDLE_VALUE )
    {
        throw std::runtime_error("Error: can't get all process handles.\n");
    }

    PROCESSENTRY32 p;
    p.dwSize = sizeof( PROCESSENTRY32 );
    int pid_target = 0;

    if ( !Process32First(snap, &p) )
    {
        throw std::runtime_error("Error: can't find first process.\n");
    }

    do 
    {
        if ( p.th32ProcessID == this->pid )
        {
            pid_target = p.th32ProcessID;
        }
    } while ( !pid_target && Process32Next( snap, &p ));

    CloseHandle( snap );

    if ( !pid_target ) 
    {
        throw 
            std::runtime_error("Error: Can't find target in process list.\n");
    }

    printf("[+] Process found: %d\n", this->pid);
}

void
manumap::find_file()
{
    if ( !std::experimental::filesystem::exists(this->path) ) 
    {
        throw std::runtime_error("Error: Can't find file.\n");
    }
    
    std::ifstream s( 
        this->path.string(), 
        std::ios::binary | std::ios::in 
    );

    s.seekg(0, std::ios::end );
    this->c.resize( s.tellg() );
    s.seekg(0, std::ios::beg );

    s.read(reinterpret_cast<char*>(&this->c[0]), this->c.size());

    if (this->c[0] != 0x4D || this->c[1] != 0x5A ) 
    {
        throw std::runtime_error("Error: Can't find pe header.\n");
    }

    printf("[+] File found: %s\n", this->path.string().c_str());
}

void manumap::alloc_in_target()
{
    long image_size = 0;
    auto dos_h = reinterpret_cast<IMAGE_DOS_HEADER*>(&(this->c[0]));
    auto tmp_h = 
        reinterpret_cast<IMAGE_NT_HEADERS64*>(
            &(this->c[dos_h->e_lfanew])
        );
    if ( tmp_h->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 ) 
    {
        this->is_64 = 0;
    }
    else if ( tmp_h->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64){}
    else
    {
        throw std::runtime_error("Error: Don't recognize arch.\n");
    }

    printf("[+] Arch found: %d\n", (this->is_64) ? 64 : 32);

    if ( this->is_64 )
    {
        auto nt_h = 
            reinterpret_cast<IMAGE_NT_HEADERS64*>(
                &(this->c[dos_h->e_lfanew])
            );
        image_size = nt_h->OptionalHeader.SizeOfImage;
    }
    else 
    {
        auto nt_h = 
            reinterpret_cast<IMAGE_NT_HEADERS32*>(
                &(this->c[dos_h->e_lfanew])
            );
        image_size = nt_h->OptionalHeader.SizeOfImage;
    }

    HANDLE h_p = OpenProcess( PROCESS_ALL_ACCESS, 0, this->pid );
    if ( !h_p )
    {
        throw std::runtime_error("Can't open process.\n");
    }

    this->alloc = VirtualAllocEx(
        h_p,
        0, 
        image_size, 
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_EXECUTE_READWRITE
    );

    if ( !this->alloc )
    {
        throw std::runtime_error("Can't allocate memory in process.\n");
    }

    printf(
        "[+] Allocated %x bytes at %p in target proces for file\n",
        image_size,
        this->alloc);

    HRSRC load;
    if ( this->is_64 )
    {
        load = FindResource(0, MAKEINTRESOURCE( LOAD64 ), RT_RCDATA);
    }
    else 
    {
        load = FindResource(0, MAKEINTRESOURCE( LOAD32 ), RT_RCDATA);
    }

    auto load_res = LoadResource(0, load);
    this->loader_sz = SizeofResource(0, load);

    this->loader= VirtualAllocEx(
        h_p,
        0, 
        this->loader_sz, 
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_EXECUTE_READWRITE
    );

    if ( !this->loader)
    {
        throw std::runtime_error("Can't allocate memory in process.\n");
    }

    printf(
        "[+] Allocated %x bytes at %p in target proces for loader\n",
        this->loader_sz, 
        this->loader);

    FreeResource(load);
    CloseHandle(h_p);

}

void manumap::build_offset32(void* data, long size)
{
    for (int i = 0; i < size - 4; i++)
    {
        if (*(long*)((unsigned char*)data + i) == manumap::pattern_ecx_32)
        {
            this->offset_orig_rcx.push_back(i);
        }
        else if (
            *(long*)
            ((unsigned char*)data + i) == manumap::pattern_eip_32
            )
        {
            this->offset_orig_rip.push_back(i);
        }
        else if (
            *(long*)
            ((unsigned char*)data + i) == manumap::pattern_ecx_alloc_32
            )
        {
            this->offset_alloc_rcx.push_back(i);
        }
    }
}

void manumap::build_offset64(void* data, long size)
{
    for (int i = 0; i < size - 8; i++)
    {
        if (
            *(long long*)
            ((unsigned char*)data + i) == manumap::pattern_ecx_64
            )
        {
            this->offset_orig_rcx.push_back(i);
        }
        else if (
            *(long long*)
            ((unsigned char*)data + i) == manumap::pattern_eip_64
            )
        {
            this->offset_orig_rip.push_back(i);
        }
        else if (
            *(long long*)
            ((unsigned char*)data + i) == manumap::pattern_ecx_alloc_64
            )
        {
            this->offset_alloc_rcx.push_back(i);
        }
    }
}

void manumap::map_loader()
{
    HRSRC load;
    if ( this->is_64 )
    {
        load = FindResource(0, MAKEINTRESOURCE( LOAD64 ), RT_RCDATA);
    }
    else 
    {
        load = FindResource(0, MAKEINTRESOURCE( LOAD32 ), RT_RCDATA);
    }

    auto load_res = LoadResource(0, load);
    auto load_data = LockResource(load_res);

    if ( this->is_64 )
    {
        manumap::build_offset64(load_data, this->loader_sz);
    }
    else 
    {
        manumap::build_offset32(load_data, this->loader_sz);
    }

    HANDLE h_p = OpenProcess( PROCESS_ALL_ACCESS, 0, this->pid );
    if ( !h_p )
    {
        throw std::runtime_error("Can't open process.\n");
    }
    
    if (!WriteProcessMemory(
            h_p, 
            this->loader, 
            load_data, 
            this->loader_sz, 
            NULL))
    {
        throw std::runtime_error("Can't write in process memory.\n");
    }

    printf("[+] Loader successfully written in target process\n");

    FreeResource(load);
    CloseHandle(h_p);
}

void manumap::map_file()
{
    HANDLE h_p = OpenProcess( PROCESS_ALL_ACCESS, 0, this->pid );
    if ( !h_p )
    {
        throw std::runtime_error("Can't open process.\n");
    }

    auto dos_h = reinterpret_cast<IMAGE_DOS_HEADER*>(&(this->c[0])); 
    
    // Don't care about 32 or 64 as NumberOfSections and SizeOptionalHeaders
    // are always at the same offset
    auto nt_h = 
        reinterpret_cast<IMAGE_NT_HEADERS*>(&(this->c[dos_h->e_lfanew])); 

    auto offset_sections = 
        nt_h->FileHeader.SizeOfOptionalHeader + 
        dos_h->e_lfanew + 0x18;

    auto number_sections = nt_h->FileHeader.NumberOfSections;

    for ( int i = 0 ; i < number_sections; i++ )
    {
        auto section = 
            reinterpret_cast<PIMAGE_SECTION_HEADER>(
                &(c[offset_sections])
            );

        if (section->SizeOfRawData)
        {
            if ( 
                !WriteProcessMemory(
                    h_p, 
                    (char*)this->alloc + section->VirtualAddress,
                    &c[section->PointerToRawData],
                    section->SizeOfRawData,
                    NULL
                ) 
            )
            {
                throw std::runtime_error( "Can't write in process memory.\n");
            }
        }

        printf(
            "[+] Successfully written section of size %x at %p\n", 
            section->SizeOfRawData,
            section->VirtualAddress + (char*)this->alloc
        );

        // Seems to be constant in 32 and 64 bits;
        offset_sections += 0x28;
    }

    // Copy headers too !!
    if (
        !WriteProcessMemory(
            h_p, 
            this->alloc,
            &c[0],
            offset_sections - 0x28,
            NULL
        )
    )
    {
        throw std::runtime_error("Can't write in process memory.\n");
    }

    printf(
        "[+] Successfully written headers of size %x at %p\n", 
        offset_sections - 0x28, 
        this->alloc
    );

    CloseHandle(h_p);
}

void manumap::launch_loader32()
{
    BOOL (*p_WOW64GetThreadContext)(HANDLE, PWOW64_CONTEXT);
    BOOL (*p_WOW64SetThreadContext)(HANDLE, PWOW64_CONTEXT);

    HMODULE h_k32 = LoadLibraryA("kernel32.dll");

    p_WOW64GetThreadContext = 
        (BOOL (*)(HANDLE, PWOW64_CONTEXT))
        GetProcAddress(
            h_k32, 
            "Wow64GetThreadContext"
        );

    p_WOW64SetThreadContext = 
        (BOOL (*)(HANDLE, PWOW64_CONTEXT)) 
        GetProcAddress(
            h_k32, 
            "Wow64SetThreadContext"
        );

    if ( !p_WOW64SetThreadContext || !p_WOW64GetThreadContext ) 
    {
        throw std::runtime_error("Can't find WOW64Get/SetThreadContext.\n");
    }

    HANDLE h_t = 
        OpenThread( 
            THREAD_ALL_ACCESS,
            0,
            this->tid
        );

    if ( !h_t )
    {
        throw std::runtime_error("Can't open thread.\n");
    }

    printf("[+] Successfully opened thread %x\n", this->tid);

    HANDLE h_p = OpenProcess( PROCESS_ALL_ACCESS, 0, this->pid );
    if ( !h_p )
    {
        throw std::runtime_error("Can't open process.\n");
    }

    WOW64_CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    long suspend_cnt;

    if ((suspend_cnt = SuspendThread(h_t)) == -1)
    {
        throw std::runtime_error("Can't suspend thread.\n");
    }

    printf("[+] Thread suspended %d\n", suspend_cnt);

    p_WOW64GetThreadContext(h_t, &ctx);

    long saved_eip = ctx.Eip;
    long saved_ecx = ctx.Ecx;
    long alloc_ecx = (long)((long long)this->alloc & 0xffffffff);

    printf("[+] Current eip is at %p\n", ctx.Eip);

    for ( auto off : this->offset_orig_rcx )
    {
        WriteProcessMemory(
            h_p,
            (char*)this->loader + off,
            &saved_ecx, 
            sizeof(long),
            NULL 
        );
    }

    for ( auto off : this->offset_orig_rip )
    {
        WriteProcessMemory(
            h_p,
            (char*)this->loader + off,
            &saved_eip, 
            sizeof(long),
            NULL 
        );
    }

    for ( auto off : this->offset_alloc_rcx )
    {
        WriteProcessMemory(
            h_p,
            (char*)this->loader + off,
            &alloc_ecx, 
            sizeof(long),
            NULL 
        );
    }

    // We don't care as this->loader is 32 bits
    ctx.Eip = (DWORD)((long long)this->loader & 0xffffffff);

    if ( !p_WOW64SetThreadContext(h_t, &ctx) )
    {
        throw std::runtime_error("Failed to change eip to the launcher.\n");
    }

    printf("[+] eip is now at the start of our launcher\n");

    if ((suspend_cnt = ResumeThread(h_t)) == -1)
    {
        throw std::runtime_error("Can't resume thread.\n");
    }

    printf("[+] Thread resumed %d\n", suspend_cnt);
    CloseHandle(h_p);
    CloseHandle(h_t);
}

void manumap::launch_loader64()
{
    HANDLE h_t = 
        OpenThread( 
            THREAD_ALL_ACCESS,
            0,
            this->tid
        );

    if ( !h_t )
    {
        throw std::runtime_error("Can't open thread.\n");
    }

    HANDLE h_p = OpenProcess( PROCESS_ALL_ACCESS, 0, this->pid );
    if ( !h_p )
    {
        throw std::runtime_error("Can't open process.\n");
    }


    printf("[+] Successfully opened thread %x\n", this->tid);

    CONTEXT ctx;

    int suspend_cnt;

    ctx.ContextFlags = CONTEXT_FULL;

    if ((suspend_cnt = SuspendThread(h_t)) == -1)
    {
        throw std::runtime_error("Can't suspend thread.\n");
    }

    printf("[+] Thread suspended %d\n", suspend_cnt);

    if ( !GetThreadContext(h_t, &ctx) )
    {
        throw std::runtime_error("Failed to get thread context.\n");
    }

    printf("[+] Current eip is at %p\n", ctx.Rip);

    long long saved_rip = ctx.Rip;
    long long saved_rcx = ctx.Rcx;
    long long alloc_rcx = (long long)this->alloc;

    for ( auto off : this->offset_orig_rcx )
    {
        WriteProcessMemory(
            h_p,
            (char*)this->loader + off,
            &saved_rcx, 
            sizeof(long long),
            NULL 
        );
    }

    for ( auto off : this->offset_orig_rip )
    {
        WriteProcessMemory(
            h_p,
            (char*)this->loader + off,
            &saved_rip, 
            sizeof(long long),
            NULL 
        );
    }

    for ( auto off : this->offset_alloc_rcx )
    {
        WriteProcessMemory(
            h_p,
            (char*)this->loader + off,
            &alloc_rcx, 
            sizeof(long long),
            NULL 
        );
    }

    ctx.Rip = (unsigned long long)this->loader;

    if ( !SetThreadContext(h_t, &ctx) )
    {
        throw std::runtime_error("Failed to change eip to the launcher.\n");
    }

    printf("[+] eip is now at the start of our launcher\n");

    if ((suspend_cnt = ResumeThread(h_t)) == -1)
    {
        throw std::runtime_error("Can't resume thread.\n");
    }

    printf("[+] Thread resumed %d\n", suspend_cnt);
    CloseHandle(h_p);
    CloseHandle(h_t);
}

void manumap::find_thread_in_target()
{
    auto snap_t = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 ); 
    if ( snap_t == INVALID_HANDLE_VALUE )
    {
        throw std::runtime_error("Error: can't get all thread handles.\n");
    }

    THREADENTRY32 t;
    t.dwSize = sizeof( THREADENTRY32 );
    long t_id = 0;

    if ( !Thread32First(snap_t, &t) )
    {
        throw std::runtime_error("Error: can't find first thread.\n");
    }

    do 
    {
        if ( t.th32OwnerProcessID == this->pid )
        {
            t_id = t.th32ThreadID;
        }
    } while ( !t_id && Thread32Next( snap_t, &t ));

    CloseHandle( snap_t );

    this->tid = t_id;
}
