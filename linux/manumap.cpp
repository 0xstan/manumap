#include <algorithm>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <filesystem>
#include <iostream>
#include <fstream>

#include "manumap.hpp"

Manumap::Manumap(
    char* dl_open_addr_s,
    char* pid, 
    char* path
)
{
    this->dl_open_addr = strtoul(dl_open_addr_s, nullptr, 16);
    this->pid = strtol(pid, nullptr, 10);
    this->path = std::filesystem::absolute(path);

    if ( !std::filesystem::exists(this->path) ) 
    {
        throw std::runtime_error("Error: Can't find file to inject.\n");
    }

    if ( !std::filesystem::exists(
            "/proc/" + std::to_string(this->pid) + "/cmdline") ) 
    {
        throw std::runtime_error("Error: Can't find process.\n");
    }
}

void Manumap::stop_process()
{
    if ( kill(this->pid, SIGSTOP) )
    {
        throw std::runtime_error("Error: Can't stop process.\n");
    }
}

void Manumap::cont_process()
{
    if ( kill(this->pid, SIGCONT) )
    {
        throw std::runtime_error("Error: Can't stop process.\n");
    }
}

void Manumap::assemble_stage_1()
{

        FILE * stage_1_file = fopen("/tmp/stage1.S", "w");
        fprintf(stage_1_file, asm_stage1.c_str(), "/tmp/stage2.bin"); 
        fclose(stage_1_file);
        system(command_compile_s1.c_str());

        FILE * stage_1_bin = fopen("/tmp/stage1.bin", "r");
        fseek(stage_1_bin, 0, SEEK_END);
        this->stage_1_sz = ftell(stage_1_bin);
        fclose(stage_1_bin);
}

void Manumap::assemble_stage_2()
{
    std::stringstream old_code_str("");
    for (auto b : this->old_code)
    {
        old_code_str << "0x" << std::hex << (int)b << ","; 
    }
    old_code_str << "0"; 

    FILE * stage_1_file = fopen("/tmp/stage2.S", "w");
    fprintf(
        stage_1_file, 
        asm_stage2.c_str(), 
        this->rip,
        this->stage_1_sz,
        this->dl_open_addr,
        this->rip,
        old_code_str.str().c_str(),
        this->path.c_str());

    fclose(stage_1_file);

    system(command_compile_s2.c_str());

}

void Manumap::read_syscall()
{
    std::string s;
    std::stringstream ss;
    std::vector<std::string> items;
    std::string item;

    std::ifstream f("/proc/" + std::to_string(this->pid) + "/syscall");

    // Reading the line
    getline(f, s, '\n');

    // Assert process is not running, it shouldn't 
    if (!s.compare("running"))
    {
        throw std::runtime_error("Error: Process is running!.\n");
    }

    ss << s;

    // split line
    while ( std::getline(ss, item, ' '))
    {
        items.push_back(item);
    }
    
    // RSP and RIP are the last values of the line
    this->rsp = strtoul(items[items.size() - 2].c_str(), 0, 16);
    this->rip = strtoul(items[items.size() - 1].c_str(), 0, 16);

    printf("RIP is %lx, RSP is %lx\n", this->rip, this->rsp);

    std::ifstream mem("/proc/" + std::to_string(this->pid) + "/mem");
    mem.seekg(this->rip, std::ios::beg);
    this->old_code.resize(this->stage_1_sz);

    mem.read(((char*)&this->old_code[0]), this->old_code.size());
    mem.close();

}

void Manumap::override_rip()
{
    std::vector<uint8_t> stage_1_b(this->stage_1_sz);

    std::ifstream f("/tmp/stage1.bin");
    f.read((char*)&stage_1_b[0], this->stage_1_sz);
    f.close();

    std::ofstream mem("/proc/" + std::to_string(this->pid) + "/mem");

    mem.seekp(this->rip, std::ios::beg); 
    mem.write((char*)&stage_1_b[0], this->stage_1_sz);
    mem.close();
}

void Manumap::inject()
{

    // Stop the target process
    stop_process();

    // Stage 1 is as short as possible, it map some RWX memory and copy stage 2
    // in it (from disk). Stage1 is written directly at RIP, this is why it 
    // must be short
    assemble_stage_1();

    // We then read /proc/pid/syscall to find out where the process has been
    // stopped
    read_syscall();

    // Stage 2 restore code at rip then call dl_open to load our library 
    // it then restore registers, and jump back to original code
    assemble_stage_2();

    // We override RIP with stage 1
    override_rip();

    // Then we continue process!
    cont_process();

    return;
}
