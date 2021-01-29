#ifndef MANUMAP_H
#define MANUMAP_H
#include <filesystem>

#if defined(__LP64__)
const std::string asm_stage1 = 
    ".intel_syntax noprefix\n"
    "do_map:\n"
    "\tpush rax\n"
    "\tpush rbx\n"
    "\tpush rcx\n"
    "\tpush rdx\n"
    "\tpush rdi\n"
    "\tpush rsi\n"
    "\tpush rbp\n"
    "\tpush r8\n"
    "\tpush r9\n"
    "\tpush r10\n"
    "\tpush r11\n"
    "\tpush r12\n"
    "\tpush r13\n"
    "\tpush r14\n"
    "\tpush r15\n"
    "\tpushf\n"
    "\tlea rdi, stage_2_path[rip]\n"
    "\txor rsi, rsi\n"
    "\txor rdx, rdx\n"
    "\tmov rax, 0x2\n"
    "\tsyscall\n"
    "\tmov r15, rax\n"
    "\txor rdi, rdi\n"
    "\tmov rsi, 0x1000\n"
    "\tmov rdx, 0x7\n"
    "\tmov r10, 0x2\n"
    "\tmov r8, r15\n"
    "\txor r9, r9\n"
    "\tmov rax, 0x9\n"
    "\tsyscall\n"
    "\tmov r14, rax\n"
    "\tmov rdi, r15\n"
    "\tmov rax, 0x3\n"
    "\tsyscall\n"
    "\tjmp r14\n"
    "stage_2_path:\n"
    "\t.ascii \"%s\\0\"\n";

const std::string asm_stage2 = 
    ".intel_syntax noprefix\n"
    "map:\n"
    "\tpush rbp\n"
    "\tmov rbp, rsp\n"
    "\tand rsp, -0x10\n"

    // open /proc/self/mem
    "\tlea rdi, proc_self_mem[rip]\n"
    "\tmov rsi, 2\n"
    "\txor rdx, rdx\n"
    "\tmov rax, 2\n"
    "\tsyscall\n"
    "\tmov r15, rax\n"        // fd

    // fseek
    "\tmov rdi, r15\n"    
    "\tmov rsi, %lu\n"
    "\txor rdx, rdx\n" 
    "\tmov rax, 8\n"
    "\tsyscall\n"

    // restore code
    "\tmov rdi, r15\n"
    "\tlea rsi, old_code[rip]\n"
    "\tmov rdx, %lu\n"
    "\tmov rax, 1\n"
    "\tsyscall\n"

    // close fd
    "\tmov rdi, r15\n"
    "\tmov rax, 3\n"
    "\tsyscall\n"

    "\tmov r14, %lu\n"
    "\tlea rdi, lib_path[rip]\n"
    "\tmov rsi, 1\n"
    "\tcall r14\n"

    "\tleave\n"

    "\tpopf\n"
    "\tpop r15\n"
    "\tpop r14\n"
    "\tpop r13\n"
    "\tpop r12\n"
    "\tpop r11\n"
    "\tpop r10\n"
    "\tpop r9\n"
    "\tpop r8\n"
    "\tpop rbp\n"
    "\tpop rsi\n"
    "\tpop rdi\n"
    "\tpop rdx\n"
    "\tpop rcx\n"
    "\tpop rbx\n"
    "\tpop rax\n"
    "\tpush QWORD PTR [rip + orig_rip]\n"
    "\tret\n"

    "orig_rip: .quad %lu\n"
    "proc_self_mem: .ascii \"/proc/self/mem\\0\"\n"
    "old_code: .byte %s\n"
    "lib_path: .ascii \"%s\\0\"\n";

const std::string command_compile_s1 = 
    "gcc -x assembler -o /tmp/stage1.bin -nostdlib"
    " -Wl,--oformat=binary -m64 /tmp/stage1.S";

const std::string command_compile_s2 = 
    "gcc -x assembler -o /tmp/stage2.bin -nostdlib"
    " -Wl,--oformat=binary -m64 /tmp/stage2.S";

#else

const std::string asm_stage1 = 
    ".intel_syntax noprefix\n"
    ".macro get sym\n"
    "call $+5\n"
    "pop eax\n"
    "add eax, \\sym - . + 1\n"
    ".endm\n"

    "do_map:\n"
    "\tpushad\n"
    "\tpushf\n"

    // open stage2
    "\tget stage_2_path\n"
    "\tmov ebx, eax\n"
    "\txor edx, edx\n"
    "\txor ecx, ecx\n"
    "\tmov eax, 0x5\n"
    "\tint 0x80\n"
    "\tmov edi, eax\n"

    // map stage 2
    "\tpush 0\n"
    "\tpush edi\n"
    "\tpush 2\n"
    "\tpush 7\n"
    "\tpush 0x1000\n"
    "\tpush 0\n"
    "\tlea ebx, [esp]\n"
    "\tmov eax, 90\n"
    "\tint 0x80\n"
    "\tlea esp, [esp + 24]\n"
    
    // close fd
    "\tmov esi, eax\n"
    "\tmov ebx, edi\n"
    "\tmov eax, 6\n"
    "\tint 0x80\n"

    // jmp stage 2
    "\tjmp esi\n"
    "stage_2_path:\n"
    "\t.ascii \"%s\\0\"\n";

const std::string asm_stage2 = 
    ".intel_syntax noprefix\n"
    ".macro get sym\n"
    "call $+5\n"
    "pop eax\n"
    "add eax, \\sym - . + 1\n"
    ".endm\n"

    "map:\n"
    "\tpush ebp\n"
    "\tmov ebp, esp\n"

    // open /proc/self/mem
    "\tget proc_self_mem\n"
    "\tmov ebx, eax\n"
    "\tmov ecx, 2\n"
    "\txor edx, edx\n"
    "\tmov eax, 5\n"
    "\tint 0x80\n"
    "\tmov edi, eax\n"        // fd

    // fseek
    "\tmov ebx, edi\n"    
    "\tmov ecx, %lu\n"
    "\txor edx, edx\n" 
    "\tmov eax, 19\n"
    "\tint 0x80\n"

    // restore code
    "\tmov ebx, edi\n"
    "\tget old_code\n"
    "\tmov ecx, eax\n"
    "\tmov edx, %lu\n"
    "\tmov eax, 4\n"
    "\tint 0x80\n"

    // close fd
    "\tmov ebx, edi\n"
    "\tmov eax, 6\n"
    "\tint 0x80\n"

    "\tget lib_path\n"
    "\tmov esi, %lu\n"
    "\tpush 1\n"
    "\tpush eax\n"
    "\tcall esi\n"
    "\tlea esp, [esp + 8]\n"

    "\tleave\n"

    "\tget orig_rip\n"
    "\tmov eax, DWORD PTR [eax]\n"
    "\tmov [esp + 36], eax\n"
    "\tpopf\n"
    "\tpopad\n"
    "\tret\n"

    "orig_rip: .long %lu\n"
    "proc_self_mem: .ascii \"/proc/self/mem\\0\"\n"
    "old_code: .byte %s\n"
    "lib_path: .ascii \"%s\\0\"\n";

const std::string command_compile_s1 = 
    "gcc -x assembler -o /tmp/stage1.bin -nostdlib"
    " -Wl,--oformat=binary -m32 /tmp/stage1.S";

const std::string command_compile_s2 = 
    "gcc -x assembler -o /tmp/stage2.bin -nostdlib"
    " -Wl,--oformat=binary -m32 /tmp/stage2.S";
#endif


class Manumap
{
    public:
        // Constructor
        Manumap( char*, char*, char* );

        // This method is the only one to call to inject in the dll.
        void inject( void );
    private:
        // pid of the target process
        int pid;

        // saved registers from stopped process
        unsigned long rip;
        unsigned long rsp;

        // size of stage 1 in bytes. 
        unsigned long stage_1_sz;

        // address of dl_open, TODO: retrieve this from disk ffs
        unsigned long dl_open_addr;

        // Binary bytes
        std::vector<uint8_t> old_code;
        
        // Path of the injected exe
        std::filesystem::path path;

        void stop_process(void);
        void cont_process(void);
        void assemble_stage_1(void);
        void assemble_stage_2(void);
        void read_syscall(void);
        void override_rip();
        
};
#endif
