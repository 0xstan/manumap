.intel_syntax noprefix
.global entry_asm_64
.text

// This program load an executable file in memory. It assumes that most of the 
// job has been done already. It assumes that the binary is already mapped at
// the address in arg1. The section are mapped, we just needed to find the 
// address of LoadLibraryA and GetProcAddress, then build the IAT and the 
// relocation directories. That's all. No export supported, ONLY IAT and 
// relocations. It also call TlsCallBacks and DllMain. The mapped section
// containing our binary must be mapped as RWX.

// Start of the loader, some values like 0x434343... 0x424242... 0x414141...
// are repladced at runtime with appropriate values.
entry_asm_64:
    push rax
    push rcx
    push rdx
    push rbx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    pushfq
    push rbp
    mov rbp, rsp
    sub rsp, 0x40
    mov r8, 0xfffffffffffffff0
    and rsp, r8                         // 16 byte align stack
    mov rcx, 0x4343434343434343
    mov [rbp - 0x18], rcx
    mov rcx, 0x3f8aaa7e                 // GetProcAddress
    call get_addr_from_hash_64
    mov [rbp - 8], rbx                  // Store address of GetProcAddress
    mov rcx, 0x6fffe488                 // LoadLibraryA
    call get_addr_from_hash_64          // Store address of LoadLibraryA
    mov [rbp - 0x10], rbx
    mov rcx, [rbp - 0x18]               // make it arg
    call make_relocations_64
    mov r8, [rbp - 8]                   // GetProcAddress
    mov rdx, [rbp - 0x10]               // LoadLibraryA
    mov rcx, [rbp - 0x18]               // make it arg
    call make_iat_64
    mov rcx, [rbp - 0x18]               // make it arg
    call call_tls_cb_64
    mov rcx, [rbp - 0x18]               // make it arg
    call call_dll_main_64
    leave
    popfq
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbx
    pop rdx
    pop rcx
    pop rax
    mov rcx, 0x4141414141414141         // original rip
    push rcx
    mov rcx, 0x4242424242424242         // original rcx
    ret

// This function simply call entry point of the Dll
call_dll_main_64:
    push rbp
    mov rbp, rsp
    sub rsp, 0x40
    mov [rbp - 8], rcx
    mov rdx, [rbp - 8]      // Get addr base
    mov ecx, [rdx + 0x3c]   //e_lfanew
    add rcx, rdx            // address NT_HEADER
    mov eax, [rcx + 0x28]   // entry point RVA
    add rax, rdx            // addr entry point
    mov r8, 0               // null ptr
    mov rdx, 1              // DLL_PROCESS_ATTACH
    mov rcx, [rbp - 8]
    call rax
    leave 
    ret

// This function call the tls callback of the dll.
call_tls_cb_64:
    push rbp
    mov rbp, rsp
    sub rsp, 0x40
    mov [rbp - 16], rcx         // base addr
    mov rdx, [rbp - 16]         // Get addr base
    mov ecx, [rdx + 0x3c]       //e_lfanew
    add rcx, rdx                // address NT_HEADER
    mov eax, [rcx + 0xd0]       // TLS directory RVA
    cmp eax, 0
    je call_tls_cb_end_64
    add rax, [rbp - 16]         // addr tls directory
    mov rax, [rax + 0x18]       // addr callbacks
    mov [rbp - 8], rax
call_tls_do_tls_64:
    mov rax, [rbp - 8]
    cmp rax, 0
    je call_tls_cb_end_64
    mov rax, [rax]
    cmp rax, 0
    je call_tls_cb_end_64
    mov r8, 0                   // null ptr
    mov rdx, 1                  // DLL_PROCESS_ATTACH
    mov rcx, [rbp - 16]
    call rax                    // Are TLS Callback relocated ? I hope so
    add QWORD PTR [rbp - 8], 8
    jmp call_tls_do_tls_64
call_tls_cb_end_64:
    leave 
    ret

// This function build the IAT 
make_iat_64:
    push rbp
    mov rbp, rsp
    sub rsp, 0x100
    mov [rbp - 72], rcx         //base addr
    mov [rbp - 80], rdx         // LoadLibraryA
    mov [rbp - 88], r8          // GetProcAddress
    mov rdx, [rbp - 72]         // Get addr base
    mov ecx, [rdx + 0x3c]       //e_lfanew
    add rcx, rdx                // address NT_HEADER
    mov eax, [rcx + 0x90]       // import directory RVA
    mov [rbp - 8], rax          // store it
    cmp rax, 0
    je make_iat_end_64
    mov eax, [rcx + 0x94]       // size import directory
    mov [rbp - 16], eax
    mov rax, [rbp - 8]
    add rax, rdx
    mov [rbp - 24], rax         // addr IMAGE_IMPORT_DESCRIPTOR
make_iat_do_descriptor_64:
    mov rax, [rbp - 24]         // addr IMAGE_IMPORT_DESCRIPTOR
    mov ebx, [rax]              // Characteristics
    cmp ebx, 0
    je make_iat_end_64
    mov ecx, [rax + 0xc]        // Name
    add rcx, [rbp - 72]
    call [rbp - 80]             // LoadLibraryA, rcx is already pointing to str
    mov [rbp - 32], rax         // handle loaded
    mov rax, [rbp - 24]
    mov edx, [rax]              // OFT RVA
    mov ecx, [rax + 0x10]       // FT RVA
    add rdx, [rbp - 72]
    add rcx, [rbp - 72]
    cmp rdx, 0
    jne make_iat_skip_64
    mov rdx, rcx
make_iat_skip_64:
    mov [rbp - 40], rdx
    mov [rbp - 48], rcx
make_iat_do_imp_64:             // loop over all imports
    mov rdx, [rbp - 40]
    mov rcx, [rbp - 48]
    mov rdx, [rdx]
    cmp rdx, 0 
    je make_iat_next_descriptor_64
    mov rcx, rdx
    mov r8, 0x8000000000000000  // Check if import is an ordinal or have a name
    and rcx, r8
    cmp rcx, 0
    je make_iat_no_ordinal_64
    and rdx, 0xffff             // value ordinal
    mov rcx, [rbp - 32]         // handle dll
    call [rbp - 88]             // GetProcAddress
    mov rcx, [rbp - 48]
    mov [rcx], rax
    jmp make_iat_next_imp_64
make_iat_no_ordinal_64:
    add rdx, [rbp - 72] 
    add rdx, 2                  // str
    mov rcx, [rbp - 32]         // handle DLL
    call [rbp - 88]             // GetProcAddress
    mov rcx, [rbp - 48]
    mov [rcx], rax
make_iat_next_imp_64:
    add QWORD PTR [rbp - 40], 8 // Increment pointer to next OFT
    add QWORD PTR [rbp - 48], 8 // Increment pointer to next FT
    jmp make_iat_do_imp_64
make_iat_next_descriptor_64:
    add QWORD PTR [rbp - 24], 20// Next descriptor
    jmp make_iat_do_descriptor_64
make_iat_end_64:
    leave
    ret

// This function perform relocations
make_relocations_64:
    push rbp
    mov rbp, rsp
    sub rsp, 0x50
    mov [rbp - 48], rcx
    mov rdx, [rbp - 48]         // Get addr base
    mov ecx, [rdx + 0x3c]       //e_lfanew
    add rcx, rdx                // address NT_HEADER
    mov rax, [rcx + 0x30]       // Image base

    // Store this substraction as it will be used for calculate relocations 
    // patches
    mov [rbp - 8], rdx          // store addr header
    sub [rbp - 8], rax          // sub image original base
    mov eax, [rcx + 0xb0]       // Offset relocation directory RVA
    cmp eax, 0                  // if there's no relocations
    jz end_make_relocations_64
    mov ebx, [rcx + 0xb4]       // Offset relocation directory size
    add rax, rdx                // Offset relocation directory
    mov rcx, rax
    // Store values
    mov [rbp - 16], rcx         // Store offset relocations directory
    mov [rbp - 24], rcx
    add [rbp - 24], rbx         // Store offset end relocations
    // Let's do the relocations 
make_relocations_do_relocations_64:
    mov esi, [rcx]              // reloc entry
    mov edi, [rcx + 4]          // size entry
    mov [rbp - 32], rdi         // this one is the counter that is decremented
    mov [rbp - 40], rdi         // this one help us to find next
    cmp rcx, [rbp - 24]         // if we reach the end of relocation directory
    jae end_make_relocations_64
make_relocation_next_item_64:
    mov rdi, [rbp - 32]
    // edi is size of block, so -2 point to the last entry as item are size 2
    sub rdi, 2              
    mov [rbp - 32], rdi
    // if edi is < 8 we're in the header and we don't want to perform
    // relocations for this block anymore
    cmp rdi, 8
    jb make_relocations_next_block_64
    add rdi, rcx                // rva item
    mov di, [rdi]               // get the item 
    mov bx, di
    shr bx, 0xc                 // ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)
    cmp bx, 0xa                 // IMAGE_REL_BASED_DIR64
    jne make_relocation_next_item_64
    and rdi, 0xfff
    add rdi, [rbp - 48]         // add addr base to get real offset
    add rdi, rsi
    mov rax, [rbp - 8]
    add [rdi], rax              // add the difference ( addr - image_base )
    jmp make_relocation_next_item_64  
    
make_relocations_next_block_64:
    add rcx, [rbp - 40]         // add the size of block to find the next one
    jmp make_relocations_do_relocations_64 
end_make_relocations_64:
    leave
    ret

// Loop over the imports and find address of function by hashs
get_addr_from_hash_64:
    push rbp
    mov rbp, rsp
    sub rsp, 0x20
    mov [rbp - 8], rcx
	mov rdx, gs:[0x60]	    // PEB
	mov rdx, [rdx +  0x18]	// PEB_LDR_DATA
	mov rdx, [rdx +  0x10]	// InMemOrderModuleList
next_mod_64:
	push rdx
	mov rdx, [rdx + 0x30]	// dll_base
	mov eax, [rdx + 0x3c] 	// get e_lfanew
	add rax, rdx			// base_pe_header
	mov eax, [rax + 0x88] 	// offset data dir
	test rax, rax
	jz get_next_mod1_64
	add rax, rdx			// EAT
	push rax
	mov ecx, [rax + 0x18] 	// EAT.NumberOfName
	mov ebx, [rax + 0x20] 	// EAT.AddressOfName
	add rbx, rdx			// AdressOfName

get_next_func_64:
	test rcx, rcx
	jz get_next_mod_64
	dec rcx
	mov esi, [rbx + rcx * 4]
	add rsi, rdx
	mov edi, 0
	
checksum_loop_64:
	xor rax, rax
	lodsb                   // Load byte in al
	rol edi, 7
	add edi, eax
	test al, al
	jnz checksum_loop_64
	cmp edi, [rbp - 8]
	jnz get_next_func_64
	pop rax
	mov ebx, [rax + 0x24]   // Address of name ordinals
	add rbx, rdx			// RVA
	mov cx, [rbx + rcx * 2] // Get good ordinal
	
	mov ebx, [rax + 0x1c]   // Adress of functions
	add rbx, rdx			// RVA
	mov ebx, [rbx + rcx * 4]// RVA
	add rbx, rdx
    leave
    ret
	
get_next_mod_64:
	pop rax
get_next_mod1_64:
	pop rdx
	mov rdx, [rdx]
	jmp next_mod_64
