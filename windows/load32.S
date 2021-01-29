.intel_syntax noprefix
.global _entry_asm_32
.text

// This program load an executable file in memory. It assumes that most of the 
// job has been done already. It assumes that the binary is already mapped at
// the address in arg1. The section are mapped, we just needed to find the 
// address of LoadLibraryA and GetProcAddress, then build the IAT and the 
// relocation directories. That's all. No export supported, ONLY IAT and 
// relocations. It also call TlsCallBacks and DllMain. The mapped section
// containing our binary must be mapped as RWX.

// The 64 bits version of this loader is way more commented!!

_entry_asm_32:
    pushad
    pushfd
    push ebp
    mov ebp, esp
    sub esp, 0x20
    mov ecx, 0x43434343
    mov [ebp - 12], ecx     // Store base addr
    push 0x3f8aaa7e         // GetProcAddress
    call get_addr_from_hash_32
    mov [ebp - 4], ebx      // Store address of GetProcAddress
    push 0x6fffe488         // LoadLibraryA
    call get_addr_from_hash_32 
    mov [ebp - 8], ebx
    push [ebp - 12]
    call make_relocations_32   
    push [ebp - 4]          // GetProcAddress
    push [ebp - 8]          // LoadLibraryA
    push [ebp - 12]
    call make_iat_32
    push [ebp - 12]
    call call_tls_cb_32
    push [ebp - 12]
    call call_dll_main_32
    leave
    popfd
    popad
    mov ecx, 0x41414141
    push ecx
    mov ecx, 0x42424242 
    ret

call_dll_main_32:
    push ebp
    mov ebp, esp
    sub esp, 0x20
    mov edx, [ebp + 8]          // Get addr base
    mov ecx, [edx + 0x3c]       //e_lfanew
    add ecx, edx                // address NT_HEADER
    mov eax, [ecx + 0x28]       // entry point RVA
    add eax, edx                // addr entry point
    push 0                      // null ptr
    push 1                      // DLL_PROCESS_ATTACH
    push [ebp + 8]
    call eax
    leave 
    ret 0x4

call_tls_cb_32:
    push ebp
    mov ebp, esp
    sub esp, 0x20
    mov edx, [ebp + 8]          // Get addr base
    mov ecx, [edx + 0x3c]       //e_lfanew
    add ecx, edx                // address NT_HEADER
    mov eax, [ecx + 0xc0]       // TLS directory RVA
    cmp eax, 0
    je call_tls_cb_end_32
    add eax, [ebp + 8]          // addr tls directory
    mov eax, [eax + 0xc]        // addr callbacks
    mov [ebp - 4], eax
call_tls_do_tls_32:
    mov eax, [ebp - 4]
    cmp eax, 0
    je call_tls_cb_end_32
    mov eax, [eax]
    cmp eax, 0
    je call_tls_cb_end_32
    push 0                      // null ptr
    push 1                      // DLL_PROCESS_ATTACH
    push [ebp + 8]
    call eax                    // Are TLS Callback relocated ? I hope so
    add DWORD PTR [ebp - 4], 4
    jmp call_tls_do_tls_32
call_tls_cb_end_32:
    leave 
    ret 0x4
    
make_iat_32:
    push ebp
    mov ebp, esp
    sub esp, 0x20
    mov edx, [ebp + 8]          // Get addr base
    mov ecx, [edx + 0x3c]       // e_lfanew
    add ecx, edx                // address NT_HEADER
    mov eax, [ecx + 0x80]       // import directory RVA
    mov [ebp - 4], eax          // store it
    cmp eax, 0
    je make_iat_end_32
    mov eax, [ecx + 0x84]       // size import directory
    mov [ebp - 8], eax
    mov eax, [ebp - 4]
    add eax, edx
    mov [ebp - 12], eax         // addr IMAGE_IMPORT_DESCRIPTOR
make_iat_do_descriptor_32:
    mov eax, [ebp - 12]         // addr IMAGE_IMPORT_DESCRIPTOR
    mov ebx, [eax]              // Characteristics
    cmp ebx, 0
    je make_iat_end_32
    mov ecx, [eax + 0xc]        // Name
    add ecx, [ebp + 8]
    push ecx
    call [ebp + 12]             // LoadLibraryA
    mov [ebp - 16], eax         // handle loaded
    mov eax, [ebp - 12]
    mov edx, [eax]              // OFT RVA
    mov ecx, [eax + 0x10]       // FT RVA
    add edx, [ebp + 8]
    add ecx, [ebp + 8]
    cmp edx, 0
    jne make_iat_skip_32 
    mov edx, ecx
make_iat_skip_32:
    mov [ebp - 20], edx
    mov [ebp - 24], ecx
make_iat_do_imp_32:
    mov edx, [ebp - 20]
    mov ecx, [ebp - 24]
    mov edx, [edx]
    cmp edx, 0 
    je make_iat_next_descriptor_32
    mov ecx, edx
    and ecx, 0x80000000
    cmp ecx, 0
    je make_iat_no_ordinal_32
    and edx, 0xffff
    push edx
    push [ebp - 16]
    call [ebp + 16]
    mov ecx, [ebp - 24]
    mov [ecx], eax
    jmp make_iat_next_imp_32
make_iat_no_ordinal_32:
    add edx, [ebp + 8] 
    add edx, 2
    push edx
    push [ebp - 16]
    call [ebp + 16]
    mov ecx, [ebp - 24]
    mov [ecx], eax
make_iat_next_imp_32:
    add DWORD PTR [ebp - 20], 4
    add DWORD PTR [ebp - 24], 4
    jmp make_iat_do_imp_32
make_iat_next_descriptor_32:
    add DWORD PTR [ebp - 12], 20
    jmp make_iat_do_descriptor_32
make_iat_end_32:
    leave
    ret 0xc

make_relocations_32:
    push ebp
    mov ebp, esp
    sub esp, 0x20
    mov edx, [ebp + 8]          // Get addr base
    mov ecx, [edx + 0x3c]       //e_lfanew
    add ecx, edx                // address NT_HEADER
    mov eax, [ecx + 0x34]       // Image base

    // Store this substraction as it will be used for calculate relocations 
    // patches
    mov [ebp - 4], edx          // store addr header
    sub [ebp - 4], eax          // sub image original base
    mov eax, [ecx + 0xa0]       // Offset relocation directory RVA
    cmp eax, 0                  // if there's no relocations
    jz end_make_relocations_32
    mov ebx, [ecx + 0xa4]       // Offset relocation directory size
    add eax, edx                // Offset relocation directory
    mov ecx, eax
    // Store values
    mov [ebp - 8], ecx          // Store offset relocations directory
    mov [ebp - 12], ecx
    add [ebp - 12], ebx         // Store offset end relocations
    // Let's do the relocations 
make_relocations_do_relocations_32:
    mov esi, [ecx]              // reloc entry
    mov edi, [ecx + 4]          // size entry
    mov [ebp - 16], edi         // this one is the counter that is decremented
    mov [ebp - 20], edi         // this one help us to find next
    cmp ecx, [ebp - 12]         // if we reach the end of relocation directory
    jae end_make_relocations_32 
make_relocation_next_item_32:
    mov edi, [ebp - 16]
    // edi is size of block, so -2 point to the last entry as item are size 2
    sub edi, 2              
    mov [ebp - 16], edi
    // if edi is < 8 we're in the header and we don't want to perform
    // relocations for this block anymore
    cmp edi, 8
    jb make_relocations_next_block_32
    add edi, ecx                // rva item
    mov di, [edi]               // get the item 
    mov bx, di
    shr bx, 0xc
    cmp bx, 0x3                 // (RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW
    jne make_relocation_next_item_32
    and edi, 0xfff              // and it as the first nibble doesn't count
    add edi, [ebp + 8]          // add addr base to get real offset
    add edi, esi
    mov eax, [ebp - 4]
    add [edi], eax              // add the difference ( addr - image_base )
    jmp make_relocation_next_item_32 
    
make_relocations_next_block_32:
    add ecx, [ebp - 20]         // add the size of block to find the next one
    jmp make_relocations_do_relocations_32
end_make_relocations_32:
    leave
    ret 0x4
     
get_addr_from_hash_32:
	mov edx, fs:[0x30]	    // PEB
	mov edx, [edx +  0xc]	// PEB_LDR_DATA
	mov edx, [edx +  0xc]	// InMemOrderModuleList
next_mod_32:
	push edx
    mov edx, [edx + 0x18]   // dll_base
	mov eax, [edx + 0x3c] 	// get e_lfanew
	add eax, edx			// base_pe_header
	mov eax, [eax + 0x78] 	// offset data dir
	test eax, eax
	jz get_next_mod1_32
	add eax, edx			// EAT
	push eax
	mov ecx, [eax + 0x18] 	// EAT.NumberOfName
	mov ebx, [eax + 0x20] 	// EAT.AddressOfName
	add ebx, edx			// AdressOfName

get_next_func_32:
	test ecx, ecx
	jz get_next_mod_32
	dec ecx
	mov esi, [ebx + ecx * 4]
	add esi, edx
	mov edi, 0
	
checksum_loop_32:
	xor eax, eax
	lodsb                   // Load byte in al
	rol edi, 7
	add edi, eax
	test al, al
	jnz checksum_loop_32
	cmp edi, [esp + 0xc]
	jnz get_next_func_32
	pop eax
	mov ebx, [eax + 0x24]   // Address of name ordinals
	add ebx, edx			// RVA
	mov cx, [ebx + ecx * 2] // Get good ordinal
	
	mov ebx, [eax + 0x1c]   // Adress of functions
	add ebx, edx			// RVA
	mov ebx, [ebx + ecx*4]  // RVA
	add ebx, edx
    pop edx
    ret
	
get_next_mod_32:
	pop eax
get_next_mod1_32:
	pop edx
	mov edx, [edx]
	jmp next_mod_32

