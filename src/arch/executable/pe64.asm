BITS 64

; --- DOS Header ---
    dw 'MZ'                     ; e_magic
    dw 0                        ; [UNUSED] e_cblp

pe_hdr:                         ; PE Header (Signature)
    dw 'PE'                     ; Signature
    dw 0                        ; Signature (Cont)

; --- Image File Header ---
    dw 0x8664                   ; Machine (x86-64)

code:
symbol:                         ; Overlapping: NumberOfSections and Function Name
    dw 0x01                     ; NumberOfSections
    db 'MessageBoxW', 0         ; The function name we want to import
    times 14-($-symbol) db 0    ; Padding out the Image File Header

    dw opt_hdr_size             ; SizeOfOptionalHeader
    dw 0x22                     ; Characteristics (EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE)

opt_hdr:                        ; Optional Header (PE32+)
    dw 0x020b                   ; Magic (PE32+)
    db 0                        ; MajorLinkerVersion
    db 0                        ; MinorLinkerVersion
    dd code_size                ; SizeOfCode
    dw 0                        ; SizeOfInitializedData
    dw 0                        ; SizeOfInitializedData (Cont)
    dd 0                        ; SizeOfUninitializedData
    dd entry                    ; AddressOfEntryPoint
    dd code                     ; BaseOfCode

; --- Optional Header (NT Additional Fields) ---
    dq 0x000140000000           ; ImageBase
    dd pe_hdr                   ; SectionAlignment (pointing back to PE header)
    dd 0x04                     ; FileAlignment
    dw 0x06                     ; MajorOperatingSystemVersion
    dw 0                        ; MinorOperatingSystemVersion
    dw 0                        ; MajorImageVersion
    dw 0                        ; MinorImageVersion
    dw 0x06                     ; MajorSubsystemVersion
    dw 0                        ; MinorSubsystemVersion
    dd 0                        ; Reserved1
    dd file_size                ; SizeOfImage
    dd hdr_size                 ; SizeOfHeaders
    dd 0                        ; CheckSum
    dw 0x02                     ; Subsystem (Windows GUI)
    dw 0x8160                   ; DllCharacteristics

    dq 0x100000                 ; SizeOfStackReserve
    dq 0x1000                   ; SizeOfStackCommit
    dq 0x100000                 ; SizeOfHeapReserve

dll_name:                       ; Overlapping: DLL Name stored in HeapCommit space
    db 'USER32.dll', 0
    times 12-($-dll_name) db 0  ; Padding

    dd 0x02                     ; NumberOfRvaAndSizes

; --- Data Directories ---
    dd 0, 0                     ; Export Directory (RVA, Size)

iatbl:                          ; Import Address Table
    dd itbl                     ; Import RVA
    dd itbl_size                ; Import Size
iatbl_size equ $-iatbl

opt_hdr_size equ $-opt_hdr

; --- Section Table ---
    section_name db '.', 0
    times 8-($-section_name) db 0
    dd sect_size                ; VirtualSize
    dd iatbl                    ; VirtualAddress
    dd code_size                ; SizeOfRawData
    dd iatbl                    ; PointerToRawData

content:                        ; The message box body text (Unicode: "ABCDEFG")
    db 0x41,0x00,0x42,0x00,0x43,0x00,0x44,0x00
    db 0x45,0x00,0x46,0x00,0x47,0x00,0,0

    times 12 db 0               ; Padding for unused section fields

hdr_size equ $-$$

title:                          ; The message box title (Unicode)
    db 0x3d,0xd8,0xaf,0xdc,0x20,0x00,0x54,0x00
    db 0x69,0x00,0x6e,0x00,0x79,0x00,0x50,0x00
    db 0x45,0x00,0x20,0x00,0x6f,0x00,0x6e,0x00
    db 0x20,0x00,0x57,0x00,0x69,0x00,0x6e,0x00
    db 0x64,0x00,0x6f,0x00,0x77,0x00,0x73,0x00
    db 0x20,0x00,0x31,0x00,0x30,0x00,0,0

; --- Execution Entry Point ---
entry:
    sub rsp, 40                 ; Shadow space for x64 calling convention
    mov r9d, 0x00240040         ; uType (Icon + Buttons)
    lea r8, [rel title]         ; lpCaption
    lea rdx, [rel content]      ; lpText
    xor ecx, ecx                ; hWnd (NULL)
    call [rel iatbl]            ; Indirect call to MessageBoxW via IAT
    add rsp, 40
    ret

; --- Import Tables ---
itbl:                           ; Import Directory Table
    dd intbl                    ; OriginalFirstThunk (Lookup Table)
    dd 0                        ; TimeDateStamp
    dd 0                        ; ForwarderChain
    dd dll_name                 ; Name RVA ("USER32.dll")
    dd iatbl                    ; FirstThunk (IAT)

intbl:                          ; Import Name Table
    dq symbol                   ; Hint/Name Table RVA ("MessageBoxW")
    dq 0                        ; Null terminator

itbl_size equ $-itbl

sect_size equ $-code
code_size equ $-code
file_size equ $-$$
