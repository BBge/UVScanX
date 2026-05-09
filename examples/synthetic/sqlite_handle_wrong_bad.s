.intel_syntax noprefix
.global _start
.global sqlite3_open
.global sqlite3_close
_start:
    sub rsp, 32
    lea rsi, [rsp+8]          # first sqlite3 **ppDb out slot
    mov rdi, 0
    call sqlite3_open
    lea rsi, [rsp+16]         # second sqlite3 **ppDb out slot
    mov rdi, 0
    call sqlite3_open
    mov rdi, [rsp+16]         # BAD: only close the second db handle
    call sqlite3_close
    mov eax, 60
    syscall
sqlite3_open:
    ret
sqlite3_close:
    ret
