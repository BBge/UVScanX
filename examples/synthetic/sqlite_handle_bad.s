.intel_syntax noprefix
.global _start
.global sqlite3_open
_start:
    sub rsp, 16
    lea rsi, [rsp+8]          # sqlite3 **ppDb out slot
    mov rdi, 0
    call sqlite3_open         # BAD: db handle is never closed
    mov eax, 60
    syscall
sqlite3_open:
    ret
