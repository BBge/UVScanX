.intel_syntax noprefix
.global _start
.global sqlite3_open
.global sqlite3_close
_start:
    sub rsp, 16
    lea rsi, [rsp+8]          # sqlite3 **ppDb out slot
    mov rdi, 0
    call sqlite3_open
    mov rdi, [rsp+8]          # GOOD: close the db returned via ppDb
    call sqlite3_close
    mov eax, 60
    syscall
sqlite3_open:
    ret
sqlite3_close:
    ret
