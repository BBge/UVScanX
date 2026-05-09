.intel_syntax noprefix
.global _start
.global sqlite3_open
_start:
    call sqlite3_open       # BAD: sqlite3_close is never called
    mov eax, 60
    syscall
sqlite3_open:
    ret
