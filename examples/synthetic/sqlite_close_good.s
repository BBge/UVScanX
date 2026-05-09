.intel_syntax noprefix
.global _start
.global sqlite3_open
.global sqlite3_close
_start:
    call sqlite3_open
    call sqlite3_close      # GOOD: release database handle
    mov eax, 60
    syscall
sqlite3_open:
    ret
sqlite3_close:
    ret
