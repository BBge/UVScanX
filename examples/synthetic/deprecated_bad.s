.intel_syntax noprefix
.global _start
.global RAND_pseudo_bytes
_start:
    call RAND_pseudo_bytes  # BAD: deprecated OpenSSL API
    mov eax, 60
    syscall
RAND_pseudo_bytes:
    ret
