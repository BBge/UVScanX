.intel_syntax noprefix
.global _start
.global SSL_CTX_set_verify
_start:
    mov rdi, 0x1234
    mov esi, 1                # OK: non-zero verification mode
    mov rdx, 0
    call SSL_CTX_set_verify
    mov eax, 60
    syscall
SSL_CTX_set_verify:
    ret
