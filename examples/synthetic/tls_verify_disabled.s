.intel_syntax noprefix
.global _start
.global SSL_CTX_set_verify
_start:
    mov rdi, 0x1234
    xor esi, esi              # BAD: arg2 SSL_VERIFY_NONE / 0 disables peer verification
    mov rdx, 0
    call SSL_CTX_set_verify
    mov eax, 60
    syscall
SSL_CTX_set_verify:
    ret
