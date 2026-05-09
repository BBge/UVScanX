.intel_syntax noprefix
.global _start
.global SSL_new
.global SSL_connect
_start:
    call SSL_new
    call SSL_connect        # BAD: missing SSL_CTX_set_verify after SSL_new and before SSL_connect
    mov eax, 60
    syscall
SSL_new:
    ret
SSL_connect:
    ret
