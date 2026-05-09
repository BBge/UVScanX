.intel_syntax noprefix
.global _start
.global SSL_new
.global SSL_CTX_set_verify
.global SSL_connect
_start:
    call SSL_new
    call SSL_CTX_set_verify # GOOD: verification is configured before handshake
    call SSL_connect
    mov eax, 60
    syscall
SSL_new:
    ret
SSL_CTX_set_verify:
    ret
SSL_connect:
    ret
