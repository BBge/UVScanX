.intel_syntax noprefix
.global _start
.global SSL_get_peer_cert_chain
.global use_cert
_start:
    call SSL_get_peer_cert_chain
    mov rdi, rax            # BAD: returned pointer is used without NULL check
    call use_cert
    mov eax, 60
    syscall
SSL_get_peer_cert_chain:
    xor eax, eax
    ret
use_cert:
    ret
