.intel_syntax noprefix
.global _start
.global SSL_get_peer_cert_chain
.global use_cert
_start:
    call SSL_get_peer_cert_chain
    test rax, rax           # GOOD: NULL check exists before use
    je .Ldone
    mov rdi, rax
    call use_cert
.Ldone:
    mov eax, 60
    syscall
SSL_get_peer_cert_chain:
    xor eax, eax
    ret
use_cert:
    ret
