.intel_syntax noprefix
.global _start
.global mbedtls_x509_crt_init
_start:
    lea rdi, [rip+ctx]
    call mbedtls_x509_crt_init  # BAD: initialized object is never freed
    mov eax, 60
    syscall
mbedtls_x509_crt_init:
    ret
.bss
.lcomm ctx, 256
