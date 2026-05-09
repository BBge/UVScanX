.intel_syntax noprefix
.global _start
.global mbedtls_x509_crt_init
.global mbedtls_x509_crt_free
_start:
    lea rdi, [rip+ctx]
    call mbedtls_x509_crt_init
    lea rdi, [rip+ctx]
    call mbedtls_x509_crt_free
    mov eax, 60
    syscall
mbedtls_x509_crt_init:
    ret
mbedtls_x509_crt_free:
    ret
.bss
.lcomm ctx, 256
