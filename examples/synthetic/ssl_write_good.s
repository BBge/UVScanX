.intel_syntax noprefix
.global _start
.global SSL_write
_start:
    call SSL_write
    test eax, eax
    jle .Lerror             # GOOD: <= 0 is handled as error
    jmp .Ldone
.Lerror:
    mov edi, 1
.Ldone:
    mov eax, 60
    syscall
SSL_write:
    xor eax, eax
    ret
