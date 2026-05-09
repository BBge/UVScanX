.intel_syntax noprefix
.global _start
.global SSL_write
_start:
    call SSL_write
    test eax, eax
    js .Lerror              # BAD: SSL_write also treats 0 as error; should be jle
    jmp .Ldone
.Lerror:
    mov edi, 1
.Ldone:
    mov eax, 60
    syscall
SSL_write:
    xor eax, eax
    ret
