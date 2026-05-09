.intel_syntax noprefix
.global _start
.global ASN1_STRING_to_UTF8
_start:
    call ASN1_STRING_to_UTF8
    test eax, eax
    jle .Lerror             # BAD for this API: zero length is not an error; only < 0 is error
    jmp .Ldone
.Lerror:
    mov edi, 1
.Ldone:
    mov eax, 60
    syscall
ASN1_STRING_to_UTF8:
    xor eax, eax
    ret
