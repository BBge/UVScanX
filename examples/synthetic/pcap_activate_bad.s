.intel_syntax noprefix
.global _start
.global pcap_activate
_start:
    call pcap_activate
    test eax, eax
    jne .Lerror             # BAD: positive warning values are not errors; only < 0 is error
    jmp .Ldone
.Lerror:
    mov edi, 1
.Ldone:
    mov eax, 60
    syscall
pcap_activate:
    xor eax, eax
    ret
