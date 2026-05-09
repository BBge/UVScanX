.intel_syntax noprefix
.global _start
.global pcap_activate
_start:
    call pcap_activate
    test eax, eax
    js .Lerror              # GOOD: strict negative means error
    jmp .Ldone
.Lerror:
    mov edi, 1
.Ldone:
    mov eax, 60
    syscall
pcap_activate:
    xor eax, eax
    ret
