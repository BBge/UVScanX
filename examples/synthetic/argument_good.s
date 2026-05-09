.intel_syntax noprefix
.global _start
.global demo_arg_api
_start:
    xor edi, edi            # GOOD: first argument is 0
    call demo_arg_api
    mov eax, 60
    syscall
demo_arg_api:
    ret
