.intel_syntax noprefix
.global _start
.global demo_arg_api
_start:
    mov edi, 1              # BAD: first argument should be 0
    call demo_arg_api
    mov eax, 60
    syscall
demo_arg_api:
    ret
