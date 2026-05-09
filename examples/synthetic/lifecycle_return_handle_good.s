.intel_syntax noprefix
.global _start
.global curl_easy_init
.global curl_easy_cleanup
_start:
    call curl_easy_init
    mov rdi, rax              # GOOD: cleanup consumes the returned handle
    call curl_easy_cleanup
    mov eax, 60
    syscall
curl_easy_init:
    mov rax, 0x1111
    ret
curl_easy_cleanup:
    ret
