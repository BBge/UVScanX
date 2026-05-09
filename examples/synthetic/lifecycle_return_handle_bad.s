.intel_syntax noprefix
.global _start
.global curl_easy_init
_start:
    call curl_easy_init       # BAD: returned handle is never cleaned up
    mov eax, 60
    syscall
curl_easy_init:
    mov rax, 0x1111
    ret
