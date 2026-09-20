.include "common.inc"

.global web_socket
.global web_bind
.global web_listen
.global web_accept
.global web_close

.section .text

web_socket:
    mov rax, SYS_SOCKET
    syscall
    ret

web_bind:
    mov rax, SYS_BIND
    syscall
    ret

web_listen:
    mov rax, SYS_LISTEN
    syscall
    ret

web_accept:
    mov rax, SYS_ACCEPT
    syscall
    ret

web_close:
    mov rax, SYS_CLOSE
    syscall
    ret
