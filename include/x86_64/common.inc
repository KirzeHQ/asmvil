.intel_syntax noprefix

# Stable public assembly ABI version.
.equ ABI_VERSION_1, 1
.equ ABI_VERSION_2, 2

# Named constants for sys calls (x86-64 Linux)
.equ SYS_READ, 0
.equ SYS_WRITE, 1
.equ SYS_CLOSE, 3
.equ SYS_SOCKET, 41
.equ SYS_ACCEPT, 43
.equ SYS_BIND, 49
.equ SYS_LISTEN, 50
.equ SYS_EXIT, 60
