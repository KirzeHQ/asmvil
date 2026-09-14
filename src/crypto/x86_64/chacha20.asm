.intel_syntax noprefix
.include "common.inc"

# ChaCha20 RFC 8439 for x86-64; see ../chacha20.inc for the API.

.section .text

CHACHA_STATE     = 0
CHACHA_STREAM    = 64
CHACHA_POS       = 128
CHACHA_EXHAUSTED = 136
CHACHA_CTX_SIZE  = 144

.macro ROTL32 reg, left, right
    movdqa xmm8, \reg
    pslld \reg, \left
    psrld xmm8, \right
    por \reg, xmm8
.endm

.macro CHACHA_QR a, b, c, d
    paddd \a, \b
    pxor \d, \a
    ROTL32 \d, 16, 16
    paddd \c, \d
    pxor \b, \c
    ROTL32 \b, 12, 20
    paddd \a, \b
    pxor \d, \a
    ROTL32 \d, 8, 24
    paddd \c, \d
    pxor \b, \c
    ROTL32 \b, 7, 25
.endm

.global chacha20_block
# chacha20_block(rdi=key32, esi=counter, rdx=nonce12, rcx=out64)
chacha20_block:
    sub rsp, 16
    mov DWORD PTR [rsp], esi
    mov rax, QWORD PTR [rdx]
    mov QWORD PTR [rsp + 4], rax
    mov eax, DWORD PTR [rdx + 8]
    mov DWORD PTR [rsp + 12], eax

    movdqa xmm0, XMMWORD PTR [rip + chacha20_constants]
    movdqu xmm1, XMMWORD PTR [rdi]
    movdqu xmm2, XMMWORD PTR [rdi + 16]
    movdqu xmm3, XMMWORD PTR [rsp]
    movdqa xmm4, xmm0
    movdqa xmm5, xmm1
    movdqa xmm6, xmm2
    movdqa xmm7, xmm3
    mov r8d, 10
.Lcb_rounds:
    CHACHA_QR xmm0, xmm1, xmm2, xmm3
    pshufd xmm1, xmm1, 0x39
    pshufd xmm2, xmm2, 0x4e
    pshufd xmm3, xmm3, 0x93
    CHACHA_QR xmm0, xmm1, xmm2, xmm3
    pshufd xmm1, xmm1, 0x93
    pshufd xmm2, xmm2, 0x4e
    pshufd xmm3, xmm3, 0x39
    dec r8d
    jnz .Lcb_rounds

    paddd xmm0, xmm4
    paddd xmm1, xmm5
    paddd xmm2, xmm6
    paddd xmm3, xmm7
    movdqu XMMWORD PTR [rcx], xmm0
    movdqu XMMWORD PTR [rcx + 16], xmm1
    movdqu XMMWORD PTR [rcx + 32], xmm2
    movdqu XMMWORD PTR [rcx + 48], xmm3
    add rsp, 16
    ret

# chacha20_refill(rdi=ctx) -> al.
chacha20_refill:
    push rbx
    mov rbx, rdi
    cmp BYTE PTR [rbx + CHACHA_EXHAUSTED], 0
    jne .Lcr_fail
    lea rdi, [rbx + CHACHA_STATE + 16]
    mov esi, DWORD PTR [rbx + CHACHA_STATE + 48]
    lea rdx, [rbx + CHACHA_STATE + 52]
    lea rcx, [rbx + CHACHA_STREAM]
    call chacha20_block
    mov eax, DWORD PTR [rbx + CHACHA_STATE + 48]
    cmp eax, -1
    je .Lcr_last
    inc eax
    mov DWORD PTR [rbx + CHACHA_STATE + 48], eax
    jmp .Lcr_ready
.Lcr_last:
    mov BYTE PTR [rbx + CHACHA_EXHAUSTED], 1
.Lcr_ready:
    mov QWORD PTR [rbx + CHACHA_POS], 0
    mov eax, 1
    pop rbx
    ret
.Lcr_fail:
    xor eax, eax
    pop rbx
    ret

.global chacha20_init
# chacha20_init(rdi=ctx, rsi=key32, edx=counter, rcx=nonce12)
chacha20_init:
    movdqa xmm0, XMMWORD PTR [rip + chacha20_constants]
    movdqu XMMWORD PTR [rdi + CHACHA_STATE], xmm0
    movdqu xmm0, XMMWORD PTR [rsi]
    movdqu XMMWORD PTR [rdi + CHACHA_STATE + 16], xmm0
    movdqu xmm0, XMMWORD PTR [rsi + 16]
    movdqu XMMWORD PTR [rdi + CHACHA_STATE + 32], xmm0
    mov DWORD PTR [rdi + CHACHA_STATE + 48], edx
    mov rax, QWORD PTR [rcx]
    mov QWORD PTR [rdi + CHACHA_STATE + 52], rax
    mov eax, DWORD PTR [rcx + 8]
    mov DWORD PTR [rdi + CHACHA_STATE + 60], eax
    pxor xmm0, xmm0
    movdqu XMMWORD PTR [rdi + CHACHA_STREAM], xmm0
    movdqu XMMWORD PTR [rdi + CHACHA_STREAM + 16], xmm0
    movdqu XMMWORD PTR [rdi + CHACHA_STREAM + 32], xmm0
    movdqu XMMWORD PTR [rdi + CHACHA_STREAM + 48], xmm0
    mov QWORD PTR [rdi + CHACHA_POS], 64
    mov BYTE PTR [rdi + CHACHA_EXHAUSTED], 0
    ret

.global chacha20_xor
# chacha20_xor(rdi=ctx, rsi=in, rdx=out, rcx=len) -> al.
chacha20_xor:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov rbx, rcx

    mov rax, 64
    sub rax, QWORD PTR [r12 + CHACHA_POS]
    cmp BYTE PTR [r12 + CHACHA_EXHAUSTED], 0
    jne .Lcx_available
    mov ecx, DWORD PTR [r12 + CHACHA_STATE + 48]
    mov rdx, 0x100000000
    sub rdx, rcx
    shl rdx, 6
    add rax, rdx
.Lcx_available:
    cmp rbx, rax
    ja .Lcx_fail

.Lcx_next:
    test rbx, rbx
    jz .Lcx_success
    mov r15, QWORD PTR [r12 + CHACHA_POS]
    cmp r15, 64
    jne .Lcx_buffered
    mov rdi, r12
    call chacha20_refill
    test al, al
    jz .Lcx_fail
    xor r15d, r15d

.Lcx_buffered:
    mov r10, 64
    sub r10, r15
    cmp rbx, r10
    cmovb r10, rbx
    lea r11, [r12 + CHACHA_STREAM]
    add r11, r15
    xor ecx, ecx
.Lcx_bytes:
    mov al, BYTE PTR [r13 + rcx]
    xor al, BYTE PTR [r11 + rcx]
    mov BYTE PTR [r14 + rcx], al
    inc rcx
    cmp rcx, r10
    jb .Lcx_bytes
    add r13, r10
    add r14, r10
    sub rbx, r10
    add r15, r10
    mov QWORD PTR [r12 + CHACHA_POS], r15
    jmp .Lcx_next

.Lcx_success:
    mov eax, 1
    jmp .Lcx_done
.Lcx_fail:
    xor eax, eax
.Lcx_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.section .rodata
.p2align 4
chacha20_constants:
    .ascii "expand 32-byte k"
