.intel_syntax noprefix
.include "common.inc"

# Poly1305 RFC 8439 for x86-64; see ../poly1305.inc for the API.

.section .text

POLY_R0        = 0
POLY_R1        = 8
POLY_R2        = 16
POLY_R3        = 24
POLY_R4        = 32
POLY_R1_5      = 40
POLY_R2_5      = 48
POLY_R3_5      = 56
POLY_R4_5      = 64
POLY_H0        = 72
POLY_H1        = 80
POLY_H2        = 88
POLY_H3        = 96
POLY_H4        = 104
POLY_PAD0      = 112
POLY_PAD1      = 116
POLY_PAD2      = 120
POLY_PAD3      = 124
POLY_BUFFER    = 128
POLY_LEFTOVER  = 144
POLY_FINALIZED = 152
POLY_TAG       = 160
POLY_CTX_SIZE  = 176

POLY_MASK26 = 0x3ffffff
POLY_HIBIT  = 0x1000000

.macro POLY_ACC hoff, roff
    mov rax, QWORD PTR [r8 + \hoff]
    imul rax, QWORD PTR [r8 + \roff]
    add rcx, rax
.endm

# poly1305_blocks(ctx,message,count,hibit) requires a nonzero count.
poly1305_blocks:
    sub rsp, 40
    mov r8, rdi
    mov r9, rsi
    mov r10, rdx
    mov r11d, ecx

.Lpb_next:
    mov eax, DWORD PTR [r9]
    and eax, POLY_MASK26
    add QWORD PTR [r8 + POLY_H0], rax
    mov eax, DWORD PTR [r9 + 3]
    shr eax, 2
    and eax, POLY_MASK26
    add QWORD PTR [r8 + POLY_H1], rax
    mov eax, DWORD PTR [r9 + 6]
    shr eax, 4
    and eax, POLY_MASK26
    add QWORD PTR [r8 + POLY_H2], rax
    mov eax, DWORD PTR [r9 + 9]
    shr eax, 6
    and eax, POLY_MASK26
    add QWORD PTR [r8 + POLY_H3], rax
    mov eax, DWORD PTR [r9 + 12]
    shr eax, 8
    or eax, r11d
    add QWORD PTR [r8 + POLY_H4], rax

    xor ecx, ecx
    POLY_ACC POLY_H0, POLY_R0
    POLY_ACC POLY_H1, POLY_R4_5
    POLY_ACC POLY_H2, POLY_R3_5
    POLY_ACC POLY_H3, POLY_R2_5
    POLY_ACC POLY_H4, POLY_R1_5
    mov QWORD PTR [rsp], rcx

    xor ecx, ecx
    POLY_ACC POLY_H0, POLY_R1
    POLY_ACC POLY_H1, POLY_R0
    POLY_ACC POLY_H2, POLY_R4_5
    POLY_ACC POLY_H3, POLY_R3_5
    POLY_ACC POLY_H4, POLY_R2_5
    mov QWORD PTR [rsp + 8], rcx

    xor ecx, ecx
    POLY_ACC POLY_H0, POLY_R2
    POLY_ACC POLY_H1, POLY_R1
    POLY_ACC POLY_H2, POLY_R0
    POLY_ACC POLY_H3, POLY_R4_5
    POLY_ACC POLY_H4, POLY_R3_5
    mov QWORD PTR [rsp + 16], rcx

    xor ecx, ecx
    POLY_ACC POLY_H0, POLY_R3
    POLY_ACC POLY_H1, POLY_R2
    POLY_ACC POLY_H2, POLY_R1
    POLY_ACC POLY_H3, POLY_R0
    POLY_ACC POLY_H4, POLY_R4_5
    mov QWORD PTR [rsp + 24], rcx

    xor ecx, ecx
    POLY_ACC POLY_H0, POLY_R4
    POLY_ACC POLY_H1, POLY_R3
    POLY_ACC POLY_H2, POLY_R2
    POLY_ACC POLY_H3, POLY_R1
    POLY_ACC POLY_H4, POLY_R0
    mov QWORD PTR [rsp + 32], rcx

    mov rax, QWORD PTR [rsp]
    mov rcx, rax
    shr rcx, 26
    and eax, POLY_MASK26
    mov QWORD PTR [r8 + POLY_H0], rax
    mov rax, QWORD PTR [rsp + 8]
    add rax, rcx
    mov rcx, rax
    shr rcx, 26
    and eax, POLY_MASK26
    mov QWORD PTR [r8 + POLY_H1], rax
    mov rax, QWORD PTR [rsp + 16]
    add rax, rcx
    mov rcx, rax
    shr rcx, 26
    and eax, POLY_MASK26
    mov QWORD PTR [r8 + POLY_H2], rax
    mov rax, QWORD PTR [rsp + 24]
    add rax, rcx
    mov rcx, rax
    shr rcx, 26
    and eax, POLY_MASK26
    mov QWORD PTR [r8 + POLY_H3], rax
    mov rax, QWORD PTR [rsp + 32]
    add rax, rcx
    mov rcx, rax
    shr rcx, 26
    and eax, POLY_MASK26
    mov QWORD PTR [r8 + POLY_H4], rax
    lea rcx, [rcx + rcx*4]
    add QWORD PTR [r8 + POLY_H0], rcx
    mov rax, QWORD PTR [r8 + POLY_H0]
    mov rcx, rax
    shr rcx, 26
    and eax, POLY_MASK26
    mov QWORD PTR [r8 + POLY_H0], rax
    add QWORD PTR [r8 + POLY_H1], rcx

    add r9, 16
    dec r10
    jnz .Lpb_next

    pxor xmm0, xmm0
    movdqu XMMWORD PTR [rsp], xmm0
    movdqu XMMWORD PTR [rsp + 16], xmm0
    mov QWORD PTR [rsp + 32], 0
    add rsp, 40
    ret

.global poly1305_init
# poly1305_init(rdi=ctx, rsi=key32)
poly1305_init:
    mov eax, DWORD PTR [rsi]
    and eax, POLY_MASK26
    mov QWORD PTR [rdi + POLY_R0], rax
    mov eax, DWORD PTR [rsi + 3]
    shr eax, 2
    and eax, 0x3ffff03
    mov QWORD PTR [rdi + POLY_R1], rax
    mov eax, DWORD PTR [rsi + 6]
    shr eax, 4
    and eax, 0x3ffc0ff
    mov QWORD PTR [rdi + POLY_R2], rax
    mov eax, DWORD PTR [rsi + 9]
    shr eax, 6
    and eax, 0x3f03fff
    mov QWORD PTR [rdi + POLY_R3], rax
    mov eax, DWORD PTR [rsi + 12]
    shr eax, 8
    and eax, 0x000fffff
    mov QWORD PTR [rdi + POLY_R4], rax

    mov rax, QWORD PTR [rdi + POLY_R1]
    lea rax, [rax + rax*4]
    mov QWORD PTR [rdi + POLY_R1_5], rax
    mov rax, QWORD PTR [rdi + POLY_R2]
    lea rax, [rax + rax*4]
    mov QWORD PTR [rdi + POLY_R2_5], rax
    mov rax, QWORD PTR [rdi + POLY_R3]
    lea rax, [rax + rax*4]
    mov QWORD PTR [rdi + POLY_R3_5], rax
    mov rax, QWORD PTR [rdi + POLY_R4]
    lea rax, [rax + rax*4]
    mov QWORD PTR [rdi + POLY_R4_5], rax

    mov eax, DWORD PTR [rsi + 16]
    mov DWORD PTR [rdi + POLY_PAD0], eax
    mov eax, DWORD PTR [rsi + 20]
    mov DWORD PTR [rdi + POLY_PAD1], eax
    mov eax, DWORD PTR [rsi + 24]
    mov DWORD PTR [rdi + POLY_PAD2], eax
    mov eax, DWORD PTR [rsi + 28]
    mov DWORD PTR [rdi + POLY_PAD3], eax

    pxor xmm0, xmm0
    movdqu XMMWORD PTR [rdi + POLY_H0], xmm0
    movdqu XMMWORD PTR [rdi + POLY_H2], xmm0
    mov QWORD PTR [rdi + POLY_H4], 0
    movdqu XMMWORD PTR [rdi + POLY_BUFFER], xmm0
    mov QWORD PTR [rdi + POLY_LEFTOVER], 0
    mov BYTE PTR [rdi + POLY_FINALIZED], 0
    movdqu XMMWORD PTR [rdi + POLY_TAG], xmm0
    ret

.global poly1305_update
# poly1305_update(rdi=ctx, rsi=message, rdx=len) -> al.
poly1305_update:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rsi
    mov rbx, rdx
    cmp BYTE PTR [r12 + POLY_FINALIZED], 0
    jne .Lpu_fail
    mov r14, QWORD PTR [r12 + POLY_LEFTOVER]
    test rbx, rbx
    jz .Lpu_store
    test r14, r14
    jz .Lpu_direct

    mov rax, 16
    sub rax, r14
    cmp rbx, rax
    cmovb rax, rbx
    lea r15, [r12 + POLY_BUFFER]
    add r15, r14
    xor ecx, ecx
.Lpu_pending_copy:
    mov r11b, BYTE PTR [r13 + rcx]
    mov BYTE PTR [r15 + rcx], r11b
    inc rcx
    cmp rcx, rax
    jb .Lpu_pending_copy
    add r13, rax
    sub rbx, rax
    add r14, rax
    cmp r14, 16
    jne .Lpu_store
    mov rdi, r12
    lea rsi, [r12 + POLY_BUFFER]
    mov edx, 1
    mov ecx, POLY_HIBIT
    call poly1305_blocks
    xor r14d, r14d

.Lpu_direct:
    mov r15, rbx
    shr r15, 4
    test r15, r15
    jz .Lpu_tail
    mov rdi, r12
    mov rsi, r13
    mov rdx, r15
    mov ecx, POLY_HIBIT
    call poly1305_blocks
    mov rax, r15
    shl rax, 4
    add r13, rax
    sub rbx, rax

.Lpu_tail:
    test rbx, rbx
    jz .Lpu_store
    xor ecx, ecx
.Lpu_tail_copy:
    mov r11b, BYTE PTR [r13 + rcx]
    mov BYTE PTR [r12 + POLY_BUFFER + rcx], r11b
    inc rcx
    cmp rcx, rbx
    jb .Lpu_tail_copy
    mov r14, rbx

.Lpu_store:
    mov QWORD PTR [r12 + POLY_LEFTOVER], r14
    mov eax, 1
    jmp .Lpu_done
.Lpu_fail:
    xor eax, eax
.Lpu_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.global poly1305_final
# poly1305_final(rdi=ctx, rsi=tag16) -> al.
poly1305_final:
    push rbx
    push r12
    push r13
    sub rsp, 64
    mov r12, rdi
    mov r13, rsi
    cmp BYTE PTR [r12 + POLY_FINALIZED], 0
    jne .Lpf_cached

    mov rax, QWORD PTR [r12 + POLY_LEFTOVER]
    test rax, rax
    jz .Lpf_normalize
    mov BYTE PTR [r12 + POLY_BUFFER + rax], 1
    inc rax
.Lpf_zero_tail:
    cmp rax, 16
    jae .Lpf_partial_ready
    mov BYTE PTR [r12 + POLY_BUFFER + rax], 0
    inc rax
    jmp .Lpf_zero_tail
.Lpf_partial_ready:
    mov rdi, r12
    lea rsi, [r12 + POLY_BUFFER]
    mov edx, 1
    xor ecx, ecx
    call poly1305_blocks
    mov QWORD PTR [r12 + POLY_LEFTOVER], 0

.Lpf_normalize:
    mov rax, QWORD PTR [r12 + POLY_H1]
    mov rcx, rax
    shr rcx, 26
    and eax, POLY_MASK26
    mov QWORD PTR [r12 + POLY_H1], rax
    add QWORD PTR [r12 + POLY_H2], rcx
    mov rax, QWORD PTR [r12 + POLY_H2]
    mov rcx, rax
    shr rcx, 26
    and eax, POLY_MASK26
    mov QWORD PTR [r12 + POLY_H2], rax
    add QWORD PTR [r12 + POLY_H3], rcx
    mov rax, QWORD PTR [r12 + POLY_H3]
    mov rcx, rax
    shr rcx, 26
    and eax, POLY_MASK26
    mov QWORD PTR [r12 + POLY_H3], rax
    add QWORD PTR [r12 + POLY_H4], rcx
    mov rax, QWORD PTR [r12 + POLY_H4]
    mov rcx, rax
    shr rcx, 26
    and eax, POLY_MASK26
    mov QWORD PTR [r12 + POLY_H4], rax
    lea rcx, [rcx + rcx*4]
    add QWORD PTR [r12 + POLY_H0], rcx
    mov rax, QWORD PTR [r12 + POLY_H0]
    mov rcx, rax
    shr rcx, 26
    and eax, POLY_MASK26
    mov QWORD PTR [r12 + POLY_H0], rax
    add QWORD PTR [r12 + POLY_H1], rcx

    mov r8, QWORD PTR [r12 + POLY_H0]
    mov r9, QWORD PTR [r12 + POLY_H1]
    mov r10, QWORD PTR [r12 + POLY_H2]
    mov r11, QWORD PTR [r12 + POLY_H3]
    mov rbx, QWORD PTR [r12 + POLY_H4]

    mov rax, r8
    add rax, 5
    mov rcx, rax
    shr rcx, 26
    and eax, POLY_MASK26
    mov QWORD PTR [rsp], rax
    mov rax, r9
    add rax, rcx
    mov rcx, rax
    shr rcx, 26
    and eax, POLY_MASK26
    mov QWORD PTR [rsp + 8], rax
    mov rax, r10
    add rax, rcx
    mov rcx, rax
    shr rcx, 26
    and eax, POLY_MASK26
    mov QWORD PTR [rsp + 16], rax
    mov rax, r11
    add rax, rcx
    mov rcx, rax
    shr rcx, 26
    and eax, POLY_MASK26
    mov QWORD PTR [rsp + 24], rax
    mov rax, rbx
    add rax, rcx
    sub rax, 0x4000000
    mov QWORD PTR [rsp + 32], rax
    mov rcx, rax
    shr rcx, 63
    sub rcx, 1

    mov rax, QWORD PTR [rsp]
    xor rax, r8
    and rax, rcx
    xor r8, rax
    mov rax, QWORD PTR [rsp + 8]
    xor rax, r9
    and rax, rcx
    xor r9, rax
    mov rax, QWORD PTR [rsp + 16]
    xor rax, r10
    and rax, rcx
    xor r10, rax
    mov rax, QWORD PTR [rsp + 24]
    xor rax, r11
    and rax, rcx
    xor r11, rax
    mov rax, QWORD PTR [rsp + 32]
    xor rax, rbx
    and rax, rcx
    xor rbx, rax

    mov rax, r9
    shl rax, 26
    or rax, r8
    mov DWORD PTR [rsp + 40], eax
    mov rax, r9
    shr rax, 6
    mov rdx, r10
    shl rdx, 20
    or rax, rdx
    mov DWORD PTR [rsp + 44], eax
    mov rax, r10
    shr rax, 12
    mov rdx, r11
    shl rdx, 14
    or rax, rdx
    mov DWORD PTR [rsp + 48], eax
    mov rax, r11
    shr rax, 18
    mov rdx, rbx
    shl rdx, 8
    or rax, rdx
    mov DWORD PTR [rsp + 52], eax

    mov r8d, DWORD PTR [rsp + 40]
    mov r9d, DWORD PTR [rsp + 44]
    mov r10d, DWORD PTR [rsp + 48]
    mov r11d, DWORD PTR [rsp + 52]
    add r8d, DWORD PTR [r12 + POLY_PAD0]
    adc r9d, DWORD PTR [r12 + POLY_PAD1]
    adc r10d, DWORD PTR [r12 + POLY_PAD2]
    adc r11d, DWORD PTR [r12 + POLY_PAD3]

    pxor xmm0, xmm0
    movdqu XMMWORD PTR [r12], xmm0
    movdqu XMMWORD PTR [r12 + 16], xmm0
    movdqu XMMWORD PTR [r12 + 32], xmm0
    movdqu XMMWORD PTR [r12 + 48], xmm0
    movdqu XMMWORD PTR [r12 + 64], xmm0
    movdqu XMMWORD PTR [r12 + 80], xmm0
    movdqu XMMWORD PTR [r12 + 96], xmm0
    movdqu XMMWORD PTR [r12 + 112], xmm0
    movdqu XMMWORD PTR [r12 + 128], xmm0
    mov QWORD PTR [r12 + POLY_LEFTOVER], 0
    mov BYTE PTR [r12 + POLY_FINALIZED], 1
    mov DWORD PTR [r12 + POLY_TAG], r8d
    mov DWORD PTR [r12 + POLY_TAG + 4], r9d
    mov DWORD PTR [r12 + POLY_TAG + 8], r10d
    mov DWORD PTR [r12 + POLY_TAG + 12], r11d
    mov DWORD PTR [r13], r8d
    mov DWORD PTR [r13 + 4], r9d
    mov DWORD PTR [r13 + 8], r10d
    mov DWORD PTR [r13 + 12], r11d
    jmp .Lpf_success

.Lpf_cached:
    movdqu xmm0, XMMWORD PTR [r12 + POLY_TAG]
    movdqu XMMWORD PTR [r13], xmm0

.Lpf_success:
    pxor xmm0, xmm0
    movdqu XMMWORD PTR [rsp], xmm0
    movdqu XMMWORD PTR [rsp + 16], xmm0
    movdqu XMMWORD PTR [rsp + 32], xmm0
    movdqu XMMWORD PTR [rsp + 48], xmm0
    mov eax, 1
    add rsp, 64
    pop r13
    pop r12
    pop rbx
    ret

.global poly1305_verify
# poly1305_verify(rdi=ctx, rsi=candidate16) -> al.
poly1305_verify:
    push rbx
    push r12
    push r13
    sub rsp, 16
    mov r12, rdi
    mov r13, rsi
    mov rdi, r12
    mov rsi, rsp
    call poly1305_final
    movdqu xmm0, XMMWORD PTR [rsp]
    movdqu xmm1, XMMWORD PTR [r13]
    pxor xmm0, xmm1
    pxor xmm1, xmm1
    pcmpeqb xmm0, xmm1
    pmovmskb eax, xmm0
    cmp eax, 0xffff
    sete al
    movzx eax, al
    pxor xmm0, xmm0
    movdqu XMMWORD PTR [rsp], xmm0
    add rsp, 16
    pop r13
    pop r12
    pop rbx
    ret
