.intel_syntax noprefix
.include "common.inc"

# GCM/GMAC SP 800-38D for x86-64; see ../gcm.inc for the API.

.section .text

GCM_KEY      = 0
GCM_H        = 240
GCM_Y        = 256
GCM_J0       = 272
GCM_TAG      = 288
GCM_NR       = 304
GCM_ALEN     = 308
GCM_CLEN     = 316
GCM_CTR      = 324
GCM_PHASE    = 340
GCM_PENDLEN  = 344
GCM_PEND     = 352
GCM_LENBUF   = 368
GCM_CTX_SIZE = 384

GCM_PHASE_AAD     = 0
GCM_PHASE_TEXT    = 1
GCM_PHASE_FINAL   = 2
GCM_PHASE_INVALID = 3

GCM_MAX_AAD  = 0x1fffffffffffffff
GCM_MAX_TEXT = 0x0fffffffe0

.macro GCM_INC_CTR ctx
    mov eax, DWORD PTR [\ctx + GCM_CTR + 12]
    bswap eax
    inc eax
    bswap eax
    mov DWORD PTR [\ctx + GCM_CTR + 12], eax
.endm

# ghash_block(rdi=ctx, rsi=block): update byte-reversed Y with H.
ghash_block:
    movdqu xmm0, XMMWORD PTR [rdi + GCM_Y]
    movdqu xmm4, XMMWORD PTR [rsi]
    pshufb xmm4, XMMWORD PTR [rip + gcm_byteswap]
    pxor xmm0, xmm4

    movdqu xmm3, XMMWORD PTR [rdi + GCM_H]
    movdqa xmm5, xmm0
    pclmulqdq xmm5, xmm3, 0x00
    movdqa xmm6, xmm0
    pclmulqdq xmm6, xmm3, 0x11

    movdqa xmm7, xmm0
    psrldq xmm7, 8
    pxor xmm7, xmm0
    movdqa xmm1, xmm3
    psrldq xmm1, 8
    pxor xmm1, xmm3
    pclmulqdq xmm7, xmm1, 0x00
    pxor xmm7, xmm5
    pxor xmm7, xmm6

    movdqa xmm1, XMMWORD PTR [rip + gcm_reduce_const]
    movdqa xmm2, xmm5
    pclmulqdq xmm2, xmm1, 0x00
    pshufd xmm5, xmm5, 0x4e
    pxor xmm7, xmm2
    pxor xmm7, xmm5

    movdqa xmm2, xmm7
    psllq xmm2, 1
    pclmulqdq xmm2, xmm1, 0x00
    pshufd xmm7, xmm7, 0x4e
    pxor xmm6, xmm7

    movdqa xmm5, xmm6
    pslld xmm5, 1
    psrld xmm6, 31
    pxor xmm2, xmm5
    pshufd xmm6, xmm6, 0x93
    pxor xmm6, xmm2
    movdqu XMMWORD PTR [rdi + GCM_Y], xmm6
    ret

# gcm_absorb(rdi=ctx, rsi=src, rdx=len) -> al=1.
gcm_absorb:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rsi
    mov rbx, rdx
    mov r14, QWORD PTR [r12 + GCM_PENDLEN]

.Labs_next:
    test rbx, rbx
    jz .Labs_store
    test r14, r14
    jnz .Labs_pending
    cmp rbx, 16
    jb .Labs_tail
    mov rdi, r12
    mov rsi, r13
    call ghash_block
    add r13, 16
    sub rbx, 16
    jmp .Labs_next

.Labs_pending:
    mov rax, 16
    sub rax, r14
    cmp rbx, rax
    cmovb rax, rbx
    lea r15, [r12 + GCM_PEND]
    add r15, r14
    xor ecx, ecx
.Labs_pending_copy:
    mov r11b, BYTE PTR [r13 + rcx]
    mov BYTE PTR [r15 + rcx], r11b
    inc rcx
    cmp rcx, rax
    jb .Labs_pending_copy
    add r13, rax
    sub rbx, rax
    add r14, rax
    cmp r14, 16
    jne .Labs_store
    mov rdi, r12
    lea rsi, [r12 + GCM_PEND]
    call ghash_block
    xor r14d, r14d
    jmp .Labs_next

.Labs_tail:
    xor ecx, ecx
.Labs_tail_copy:
    mov r11b, BYTE PTR [r13 + rcx]
    mov BYTE PTR [r12 + GCM_PEND + rcx], r11b
    inc rcx
    cmp rcx, rbx
    jb .Labs_tail_copy
    mov r14, rbx

.Labs_store:
    mov QWORD PTR [r12 + GCM_PENDLEN], r14
    mov eax, 1
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

# gcm_crypt_core(rdi=ctx, rsi=in, rdx=out, rcx=len, r8=ct_src) -> al.
gcm_crypt_core:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, r8
    mov rbx, rcx

    cmp BYTE PTR [r12 + GCM_PHASE], GCM_PHASE_FINAL
    jae .Lcc_fail
    mov rax, QWORD PTR [r12 + GCM_CLEN]
    mov r10, GCM_MAX_TEXT
    cmp rax, r10
    ja .Lcc_fail
    sub r10, rax
    cmp rbx, r10
    ja .Lcc_fail

    cmp BYTE PTR [r12 + GCM_PHASE], GCM_PHASE_TEXT
    je .Lcc_ready
    mov rax, QWORD PTR [r12 + GCM_PENDLEN]
    test rax, rax
    jz .Lcc_aad_flushed
    lea rcx, [r12 + GCM_PEND]
    add rcx, rax
    mov rdx, 16
    sub rdx, rax
.Lcc_aad_pad:
    mov BYTE PTR [rcx], 0
    inc rcx
    dec rdx
    jnz .Lcc_aad_pad
    mov rdi, r12
    lea rsi, [r12 + GCM_PEND]
    call ghash_block
.Lcc_aad_flushed:
    mov QWORD PTR [r12 + GCM_PENDLEN], 0
    mov BYTE PTR [r12 + GCM_PHASE], GCM_PHASE_TEXT

.Lcc_ready:
    add QWORD PTR [r12 + GCM_CLEN], rbx
    test rbx, rbx
    jz .Lcc_success
    cmp QWORD PTR [r12 + GCM_PENDLEN], 0
    jne .Lcc_pending

.Lcc_blocks:
    test rbx, rbx
    jz .Lcc_success
    cmp rbx, 16
    jb .Lcc_tail
    lea rdi, [r12 + GCM_KEY]
    lea rsi, [r12 + GCM_CTR]
    lea rdx, [r12 + GCM_TAG]
    mov ecx, DWORD PTR [r12 + GCM_NR]
    call aes_encrypt
    movdqu xmm0, XMMWORD PTR [r13]
    pxor xmm0, XMMWORD PTR [r12 + GCM_TAG]
    movdqu XMMWORD PTR [r14], xmm0
    mov rdi, r12
    mov rsi, r15
    call ghash_block
    GCM_INC_CTR r12
    add r13, 16
    add r14, 16
    add r15, 16
    sub rbx, 16
    jmp .Lcc_blocks

.Lcc_tail:
    lea rdi, [r12 + GCM_KEY]
    lea rsi, [r12 + GCM_CTR]
    lea rdx, [r12 + GCM_TAG]
    mov ecx, DWORD PTR [r12 + GCM_NR]
    call aes_encrypt
    xor r10d, r10d
.Lcc_tail_loop:
    mov al, BYTE PTR [r13 + r10]
    xor al, BYTE PTR [r12 + GCM_TAG + r10]
    mov BYTE PTR [r14 + r10], al
    mov al, BYTE PTR [r15 + r10]
    mov BYTE PTR [r12 + GCM_PEND + r10], al
    inc r10
    cmp r10, rbx
    jb .Lcc_tail_loop
    mov QWORD PTR [r12 + GCM_PENDLEN], rbx
    jmp .Lcc_success

.Lcc_pending:
    lea rdi, [r12 + GCM_KEY]
    lea rsi, [r12 + GCM_CTR]
    lea rdx, [r12 + GCM_TAG]
    mov ecx, DWORD PTR [r12 + GCM_NR]
    call aes_encrypt
    mov r11, QWORD PTR [r12 + GCM_PENDLEN]
    mov r10, 16
    sub r10, r11
    cmp rbx, r10
    cmovb r10, rbx
    lea r8, [r12 + GCM_TAG]
    add r8, r11
    lea r9, [r12 + GCM_PEND]
    add r9, r11
    xor ecx, ecx
.Lcc_pending_loop:
    mov dl, BYTE PTR [r13 + rcx]
    xor dl, BYTE PTR [r8 + rcx]
    mov BYTE PTR [r14 + rcx], dl
    mov al, BYTE PTR [r15 + rcx]
    mov BYTE PTR [r9 + rcx], al
    inc rcx
    cmp rcx, r10
    jb .Lcc_pending_loop
    add r11, r10
    add r13, r10
    add r14, r10
    add r15, r10
    sub rbx, r10
    cmp r11, 16
    jne .Lcc_pending_partial
    mov QWORD PTR [r12 + GCM_PENDLEN], 0
    mov rdi, r12
    lea rsi, [r12 + GCM_PEND]
    call ghash_block
    GCM_INC_CTR r12
    jmp .Lcc_blocks

.Lcc_pending_partial:
    mov QWORD PTR [r12 + GCM_PENDLEN], r11

.Lcc_success:
    mov eax, 1
    jmp .Lcc_done
.Lcc_fail:
    xor eax, eax
.Lcc_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.global gcm_seal
# gcm_seal(rdi=ctx, rsi=in, rdx=out, rcx=len) -> al.
gcm_seal:
    mov r8, rdx
    jmp gcm_crypt_core

.global gcm_open
# gcm_open(rdi=ctx, rsi=in, rdx=out, rcx=len) -> al.
gcm_open:
    mov r8, rsi
    jmp gcm_crypt_core

.global gcm_update_aad
# gcm_update_aad(rdi=ctx, rsi=aad, rdx=aadlen) -> al.
gcm_update_aad:
    cmp BYTE PTR [rdi + GCM_PHASE], GCM_PHASE_AAD
    jne .Lga_fail
    mov rax, QWORD PTR [rdi + GCM_ALEN]
    mov rcx, GCM_MAX_AAD
    cmp rax, rcx
    ja .Lga_fail
    sub rcx, rax
    cmp rdx, rcx
    ja .Lga_fail
    add QWORD PTR [rdi + GCM_ALEN], rdx
    jmp gcm_absorb
.Lga_fail:
    xor eax, eax
    ret

.global gcm_init
# gcm_init(rdi=ctx, rsi=key, edx=nr, rcx=nonce12) -> al.
gcm_init:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rsi
    mov r14d, edx
    mov r15, rcx

    cmp r14d, 10
    je .Lgi_128
    cmp r14d, 14
    jne .Lgi_invalid
    mov rdi, r13
    lea rsi, [r12 + GCM_KEY]
    call aes256_expand
    jmp .Lgi_expanded
.Lgi_128:
    mov rdi, r13
    lea rsi, [r12 + GCM_KEY]
    call aes128_expand

.Lgi_expanded:
    lea rdi, [r12 + GCM_KEY]
    lea rsi, [rip + gcm_zero_block]
    lea rdx, [r12 + GCM_H]
    mov ecx, r14d
    call aes_encrypt
    movdqu xmm0, XMMWORD PTR [r12 + GCM_H]
    pshufb xmm0, XMMWORD PTR [rip + gcm_byteswap]
    movdqu XMMWORD PTR [r12 + GCM_H], xmm0

    mov rax, QWORD PTR [r15]
    mov QWORD PTR [r12 + GCM_J0], rax
    mov eax, DWORD PTR [r15 + 8]
    mov DWORD PTR [r12 + GCM_J0 + 8], eax
    mov DWORD PTR [r12 + GCM_J0 + 12], 0x01000000
    movdqu xmm0, XMMWORD PTR [r12 + GCM_J0]
    movdqu XMMWORD PTR [r12 + GCM_CTR], xmm0
    GCM_INC_CTR r12

    pxor xmm0, xmm0
    movdqu XMMWORD PTR [r12 + GCM_Y], xmm0
    movdqu XMMWORD PTR [r12 + GCM_TAG], xmm0
    movdqu XMMWORD PTR [r12 + GCM_PEND], xmm0
    movdqu XMMWORD PTR [r12 + GCM_LENBUF], xmm0
    mov QWORD PTR [r12 + GCM_PENDLEN], 0
    mov QWORD PTR [r12 + GCM_ALEN], 0
    mov QWORD PTR [r12 + GCM_CLEN], 0
    mov BYTE PTR [r12 + GCM_PHASE], GCM_PHASE_AAD
    mov DWORD PTR [r12 + GCM_NR], r14d
    mov eax, 1
    jmp .Lgi_done

.Lgi_invalid:
    pxor xmm0, xmm0
    movdqu XMMWORD PTR [r12 + GCM_TAG], xmm0
    mov QWORD PTR [r12 + GCM_PENDLEN], 0
    mov QWORD PTR [r12 + GCM_ALEN], 0
    mov QWORD PTR [r12 + GCM_CLEN], 0
    mov DWORD PTR [r12 + GCM_NR], 0
    mov BYTE PTR [r12 + GCM_PHASE], GCM_PHASE_INVALID
    xor eax, eax

.Lgi_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.global gcm_final_tag
# gcm_final_tag(rdi=ctx, rsi=tag16) -> al.
gcm_final_tag:
    push rbx
    push r12
    push r13
    mov r12, rdi
    mov r13, rsi

    cmp BYTE PTR [r12 + GCM_PHASE], GCM_PHASE_FINAL
    je .Lft_cached
    cmp BYTE PTR [r12 + GCM_PHASE], GCM_PHASE_INVALID
    je .Lft_invalid

    mov rax, QWORD PTR [r12 + GCM_PENDLEN]
    test rax, rax
    jz .Lft_lengths
    lea rcx, [r12 + GCM_PEND]
    add rcx, rax
    mov rdx, 16
    sub rdx, rax
.Lft_pad:
    mov BYTE PTR [rcx], 0
    inc rcx
    dec rdx
    jnz .Lft_pad
    mov rdi, r12
    lea rsi, [r12 + GCM_PEND]
    call ghash_block
    mov QWORD PTR [r12 + GCM_PENDLEN], 0

.Lft_lengths:
    mov rax, QWORD PTR [r12 + GCM_ALEN]
    shl rax, 3
    bswap rax
    mov QWORD PTR [r12 + GCM_LENBUF], rax
    mov rax, QWORD PTR [r12 + GCM_CLEN]
    shl rax, 3
    bswap rax
    mov QWORD PTR [r12 + GCM_LENBUF + 8], rax
    mov rdi, r12
    lea rsi, [r12 + GCM_LENBUF]
    call ghash_block

    lea rdi, [r12 + GCM_KEY]
    lea rsi, [r12 + GCM_J0]
    lea rdx, [r12 + GCM_TAG]
    mov ecx, DWORD PTR [r12 + GCM_NR]
    call aes_encrypt
    movdqu xmm0, XMMWORD PTR [r12 + GCM_Y]
    pshufb xmm0, XMMWORD PTR [rip + gcm_byteswap]
    pxor xmm0, XMMWORD PTR [r12 + GCM_TAG]
    movdqu XMMWORD PTR [r12 + GCM_TAG], xmm0
    movdqu XMMWORD PTR [r13], xmm0
    mov BYTE PTR [r12 + GCM_PHASE], GCM_PHASE_FINAL
    mov eax, 1
    jmp .Lft_done

.Lft_cached:
    movdqu xmm0, XMMWORD PTR [r12 + GCM_TAG]
    movdqu XMMWORD PTR [r13], xmm0
    mov eax, 1
    jmp .Lft_done

.Lft_invalid:
    pxor xmm0, xmm0
    movdqu XMMWORD PTR [r13], xmm0
    xor eax, eax

.Lft_done:
    pop r13
    pop r12
    pop rbx
    ret

.global gcm_verify
# gcm_verify(rdi=ctx, rsi=candidate16) -> al.
gcm_verify:
    push rbx
    push r12
    push r13
    sub rsp, 16
    mov r12, rdi
    mov r13, rsi
    mov rdi, r12
    mov rsi, rsp
    call gcm_final_tag
    test al, al
    jz .Lgv_fail
    movdqu xmm0, XMMWORD PTR [rsp]
    movdqu xmm1, XMMWORD PTR [r13]
    pxor xmm0, xmm1
    pxor xmm1, xmm1
    pcmpeqb xmm0, xmm1
    pmovmskb eax, xmm0
    cmp eax, 0xffff
    sete al
    movzx eax, al
    jmp .Lgv_done
.Lgv_fail:
    xor eax, eax
.Lgv_done:
    pxor xmm0, xmm0
    movdqu XMMWORD PTR [rsp], xmm0
    add rsp, 16
    pop r13
    pop r12
    pop rbx
    ret

.section .rodata
.p2align 4
gcm_byteswap:
    .byte 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
gcm_zero_block:
    .quad 0, 0
gcm_reduce_const:
    .quad 0xc200000000000000, 0
