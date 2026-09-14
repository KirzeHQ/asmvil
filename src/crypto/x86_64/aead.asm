.intel_syntax noprefix
.include "common.inc"

# ChaCha20-Poly1305 AEAD composition, RFC 8439 section 2.8.

.section .text

AEAD_CHACHA = 0
AEAD_POLY   = 144
AEAD_SCRATCH = 320
AEAD_ALEN   = 384
AEAD_CLEN   = 392
AEAD_PHASE  = 400
AEAD_CTX_SIZE = 408

AEAD_AAD  = 0
AEAD_TEXT = 1
AEAD_FINAL = 2

.macro AEAD_PAD ctx, length
    mov rax, QWORD PTR [\ctx + \length]
    and eax, 15
    jz .Lpad_done\@ 
    mov rcx, 16
    sub rcx, rax
    lea rdi, [\ctx + AEAD_SCRATCH]
    lea rsi, [\ctx + AEAD_SCRATCH]
    mov rdx, rcx
    call poly1305_update
.Lpad_done\@:
.endm

.global aead_init
# aead_init(rdi=ctx, rsi=key32, rdx=nonce12)
aead_init:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx

    # The first ChaCha block with counter zero supplies Poly1305 r and s.
    lea rdi, [r13]
    xor esi, esi
    mov rdx, r14
    lea rcx, [r12 + AEAD_SCRATCH]
    call chacha20_block
    lea rdi, [r12 + AEAD_POLY]
    lea rsi, [r12 + AEAD_SCRATCH]
    call poly1305_init

    lea rdi, [r12 + AEAD_CHACHA]
    mov rsi, r13
    mov edx, 1
    mov rcx, r14
    call chacha20_init

    pxor xmm0, xmm0
    movdqu XMMWORD PTR [r12 + AEAD_SCRATCH], xmm0
    movdqu XMMWORD PTR [r12 + AEAD_SCRATCH + 16], xmm0
    movdqu XMMWORD PTR [r12 + AEAD_SCRATCH + 32], xmm0
    movdqu XMMWORD PTR [r12 + AEAD_SCRATCH + 48], xmm0
    mov QWORD PTR [r12 + AEAD_ALEN], 0
    mov QWORD PTR [r12 + AEAD_CLEN], 0
    mov BYTE PTR [r12 + AEAD_PHASE], AEAD_AAD
    mov eax, 1
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.global aead_update_aad
# aead_update_aad(rdi=ctx, rsi=aad, rdx=len) -> al.
aead_update_aad:
    push rbx
    push r12
    push r13
    mov r12, rdi
    mov r13, rsi
    mov rbx, rdx
    cmp BYTE PTR [r12 + AEAD_PHASE], AEAD_AAD
    jne .Laa_fail
    mov rax, QWORD PTR [r12 + AEAD_ALEN]
    add rax, rbx
    jc .Laa_fail
    lea rdi, [r12 + AEAD_POLY]
    mov rsi, r13
    mov rdx, rbx
    call poly1305_update
    test al, al
    jz .Laa_fail
    add QWORD PTR [r12 + AEAD_ALEN], rbx
    mov eax, 1
    jmp .Laa_done
.Laa_fail:
    xor eax, eax
.Laa_done:
    pop r13
    pop r12
    pop rbx
    ret

.global aead_seal
# aead_seal(rdi=ctx, rsi=plaintext, rdx=ciphertext, rcx=len) -> al.
aead_seal:
    mov r8, rdx
    jmp aead_crypt

.global aead_open
# aead_open(rdi=ctx, rsi=ciphertext, rdx=plaintext, rcx=len) -> al.
aead_open:
    mov r8, rsi
    jmp aead_crypt

# aead_crypt(rdi=ctx, rsi=in, rdx=out, rcx=len, r8=ct_src) -> al.
aead_crypt:
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
    cmp BYTE PTR [r12 + AEAD_PHASE], AEAD_FINAL
    jae .Lac_fail

    mov rax, QWORD PTR [r12 + AEAD_CLEN]
    add rax, rbx
    jc .Lac_fail
    mov r10, 64
    sub r10, QWORD PTR [r12 + 128]
    cmp BYTE PTR [r12 + 136], 0
    jne .Lac_capacity
    mov ecx, DWORD PTR [r12 + 48]
    mov rdx, 0x100000000
    sub rdx, rcx
    shl rdx, 6
    add r10, rdx
.Lac_capacity:
    cmp rbx, r10
    ja .Lac_fail

    cmp BYTE PTR [r12 + AEAD_PHASE], AEAD_TEXT
    je .Lac_text
    mov rax, QWORD PTR [r12 + AEAD_ALEN]
    and eax, 15
    jz .Lac_aad_padded
    mov rcx, 16
    sub rcx, rax
    lea rdi, [r12 + AEAD_POLY]
    lea rsi, [r12 + AEAD_SCRATCH]
    mov rdx, rcx
    call poly1305_update
    test al, al
    jz .Lac_fail
.Lac_aad_padded:
    mov BYTE PTR [r12 + AEAD_PHASE], AEAD_TEXT

.Lac_text:
    lea rdi, [r12 + AEAD_CHACHA]
    mov rsi, r13
    mov rdx, r14
    mov rcx, rbx
    call chacha20_xor
    test al, al
    jz .Lac_fail
    lea rdi, [r12 + AEAD_POLY]
    mov rsi, r15
    mov rdx, rbx
    call poly1305_update
    test al, al
    jz .Lac_fail
    add QWORD PTR [r12 + AEAD_CLEN], rbx
    mov eax, 1
    jmp .Lac_done
.Lac_fail:
    xor eax, eax
.Lac_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.global aead_final
# aead_final(rdi=ctx, rsi=tag16) -> al.
aead_final:
    push rbx
    push r12
    push r13
    sub rsp, 16
    mov r12, rdi
    mov r13, rsi
    cmp BYTE PTR [r12 + AEAD_PHASE], AEAD_FINAL
    je .Laf_cached
    cmp BYTE PTR [r12 + AEAD_PHASE], AEAD_AAD
    jne .Laf_ct_pad
    mov rax, QWORD PTR [r12 + AEAD_ALEN]
    and eax, 15
    jz .Laf_aad_done
    mov rcx, 16
    sub rcx, rax
    lea rdi, [r12 + AEAD_POLY]
    lea rsi, [r12 + AEAD_SCRATCH]
    mov rdx, rcx
    call poly1305_update
    test al, al
    jz .Laf_fail
.Laf_aad_done:
.Laf_ct_pad:
    mov rax, QWORD PTR [r12 + AEAD_CLEN]
    and eax, 15
    jz .Laf_lengths
    mov rcx, 16
    sub rcx, rax
    lea rdi, [r12 + AEAD_POLY]
    lea rsi, [r12 + AEAD_SCRATCH]
    mov rdx, rcx
    call poly1305_update
    test al, al
    jz .Laf_fail
.Laf_lengths:
    mov rax, QWORD PTR [r12 + AEAD_ALEN]
    mov QWORD PTR [r12 + AEAD_SCRATCH], rax
    mov rax, QWORD PTR [r12 + AEAD_CLEN]
    mov QWORD PTR [r12 + AEAD_SCRATCH + 8], rax
    lea rdi, [r12 + AEAD_POLY]
    lea rsi, [r12 + AEAD_SCRATCH]
    mov edx, 16
    call poly1305_update
    test al, al
    jz .Laf_fail
    lea rdi, [r12 + AEAD_POLY]
    mov rsi, rsp
    call poly1305_final
    test al, al
    jz .Laf_fail
    movdqu xmm0, XMMWORD PTR [rsp]
    movdqu XMMWORD PTR [r12 + AEAD_SCRATCH], xmm0
    movdqu XMMWORD PTR [r13], xmm0
    mov BYTE PTR [r12 + AEAD_PHASE], AEAD_FINAL
    mov eax, 1
    jmp .Laf_done
.Laf_cached:
    movdqu xmm0, XMMWORD PTR [r12 + AEAD_SCRATCH]
    movdqu XMMWORD PTR [r13], xmm0
    mov eax, 1
    jmp .Laf_done
.Laf_fail:
    xor eax, eax
.Laf_done:
    add rsp, 16
    pop r13
    pop r12
    pop rbx
    ret

.global aead_verify
# aead_verify(rdi=ctx, rsi=candidate16) -> al.
aead_verify:
    push rbx
    push r12
    push r13
    sub rsp, 16
    mov r12, rdi
    mov r13, rsi
    mov rdi, r12
    mov rsi, rsp
    call aead_final
    test eax, eax
    jz .Lav_fail
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
    jmp .Lav_done
.Lav_fail:
    xor eax, eax
.Lav_done:
    add rsp, 16
    pop r13
    pop r12
    pop rbx
    ret
