.intel_syntax noprefix
.include "common.inc"

# AES-128/256 FIPS 197 with AES-NI; see ../aes.inc for the API.

.section .text

# Key expansion uses cumulative prefix XORs to reproduce the FIPS schedule.

.macro RAW_STEP src, tmp, t, off, store
    movdqa \tmp, \src
    pslldq \tmp, 4
    pxor \src, \tmp
    pslldq \tmp, 4
    pxor \src, \tmp
    pslldq \tmp, 4
    pxor \src, \tmp
    pxor \src, \t
    \store XMMWORD PTR [rsi+\off], \src
.endm

.global aes128_expand
# aes128_expand(rdi=key, rsi=sched): writes 176 bytes.
aes128_expand:
    movdqu xmm0, XMMWORD PTR [rdi]
    movdqu XMMWORD PTR [rsi], xmm0
    aeskeygenassist xmm1, xmm0, 0x01
    pshufd xmm1, xmm1, 0xff
    RAW_STEP xmm0, xmm2, xmm1, 16, movdqu
    aeskeygenassist xmm1, xmm0, 0x02
    pshufd xmm1, xmm1, 0xff
    RAW_STEP xmm0, xmm2, xmm1, 32, movdqu
    aeskeygenassist xmm1, xmm0, 0x04
    pshufd xmm1, xmm1, 0xff
    RAW_STEP xmm0, xmm2, xmm1, 48, movdqu
    aeskeygenassist xmm1, xmm0, 0x08
    pshufd xmm1, xmm1, 0xff
    RAW_STEP xmm0, xmm2, xmm1, 64, movdqu
    aeskeygenassist xmm1, xmm0, 0x10
    pshufd xmm1, xmm1, 0xff
    RAW_STEP xmm0, xmm2, xmm1, 80, movdqu
    aeskeygenassist xmm1, xmm0, 0x20
    pshufd xmm1, xmm1, 0xff
    RAW_STEP xmm0, xmm2, xmm1, 96, movdqu
    aeskeygenassist xmm1, xmm0, 0x40
    pshufd xmm1, xmm1, 0xff
    RAW_STEP xmm0, xmm2, xmm1, 112, movdqu
    aeskeygenassist xmm1, xmm0, 0x80
    pshufd xmm1, xmm1, 0xff
    RAW_STEP xmm0, xmm2, xmm1, 128, movdqu
    aeskeygenassist xmm1, xmm0, 0x1b
    pshufd xmm1, xmm1, 0xff
    RAW_STEP xmm0, xmm2, xmm1, 144, movdqu
    aeskeygenassist xmm1, xmm0, 0x36
    pshufd xmm1, xmm1, 0xff
    RAW_STEP xmm0, xmm2, xmm1, 160, movdqu
    ret

# AES-256 expansion derives alternating g and h words from two XMM registers.

.global aes256_expand
# aes256_expand(rdi=key, rsi=sched): writes 240 bytes.
aes256_expand:
    movdqu xmm0, XMMWORD PTR [rdi]
    movdqu XMMWORD PTR [rsi], xmm0
    movdqu xmm1, XMMWORD PTR [rdi+16]
    movdqu XMMWORD PTR [rsi+16], xmm1
    aeskeygenassist xmm2, xmm1, 0x01
    pshufd xmm2, xmm2, 0xff
    RAW_STEP xmm0, xmm3, xmm2, 32, movdqu
    aeskeygenassist xmm2, xmm0, 0x00
    pshufd xmm2, xmm2, 0xaa
    RAW_STEP xmm1, xmm3, xmm2, 48, movdqu
    aeskeygenassist xmm2, xmm1, 0x02
    pshufd xmm2, xmm2, 0xff
    RAW_STEP xmm0, xmm3, xmm2, 64, movdqu
    aeskeygenassist xmm2, xmm0, 0x00
    pshufd xmm2, xmm2, 0xaa
    RAW_STEP xmm1, xmm3, xmm2, 80, movdqu
    aeskeygenassist xmm2, xmm1, 0x04
    pshufd xmm2, xmm2, 0xff
    RAW_STEP xmm0, xmm3, xmm2, 96, movdqu
    aeskeygenassist xmm2, xmm0, 0x00
    pshufd xmm2, xmm2, 0xaa
    RAW_STEP xmm1, xmm3, xmm2, 112, movdqu
    aeskeygenassist xmm2, xmm1, 0x08
    pshufd xmm2, xmm2, 0xff
    RAW_STEP xmm0, xmm3, xmm2, 128, movdqu
    aeskeygenassist xmm2, xmm0, 0x00
    pshufd xmm2, xmm2, 0xaa
    RAW_STEP xmm1, xmm3, xmm2, 144, movdqu
    aeskeygenassist xmm2, xmm1, 0x10
    pshufd xmm2, xmm2, 0xff
    RAW_STEP xmm0, xmm3, xmm2, 160, movdqu
    aeskeygenassist xmm2, xmm0, 0x00
    pshufd xmm2, xmm2, 0xaa
    RAW_STEP xmm1, xmm3, xmm2, 176, movdqu
    aeskeygenassist xmm2, xmm1, 0x20
    pshufd xmm2, xmm2, 0xff
    RAW_STEP xmm0, xmm3, xmm2, 192, movdqu
    aeskeygenassist xmm2, xmm0, 0x00
    pshufd xmm2, xmm2, 0xaa
    RAW_STEP xmm1, xmm3, xmm2, 208, movdqu
    aeskeygenassist xmm2, xmm1, 0x40
    pshufd xmm2, xmm2, 0xff
    RAW_STEP xmm0, xmm3, xmm2, 224, movdqu
    ret

.global aes128_encrypt
# aes128_encrypt(rdi=sched, rsi=in, rdx=out).
aes128_encrypt:
    movdqu xmm2, XMMWORD PTR [rsi]
    pxor xmm2, XMMWORD PTR [rdi]
    aesenc xmm2, XMMWORD PTR [rdi+16]
    aesenc xmm2, XMMWORD PTR [rdi+32]
    aesenc xmm2, XMMWORD PTR [rdi+48]
    aesenc xmm2, XMMWORD PTR [rdi+64]
    aesenc xmm2, XMMWORD PTR [rdi+80]
    aesenc xmm2, XMMWORD PTR [rdi+96]
    aesenc xmm2, XMMWORD PTR [rdi+112]
    aesenc xmm2, XMMWORD PTR [rdi+128]
    aesenc xmm2, XMMWORD PTR [rdi+144]
    aesenclast xmm2, XMMWORD PTR [rdi+160]
    movdqu XMMWORD PTR [rdx], xmm2
    ret

.global aes256_encrypt
# aes256_encrypt(rdi=sched, rsi=in, rdx=out).
aes256_encrypt:
    movdqu xmm2, XMMWORD PTR [rsi]
    pxor xmm2, XMMWORD PTR [rdi]
    aesenc xmm2, XMMWORD PTR [rdi+16]
    aesenc xmm2, XMMWORD PTR [rdi+32]
    aesenc xmm2, XMMWORD PTR [rdi+48]
    aesenc xmm2, XMMWORD PTR [rdi+64]
    aesenc xmm2, XMMWORD PTR [rdi+80]
    aesenc xmm2, XMMWORD PTR [rdi+96]
    aesenc xmm2, XMMWORD PTR [rdi+112]
    aesenc xmm2, XMMWORD PTR [rdi+128]
    aesenc xmm2, XMMWORD PTR [rdi+144]
    aesenc xmm2, XMMWORD PTR [rdi+160]
    aesenc xmm2, XMMWORD PTR [rdi+176]
    aesenc xmm2, XMMWORD PTR [rdi+192]
    aesenc xmm2, XMMWORD PTR [rdi+208]
    aesenclast xmm2, XMMWORD PTR [rdi+224]
    movdqu XMMWORD PTR [rdx], xmm2
    ret

.global aes128_decrypt
# aes128_decrypt(rdi=sched, rsi=in, rdx=out); aesimc derives inverse keys.
aes128_decrypt:
    movdqu xmm2, XMMWORD PTR [rsi]
    pxor xmm2, XMMWORD PTR [rdi+160]
    aesimc xmm3, XMMWORD PTR [rdi+144]
    aesdec xmm2, xmm3
    aesimc xmm3, XMMWORD PTR [rdi+128]
    aesdec xmm2, xmm3
    aesimc xmm3, XMMWORD PTR [rdi+112]
    aesdec xmm2, xmm3
    aesimc xmm3, XMMWORD PTR [rdi+96]
    aesdec xmm2, xmm3
    aesimc xmm3, XMMWORD PTR [rdi+80]
    aesdec xmm2, xmm3
    aesimc xmm3, XMMWORD PTR [rdi+64]
    aesdec xmm2, xmm3
    aesimc xmm3, XMMWORD PTR [rdi+48]
    aesdec xmm2, xmm3
    aesimc xmm3, XMMWORD PTR [rdi+32]
    aesdec xmm2, xmm3
    aesimc xmm3, XMMWORD PTR [rdi+16]
    aesdec xmm2, xmm3
    aesdeclast xmm2, XMMWORD PTR [rdi]
    movdqu XMMWORD PTR [rdx], xmm2
    ret

.global aes256_decrypt
# aes256_decrypt(rdi=sched, rsi=in, rdx=out).
aes256_decrypt:
    movdqu xmm2, XMMWORD PTR [rsi]
    pxor xmm2, XMMWORD PTR [rdi+224]
    aesimc xmm3, XMMWORD PTR [rdi+208]
    aesdec xmm2, xmm3
    aesimc xmm3, XMMWORD PTR [rdi+192]
    aesdec xmm2, xmm3
    aesimc xmm3, XMMWORD PTR [rdi+176]
    aesdec xmm2, xmm3
    aesimc xmm3, XMMWORD PTR [rdi+160]
    aesdec xmm2, xmm3
    aesimc xmm3, XMMWORD PTR [rdi+144]
    aesdec xmm2, xmm3
    aesimc xmm3, XMMWORD PTR [rdi+128]
    aesdec xmm2, xmm3
    aesimc xmm3, XMMWORD PTR [rdi+112]
    aesdec xmm2, xmm3
    aesimc xmm3, XMMWORD PTR [rdi+96]
    aesdec xmm2, xmm3
    aesimc xmm3, XMMWORD PTR [rdi+80]
    aesdec xmm2, xmm3
    aesimc xmm3, XMMWORD PTR [rdi+64]
    aesdec xmm2, xmm3
    aesimc xmm3, XMMWORD PTR [rdi+48]
    aesdec xmm2, xmm3
    aesimc xmm3, XMMWORD PTR [rdi+32]
    aesdec xmm2, xmm3
    aesimc xmm3, XMMWORD PTR [rdi+16]
    aesdec xmm2, xmm3
    aesdeclast xmm2, XMMWORD PTR [rdi]
    movdqu XMMWORD PTR [rdx], xmm2
    ret

.global aes_encrypt
# aes_encrypt(rdi=sched, rsi=in, rdx=out, ecx=nr): nr = 10 or 14.
aes_encrypt:
    movdqu xmm2, XMMWORD PTR [rsi]
    pxor xmm2, XMMWORD PTR [rdi]
    mov r8d, ecx
    dec r8d
    lea r9, [rdi + 16]
0:
    test r8d, r8d
    jz 1f
    aesenc xmm2, XMMWORD PTR [r9]
    add r9, 16
    dec r8d
    jmp 0b
1:
    aesenclast xmm2, XMMWORD PTR [r9]
    movdqu XMMWORD PTR [rdx], xmm2
    ret
