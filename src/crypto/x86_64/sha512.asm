.intel_syntax noprefix
.include "common.inc"

# SHA-384/SHA-512 for x86-64
# See ../sha512.inc for the shared API and context layout.

.section .text

.equ SHA512_STATE,      0
.equ SHA512_BUF,        64
.equ SHA512_TOTAL,      192
.equ SHA512_BUF_LEN,    200
.equ SHA512_DIGEST_LEN, 208

.global sha512_init
.global sha384_init
.global sha512_update
.global sha512_final

# sha512_init(rdi=ctx)
sha512_init:
    movabs rax, 0x6a09e667f3bcc908
    mov [rdi + 0], rax
    movabs rax, 0xbb67ae8584caa73b
    mov [rdi + 8], rax
    movabs rax, 0x3c6ef372fe94f82b
    mov [rdi + 16], rax
    movabs rax, 0xa54ff53a5f1d36f1
    mov [rdi + 24], rax
    movabs rax, 0x510e527fade682d1
    mov [rdi + 32], rax
    movabs rax, 0x9b05688c2b3e6c1f
    mov [rdi + 40], rax
    movabs rax, 0x1f83d9abfb41bd6b
    mov [rdi + 48], rax
    movabs rax, 0x5be0cd19137e2179
    mov [rdi + 56], rax
    mov qword ptr [rdi + SHA512_TOTAL], 0
    mov qword ptr [rdi + SHA512_BUF_LEN], 0
    mov qword ptr [rdi + SHA512_DIGEST_LEN], 64
    ret

# sha384_init(rdi=ctx)
sha384_init:
    call sha512_init
    movabs rax, 0xcbbb9d5dc1059ed8
    mov [rdi + 0], rax
    movabs rax, 0x629a292a367cd507
    mov [rdi + 8], rax
    movabs rax, 0x9159015a3070dd17
    mov [rdi + 16], rax
    movabs rax, 0x152fecd8f70e5939
    mov [rdi + 24], rax
    movabs rax, 0x67332667ffc00b31
    mov [rdi + 32], rax
    movabs rax, 0x8eb44a8768581511
    mov [rdi + 40], rax
    movabs rax, 0xdb0c2e0d64f98fa7
    mov [rdi + 48], rax
    movabs rax, 0x47b5481dbefa4fa4
    mov [rdi + 56], rax
    mov qword ptr [rdi + SHA512_DIGEST_LEN], 48
    ret

# sha512_update(rdi=ctx, rsi=data, rdx=len)
sha512_update:
    push rbx
    push r12
    push r13
    push r14
    push r15
    cld
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    add [r12 + SHA512_TOTAL], r14

    mov r15, [r12 + SHA512_BUF_LEN]
    test r15, r15
    jz 1f

    mov rbx, 128
    sub rbx, r15
    cmp r14, rbx
    jae 2f
    mov rbx, r14
2:
    lea rdi, [r12 + SHA512_BUF]
    add rdi, r15
    mov rsi, r13
    mov rcx, rbx
    rep movsb
    add r13, rbx
    sub r14, rbx
    add r15, rbx
    cmp r15, 128
    jne 4f
    mov rdi, r12
    lea rsi, [r12 + SHA512_BUF]
    call sha512_compress
    mov r15, 0
1:
    cmp r14, 128
    jb 3f
    mov rdi, r12
    mov rsi, r13
    call sha512_compress
    add r13, 128
    sub r14, 128
    jmp 1b
3:
    mov [r12 + SHA512_BUF_LEN], r14
    test r14, r14
    jz 5f
    lea rdi, [r12 + SHA512_BUF]
    mov rsi, r13
    mov rcx, r14
    rep movsb
    jmp 5f
4:
    mov [r12 + SHA512_BUF_LEN], r15
5:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

# sha512_final(rdi=ctx, rsi=digest)
sha512_final:
    push rbx
    push r12
    push r13
    push r14
    push r15
    cld
    mov r12, rdi
    mov r13, rsi
    mov r15, [r12 + SHA512_BUF_LEN]
    lea r14, [r12 + SHA512_BUF]

    lea rdi, [r14 + r15]
    mov byte ptr [rdi], 0x80
    inc r15
zloop:
    cmp r15, 112
    jbe 1f
    mov rbx, 128
    sub rbx, r15
    xor eax, eax
    lea rdi, [r14 + r15]
    mov rcx, rbx
    rep stosb
    mov rdi, r12
    mov rsi, r14
    call sha512_compress
    mov r15, 0
    jmp zloop
1:
    mov rbx, 112
    sub rbx, r15
    xor eax, eax
    lea rdi, [r14 + r15]
    mov rcx, rbx
    rep stosb
    mov rax, [r12 + SHA512_TOTAL]
    shl rax, 3
    bswap rax
    mov qword ptr [r14 + 112], 0
    mov [r14 + 120], rax

    mov rdi, r12
    mov rsi, r14
    call sha512_compress

    xor rbx, rbx
    mov rcx, [r12 + SHA512_DIGEST_LEN]
    shr rcx, 3
2:
    mov rax, [r12 + rbx*8]
    bswap rax
    mov [r13 + rbx*8], rax
    inc rbx
    cmp rbx, rcx
    jb 2b

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

# sha512_compress(rdi=state, rsi=block) - one 128-byte block, in-place state
sha512_compress:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 648
    mov rbp, rsp

    xor ebx, ebx
0:
    mov rax, [rsi + rbx*8]
    bswap rax
    mov [rbp + rbx*8], rax
    inc ebx
    cmp ebx, 16
    jb 0b

    mov ebx, 16
1:
    mov rax, [rbp + rbx*8 - 16]
    mov r8, rax
    ror r8, 19
    mov r9, rax
    ror r9, 61
    xor r8, r9
    shr rax, 6
    xor r8, rax
    add r8, [rbp + rbx*8 - 56]
    mov rax, [rbp + rbx*8 - 120]
    mov r9, rax
    ror r9, 1
    mov r10, rax
    ror r10, 8
    xor r9, r10
    shr rax, 7
    xor r9, rax
    add r8, r9
    add r8, [rbp + rbx*8 - 128]
    mov [rbp + rbx*8], r8
    inc ebx
    cmp ebx, 80
    jb 1b

    mov r8,  [rdi]
    mov r9,  [rdi + 8]
    mov r10, [rdi + 16]
    mov r11, [rdi + 24]
    mov r12, [rdi + 32]
    mov r13, [rdi + 40]
    mov r14, [rdi + 48]
    mov r15, [rdi + 56]

    lea rsi, [rip + sha512_k]
    xor ebx, ebx
2:
    mov rcx, r12
    ror rcx, 14
    mov rax, rcx
    mov rcx, r12
    ror rcx, 18
    xor rax, rcx
    mov rcx, r12
    ror rcx, 41
    xor rax, rcx
    mov rdx, r12
    and rdx, r13
    mov rcx, r12
    not rcx
    and rcx, r14
    xor rdx, rcx
    add rax, rdx
    add rax, r15
    add rax, [rsi + rbx*8]
    add rax, [rbp + rbx*8]
    mov rcx, rax
    mov rdx, r8
    ror rdx, 28
    mov rax, rdx
    mov rdx, r8
    ror rdx, 34
    xor rax, rdx
    mov rdx, r8
    ror rdx, 39
    xor rax, rdx
    mov [rbp + 640], rax
    mov rax, r8
    and rax, r9
    mov rdx, r8
    and rdx, r10
    xor rax, rdx
    mov rdx, r9
    and rdx, r10
    xor rax, rdx
    add rax, [rbp + 640]
    add rax, rcx
    mov rdx, r11
    add rdx, rcx
    mov r15, r14
    mov r14, r13
    mov r13, r12
    mov r12, rdx
    mov r11, r10
    mov r10, r9
    mov r9, r8
    mov r8, rax
    inc ebx
    cmp ebx, 80
    jb 2b

    add [rdi], r8
    add [rdi + 8], r9
    add [rdi + 16], r10
    add [rdi + 24], r11
    add [rdi + 32], r12
    add [rdi + 40], r13
    add [rdi + 48], r14
    add [rdi + 56], r15

    add rsp, 648
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.section .rodata
sha512_k:
    .quad 0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc
    .quad 0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118
    .quad 0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2
    .quad 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694
    .quad 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65
    .quad 0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5
    .quad 0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4
    .quad 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70
    .quad 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df
    .quad 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b
    .quad 0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30
    .quad 0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8
    .quad 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8
    .quad 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3
    .quad 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec
    .quad 0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b
    .quad 0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178
    .quad 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b
    .quad 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c
    .quad 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
