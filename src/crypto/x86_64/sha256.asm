.intel_syntax noprefix
.include "common.inc"

# SHA-256 for x86-64
# See ../sha256.inc for the shared API and context layout.

.section .text

.equ SHA256_STATE,  0
.equ SHA256_BUF,    32
.equ SHA256_TOTAL,  96
.equ SHA256_BUF_LEN, 104

.global sha256_init
.global sha256_update
.global sha256_final
.global sha256_compress

# sha256_init(rdi=ctx)
sha256_init:
    mov dword ptr [rdi + 0],  0x6a09e667
    mov dword ptr [rdi + 4],  0xbb67ae85
    mov dword ptr [rdi + 8],  0x3c6ef372
    mov dword ptr [rdi + 12], 0xa54ff53a
    mov dword ptr [rdi + 16], 0x510e527f
    mov dword ptr [rdi + 20], 0x9b05688c
    mov dword ptr [rdi + 24], 0x1f83d9ab
    mov dword ptr [rdi + 28], 0x5be0cd19
    mov qword ptr [rdi + SHA256_TOTAL], 0
    mov qword ptr [rdi + SHA256_BUF_LEN], 0
    ret

# sha256_update(rdi=ctx, rsi=data, rdx=len)
sha256_update:
    push rbx
    push r12
    push r13
    push r14
    push r15
    cld
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    add [r12 + SHA256_TOTAL], r14

    mov r15, [r12 + SHA256_BUF_LEN]
    test r15, r15
    jz 1f

    mov rbx, 64
    sub rbx, r15
    cmp r14, rbx
    jae 2f
    mov rbx, r14
2:
    lea rdi, [r12 + SHA256_BUF]
    add rdi, r15
    mov rsi, r13
    mov rcx, rbx
    rep movsb
    add r13, rbx
    sub r14, rbx
    add r15, rbx
    cmp r15, 64
    jne 4f
    mov rdi, r12
    lea rsi, [r12 + SHA256_BUF]
    call sha256_compress
    mov r15, 0
1:
    cmp r14, 64
    jb 3f
    mov rdi, r12
    mov rsi, r13
    call sha256_compress
    add r13, 64
    sub r14, 64
    jmp 1b
3:
    mov [r12 + SHA256_BUF_LEN], r14
    test r14, r14
    jz 5f
    lea rdi, [r12 + SHA256_BUF]
    mov rsi, r13
    mov rcx, r14
    rep movsb
    jmp 5f
4:
    mov [r12 + SHA256_BUF_LEN], r15
5:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

# sha256_final(rdi=ctx, rsi=digest)
sha256_final:
    push rbx
    push r12
    push r13
    push r14
    push r15
    cld
    mov r12, rdi
    mov r13, rsi
    mov r15, [r12 + SHA256_BUF_LEN]
    lea r14, [r12 + SHA256_BUF]

    lea rdi, [r14 + r15]
    mov byte ptr [rdi], 0x80
    inc r15
zloop:
    cmp r15, 56
    jbe 1f
    mov rbx, 64
    sub rbx, r15
    xor eax, eax
    lea rdi, [r14 + r15]
    mov rcx, rbx
    rep stosb
    mov rdi, r12
    mov rsi, r14
    call sha256_compress
    mov r15, 0
    jmp zloop
1:
    mov rbx, 56
    sub rbx, r15
    xor eax, eax
    lea rdi, [r14 + r15]
    mov rcx, rbx
    rep stosb
    mov rax, [r12 + SHA256_TOTAL]
    shl rax, 3
    bswap rax
    mov [r14 + 56], rax

    mov rdi, r12
    mov rsi, r14
    call sha256_compress

    xor ebx, ebx
2:
    mov eax, [r12 + rbx*4]
    bswap eax
    mov [r13 + rbx*4], eax
    inc ebx
    cmp ebx, 8
    jb 2b

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

# sha256_compress(rdi=state, rsi=block) - one 64-byte block, in-place state
sha256_compress:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 260
    mov rbp, rsp

    xor ebx, ebx
0:
    mov eax, [rsi + rbx*4]
    bswap eax
    mov [rbp + rbx*4], eax
    inc ebx
    cmp ebx, 16
    jb 0b

    mov ebx, 16
1:
    mov eax, [rbp + rbx*4 - 8]
    mov r8d, eax
    ror r8d, 17
    mov r9d, eax
    ror r9d, 19
    xor r8d, r9d
    shr eax, 10
    xor r8d, eax
    add r8d, [rbp + rbx*4 - 28]
    mov eax, [rbp + rbx*4 - 60]
    mov r9d, eax
    ror r9d, 7
    mov r10d, eax
    ror r10d, 18
    xor r9d, r10d
    shr eax, 3
    xor r9d, eax
    add r8d, r9d
    add r8d, [rbp + rbx*4 - 64]
    mov [rbp + rbx*4], r8d
    inc ebx
    cmp ebx, 64
    jb 1b

    mov r8d,  [rdi]
    mov r9d,  [rdi + 4]
    mov r10d, [rdi + 8]
    mov r11d, [rdi + 12]
    mov r12d, [rdi + 16]
    mov r13d, [rdi + 20]
    mov r14d, [rdi + 24]
    mov r15d, [rdi + 28]

    lea rsi, [rip + sha256_k]
    xor ebx, ebx
2:
    mov ecx, r12d
    ror ecx, 6
    mov eax, ecx
    mov ecx, r12d
    ror ecx, 11
    xor eax, ecx
    mov ecx, r12d
    ror ecx, 25
    xor eax, ecx
    mov edx, r12d
    and edx, r13d
    mov ecx, r12d
    not ecx
    and ecx, r14d
    xor edx, ecx
    add eax, edx
    add eax, r15d
    add eax, [rsi + rbx*4]
    add eax, [rbp + rbx*4]
    mov ecx, eax
    mov edx, r8d
    ror edx, 2
    mov eax, edx
    mov edx, r8d
    ror edx, 13
    xor eax, edx
    mov edx, r8d
    ror edx, 22
    xor eax, edx
    mov [rbp + 256], eax
    mov eax, r8d
    and eax, r9d
    mov edx, r8d
    and edx, r10d
    xor eax, edx
    mov edx, r9d
    and edx, r10d
    xor eax, edx
    add eax, [rbp + 256]
    add eax, ecx
    mov edx, r11d
    add edx, ecx
    mov r15d, r14d
    mov r14d, r13d
    mov r13d, r12d
    mov r12d, edx
    mov r11d, r10d
    mov r10d, r9d
    mov r9d, r8d
    mov r8d, eax
    inc ebx
    cmp ebx, 64
    jb 2b

    add [rdi], r8d
    add [rdi + 4], r9d
    add [rdi + 8], r10d
    add [rdi + 12], r11d
    add [rdi + 16], r12d
    add [rdi + 20], r13d
    add [rdi + 24], r14d
    add [rdi + 28], r15d

    add rsp, 260
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.section .rodata
sha256_k:
    .long 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
    .long 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
    .long 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
    .long 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
    .long 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
    .long 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
    .long 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
    .long 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
    .long 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
    .long 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
    .long 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
    .long 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
    .long 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
    .long 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
    .long 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
    .long 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
