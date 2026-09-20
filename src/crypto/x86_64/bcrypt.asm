.intel_syntax noprefix

.include "common.inc"

.equ BF_P, 0
.equ BF_S, 72
.equ BF_STATE, 4176
.equ BCRYPT_MIN_COST, 4
.equ BCRYPT_MAX_COST, 31
.equ BCRYPT_APP_MAX_COST, 16

.section .text

# Read one cyclic big-endian word and return the next index.
bcrypt_word:
    xor r8d, r8d
    movzx eax, byte ptr [rdi + rdx]
    shl eax, 24
    mov r8d, eax
    inc rdx
    cmp rdx, rsi
    jb 1f
    xor edx, edx
1:
    movzx eax, byte ptr [rdi + rdx]
    shl eax, 16
    or r8d, eax
    inc rdx
    cmp rdx, rsi
    jb 2f
    xor edx, edx
2:
    movzx eax, byte ptr [rdi + rdx]
    shl eax, 8
    or r8d, eax
    inc rdx
    cmp rdx, rsi
    jb 3f
    xor edx, edx
3:
    movzx eax, byte ptr [rdi + rdx]
    or r8d, eax
    inc rdx
    cmp rdx, rsi
    jb 4f
    xor edx, edx
4:
    mov eax, r8d
    ret

.macro BF_ROUND left, right, n
    xor \right, dword ptr [r12 + BF_P + (\n * 4)]
    mov r8d, \right
    mov r9d, r8d
    shr r9d, 24
    mov r10d, dword ptr [r12 + BF_S + r9 * 4]
    mov r9d, r8d
    shr r9d, 16
    and r9d, 255
    add r10d, dword ptr [r12 + BF_S + 1024 + r9 * 4]
    mov r9d, r8d
    shr r9d, 8
    and r9d, 255
    xor r10d, dword ptr [r12 + BF_S + 2048 + r9 * 4]
    mov r9d, r8d
    and r9d, 255
    add r10d, dword ptr [r12 + BF_S + 3072 + r9 * 4]
    xor \left, r10d
.endm

# Encrypt one block in esi:edx and return the ciphertext in eax:edx.
bcrypt_encrypt:
    BF_ROUND edx, esi, 0
    BF_ROUND esi, edx, 1
    BF_ROUND edx, esi, 2
    BF_ROUND esi, edx, 3
    BF_ROUND edx, esi, 4
    BF_ROUND esi, edx, 5
    BF_ROUND edx, esi, 6
    BF_ROUND esi, edx, 7
    BF_ROUND edx, esi, 8
    BF_ROUND esi, edx, 9
    BF_ROUND edx, esi, 10
    BF_ROUND esi, edx, 11
    BF_ROUND edx, esi, 12
    BF_ROUND esi, edx, 13
    BF_ROUND edx, esi, 14
    BF_ROUND esi, edx, 15
    xor esi, dword ptr [r12 + BF_P + 64]
    xor edx, dword ptr [r12 + BF_P + 68]
    mov eax, edx
    mov edx, esi
    ret

# ExpandKey(state, salt, key).
bcrypt_expand:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 16
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    mov dword ptr [rsp], 0
    mov dword ptr [rsp + 4], 0

    xor r10d, r10d
1:
    mov rdi, r14
    mov rsi, r15
    mov edx, dword ptr [rsp]
    call bcrypt_word
    mov dword ptr [rsp], edx
    xor dword ptr [r12 + BF_P + r10 * 4], eax
    inc r10d
    cmp r10d, 18
    jb 1b

    xor ebx, ebx
    xor ecx, ecx
    xor r10d, r10d
2:
    mov rdi, r13
    mov esi, 16
    mov edx, dword ptr [rsp + 4]
    call bcrypt_word
    mov dword ptr [rsp + 4], edx
    xor ebx, eax
    mov rdi, r13
    mov esi, 16
    mov edx, dword ptr [rsp + 4]
    call bcrypt_word
    mov dword ptr [rsp + 4], edx
    xor ecx, eax
    mov rdi, r12
    mov esi, ebx
    mov edx, ecx
    mov dword ptr [rsp + 8], r10d
    call bcrypt_encrypt
    mov r10d, dword ptr [rsp + 8]
    mov dword ptr [r12 + BF_P + r10 * 4], eax
    mov dword ptr [r12 + BF_P + r10 * 4 + 4], edx
    add r10d, 2
    cmp r10d, 1042
    jb 2b

    add rsp, 16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.global bcrypt_hash
bcrypt_hash:
    cmp ecx, BCRYPT_MIN_COST
    jb .Lbcrypt_hash_invalid
    cmp ecx, BCRYPT_MAX_COST
    ja .Lbcrypt_hash_invalid
    cmp ecx, BCRYPT_APP_MAX_COST
    ja .Lbcrypt_hash_invalid
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 4248
    mov rbp, rsp
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov r14, rcx
    mov r15, r8
    mov qword ptr [rbp + 4224], rbx

    lea rsi, [rip + bcrypt_initial]
    mov rdi, rbp
    mov ecx, 1042
    rep movsd
    lea rdi, [rbp + BF_STATE]
    xor eax, eax
    mov ecx, 4
    rep stosd

    mov rdi, rbp
    mov rsi, r13
    mov rdx, rbx
    mov rcx, r12
    call bcrypt_expand

    mov eax, 1
    mov ecx, r14d
    shl eax, cl
    mov dword ptr [rbp + 4220], eax
1:
    lea rdi, [rbp]
    lea rsi, [rbp + BF_STATE]
    mov rdx, qword ptr [rbp + 4224]
    mov rcx, r12
    call bcrypt_expand
    mov rdi, rbp
    mov rsi, r13
    mov rdx, qword ptr [rbp + 4224]
    mov rcx, r12
    call bcrypt_expand
    dec dword ptr [rbp + 4220]
    jnz 1b

    mov r12, rbp
    mov eax, 0x4f727068
    mov edx, 0x65616e42
    mov rdi, rbp
    mov ecx, 64
3:
    call bcrypt_encrypt
    mov esi, eax
    dec ecx
    jnz 3b
    bswap eax
    bswap edx
    mov dword ptr [rbp + BF_STATE], eax
    mov dword ptr [rbp + BF_STATE + 4], edx
    mov eax, 0x65686f6c
    mov edx, 0x64657253
    mov rdi, rbp
    mov ecx, 64
4:
    call bcrypt_encrypt
    mov esi, eax
    dec ecx
    jnz 4b
    bswap eax
    bswap edx
    mov dword ptr [rbp + BF_STATE + 8], eax
    mov dword ptr [rbp + BF_STATE + 12], edx
    mov eax, 0x63727944
    mov edx, 0x6f756274
    mov rdi, rbp
    mov ecx, 64
5:
    call bcrypt_encrypt
    mov esi, eax
    dec ecx
    jnz 5b
    bswap eax
    bswap edx
    mov dword ptr [rbp + BF_STATE + 16], eax
    mov dword ptr [rbp + BF_STATE + 20], edx

    mov rsi, rbp
    mov rdi, r15
    mov ecx, 6
    rep movsd
    add rsp, 4248
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    xor eax, eax
    ret

.Lbcrypt_hash_invalid:
    mov eax, 1
    ret

.global bcrypt_verify
bcrypt_verify:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 40
    mov rbp, rsp
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov r14, rcx
    mov r15, r8
    lea r8, [rbp + 8]
    call bcrypt_hash
    test eax, eax
    jnz .Lbcrypt_verify_invalid

    mov rsi, r15
    lea rdi, [rbp + 8]
    xor eax, eax
    mov rdx, qword ptr [rdi]
    xor rdx, qword ptr [rsi]
    or rax, rdx
    mov rdx, qword ptr [rdi + 8]
    xor rdx, qword ptr [rsi + 8]
    or rax, rdx
    mov rdx, qword ptr [rdi + 16]
    xor rdx, qword ptr [rsi + 16]
    or rax, rdx
    test rax, rax
    sete al
    movzx eax, al
    add rsp, 40
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.Lbcrypt_verify_invalid:
    xor eax, eax
    add rsp, 40
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.section .rodata
.include "crypto/blowfish_constants.inc"
