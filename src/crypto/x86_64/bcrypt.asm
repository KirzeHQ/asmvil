.intel_syntax noprefix

.include "common.inc"
.include "abi.inc"

.equ BF_P, 0
.equ BF_S, 72
.equ BF_STATE, 4176
.equ BCRYPT_MIN_COST, 4
.equ BCRYPT_MAX_COST, 31
.equ BCRYPT_APP_MAX_COST, 31
.equ BCRYPT_OUTPUT_INVALID, 4
.equ BCRYPT_VARIANT_2A, 1
.equ BCRYPT_VARIANT_2B, 2
.equ BCRYPT_VARIANT_2Y, 3
.equ BCRYPT_HASH_V2_SIZE, 72
.equ BCRYPT_REQ_VERSION, 0
.equ BCRYPT_REQ_SIZE, 4
.equ BCRYPT_REQ_VARIANT, 8
.equ BCRYPT_REQ_PASSWORD, 16
.equ BCRYPT_REQ_PASSWORD_LEN, 24
.equ BCRYPT_REQ_SALT, 32
.equ BCRYPT_REQ_SALT_LEN, 40
.equ BCRYPT_REQ_COST, 48
.equ BCRYPT_REQ_OUTPUT, 56
.equ BCRYPT_REQ_OUTPUT_LEN, 64
.equ BCRYPT_MODE, 4292
.equ BCRYPT_ENCODE_V2_SIZE, 56
.equ BCRYPT_ENCODE_REQ_SALT, 16
.equ BCRYPT_ENCODE_REQ_CHECKSUM, 24
.equ BCRYPT_ENCODE_REQ_COST, 32
.equ BCRYPT_ENCODE_REQ_OUTPUT, 40
.equ BCRYPT_ENCODE_REQ_OUTPUT_LEN, 48
.equ BCRYPT_DECODE_V2_SIZE, 56
.equ BCRYPT_DECODE_REQ_HASH, 8
.equ BCRYPT_DECODE_REQ_HASH_LEN, 16
.equ BCRYPT_DECODE_REQ_SALT, 24
.equ BCRYPT_DECODE_REQ_COST, 32
.equ BCRYPT_DECODE_REQ_CHECKSUM, 40
.equ BCRYPT_DECODE_REQ_VARIANT, 48
.equ BCRYPT_MAX_PASSWORD, 72
.equ BCRYPT_SALT_LEN, 16
.equ SYS_GETRANDOM, 318
.equ BCRYPT_STACK, 4336
.equ BCRYPT_SALT, 4176
.equ BCRYPT_KEY, 4192
.equ BCRYPT_KEY_PTR, 4280
.equ BCRYPT_KEY_LEN, 4288
.equ BCRYPT_ROUNDS, 4276

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

bcrypt_word_2a:
    xor r8d, r8d
    xor r9d, r9d
    movsx eax, byte ptr [rdi + rdx]
    shl eax, 24
    mov r8d, eax
    inc rdx
    cmp rdx, rsi
    jb 5f
    xor edx, edx
5:
    movsx eax, byte ptr [rdi + rdx]
    test eax, 0x80
    jz 6f
    or r9d, 0x80
6:
    shl eax, 16
    or r8d, eax
    inc rdx
    cmp rdx, rsi
    jb 7f
    xor edx, edx
7:
    movsx eax, byte ptr [rdi + rdx]
    test eax, 0x80
    jz 8f
    or r9d, 0x80
8:
    shl eax, 8
    or r8d, eax
    inc rdx
    cmp rdx, rsi
    jb 9f
    xor edx, edx
9:
    movsx eax, byte ptr [rdi + rdx]
    test eax, 0x80
    jz 10f
    or r9d, 0x80
10:
    or r8d, eax
    inc rdx
    cmp rdx, rsi
    jb 11f
    xor edx, edx
11:
    mov eax, r8d
    ret

.ifdef ASMVIL_TESTING
.global bcrypt_debug_stream_word
bcrypt_debug_stream_word:
    call bcrypt_word
    mov r8d, eax
    shl r8, 32
    mov eax, edx
    or rax, r8
    ret
.endif

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
    sub rsp, 32
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    mov dword ptr [rsp + 12], r8d
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

    cmp dword ptr [rsp + 12], BCRYPT_VARIANT_2A
    jne 18f
    mov dword ptr [rsp + 16], 0
    mov dword ptr [rsp + 20], 0
    mov dword ptr [rsp + 24], 0
    xor r10d, r10d
12:
    cmp r10d, 18
    jae 16f
    mov rdi, r14
    mov rsi, r15
    mov edx, dword ptr [rsp + 24]
    mov dword ptr [rsp + 28], edx
    call bcrypt_word
    mov dword ptr [rsp + 24], edx
    mov ebx, eax
    mov rdi, r14
    mov rsi, r15
    mov edx, dword ptr [rsp + 28]
    call bcrypt_word_2a
    xor ebx, eax
    or dword ptr [rsp + 16], ebx
    or dword ptr [rsp + 20], r9d
    inc r10d
    jmp 12b
16:
    mov eax, dword ptr [rsp + 16]
    shr eax, 16
    or eax, dword ptr [rsp + 16]
    and eax, 0xffff
    add eax, 0xffff
    mov ecx, dword ptr [rsp + 20]
    shl ecx, 9
    and ecx, 0x10000
    not eax
    and ecx, eax
    test ecx, ecx
    jz 17f
    xor dword ptr [r12 + BF_P], 0x10000
17:
18:
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
    mov ebx, eax
    mov ecx, edx
    mov dword ptr [r12 + BF_P + r10 * 4], eax
    mov dword ptr [r12 + BF_P + r10 * 4 + 4], edx
    add r10d, 2
    cmp r10d, 1042
    jb 2b

    add rsp, 32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.global bcrypt_hash
bcrypt_hash:
    mov r10d, BCRYPT_VARIANT_2B
    jmp .Lbcrypt_hash_core

.global bcrypt_hash_v2
bcrypt_hash_v2:
    test rdi, rdi
    jz .Lbcrypt_hash_v2_invalid
    cmp dword ptr [rdi + BCRYPT_REQ_VERSION], ABI_VERSION_2
    jne .Lbcrypt_hash_v2_invalid
    cmp dword ptr [rdi + BCRYPT_REQ_SIZE], BCRYPT_HASH_V2_SIZE
    jb .Lbcrypt_hash_v2_invalid
    mov r11, rdi
    mov r10d, dword ptr [r11 + BCRYPT_REQ_VARIANT]
    cmp r10d, BCRYPT_VARIANT_2A
    jb .Lbcrypt_hash_v2_invalid
    cmp r10d, BCRYPT_VARIANT_2Y
    ja .Lbcrypt_hash_v2_invalid
    mov rdi, qword ptr [r11 + BCRYPT_REQ_PASSWORD]
    mov rsi, qword ptr [r11 + BCRYPT_REQ_PASSWORD_LEN]
    mov rdx, qword ptr [r11 + BCRYPT_REQ_SALT]
    mov rcx, qword ptr [r11 + BCRYPT_REQ_SALT_LEN]
    mov r8d, dword ptr [r11 + BCRYPT_REQ_COST]
    mov r9, qword ptr [r11 + BCRYPT_REQ_OUTPUT]
    cmp qword ptr [r11 + BCRYPT_REQ_OUTPUT_LEN], 23
    jb .Lbcrypt_output_invalid
    jmp .Lbcrypt_hash_core

.Lbcrypt_hash_v2_invalid:
    mov eax, 1
    ret

.Lbcrypt_hash_core:
    cmp r8d, BCRYPT_MIN_COST
    jb .Lbcrypt_hash_invalid
    cmp r8d, BCRYPT_MAX_COST
    ja .Lbcrypt_hash_invalid
    cmp r8d, BCRYPT_APP_MAX_COST
    ja .Lbcrypt_hash_invalid
    cmp rsi, BCRYPT_MAX_PASSWORD
    ja .Lbcrypt_password_invalid
    cmp ecx, BCRYPT_SALT_LEN
    jne .Lbcrypt_salt_invalid
    test r9, r9
    jz .Lbcrypt_output_invalid
    test rdx, rdx
    jz .Lbcrypt_salt_invalid
    test rsi, rsi
    jz 8f
    test rdi, rdi
    jz .Lbcrypt_password_invalid
8:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, BCRYPT_STACK
    mov rbp, rsp
    mov dword ptr [rbp + BCRYPT_MODE], r10d
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov r14, r8
    mov r15, r9
    lea rdi, [rbp + BCRYPT_KEY]
    mov rcx, r12
    mov rsi, rbx
    rep movsb
    mov byte ptr [rbp + BCRYPT_KEY + r12], 0
    lea rax, [rbp + BCRYPT_KEY]
    mov qword ptr [rbp + BCRYPT_KEY_PTR], rax
    lea eax, [r12 + 1]
    cmp eax, BCRYPT_MAX_PASSWORD
    jbe 6f
    mov eax, BCRYPT_MAX_PASSWORD
6:
    mov dword ptr [rbp + BCRYPT_KEY_LEN], eax

    lea rsi, [rip + bcrypt_initial]
    mov rdi, rbp
    mov ecx, 1042
    rep movsd
    lea rdi, [rbp + BCRYPT_SALT]
    xor eax, eax
    mov ecx, 4
    rep stosd

    mov rdi, rbp
    mov rsi, r13
    mov rdx, qword ptr [rbp + BCRYPT_KEY_PTR]
    mov ecx, dword ptr [rbp + BCRYPT_KEY_LEN]
    mov r8d, dword ptr [rbp + BCRYPT_MODE]
    call bcrypt_expand

    mov eax, 1
    mov ecx, r14d
    shl eax, cl
    mov dword ptr [rbp + BCRYPT_ROUNDS], eax
1:
    lea rdi, [rbp]
    lea rsi, [rbp + BCRYPT_SALT]
    mov rdx, qword ptr [rbp + BCRYPT_KEY_PTR]
    mov ecx, dword ptr [rbp + BCRYPT_KEY_LEN]
    xor r8d, r8d
    call bcrypt_expand
    mov rdi, rbp
    lea rsi, [rbp + BCRYPT_SALT]
    mov rdx, r13
    mov ecx, BCRYPT_SALT_LEN
    xor r8d, r8d
    call bcrypt_expand
    dec dword ptr [rbp + BCRYPT_ROUNDS]
    jnz 1b

    mov r12, rbp
    mov eax, 0x4f727068
    mov esi, eax
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
    mov esi, eax
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
    mov esi, eax
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

    lea rsi, [rbp + BF_STATE]
    mov rdi, r15
    mov ecx, 23
    rep movsb
    xor eax, eax
    mov ecx, BCRYPT_STACK / 8
    mov rdi, rbp
    rep stosq
    add rsp, BCRYPT_STACK
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

.ifdef ASMVIL_TESTING
.global bcrypt_debug_initial_state
bcrypt_debug_initial_state:
    cmp rsi, BCRYPT_MAX_PASSWORD
    ja .Lbcrypt_debug_state_invalid
    cmp rcx, BCRYPT_SALT_LEN
    jne .Lbcrypt_debug_state_invalid
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, BCRYPT_STACK
    mov rbp, rsp
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov r14, r8
    mov r15, r9
    lea rdi, [rbp + BCRYPT_KEY]
    mov rcx, r12
    mov rsi, rbx
    rep movsb
    mov byte ptr [rbp + BCRYPT_KEY + r12], 0
    lea rax, [rbp + BCRYPT_KEY]
    mov qword ptr [rbp + BCRYPT_KEY_PTR], rax
    lea eax, [r12 + 1]
    cmp eax, BCRYPT_MAX_PASSWORD
    jbe 7f
    mov eax, BCRYPT_MAX_PASSWORD
7:
    mov dword ptr [rbp + BCRYPT_KEY_LEN], eax
    lea rsi, [rip + bcrypt_initial]
    mov rdi, rbp
    mov ecx, 1042
    rep movsd
    lea rdi, [rbp + BCRYPT_SALT]
    xor eax, eax
    mov ecx, 4
    rep stosd
    mov rdi, rbp
    mov rsi, r13
    mov rdx, qword ptr [rbp + BCRYPT_KEY_PTR]
    mov ecx, dword ptr [rbp + BCRYPT_KEY_LEN]
    call bcrypt_expand
    mov rdi, r14
    mov rsi, rbp
    mov ecx, 18
    rep movsd
    mov rdi, r15
    lea rsi, [rbp + BF_S]
    mov ecx, 16
    rep movsd
    xor eax, eax
    mov ecx, BCRYPT_STACK / 8
    mov rdi, rbp
    rep stosq
    add rsp, BCRYPT_STACK
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    xor eax, eax
    ret
.Lbcrypt_debug_state_invalid:
    mov eax, 1
    ret
.endif

.Lbcrypt_password_invalid:
    mov eax, 2
    ret

.Lbcrypt_salt_invalid:
    mov eax, 3
    ret
.Lbcrypt_output_invalid:
    mov eax, BCRYPT_OUTPUT_INVALID
    ret

.global bcrypt_verify
bcrypt_verify:
    cmp rcx, BCRYPT_SALT_LEN
    jne .Lbcrypt_verify_invalid_args
    test rdx, rdx
    jz .Lbcrypt_verify_invalid_args
    test r9, r9
    jz .Lbcrypt_verify_invalid_args
    test rsi, rsi
    jz 9f
    test rdi, rdi
    jz .Lbcrypt_verify_invalid_args
9:
    cmp rsi, BCRYPT_MAX_PASSWORD
    ja .Lbcrypt_verify_invalid_args
    cmp r8d, BCRYPT_MIN_COST
    jb .Lbcrypt_verify_invalid_args
    cmp r8d, BCRYPT_APP_MAX_COST
    ja .Lbcrypt_verify_invalid_args
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
    mov r14, r8
    mov r15, r9
    mov rdi, rbx
    mov rsi, r12
    mov rdx, r13
    mov ecx, BCRYPT_SALT_LEN
    mov r8, r14
    lea r9, [rbp + 8]
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
    movabs rcx, 0x00ffffffffffffff
    and rdx, rcx
    or rax, rdx
    test rax, rax
    sete al
    movzx eax, al
    mov r10d, eax
    xor eax, eax
    lea rdi, [rbp]
    mov ecx, 5
    rep stosq
    mov eax, r10d
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
    mov r10d, eax
    xor eax, eax
    lea rdi, [rbp]
    mov ecx, 5
    rep stosq
    mov eax, r10d
    add rsp, 40
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.Lbcrypt_verify_invalid_args:
    xor eax, eax
    ret

.global bcrypt_generate_salt
bcrypt_generate_salt:
    test rdi, rdi
    jz .Lbcrypt_null_salt_fail
    push rbx
    push r12
    push r13
    mov rbx, rdi
    xor r12d, r12d
    mov r13d, BCRYPT_SALT_LEN
.Lbcrypt_getrandom:
    lea rdi, [rbx + r12]
    mov rsi, r13
    xor edx, edx
    mov eax, SYS_GETRANDOM
    syscall
    test rax, rax
    js .Lbcrypt_getrandom_fail
    test rax, rax
    jz .Lbcrypt_getrandom
    add r12, rax
    sub r13, rax
    jnz .Lbcrypt_getrandom
    xor eax, eax
    pop r13
    pop r12
    pop rbx
    ret
.Lbcrypt_null_salt_fail:
    mov eax, 1
    ret
.Lbcrypt_getrandom_fail:
    mov eax, 1
    pop r13
    pop r12
    pop rbx
    ret

.type bcrypt_b64_value, @function
bcrypt_b64_value:
    lea rsi, [rip + bcrypt_alphabet]
    xor ecx, ecx
1:
    cmp cl, 64
    jae 2f
    cmp dil, byte ptr [rsi + rcx]
    je 3f
    inc ecx
    jmp 1b
2:
    mov eax, -1
    ret
3:
    mov eax, ecx
    ret

.type bcrypt_b64_encode, @function
bcrypt_b64_encode:
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    lea rsi, [rip + bcrypt_alphabet]
    xor edx, edx
1:
    cmp rdx, r13
    jae 5f
    movzx eax, byte ptr [r12 + rdx]
    mov ecx, eax
    shr eax, 2
    movzx eax, byte ptr [rsi + rax]
    mov byte ptr [r15], al
    mov eax, ecx
    and eax, 3
    shl eax, 4
    inc rdx
    cmp rdx, r13
    jae 4f
    movzx ecx, byte ptr [r12 + rdx]
    mov eax, eax
    mov edi, ecx
    shr edi, 4
    or eax, edi
    movzx eax, byte ptr [rsi + rax]
    mov byte ptr [r15 + 1], al
    mov eax, ecx
    and eax, 15
    shl eax, 2
    inc rdx
    cmp rdx, r13
    jae 3f
    movzx ecx, byte ptr [r12 + rdx]
    mov edi, ecx
    shr edi, 6
    or eax, edi
    movzx eax, byte ptr [rsi + rax]
    mov byte ptr [r15 + 2], al
    mov eax, ecx
    and eax, 63
    movzx eax, byte ptr [rsi + rax]
    mov byte ptr [r15 + 3], al
    add r15, 4
    inc rdx
    jmp 1b
3:
    movzx eax, byte ptr [rsi + rax]
    mov byte ptr [r15 + 2], al
    add r15, 3
    jmp 1b
4:
    movzx eax, byte ptr [rsi + rax]
    mov byte ptr [r15 + 1], al
    add r15, 2
    jmp 1b
5:
    mov rax, r15
    sub rax, rcx
    pop r15
    pop r14
    pop r13
    pop r12
    ret

.type bcrypt_b64_decode, @function
bcrypt_b64_decode:
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    xor edx, edx
1:
    cmp r13, 4
    jb 4f
    movzx edi, byte ptr [r12]
    call bcrypt_b64_value
    test eax, eax
    js 6f
    mov dword ptr [rsp], eax
    movzx edi, byte ptr [r12 + 1]
    call bcrypt_b64_value
    test eax, eax
    js 6f
    mov dword ptr [rsp + 4], eax
    movzx edi, byte ptr [r12 + 2]
    call bcrypt_b64_value
    test eax, eax
    js 6f
    mov dword ptr [rsp + 8], eax
    movzx edi, byte ptr [r12 + 3]
    call bcrypt_b64_value
    test eax, eax
    js 6f
    mov dword ptr [rsp + 12], eax
    mov eax, dword ptr [rsp]
    shl eax, 2
    mov ecx, dword ptr [rsp + 4]
    shr ecx, 4
    or eax, ecx
    mov byte ptr [r14], al
    mov eax, dword ptr [rsp + 4]
    shl eax, 4
    mov ecx, dword ptr [rsp + 8]
    shr ecx, 2
    or eax, ecx
    mov byte ptr [r14 + 1], al
    mov eax, dword ptr [rsp + 8]
    shl eax, 6
    or eax, dword ptr [rsp + 12]
    mov byte ptr [r14 + 2], al
    add r12, 4
    sub r13, 4
    add r14, 3
    sub r15, 3
    jmp 1b
4:
    cmp r13, 2
    jb 6f
    movzx edi, byte ptr [r12]
    call bcrypt_b64_value
    test eax, eax
    js 6f
    mov dword ptr [rsp], eax
    movzx edi, byte ptr [r12 + 1]
    call bcrypt_b64_value
    test eax, eax
    js 6f
    mov dword ptr [rsp + 4], eax
    mov eax, dword ptr [rsp]
    shl eax, 2
    mov ecx, dword ptr [rsp + 4]
    shr ecx, 4
    or eax, ecx
    mov byte ptr [r14], al
    cmp r13, 2
    jne 8f
    test dword ptr [rsp + 4], 15
    jnz 6f
    jmp 5f
8:
    movzx edi, byte ptr [r12 + 2]
    call bcrypt_b64_value
    test eax, eax
    js 6f
    test eax, 3
    jnz 6f
    mov ecx, dword ptr [rsp + 4]
    shl ecx, 4
    shr eax, 2
    or eax, ecx
    mov byte ptr [r14 + 1], al
5:
    xor eax, eax
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    ret
6:
    mov eax, 1
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    ret

.global bcrypt_encode
bcrypt_encode:
    mov r10d, BCRYPT_VARIANT_2B
    jmp .Lbcrypt_encode_core

.global bcrypt_encode_v2
bcrypt_encode_v2:
    test rdi, rdi
    jz .Lbcrypt_encode_invalid
    cmp dword ptr [rdi], ABI_VERSION_2
    jne .Lbcrypt_encode_invalid
    cmp dword ptr [rdi + 4], BCRYPT_ENCODE_V2_SIZE
    jb .Lbcrypt_encode_invalid
    mov r11, rdi
    mov r10d, dword ptr [r11 + 8]
    cmp r10d, BCRYPT_VARIANT_2A
    jb .Lbcrypt_encode_invalid
    cmp r10d, BCRYPT_VARIANT_2Y
    ja .Lbcrypt_encode_invalid
    mov rdi, qword ptr [r11 + BCRYPT_ENCODE_REQ_SALT]
    mov rsi, qword ptr [r11 + BCRYPT_ENCODE_REQ_CHECKSUM]
    mov edx, dword ptr [r11 + BCRYPT_ENCODE_REQ_COST]
    mov rcx, qword ptr [r11 + BCRYPT_ENCODE_REQ_OUTPUT]
    cmp qword ptr [r11 + BCRYPT_ENCODE_REQ_OUTPUT_LEN], 61
    jb .Lbcrypt_encode_invalid

.Lbcrypt_encode_core:
    test rdi, rdi
    jz .Lbcrypt_encode_invalid
    test rsi, rsi
    jz .Lbcrypt_encode_invalid
    test rcx, rcx
    jz .Lbcrypt_encode_invalid
    cmp edx, BCRYPT_MIN_COST
    jb .Lbcrypt_encode_invalid
    cmp edx, BCRYPT_APP_MAX_COST
    ja .Lbcrypt_encode_invalid
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    mov r12, rsi
    mov r13, rcx
    mov r14d, edx
    mov dword ptr [r13], 0x24623224
    cmp r10d, BCRYPT_VARIANT_2B
    je 11f
    cmp r10d, BCRYPT_VARIANT_2A
    jne 12f
    mov byte ptr [r13 + 2], 'a'
    jmp 12f
11:
    mov byte ptr [r13 + 2], 'b'
12:
    cmp r10d, BCRYPT_VARIANT_2Y
    jne 13f
    mov byte ptr [r13 + 2], 'y'
13:
    mov eax, r14d
    xor edx, edx
    mov ecx, 10
    div ecx
    add eax, '0'
    mov byte ptr [r13 + 4], al
    add edx, '0'
    mov byte ptr [r13 + 5], dl
    mov byte ptr [r13 + 6], '$'
    mov rdi, rbx
    mov esi, 16
    lea rdx, [r13 + 7]
    mov rcx, rdx
    call bcrypt_b64_encode
    mov rdi, r12
    mov esi, 23
    lea rdx, [r13 + 29]
    mov rcx, rdx
    call bcrypt_b64_encode
    mov byte ptr [r13 + 60], 0
    xor eax, eax
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.Lbcrypt_encode_invalid:
    mov eax, 1
    ret

.global bcrypt_decode
bcrypt_decode:
    test rdi, rdi
    jz .Lbcrypt_decode_invalid
    test rdx, rdx
    jz .Lbcrypt_decode_invalid
    test rcx, rcx
    jz .Lbcrypt_decode_invalid
    test r8, r8
    jz .Lbcrypt_decode_invalid
    cmp rsi, 60
    jne .Lbcrypt_decode_invalid
    cmp byte ptr [rdi], '$'
    jne .Lbcrypt_decode_invalid
    cmp byte ptr [rdi + 1], '2'
    jne .Lbcrypt_decode_invalid
    movzx eax, byte ptr [rdi + 2]
    cmp al, 'b'
    je 7f
    cmp al, 'y'
    jne .Lbcrypt_decode_invalid
7:
    cmp byte ptr [rdi + 3], '$'
    jne .Lbcrypt_decode_invalid
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 80
    mov rbx, rdi
    mov r12, rdx
    mov r13, rcx
    mov r14, r8
    movzx eax, byte ptr [rbx + 4]
    sub eax, '0'
    cmp eax, 9
    ja .Lbcrypt_decode_invalid_pop
    imul eax, 10
    movzx ecx, byte ptr [rbx + 5]
    sub ecx, '0'
    cmp ecx, 9
    ja .Lbcrypt_decode_invalid_pop
    add eax, ecx
    cmp eax, BCRYPT_MIN_COST
    jb .Lbcrypt_decode_invalid_pop
    cmp eax, BCRYPT_APP_MAX_COST
    ja .Lbcrypt_decode_invalid_pop
    mov dword ptr [rsp + 16], eax
    lea rdi, [rbx + 7]
    mov esi, 22
    lea rdx, [rsp + 32]
    mov ecx, 16
    call bcrypt_b64_decode
    test eax, eax
    jnz .Lbcrypt_decode_invalid_pop
    lea rdi, [rbx + 29]
    mov esi, 31
    lea rdx, [rsp + 48]
    mov ecx, 23
    call bcrypt_b64_decode
    test eax, eax
    jnz .Lbcrypt_decode_invalid_pop
    mov eax, dword ptr [rsp + 16]
    mov dword ptr [r13], eax
    lea rsi, [rsp + 32]
    mov rdi, r12
    mov ecx, 16
    rep movsb
    lea rsi, [rsp + 48]
    mov rdi, r14
    mov ecx, 23
    rep movsb
    xor eax, eax
    jmp .Lbcrypt_decode_done
.Lbcrypt_decode_invalid_pop:
    mov eax, 1
.Lbcrypt_decode_done:
    add rsp, 80
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.Lbcrypt_decode_invalid:
    mov eax, 1
    ret

.global bcrypt_decode_v2
bcrypt_decode_v2:
    test rdi, rdi
    jz .Lbcrypt_decode_v2_invalid
    cmp dword ptr [rdi], ABI_VERSION_2
    jne .Lbcrypt_decode_v2_invalid
    cmp dword ptr [rdi + 4], BCRYPT_DECODE_V2_SIZE
    jb .Lbcrypt_decode_v2_invalid
    mov r11, rdi
    mov rdi, qword ptr [r11 + BCRYPT_DECODE_REQ_HASH]
    mov rsi, qword ptr [r11 + BCRYPT_DECODE_REQ_HASH_LEN]
    mov rdx, qword ptr [r11 + BCRYPT_DECODE_REQ_SALT]
    mov rcx, qword ptr [r11 + BCRYPT_DECODE_REQ_COST]
    mov r8, qword ptr [r11 + BCRYPT_DECODE_REQ_CHECKSUM]
    mov r9, qword ptr [r11 + BCRYPT_DECODE_REQ_VARIANT]
    test rdi, rdi
    jz .Lbcrypt_decode_v2_invalid
    test rdx, rdx
    jz .Lbcrypt_decode_v2_invalid
    test rcx, rcx
    jz .Lbcrypt_decode_v2_invalid
    test r8, r8
    jz .Lbcrypt_decode_v2_invalid
    test r9, r9
    jz .Lbcrypt_decode_v2_invalid
    cmp rsi, 60
    jne .Lbcrypt_decode_v2_invalid
    sub rsp, 80
    mov qword ptr [rsp + 68], r9
    mov r10, rdi
    mov rdi, rsp
    mov rsi, r10
    mov ecx, 60
    rep movsb
    movzx eax, byte ptr [rsp + 2]
    cmp al, 'a'
    je 14f
    cmp al, 'b'
    je 15f
    cmp al, 'y'
    jne .Lbcrypt_decode_v2_cleanup_invalid
    mov dword ptr [rsp + 64], BCRYPT_VARIANT_2Y
    jmp 16f
14:
    mov dword ptr [rsp + 64], BCRYPT_VARIANT_2A
    mov byte ptr [rsp + 2], 'b'
    jmp 16f
15:
    mov dword ptr [rsp + 64], BCRYPT_VARIANT_2B
16:
    mov rdi, rsp
    mov esi, 60
    mov rdx, qword ptr [r11 + BCRYPT_DECODE_REQ_SALT]
    mov rcx, qword ptr [r11 + BCRYPT_DECODE_REQ_COST]
    mov r8, qword ptr [r11 + BCRYPT_DECODE_REQ_CHECKSUM]
    call bcrypt_decode
    test eax, eax
    jnz .Lbcrypt_decode_v2_cleanup_invalid
    mov rdi, qword ptr [rsp + 68]
    mov eax, dword ptr [rsp + 64]
    mov dword ptr [rdi], eax
    xor eax, eax
    add rsp, 80
    ret
.Lbcrypt_decode_v2_cleanup_invalid:
    mov eax, 1
    add rsp, 80
    ret
.Lbcrypt_decode_v2_invalid:
    mov eax, 1
    ret

.global bcrypt_hash_v1
.set bcrypt_hash_v1, bcrypt_hash
.global bcrypt_verify_v1
.set bcrypt_verify_v1, bcrypt_verify
.global bcrypt_generate_salt_v1
.set bcrypt_generate_salt_v1, bcrypt_generate_salt
.global bcrypt_encode_v1
.set bcrypt_encode_v1, bcrypt_encode
.global bcrypt_decode_v1
.set bcrypt_decode_v1, bcrypt_decode

.section .rodata
.include "crypto/blowfish_constants.inc"
bcrypt_alphabet:
    .ascii "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
