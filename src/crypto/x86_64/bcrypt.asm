.intel_syntax noprefix

.include "common.inc"

.equ BF_P, 0
.equ BF_S, 72
.equ BF_STATE, 4176
.equ BCRYPT_MIN_COST, 4
.equ BCRYPT_MAX_COST, 31
.equ BCRYPT_APP_MAX_COST, 31
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
    mov ebx, eax
    mov ecx, edx
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
    call bcrypt_expand
    mov rdi, rbp
    lea rsi, [rbp + BCRYPT_SALT]
    mov rdx, r13
    mov ecx, BCRYPT_SALT_LEN
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
    mov ecx, 6
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

.global bcrypt_verify
bcrypt_verify:
    cmp rcx, BCRYPT_SALT_LEN
    jne .Lbcrypt_verify_invalid_args
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
    je 5f
    movzx edi, byte ptr [r12 + 2]
    call bcrypt_b64_value
    test eax, eax
    js 6f
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
    cmp rsi, 60
    jne .Lbcrypt_decode_invalid
    cmp byte ptr [rdi], '$'
    jne .Lbcrypt_decode_invalid
    cmp byte ptr [rdi + 1], '2'
    jne .Lbcrypt_decode_invalid
    cmp byte ptr [rdi + 2], 'b'
    jne .Lbcrypt_decode_invalid
    cmp byte ptr [rdi + 3], '$'
    jne .Lbcrypt_decode_invalid
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 8
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
    mov dword ptr [r13], eax
    lea rdi, [rbx + 7]
    mov esi, 22
    mov rdx, r12
    mov ecx, 16
    call bcrypt_b64_decode
    test eax, eax
    jnz .Lbcrypt_decode_invalid_pop
    lea rdi, [rbx + 29]
    mov esi, 31
    mov rdx, r14
    mov ecx, 23
    call bcrypt_b64_decode
    test eax, eax
    jnz .Lbcrypt_decode_invalid_pop
    xor eax, eax
    jmp .Lbcrypt_decode_done
.Lbcrypt_decode_invalid_pop:
    mov eax, 1
.Lbcrypt_decode_done:
    add rsp, 8
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.Lbcrypt_decode_invalid:
    mov eax, 1
    ret

.section .rodata
.include "crypto/blowfish_constants.inc"
bcrypt_alphabet:
    .ascii "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
