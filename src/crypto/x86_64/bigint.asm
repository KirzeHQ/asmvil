.intel_syntax noprefix
.include "common.inc"

# Big-integer arithmetic for x86-64
# See ../bigint.inc for the shared API and semantics.

# SysV args: arg1=rdi, arg2=rsi, arg3=rdx, arg4=rcx.

.section .text

.global bigint_add
.global bigint_sub
.global bigint_mul
.global bigint_sqr
.global bigint_shl
.global bigint_shr
.global bigint_cmp
.global ct_eq
.global ct_lt
.global ct_select

# bigint_add(rdi=dst, rsi=a, rdx=b, rcx=limbs) -> rax=carry
bigint_add:
    xor eax, eax
    clc
    test rcx, rcx
    jz 1f
0:
    mov r8, [rsi]
    adc r8, [rdx]
    mov [rdi], r8
    lea rsi, [rsi + 8]
    lea rdx, [rdx + 8]
    lea rdi, [rdi + 8]
    dec rcx
    jnz 0b
    adc eax, 0
1:
    ret

# bigint_sub(rdi=dst, rsi=a, rdx=b, rcx=limbs) -> rax=borrow
bigint_sub:
    xor eax, eax
    clc
    test rcx, rcx
    jz 1f
0:
    mov r8, [rsi]
    sbb r8, [rdx]
    mov [rdi], r8
    lea rsi, [rsi + 8]
    lea rdx, [rdx + 8]
    lea rdi, [rdi + 8]
    dec rcx
    jnz 0b
    sbb eax, 0
    and eax, 1
1:
    ret

# bigint_mul(rdi=dst, rsi=a, rdx=b, rcx=limbs), dst has 2*limbs
bigint_mul:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx

    xor eax, eax
    lea rcx, [r15*2]
    mov rdi, r12
    rep stosq

    xor ebx, ebx
1:
    cmp rbx, r15
    jae 4f
    mov r10, [r13 + rbx*8]
    xor ecx, ecx
    xor r11d, r11d
2:
    cmp rcx, r15
    jae 3f
    mov rax, r10
    mul qword ptr [r14 + rcx*8]
    add rax, r11
    adc rdx, 0
    lea r9, [rbx + rcx]
    mov r8, [r12 + r9*8]
    add rax, r8
    adc rdx, 0
    lea r9, [rbx + rcx]
    mov [r12 + r9*8], rax
    mov r11, rdx
    add rcx, 1
    jmp 2b
3:
    lea rax, [rbx + r15]
    mov rdx, [r12 + rax*8]
    add rdx, r11
    mov [r12 + rax*8], rdx
    add rbx, 1
    jmp 1b
4:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

# bigint_sqr(rdi=dst, rsi=a, rdx=limbs), dst has 2*limbs
bigint_sqr:
    mov rcx, rdx
    mov rdx, rsi
    jmp bigint_mul

# bigint_shl(rdi=dst, rsi=a, rdx=limbs, rcx=bits) - bits < 64
# new[0] = a[0] << bits; new[i] = (a[i] << bits) | (a[i-1] >> (64-bits))
bigint_shl:
    push rbx
    push r12
    push r13
    mov r12, rdi
    mov r13, rsi
    mov rbx, rdx
    mov r8, rcx
    mov r9, 64
    sub r9, r8          # r9 = 64 - bits
    test rbx, rbx
    jz 3f
    mov r10, [r13]
    mov rcx, r8
    shl r10, cl
    mov [r12], r10
    mov rax, 1
1:
    cmp rax, rbx
    jae 3f
    mov r10, [r13 + rax*8]
    mov rcx, r8
    shl r10, cl
    mov rcx, r9
    mov rdx, [r13 + rax*8 - 8]
    shr rdx, cl
    or r10, rdx
    mov [r12 + rax*8], r10
    add rax, 1
    jmp 1b
3:
    pop r13
    pop r12
    pop rbx
    ret

# bigint_shr(rdi=dst, rsi=a, rdx=limbs, rcx=bits) - bits < 64
# new[last] = a[last] >> bits; new[i] = (a[i] >> bits) | (a[i+1] << (64-bits))
bigint_shr:
    push rbx
    push r12
    push r13
    mov r12, rdi
    mov r13, rsi
    mov rbx, rdx
    mov r8, rcx
    mov r9, 64
    sub r9, r8          # r9 = 64 - bits
    test rbx, rbx
    jz 3f
    lea rax, [rbx - 1]
    mov r10, [r13 + rax*8]
    mov rcx, r8
    shr r10, cl
    mov [r12 + rax*8], r10
    test rax, rax
    jz 3f
1:
    lea r11, [rax - 1]
    mov r10, [r13 + r11*8]
    mov rcx, r8
    shr r10, cl
    mov rcx, r9
    mov rdx, [r13 + rax*8]
    shl rdx, cl
    or r10, rdx
    mov [r12 + r11*8], r10
    mov rax, r11
    test rax, rax
    jnz 1b
3:
    pop r13
    pop r12
    pop rbx
    ret

# bigint_cmp(rdi=a, rsi=b, rdx=limbs) -> rax = -1/0/1 (unsigned)
bigint_cmp:
    lea rax, [rdx - 1]
0:
    mov r8, [rdi + rax*8]
    mov r9, [rsi + rax*8]
    cmp r8, r9
    ja 1f
    jb 2f
    test rax, rax
    jz 3f
    sub rax, 1
    jmp 0b
1:
    mov rax, 1
    ret
2:
    mov rax, -1
    ret
3:
    xor eax, eax
    ret

# ct_eq(rdi=a, rsi=b, rdx=limbs) -> rax = 1 if a == b else 0, constant time
ct_eq:
    xor eax, eax
0:
    test rdx, rdx
    jz 1f
    mov r8, [rdi]
    xor r8, [rsi]
    or rax, r8
    lea rdi, [rdi + 8]
    lea rsi, [rsi + 8]
    dec rdx
    jnz 0b
1:
    or rax, rax
    sete al
    movzx eax, al
    ret

# ct_lt(rdi=a, rsi=b, rdx=limbs) -> rax = 1 if a < b else 0, constant time
ct_lt:
    clc
0:
    test rdx, rdx
    jz 1f
    mov r8, [rdi]
    mov r9, [rsi]
    sbb r8, r9
    lea rdi, [rdi + 8]
    lea rsi, [rsi + 8]
    dec rdx
    jnz 0b
1:
    setc al
    ret

# ct_select(rdi=dst, rsi=a, rdx=b, rcx=limbs, r8=bit) - dst = bit ? b : a, constant time
ct_select:
    neg r8
    sbb r9, r9
    push rbx
    xor ebx, ebx
0:
    cmp rbx, rcx
    jae 2f
    mov rax, [rsi + rbx*8]
    mov r10, [rdx + rbx*8]
    xor r10, rax
    and r10, r9
    xor rax, r10
    mov [rdi + rbx*8], rax
    add rbx, 1
    jmp 0b
2:
    pop rbx
    ret
