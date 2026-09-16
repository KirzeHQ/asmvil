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
.global bigint_mod_reduce
.global bigint_mod_inv_prime
.global bigint_mod_inv_odd

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
    test rdx, rdx
    jz 1f
    clc
0:
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

# bigint_mod_reduce(rdi=dst, rsi=input[2*n], rdx=modulus[n], rcx=n)
# Reduces a wide unsigned value with a fixed 128*n-bit restoring division.
bigint_mod_reduce:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    lea rax, [r15*8]
    lea rdx, [rax*2]
    sub rsp, rdx
    mov rbp, rsp
    mov rdi, rbp
    xor eax, eax
    mov rcx, r15
    rep stosq
    lea r8, [rbp + r15*8]
    mov rbx, r15
    shl rbx, 7
.Lred_bit:
    lea rax, [rbx - 1]
    mov rdx, rax
    shr rdx, 6
    and eax, 63
    mov rcx, [r13 + rdx*8]
    bt rcx, rax
    setc r10b
    xor edx, edx
    mov r11, r15
    bt r10, 0
.Lred_shift:
    mov rax, [rbp + rdx*8]
    adc rax, rax
    mov [rbp + rdx*8], rax
    inc rdx
    dec r11
    jnz .Lred_shift
.Lred_shift_done:
    setc r10b
    mov rdi, r8
    mov rsi, rbp
    mov rdx, r14
    mov rcx, r15
    clc
.Lred_sub:
    mov rax, [rsi]
    sbb rax, [rdx]
    mov [rdi], rax
    lea rsi, [rsi + 8]
    lea rdx, [rdx + 8]
    lea rdi, [rdi + 8]
    dec rcx
    jnz .Lred_sub
.Lred_sub_done:
    setc r11b
    movzx r10d, r10b
    movzx r11d, r11b
    xor r11d, 1
    or r10d, r11d
    neg r10
    xor edx, edx
.Lred_select:
    cmp rdx, r15
    jae .Lred_select_done
    mov rax, [rbp + rdx*8]
    mov rcx, [r8 + rdx*8]
    xor rcx, rax
    and rcx, r10
    xor rax, rcx
    mov [rbp + rdx*8], rax
    inc rdx
    jmp .Lred_select
.Lred_select_done:
    dec rbx
    jnz .Lred_bit
    mov rsi, rbp
    mov rdi, r12
    mov rcx, r15
    rep movsq
    mov rax, rsp
    lea rdx, [r15*8]
    add rax, rdx
    add rax, rdx
    add rsp, rdx
    add rsp, rdx
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

# bigint_mod_inv_prime(rdi=dst, rsi=a, rdx=prime, rcx=n) -> rax=0
# Computes a^(prime-2) mod prime with a fixed n*64-bit exponentiation.
bigint_mod_inv_prime:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    lea rax, [r15*8]
    lea rdx, [rax*4]
    add rdx, rax
    add rdx, rax
    sub rsp, rdx
    mov rbp, rsp
    lea r8, [rbp + r15*8]
    mov rcx, r15
    mov rdi, r8
    mov rsi, r13
    rep movsq
    lea r9, [rbp + r15*8]
    lea rax, [r15*8]
    shl rax, 2
    add r9, rax
    mov rdi, r9
    mov rsi, r14
    mov rcx, r15
    rep movsq
    mov rax, [r9]
    sub rax, 2
    mov [r9], rax
    mov rdi, rbp
    xor eax, eax
    mov rcx, r15
    rep stosq
    mov QWORD PTR [rbp], 1
    mov rbx, r15
    shl rbx, 6
.Linv_loop:
    lea rax, [r15*8]
    lea rdi, [rbp + rax*2]
    mov rsi, rbp
    mov rdx, rbp
    add rdx, 0
    mov rcx, r15
    call bigint_mul
    lea rsi, [rbp + r15*8]
    lea rax, [r15*8]
    add rsi, rax
    mov rdi, rbp
    mov rdx, r14
    mov rcx, r15
    call bigint_mod_reduce
    lea r9, [rbp + r15*8]
    lea rax, [r15*8]
    shl rax, 2
    add r9, rax
    lea rax, [rbx - 1]
    mov rdx, rax
    shr rdx, 6
    and eax, 63
    mov rcx, [r9 + rdx*8]
    bt rcx, rax
    setc r10b
    lea rax, [r15*8]
    lea rdx, [rax*4]
    add rdx, rax
    add rdx, rax
    add rdx, rbp
    mov BYTE PTR [rdx], r10b
    lea rax, [r15*8]
    lea rdi, [rbp + rax*2]
    mov rsi, rbp
    lea rdx, [rbp + r15*8]
    mov rcx, r15
    call bigint_mul
    lea rsi, [rbp + r15*8]
    lea rax, [r15*8]
    add rsi, rax
    lea rdi, [rbp]
    lea rax, [r15*8]
    shl rax, 2
    add rdi, rax
    mov rdx, r14
    mov rcx, r15
    call bigint_mod_reduce
    lea rdi, [rbp]
    lea rax, [r15*8]
    shl rax, 2
    add rdi, rax
    lea rax, [r15*8]
    lea rdx, [rax*4]
    add rdx, rax
    add rdx, rax
    add rdx, rbp
    mov r11, rdx
    movzx r10d, BYTE PTR [r11]
    neg r10
    xor edx, edx
.Linv_select:
    cmp rdx, r15
    jae .Linv_select_done
    mov rax, [rbp + rdx*8]
    mov rcx, [rdi + rdx*8]
    xor rcx, rax
    and rcx, r10
    xor rax, rcx
    mov [rbp + rdx*8], rax
    inc rdx
    jmp .Linv_select
.Linv_select_done:
    dec rbx
    jnz .Linv_loop
    mov rsi, rbp
    mov rdi, r12
    mov rcx, r15
    rep movsq
    mov rax, 0
    lea rdx, [r15*8]
    lea rcx, [rdx*4]
    add rcx, rdx
    add rcx, rdx
    add rsp, rcx
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

# Address one of the ten n-limb work arrays used by bigint_mod_inv_odd.
.macro INV_ODD_PTR reg, slot
    .if \slot == 0
        mov \reg, rbp
    .else
        lea \reg, [r15*8]
        imul \reg, \slot
        add \reg, rbp
    .endif
.endm

# (a - (b & mask)) / 2. The selected subtraction is known not to borrow.
inv_odd_num_candidate:
    push rbx
    push r12
    mov rbx, rcx
    xor r10d, r10d
    clc
.Linv_num_sub:
    mov rax, [rsi + r10*8]
    mov r11, [rdx + r10*8]
    setc r12b
    and r11, r8
    bt r12, 0
    sbb rax, r11
    mov [rdi + r10*8], rax
    lea r10, [r10 + 1]
    dec rcx
    jnz .Linv_num_sub
    lea r10, [rbx - 1]
    clc
.Linv_num_half:
    mov rax, [rdi + r10*8]
    rcr rax, 1
    mov [rdi + r10*8], rax
    dec r10
    jns .Linv_num_half
    pop r12
    pop rbx
    ret

# Half (a - (b & mask)) modulo m, keeping the coefficient in [0,m).
inv_odd_coef_candidate:
    push rbx
    push r12
    mov rbx, rcx
    xor r10d, r10d
    clc
.Linv_coef_sub:
    mov rax, [rsi + r10*8]
    mov r11, [rdx + r10*8]
    setc r12b
    and r11, r8
    bt r12, 0
    sbb rax, r11
    mov [rdi + r10*8], rax
    lea r10, [r10 + 1]
    dec rcx
    jnz .Linv_coef_sub
    setc r11b
    movzx r8d, r11b
    neg r8
    xor r10d, r10d
    mov rcx, rbx
    clc
.Linv_coef_restore:
    setc r12b
    mov rax, [r9 + r10*8]
    and rax, r8
    bt r12, 0
    adc [rdi + r10*8], rax
    lea r10, [r10 + 1]
    dec rcx
    jnz .Linv_coef_restore
    mov r8, [rdi]
    and r8d, 1
    neg r8
    xor r10d, r10d
    mov rcx, rbx
    clc
.Linv_coef_make_even:
    setc r12b
    mov rax, [r9 + r10*8]
    and rax, r8
    bt r12, 0
    adc [rdi + r10*8], rax
    lea r10, [r10 + 1]
    dec rcx
    jnz .Linv_coef_make_even
    setc r11b
    movzx r11d, r11b
    lea r10, [rbx - 1]
    bt r11, 0
.Linv_coef_half:
    mov rax, [rdi + r10*8]
    rcr rax, 1
    mov [rdi + r10*8], rax
    dec r10
    jns .Linv_coef_half
    pop r12
    pop rbx
    ret

# bigint_mod_inv_odd(rdi=dst, rsi=a, rdx=modulus, rcx=n) -> rax=status
# Fixed-schedule binary extended GCD for odd moduli greater than one.
bigint_mod_inv_odd:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx

    # Ten n-limb arrays and 72 bytes of metadata preserve call alignment.
    lea rax, [r15*8]
    imul rax, 10
    add rax, 72
    sub rsp, rax
    mov rbp, rsp
    INV_ODD_PTR rbx, 10

    # Reduce the n-limb input through a zero-extended 2n-limb temporary.
    INV_ODD_PTR rdi, 8
    xor eax, eax
    lea rcx, [r15*2]
    rep stosq
    INV_ODD_PTR rdi, 8
    mov rsi, r13
    mov rcx, r15
    rep movsq
    INV_ODD_PTR rdi, 0
    INV_ODD_PTR rsi, 8
    mov rdx, r14
    mov rcx, r15
    call bigint_mod_reduce

    INV_ODD_PTR rdi, 1
    mov rsi, r14
    mov rcx, r15
    rep movsq
    INV_ODD_PTR rdi, 2
    xor eax, eax
    lea rcx, [r15*2]
    rep stosq
    INV_ODD_PTR rdi, 2
    mov QWORD PTR [rdi], 1

    # Two bit-widths suffice for the fixed binary-GCD schedule.
    mov rax, r15
    shl rax, 7
    mov [rbx], rax
.Linv_odd_iter:
    # Exclusive cases: u-even, then v-even, then the two odd comparisons.
    mov rax, [rbp]
    and eax, 1
    xor eax, 1
    neg rax
    mov [rbx + 8], rax
    INV_ODD_PTR r8, 1
    mov rax, [r8]
    and eax, 1
    xor eax, 1
    neg rax
    mov rdx, [rbx + 8]
    not rdx
    and rax, rdx
    mov [rbx + 16], rax
    mov rdi, r8
    mov rsi, rbp
    mov rdx, r15
    call ct_lt
    neg rax
    mov rdx, [rbx + 8]
    or rdx, [rbx + 16]
    not rdx
    and rax, rdx
    mov [rbx + 24], rax
    not rax
    and rax, rdx
    mov [rbx + 32], rax

    INV_ODD_PTR rdi, 4
    INV_ODD_PTR rsi, 0
    INV_ODD_PTR rdx, 1
    mov rcx, r15
    mov r8, [rbx + 24]
    call inv_odd_num_candidate
    INV_ODD_PTR rdi, 5
    INV_ODD_PTR rsi, 1
    INV_ODD_PTR rdx, 0
    mov rcx, r15
    mov r8, [rbx + 32]
    call inv_odd_num_candidate
    INV_ODD_PTR rdi, 6
    INV_ODD_PTR rsi, 2
    INV_ODD_PTR rdx, 3
    mov rcx, r15
    mov r8, [rbx + 24]
    mov r9, r14
    call inv_odd_coef_candidate
    INV_ODD_PTR rdi, 7
    INV_ODD_PTR rsi, 3
    INV_ODD_PTR rdx, 2
    mov rcx, r15
    mov r8, [rbx + 32]
    mov r9, r14
    call inv_odd_coef_candidate

    xor eax, eax
.Linv_odd_select:
    mov rdx, [rbx + 8]
    or rdx, [rbx + 24]
    mov rsi, [rbp + rax*8]
    INV_ODD_PTR rdi, 4
    mov rcx, [rdi + rax*8]
    xor rcx, rsi
    and rcx, rdx
    xor rsi, rcx
    mov [rbp + rax*8], rsi
    mov rdx, [rbx + 16]
    or rdx, [rbx + 32]
    INV_ODD_PTR rdi, 1
    mov rsi, [rdi + rax*8]
    INV_ODD_PTR rdi, 5
    mov rcx, [rdi + rax*8]
    xor rcx, rsi
    and rcx, rdx
    xor rsi, rcx
    INV_ODD_PTR rdi, 1
    mov [rdi + rax*8], rsi
    mov rdx, [rbx + 8]
    or rdx, [rbx + 24]
    INV_ODD_PTR rdi, 2
    mov rsi, [rdi + rax*8]
    INV_ODD_PTR rdi, 6
    mov rcx, [rdi + rax*8]
    xor rcx, rsi
    and rcx, rdx
    xor rsi, rcx
    INV_ODD_PTR rdi, 2
    mov [rdi + rax*8], rsi
    mov rdx, [rbx + 16]
    or rdx, [rbx + 32]
    INV_ODD_PTR rdi, 3
    mov rsi, [rdi + rax*8]
    INV_ODD_PTR rdi, 7
    mov rcx, [rdi + rax*8]
    xor rcx, rsi
    and rcx, rdx
    xor rsi, rcx
    INV_ODD_PTR rdi, 3
    mov [rdi + rax*8], rsi
    inc rax
    cmp rax, r15
    jb .Linv_odd_select
    dec QWORD PTR [rbx]
    jnz .Linv_odd_iter

    # Compute constant-time u==1 and v==1 flags.
    mov rax, [rbp]
    xor rax, 1
    INV_ODD_PTR r8, 1
    mov rdx, [r8]
    xor rdx, 1
    mov rcx, 1
.Linv_odd_eq_one:
    cmp rcx, r15
    jae .Linv_odd_eq_done
    or rax, [rbp + rcx*8]
    or rdx, [r8 + rcx*8]
    inc rcx
    jmp .Linv_odd_eq_one
.Linv_odd_eq_done:
    test rax, rax
    sete al
    movzx eax, al
    mov [rbx + 40], rax
    test rdx, rdx
    sete dl
    movzx edx, dl
    mov [rbx + 48], rdx
    neg rax
    neg rdx
    xor ecx, ecx
.Linv_odd_output:
    INV_ODD_PTR r8, 2
    mov rsi, [r8 + rcx*8]
    and rsi, rax
    INV_ODD_PTR r8, 3
    mov rdi, [r8 + rcx*8]
    and rdi, rdx
    or rsi, rdi
    mov [r12 + rcx*8], rsi
    inc rcx
    cmp rcx, r15
    jb .Linv_odd_output
    mov rax, [rbx + 40]
    or rax, [rbx + 48]
    xor rax, 1
    and eax, 1
    lea rdx, [r15*8]
    imul rdx, 10
    add rdx, 72
    add rsp, rdx
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

# Preserved first implementation for comparison while the replacement is tested.
bigint_mod_inv_odd_wip:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx

    # u, v, x, y and four candidate arrays, plus four masks.
    lea rax, [r15*8]
    lea rdx, [rax*8]
    add rdx, 72
    sub rsp, rdx
    mov rbp, rsp
    lea r8, [rbp + r15*8]
    lea rax, [r15*8]
    lea rdx, [rax*2]
    add rdx, rax
    lea r9, [r8 + rdx]
    lea r10, [r9 + r15*8]
    lea r11, [r10 + r15*8]

    mov rdi, rbp
    mov rsi, r13
    mov rcx, r15
    rep movsq
    mov rdi, r8
    mov rsi, r14
    mov rcx, r15
    rep movsq
    xor eax, eax
    lea rax, [r15*8]
    lea rdi, [rbp + rax*2]
    mov rcx, r15
    rep stosq
    mov QWORD PTR [rbp + rax*2], 1
    lea rdi, [rbp + rax*2]
    add rdi, rax
    mov rcx, r15
    rep stosq

    # Normalize u once, without making the input range part of the schedule.
    mov rdi, r9
    mov rsi, rbp
    mov rdx, r8
    mov rcx, r15
    call bigint_sub
    neg rax
    mov rdx, rax
    lea r8, [rbp + r15*8]
    lea r9, [r8 + r15*8]
    lea rax, [r15*8]
    add r9, rax
    add r9, rax
    lea r10, [r9 + r15*8]
    lea r11, [r10 + r15*8]
    xor eax, eax
    xor ebx, ebx
.Linvodd_norm:
    cmp rax, r15
    jae .Linvodd_norm_done
    mov rsi, [rbp + rax*8]
    mov rdi, [r9 + rax*8]
    xor rdi, rsi
    and rdi, rdx
    xor rsi, rdi
    mov [rbp + rax*8], rsi
    inc rax
    jmp .Linvodd_norm
.Linvodd_norm_done:
    lea rsi, [r15*8]
    lea rdx, [rsi*8]
    lea rbx, [rbp + rdx]
    lea rax, [rbp + rsi*4]
    mov [rbx + 40], rax
    add rax, rsi
    mov [rbx + 48], rax
    add rax, rsi
    mov [rbx + 56], rax
    add rax, rsi
    mov [rbx + 64], rax
    lea rdx, [r15*8]
    shl rdx, 7
    mov [rbx + 32], rdx
.Linvodd_iter:
    # Masks are: u-even, v-even, odd-and-u-greater, odd-and-v-greater.
    mov rax, [rbp]
    and eax, 1
    xor eax, 1
    neg rax
    mov [rbx], rax
    mov rax, [r8]
    and eax, 1
    xor eax, 1
    neg rax
    mov [rbx + 8], rax
    mov rdi, r8
    mov rsi, rbp
    mov rdx, r15
    call ct_lt
    lea r8, [rbp + r15*8]
    mov r9, [rbx + 40]
    mov r10, [rbx + 48]
    mov r11, [rbx + 56]
    neg rax
    mov rdx, rax
    mov rax, [rbx]
    not rax
    mov rdi, [rbx + 8]
    not rdi
    and rax, rdi
    and rax, rdx
    mov [rbx + 16], rax
    not rdx
    mov rax, [rbx]
    not rax
    mov rdi, [rbx + 8]
    not rdi
    and rax, rdi
    and rax, rdx
    mov [rbx + 24], rax

    # Candidate numerators: tu=u-(u>v ? v : 0), and similarly for tv.
    xor eax, eax
    clc
.Lio_num:
    cmp rax, r15
    jae .Lio_num_done
    mov rdx, [rbx + 16]
    mov rdi, [r8 + rax*8]
    and rdi, rdx
    mov rsi, [rbp + rax*8]
    sbb rsi, rdi
    mov [r9 + rax*8], rsi
    mov rdx, [rbx + 24]
    mov rdi, [rbp + rax*8]
    and rdi, rdx
    mov rsi, [r8 + rax*8]
    sbb rsi, rdi
    mov [r10 + rax*8], rsi
    inc rax
    jmp .Lio_num
.Lio_num_done:
    # Odd/odd subtraction candidates also take the required division by two.
    lea rax, [r15 - 1]
    clc
.Lio_half_u:
    mov rdx, [r9 + rax*8]
    rcr rdx, 1
    mov [r9 + rax*8], rdx
    test rax, rax
    jz .Lio_half_v_start
    dec rax
    jmp .Lio_half_u
.Lio_half_v_start:
    lea rax, [r15 - 1]
    clc
.Lio_half_v:
    mov rdx, [r10 + rax*8]
    rcr rdx, 1
    mov [r10 + rax*8], rdx
    test rax, rax
    jz .Lio_num_halved
    dec rax
    jmp .Lio_half_v
.Lio_num_halved:
    # Candidate coefficient numerators are reduced modulo m.
    xor eax, eax
    clc
.Lio_coef:
    cmp rax, r15
    jae .Lio_coef_done
     mov rdx, [rbx]
     or rdx, [rbx + 16]
    mov rdi, [rbx + 16]
    or rdi, rdx
    mov rdi, [rbx + 48]
    mov rdx, [rdi + rax*8]
     mov rdi, [rbx + 56]
    mov rsi, [rdi + rax*8]
    and rsi, rdi
    sub rdx, rsi
    mov [r11 + rax*8], rdx
     mov rdx, [rbx + 8]
     or rdx, [rbx + 24]
    mov rdi, [rbx + 24]
    or rdi, rdx
    mov rdi, [rbx + 40]
    mov rdx, [rdi + rax*8]
     mov rdi, [rbx + 64]
    mov rsi, [rdi + rax*8]
    and rsi, rdi
    sub rdx, rsi
    mov rdi, [rbx + 64]
    mov [rdi + rax*8], rdx
    inc rax
    jmp .Lio_coef
.Lio_coef_done:
    # Add m back after coefficient subtraction when it borrowed.
    mov rdi, [rbx + 16]
    neg rdi
    xor eax, eax
    clc
.Lio_addx:
    cmp rax, r15
    jae .Lio_addx_done
    mov rdx, [r14 + rax*8]
    and rdx, rdi
    mov rsi, [r11 + rax*8]
    adc rsi, rdx
    mov [r11 + rax*8], rsi
    inc rax
    jmp .Lio_addx
.Lio_addx_done:
    mov rdi, [rbx + 24]
    neg rdi
    xor eax, eax
    clc
.Lio_addy:
    cmp rax, r15
    jae .Lio_addy_done
    mov rdx, [r14 + rax*8]
    and rdx, rdi
    mov rdi, [rbx + 64]
    mov rsi, [rdi + rax*8]
    adc rsi, rdx
    mov rdi, [rbx + 64]
    mov [rdi + rax*8], rsi
    inc rax
    jmp .Lio_addy
.Lio_addy_done:
    # Divide candidates by two, adding m first for odd coefficients.
    mov rdi, [rbx]
    neg rdi
    xor eax, eax
    clc
.Lio_halfx_add:
    cmp rax, r15
    jae .Lio_halfx_shift
    mov rdx, [r14 + rax*8]
    and rdx, rdi
    mov rsi, [r11 + rax*8]
    adc rsi, rdx
    mov [r11 + rax*8], rsi
    inc rax
    jmp .Lio_halfx_add
.Lio_halfx_shift:
    lea rax, [r15 - 1]
    clc
.Lio_halfx:
    mov rdx, [r11 + rax*8]
    rcr rdx, 1
    mov [r11 + rax*8], rdx
    test rax, rax
    jz .Lio_halfy_add
    dec rax
    jmp .Lio_halfx
.Lio_halfy_add:
    mov rdi, [rbx + 8]
    neg rdi
    xor eax, eax
    clc
.Lio_halfy_add_loop:
    cmp rax, r15
    jae .Lio_halfy_shift
    mov rdx, [r14 + rax*8]
    and rdx, rdi
    mov rdi, [rbx + 64]
    mov rsi, [rdi + rax*8]
    adc rsi, rdx
    mov rdi, [rbx + 64]
    mov [rdi + rax*8], rsi
    inc rax
    jmp .Lio_halfy_add_loop
.Lio_halfy_shift:
    lea rax, [r15 - 1]
    clc
.Lio_halfy:
    mov rdi, [rbx + 64]
    mov rdx, [rdi + rax*8]
    rcr rdx, 1
    mov rdi, [rbx + 56]
    mov [rdi + rax*8], rdx
    test rax, rax
    jz .Lio_select
    dec rax
    jmp .Lio_halfy
.Lio_select:
    xor eax, eax
.Lio_select_loop:
    cmp rax, r15
    jae .Lio_next
    mov rdx, [rbx]
    mov rsi, [rbp + rax*8]
    mov rdi, [r9 + rax*8]
    xor rdi, rsi
    and rdi, rdx
    xor rsi, rdi
    mov [rbp + rax*8], rsi
    mov rdx, [rbx + 8]
    mov rsi, [r8 + rax*8]
    mov rdi, [r10 + rax*8]
    xor rdi, rsi
    and rdi, rdx
    xor rsi, rdi
     mov [r8 + rax*8], rsi
     mov rdx, [rbx]
     or rdx, [rbx + 16]
     lea r11, [r15*8]
     lea r11, [rbp + r11*2]
     mov rsi, [r11 + rax*8]
     mov rdi, [rbx + 56]
     mov rdi, [rdi + rax*8]
     xor rdi, rsi
     and rdi, rdx
     xor rsi, rdi
     mov [r11 + rax*8], rsi
     mov rdx, [rbx + 8]
     or rdx, [rbx + 24]
     lea r11, [r15*8]
     lea r11, [rbp + r11*2]
     lea rsi, [r15*8]
     add r11, rsi
     mov rsi, [r11 + rax*8]
     mov rdi, [rbx + 64]
     mov rdi, [rdi + rax*8]
     xor rdi, rsi
     and rdi, rdx
     xor rsi, rdi
     mov [r11 + rax*8], rsi
     lea r8, [rbp + r15*8]
    inc rax
    jmp .Lio_select_loop
.Lio_next:
    dec QWORD PTR [rbx + 32]
    jnz .Linvodd_iter

    # Select the coefficient belonging to gcd 1 and report failure otherwise.
    mov rdi, rbp
    mov rsi, r14
    mov rdx, r15
    call ct_eq
    mov [rbx + 24], rax
    lea rsi, [rbp + r15*8]
    mov rdi, rsi
    mov rsi, r14
    mov rdx, r15
    call ct_eq
    mov r10, rax
    mov r9, [rbx + 24]
    neg r9
    neg r10
    xor eax, eax
.Lio_out:
    cmp rax, r15
    jae .Lio_out_done
     mov rdi, [rbx + 56]
     mov rsi, [rdi + rax*8]
     mov rdi, [rbx + 64]
     mov rdx, [rdi + rax*8]
     and rsi, r9
     and rdx, r10
     or rsi, rdx
     mov [r12 + rax*8], rsi
    inc rax
    jmp .Lio_out
.Lio_out_done:
    xor eax, eax
     or r8, [rbx + 24]
     cmp r8, 1
    sete al
    xor eax, 1
    lea rdx, [r15*8]
    lea rcx, [rdx*8]
    add rcx, 72
    add rsp, rcx
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
