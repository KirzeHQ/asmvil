.intel_syntax noprefix
.include "common.inc"

.section .text

X_MASK = 0x3ffffff
X_BASE = 0x4000000
X_TOP_MASK = 0x1fffff
.ifndef X25519_TRACE
X25519_TRACE = 0
.endif

.macro X_TRACE
.if X25519_TRACE
    mov rdi, rsp
    mov esi, r15d
    mov edx, DWORD PTR [rsp + 1404]
    call x25519_trace_record
.endif
.endm
.set X_TRACE_BOUNDARY_RECORD_SIZE, 376
.set X_TRACE_BIT_END, 1
.set X_TRACE_PRE_CSWAP, 2
.set X_TRACE_POST_CSWAP, 3
.macro X_TRACE_BOUNDARY stage
.if X25519_TRACE
    mov rdi, rsp
    mov esi, r15d
    mov edx, \stage
    mov ecx, DWORD PTR [rsp + 1404]
    call x25519_trace_boundary
.endif
.endm
.macro X_SNAPSHOT src, dst
.if X25519_TRACE
    xor ecx, ecx
.Lxtrace_snapshot\@:
    mov rax, QWORD PTR [rsp + \src + rcx*8]
    mov QWORD PTR [rsp + \dst + rcx*8], rax
    inc ecx
    cmp ecx, 10
    jb .Lxtrace_snapshot\@
.endif
.endm
.macro X_TRACE_STAGE src, dst
.if X25519_TRACE
    lea rsi, [rsp + \src]
    lea rdi, [rip + \dst]
    mov ecx, 10
.Lxtrace_stage\@:
    mov rax, QWORD PTR [rsi]
    mov QWORD PTR [rdi], rax
    add rsi, 8
    add rdi, 8
    dec ecx
    jnz .Lxtrace_stage\@
.endif
.endm
.macro X_TRACE_BYTES src, dst
.if X25519_TRACE
    lea rsi, [rsp + \src]
    lea rdi, [rip + \dst]
    mov ecx, 32
.Lxtrace_bytes\@:
    mov al, BYTE PTR [rsi]
    mov BYTE PTR [rdi], al
    inc rsi
    inc rdi
    dec ecx
    jnz .Lxtrace_bytes\@
.endif
.endm
.macro X_TRACE_FIRST_STAGE src, dst
.if X25519_TRACE
    cmp r15d, 254
    jne .Lxtrace_first_skip\@
    X_TRACE_STAGE \src, \dst
.Lxtrace_first_skip\@:
.endif
.endm
.macro X_TRACE_FIRST_CAPTURE src, offset
.if X25519_TRACE
    cmp r15d, 254
    jne .Lxtrace_capture_skip\@
    lea rsi, [rsp + \src]
    lea rdi, [rip + x25519_trace_ops]
    add rdi, \offset
    mov ecx, 10
.Lxtrace_capture\@:
    mov rax, QWORD PTR [rsi]
    mov QWORD PTR [rdi], rax
    add rsi, 8
    add rdi, 8
    dec ecx
    jnz .Lxtrace_capture\@
.Lxtrace_capture_skip\@:
.endif
.endm
.set X_TRACE_OPS, 17
.set X_TRACE_RECORD_SIZE, 104
.set X_TRACE_BIT_SIZE, X_TRACE_OPS * X_TRACE_RECORD_SIZE
.macro X_TRACE_NAMED op, var, src
.if X25519_TRACE
    mov eax, 254
    sub eax, r15d
    imul eax, X_TRACE_BIT_SIZE
    lea r9, [rip + x25519_trace_named]
    add r9, rax
    mov edx, \op
    imul edx, 104
    add r9, rdx
    mov QWORD PTR [r9], r15
    mov QWORD PTR [r9 + 8], \op
    mov QWORD PTR [r9 + 16], \var
    lea r8, [rsp + \src]
    lea rdi, [r9 + 24]
    mov ecx, 10
.Lxtrace_named\@:
    mov rax, QWORD PTR [r8]
    mov QWORD PTR [rdi], rax
    add r8, 8
    add rdi, 8
    dec ecx
    jnz .Lxtrace_named\@
.endif
.endm
.macro X_TRACE_INIT_EVENT
.if X25519_TRACE
    mov rax, QWORD PTR [rsp + 272]
    lea rdx, [rip + x25519_trace_init_events]
    mov QWORD PTR [rdx + r11*8], rax
    inc r11
.endif
.endm
.macro X_TRACE_MUL_STAGE dst
.if X25519_TRACE
    lea rsi, [rsp]
    lea rdi, [rip + \dst]
    mov ecx, 19
.Lxtrace_mul\@:
    mov rax, QWORD PTR [rsi]
    mov QWORD PTR [rdi], rax
    add rsi, 8
    add rdi, 8
    dec ecx
    jnz .Lxtrace_mul\@
.endif
.endm
.set X_TRACE_INV_RECORD_SIZE, 424
.macro X_TRACE_INV_BEFORE
.if X25519_TRACE
    lea rsi, [rsp + 1152]
    lea rdi, [rip + x25519_trace_inv_buffer]
    mov rax, QWORD PTR [rip + x25519_trace_inv_count]
    imul rax, X_TRACE_INV_RECORD_SIZE
    add rdi, rax
    mov QWORD PTR [rdi], r15
    lea rdi, [rdi + 24]
    mov ecx, 10
.Lxtrace_inv_before\@:
    mov rax, QWORD PTR [rsi]
    mov QWORD PTR [rdi], rax
    add rsi, 8
    add rdi, 8
    dec ecx
    jnz .Lxtrace_inv_before\@
.endif
.endm
.macro X_TRACE_INV_AFTER
.if X25519_TRACE
    lea rdi, [rip + x25519_trace_inv_buffer]
    mov rax, QWORD PTR [rip + x25519_trace_inv_count]
    imul rax, X_TRACE_INV_RECORD_SIZE
    add rdi, rax
    mov rax, QWORD PTR [rsp + 1400]
    mov QWORD PTR [rdi + 8], rax
    mov rax, QWORD PTR [rsp + 1392]
    mov QWORD PTR [rdi + 16], rax
    lea rsi, [rsp + 1072]
    lea rdi, [rdi + 104]
    mov ecx, 10
.Lxtrace_inv_sq\@:
    mov rax, QWORD PTR [rsi]
    mov QWORD PTR [rdi], rax
    add rsi, 8
    add rdi, 8
    dec ecx
    jnz .Lxtrace_inv_sq\@
    lea rsi, [rsp + 1232]
    lea rdi, [rip + x25519_trace_inv_buffer]
    mov rax, QWORD PTR [rip + x25519_trace_inv_count]
    imul rax, X_TRACE_INV_RECORD_SIZE
    add rdi, rax
    add rdi, 184
    mov ecx, 10
.Lxtrace_inv_mul_input\@:
    mov rax, QWORD PTR [rsi]
    mov QWORD PTR [rdi], rax
    add rsi, 8
    add rdi, 8
    dec ecx
    jnz .Lxtrace_inv_mul_input\@
    lea rsi, [rsp + 1152]
    lea rdi, [rip + x25519_trace_inv_buffer]
    mov rax, QWORD PTR [rip + x25519_trace_inv_count]
    imul rax, X_TRACE_INV_RECORD_SIZE
    add rdi, rax
    add rdi, 264
    mov ecx, 10
.Lxtrace_inv_after\@:
    mov rax, QWORD PTR [rsi]
    mov QWORD PTR [rdi], rax
    add rsi, 8
    add rdi, 8
    dec ecx
    jnz .Lxtrace_inv_after\@
    inc QWORD PTR [rip + x25519_trace_inv_count]
.endif
.endm

# field_mul(a,b,out), with normalized ten-limb output
.if X25519_TRACE
.global field_mul
.endif
field_mul:
.if X25519_TRACE
    cmp QWORD PTR [rip + x25519_trace_sq_active], 1
    jne .Lxmul_no_sq_trace
    mov QWORD PTR [rip + x25519_trace_mul_dest], rdx
    mov QWORD PTR [rip + x25519_trace_mul_src1], rdi
    mov QWORD PTR [rip + x25519_trace_mul_src2], rsi
    lea r8, [rdi]
    lea r9, [rip + x25519_trace_mul_input]
    mov ecx, 10
.Lxmul_sq_copy:
    mov rax, QWORD PTR [r8]
    mov QWORD PTR [r9], rax
    add r8, 8
    add r9, 8
    dec ecx
    jnz .Lxmul_sq_copy
    lea r8, [rsi]
    lea r9, [rip + x25519_trace_mul_input2]
    mov ecx, 10
.Lxmul_sq_copy2:
    mov rax, QWORD PTR [r8]
    mov QWORD PTR [r9], rax
    add r8, 8
    add r9, 8
    dec ecx
    jnz .Lxmul_sq_copy2
.Lxmul_no_sq_trace:
.endif
    sub rsp, 176
    mov QWORD PTR [rsp + 160], rdx
    xor ecx, ecx
.Lxm_zero:
    mov QWORD PTR [rsp + rcx], 0
    add ecx, 8
    cmp ecx, 152
    jb .Lxm_zero
    xor r8d, r8d
.Lxm_i:
    xor r9d, r9d
.Lxm_j:
    mov eax, DWORD PTR [rdi + r8*8]
    imul rax, QWORD PTR [rsi + r9*8]
    mov ecx, r8d
    add ecx, r9d
    add QWORD PTR [rsp + rcx*8], rax
    inc r9d
    cmp r9d, 10
    jb .Lxm_j
    inc r8d
    cmp r8d, 10
    jb .Lxm_i
    X_TRACE_MUL_STAGE x25519_mul_trace
    # Bound coefficients before multiplying the high half by 608.
    xor ecx, ecx
.Lxm_convolution_carry:
    mov rax, QWORD PTR [rsp + rcx*8]
    mov rdx, rax
    shr rdx, 26
    and eax, X_MASK
    mov QWORD PTR [rsp + rcx*8], rax
    add QWORD PTR [rsp + rcx*8 + 8], rdx
    inc ecx
    cmp ecx, 18
    jb .Lxm_convolution_carry
    mov ecx, 10
.Lxm_fold:
    mov rax, QWORD PTR [rsp + rcx*8]
     imul rax, 608
    add QWORD PTR [rsp + rcx*8 - 80], rax
    inc ecx
    cmp ecx, 19
    jb .Lxm_fold
    X_TRACE_MUL_STAGE x25519_mul_trace_folded
    xor ecx, ecx
.Lxm_carry:
    mov rax, QWORD PTR [rsp + rcx*8]
    mov rdx, rax
    shr rdx, 26
    and eax, X_MASK
    mov QWORD PTR [rsp + rcx*8], rax
    add QWORD PTR [rsp + rcx*8 + 8], rdx
    inc ecx
    cmp ecx, 9
    jb .Lxm_carry
    mov rax, QWORD PTR [rsp + 72]
    mov rdx, rax
    shr rdx, 26
    and eax, X_MASK
    mov QWORD PTR [rsp + 72], rax
    imul rdx, 608
    add QWORD PTR [rsp], rdx
    X_TRACE_MUL_STAGE x25519_mul_trace_carry0
    xor ecx, ecx
.Lxm_carry2:
    mov rax, QWORD PTR [rsp + rcx*8]
    mov rdx, rax
    shr rdx, 26
    and eax, X_MASK
    mov QWORD PTR [rsp + rcx*8], rax
    add QWORD PTR [rsp + rcx*8 + 8], rdx
    inc ecx
    cmp ecx, 9
    jb .Lxm_carry2
    mov rax, QWORD PTR [rsp + 72]
    mov rdx, rax
    shr rdx, 26
    and eax, X_MASK
    mov QWORD PTR [rsp + 72], rax
    imul rdx, 608
    add QWORD PTR [rsp], rdx
    X_TRACE_MUL_STAGE x25519_mul_trace_carry1
    xor ecx, ecx
.Lxm_carry3:
    mov rax, QWORD PTR [rsp + rcx*8]
    mov rdx, rax
    shr rdx, 26
    and eax, X_MASK
    mov QWORD PTR [rsp + rcx*8], rax
    add QWORD PTR [rsp + rcx*8 + 8], rdx
    inc ecx
    cmp ecx, 9
    jb .Lxm_carry3
    mov rax, QWORD PTR [rsp + 72]
    mov rdx, rax
    shr rdx, 26
    and eax, X_MASK
    mov QWORD PTR [rsp + 72], rax
    imul rdx, 608
    add QWORD PTR [rsp], rdx
    X_TRACE_MUL_STAGE x25519_mul_trace_carry2
    xor ecx, ecx
.Lxm_carry4:
    mov rax, QWORD PTR [rsp + rcx*8]
    mov rdx, rax
    shr rdx, 26
    and eax, X_MASK
    mov QWORD PTR [rsp + rcx*8], rax
    add QWORD PTR [rsp + rcx*8 + 8], rdx
    inc ecx
    cmp ecx, 9
    jb .Lxm_carry4
    mov rax, QWORD PTR [rsp + 72]
    mov rdx, rax
    shr rdx, 26
    and eax, X_MASK
    mov QWORD PTR [rsp + 72], rax
    imul rdx, 608
    add QWORD PTR [rsp], rdx
    X_TRACE_MUL_STAGE x25519_mul_trace_carry3
    xor ecx, ecx
.Lxm_carry5:
    mov rax, QWORD PTR [rsp + rcx*8]
    mov rdx, rax
    shr rdx, 26
    and eax, X_MASK
    mov QWORD PTR [rsp + rcx*8], rax
    add QWORD PTR [rsp + rcx*8 + 8], rdx
    inc ecx
    cmp ecx, 9
    jb .Lxm_carry5
    mov rax, QWORD PTR [rsp + 72]
    mov rdx, rax
    shr rdx, 26
    and eax, X_MASK
    mov QWORD PTR [rsp + 72], rax
    imul rdx, 608
    add QWORD PTR [rsp], rdx
    X_TRACE_MUL_STAGE x25519_mul_trace_carry4
    xor ecx, ecx
.Lxm_carry6:
    mov rax, QWORD PTR [rsp + rcx*8]
    mov rdx, rax
    shr rdx, 26
    and eax, X_MASK
    mov QWORD PTR [rsp + rcx*8], rax
    add QWORD PTR [rsp + rcx*8 + 8], rdx
    inc ecx
    cmp ecx, 9
    jb .Lxm_carry6
    mov rax, QWORD PTR [rsp + 72]
    mov rdx, rax
    shr rdx, 21
    and eax, X_TOP_MASK
    mov QWORD PTR [rsp + 72], rax
    imul rdx, 19
    add QWORD PTR [rsp], rdx
    X_TRACE_MUL_STAGE x25519_mul_trace_carry5
    xor ecx, ecx
.Lxm_carry7:
    mov rax, QWORD PTR [rsp + rcx*8]
    mov rdx, rax
    shr rdx, 26
    and eax, X_MASK
    mov QWORD PTR [rsp + rcx*8], rax
    add QWORD PTR [rsp + rcx*8 + 8], rdx
    inc ecx
    cmp ecx, 9
    jb .Lxm_carry7
    mov rax, QWORD PTR [rsp + 72]
    and eax, X_TOP_MASK
    mov QWORD PTR [rsp + 72], rax
    X_TRACE_MUL_STAGE x25519_mul_trace_carry6
    mov rdi, QWORD PTR [rsp + 160]
    xor ecx, ecx
.Lxm_out:
    mov rax, QWORD PTR [rsp + rcx*8]
    mov QWORD PTR [rdi + rcx*8], rax
    inc ecx
    cmp ecx, 10
    jb .Lxm_out
    add rsp, 176
    ret

field_sqr:
.if X25519_TRACE
    cmp r15d, 254
    jne .Lxsq_normal
    inc QWORD PTR [rip + x25519_trace_sq_count]
    cmp QWORD PTR [rip + x25519_trace_sq_count], 3
    jne .Lxsq_normal
    mov QWORD PTR [rip + x25519_trace_sq_active], 1
    mov QWORD PTR [rip + x25519_trace_sq_a], rdi
    mov QWORD PTR [rip + x25519_trace_sq_b], rsi
    mov QWORD PTR [rip + x25519_trace_sq_dest], rdx
    lea r8, [rdi]
    lea r9, [rip + x25519_trace_sq_input]
    mov ecx, 10
.Lxsq_copy:
    mov rax, QWORD PTR [r8]
    mov QWORD PTR [r9], rax
    add r8, 8
    add r9, 8
    dec ecx
    jnz .Lxsq_copy
    call field_mul
    lea r8, [rip + x25519_trace_sq_output]
    mov r9, QWORD PTR [rip + x25519_trace_sq_dest]
    mov ecx, 10
.Lxsq_return:
    mov rax, QWORD PTR [r9]
    mov QWORD PTR [r8], rax
    add r8, 8
    add r9, 8
    dec ecx
    jnz .Lxsq_return
    mov QWORD PTR [rip + x25519_trace_sq_active], 0
    ret
.Lxsq_normal:
.endif
    jmp field_mul

.global field_add
field_add:
    xor ecx, ecx
.Lxa:
    mov rax, QWORD PTR [rdi + rcx*8]
    add rax, QWORD PTR [rsi + rcx*8]
    mov QWORD PTR [rdx + rcx*8], rax
    inc ecx
    cmp ecx, 10
    jb .Lxa
    ret

field_sub:
    lea r8, [rip + x25519_prime]
    xor r10d, r10d
    xor ecx, ecx
.Lxs:
    mov rax, QWORD PTR [r8 + rcx*8]
    sub rax, QWORD PTR [rsi + rcx*8]
    sub rax, r10
    setc r10b
    movzx r10d, r10b
    mov r9, r10
    imul r9, X_BASE
    add rax, r9
    add rax, QWORD PTR [rdi + rcx*8]
    mov QWORD PTR [rdx + rcx*8], rax
    inc ecx
    cmp ecx, 10
    jb .Lxs
    ret

.global field_normalize
# field_normalize(rdi=field), tightens ten radix-2^26 limbs in place.
field_normalize:
    xor ecx, ecx
.Lxn_carry0:
    mov rax, QWORD PTR [rdi + rcx*8]
    mov rdx, rax
    shr rdx, 26
    and eax, X_MASK
    mov QWORD PTR [rdi + rcx*8], rax
    add QWORD PTR [rdi + rcx*8 + 8], rdx
    inc ecx
    cmp ecx, 9
    jb .Lxn_carry0
    mov rax, QWORD PTR [rdi + 72]
    mov rdx, rax
    shr rdx, 21
    and eax, X_TOP_MASK
    mov QWORD PTR [rdi + 72], rax
    imul rdx, 19
    add QWORD PTR [rdi], rdx
    xor ecx, ecx
.Lxn_carry1:
    mov rax, QWORD PTR [rdi + rcx*8]
    mov rdx, rax
    shr rdx, 26
    and eax, X_MASK
    mov QWORD PTR [rdi + rcx*8], rax
    add QWORD PTR [rdi + rcx*8 + 8], rdx
    inc ecx
    cmp ecx, 9
    jb .Lxn_carry1
    mov rax, QWORD PTR [rdi + 72]
    mov rdx, rax
    shr rdx, 21
    and eax, X_TOP_MASK
    mov QWORD PTR [rdi + 72], rax
    imul rdx, 19
    add QWORD PTR [rdi], rdx
    xor ecx, ecx
.Lxn_carry2:
    mov rax, QWORD PTR [rdi + rcx*8]
    mov rdx, rax
    shr rdx, 26
    and eax, X_MASK
    mov QWORD PTR [rdi + rcx*8], rax
    add QWORD PTR [rdi + rcx*8 + 8], rdx
    inc ecx
    cmp ecx, 9
    jb .Lxn_carry2
    mov rax, QWORD PTR [rdi + 72]
    and eax, X_TOP_MASK
    mov QWORD PTR [rdi + 72], rax
    ret

.global field_reduce
# field_reduce(rdi=field), canonicalizes a tight or loose field element.
field_reduce:
    sub rsp, 88
    mov QWORD PTR [rsp + 80], rdi
    call field_normalize
    mov rdi, QWORD PTR [rsp + 80]
    lea r8, [rip + x25519_prime]
    xor r10d, r10d
    xor ecx, ecx
.Lxr_sub:
    mov rax, QWORD PTR [rdi + rcx*8]
    sub rax, QWORD PTR [r8 + rcx*8]
    setc r11b
    movzx r11d, r11b
    sub rax, r10
    setc r10b
    movzx r10d, r10b
    or r10, r11
    mov r9, r10
    imul r9, X_BASE
    add rax, r9
    mov QWORD PTR [rsp + rcx*8], rax
    inc ecx
    cmp ecx, 9
    jb .Lxr_sub
    mov rax, QWORD PTR [rdi + 72]
    sub rax, QWORD PTR [r8 + 72]
    setc r11b
    movzx r11d, r11b
    sub rax, r10
    setc r10b
    movzx r10d, r10b
    or r10, r11
    mov r9, r10
    imul r9, 2097152
    add rax, r9
    mov QWORD PTR [rsp + 72], rax
    mov r11, r10
    neg r11
    xor ecx, ecx
.Lxr_select:
    mov r8, QWORD PTR [rsp + rcx*8]
    mov r9, QWORD PTR [rdi + rcx*8]
    mov rax, r8
    xor rax, r9
    and rax, r11
    xor rax, r8
    mov QWORD PTR [rdi + rcx*8], rax
    inc ecx
    cmp ecx, 10
    jb .Lxr_select
    add rsp, 88
    ret

.macro X_CSWAP a, b
    xor ecx, ecx
.Lxcs\@:
    mov rax, QWORD PTR [rsp + \a + rcx*8]
    mov rdx, QWORD PTR [rsp + \b + rcx*8]
    xor rax, rdx
    and rax, r11
    xor QWORD PTR [rsp + \a + rcx*8], rax
    xor QWORD PTR [rsp + \b + rcx*8], rax
    inc ecx
    cmp ecx, 10
    jb .Lxcs\@
.endm

.global x25519
.global x25519_cswap
 x25519_cswap:
    mov r8, rdx
    neg r8
    xor ecx, ecx
.Lxcs_test:
    mov rax, QWORD PTR [rdi + rcx*8]
    mov rdx, QWORD PTR [rsi + rcx*8]
    xor rax, rdx
    and rax, r8
    xor QWORD PTR [rdi + rcx*8], rax
    xor QWORD PTR [rsi + rcx*8], rax
    inc ecx
    cmp ecx, 10
    jb .Lxcs_test
    ret
# x25519(rdi=out32, rsi=scalar32, rdx=u32)
x25519:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 2048
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov rax, QWORD PTR [r13]
    mov QWORD PTR [rsp], rax
    mov rax, QWORD PTR [r13 + 8]
    mov QWORD PTR [rsp + 8], rax
    mov rax, QWORD PTR [r13 + 16]
    mov QWORD PTR [rsp + 16], rax
    mov rax, QWORD PTR [r13 + 24]
    mov QWORD PTR [rsp + 24], rax
    and BYTE PTR [rsp], 248
    and BYTE PTR [rsp + 31], 127
    or BYTE PTR [rsp + 31], 64
    mov rax, QWORD PTR [r14]
    mov QWORD PTR [rsp + 1312], rax
    mov rax, QWORD PTR [r14 + 8]
    mov QWORD PTR [rsp + 1320], rax
    mov rax, QWORD PTR [r14 + 16]
    mov QWORD PTR [rsp + 1328], rax
    mov rax, QWORD PTR [r14 + 24]
    mov QWORD PTR [rsp + 1336], rax
    and BYTE PTR [rsp + 1343], 127
    mov QWORD PTR [rsp + 1344], 0

    mov rax, QWORD PTR [rsp + 1312]
    and eax, X_MASK
    mov QWORD PTR [rsp + 32], rax
    mov rax, QWORD PTR [rsp + 1315]
    shr eax, 2
    and eax, X_MASK
    mov QWORD PTR [rsp + 40], rax
    mov rax, QWORD PTR [rsp + 1318]
    shr eax, 4
    and eax, X_MASK
    mov QWORD PTR [rsp + 48], rax
    mov rax, QWORD PTR [rsp + 1321]
    shr eax, 6
    and eax, X_MASK
    mov QWORD PTR [rsp + 56], rax
    mov rax, QWORD PTR [rsp + 1325]
    and eax, X_MASK
    mov QWORD PTR [rsp + 64], rax
    mov rax, QWORD PTR [rsp + 1328]
    shr eax, 2
    and eax, X_MASK
    mov QWORD PTR [rsp + 72], rax
    mov rax, QWORD PTR [rsp + 1331]
    shr eax, 4
    and eax, X_MASK
    mov QWORD PTR [rsp + 80], rax
    mov rax, QWORD PTR [rsp + 1334]
    shr eax, 6
    and eax, X_MASK
    mov QWORD PTR [rsp + 88], rax
    mov rax, QWORD PTR [rsp + 1338]
    and eax, X_MASK
    mov QWORD PTR [rsp + 96], rax
    mov rax, QWORD PTR [rsp + 1341]
    shr eax, 2
    and eax, X_TOP_MASK
    mov QWORD PTR [rsp + 104], rax
    X_TRACE_BYTES 1312, x25519_trace_input
    X_TRACE_STAGE 32, x25519_trace_decoded

    mov QWORD PTR [rsp + 112], 1
    mov QWORD PTR [rsp + 192], 0
    mov QWORD PTR [rsp + 272], 0
    mov QWORD PTR [rsp + 352], 1
    .if X25519_TRACE
    mov QWORD PTR [rip + x25519_trace_init_frame], rsp
    mov rax, QWORD PTR [rsp + 32]
    mov QWORD PTR [rip + x25519_trace_init_u0], rax
    lea rax, [rsp + 32]
    mov QWORD PTR [rip + x25519_trace_init_ranges + 0], rax
    lea rax, [rsp + 112]
    mov QWORD PTR [rip + x25519_trace_init_ranges + 8], rax
    lea rax, [rsp + 192]
    mov QWORD PTR [rip + x25519_trace_init_ranges + 16], rax
    lea rax, [rsp + 272]
    mov QWORD PTR [rip + x25519_trace_init_x3_address], rax
    mov QWORD PTR [rip + x25519_trace_init_ranges + 24], rax
    lea rax, [rsp + 352]
    mov QWORD PTR [rip + x25519_trace_init_ranges + 32], rax
    mov r11d, 0
    .endif
    mov DWORD PTR [rsp + 1400], 0
    mov DWORD PTR [rsp + 1404], 0
    xor ecx, ecx
.Lxinit:
    mov QWORD PTR [rsp + 120 + rcx*8], 0
    X_TRACE_INIT_EVENT
    mov QWORD PTR [rsp + 192 + rcx*8], 0
    X_TRACE_INIT_EVENT
    mov rax, QWORD PTR [rsp + 32 + rcx*8]
    mov QWORD PTR [rsp + 272 + rcx*8], rax
    X_TRACE_INIT_EVENT
    mov QWORD PTR [rsp + 352 + rcx*8], 0
    X_TRACE_INIT_EVENT
    inc ecx
    cmp ecx, 10
    jb .Lxinit
    mov QWORD PTR [rsp + 112], 1
    mov QWORD PTR [rsp + 352], 1
    X_TRACE_STAGE 272, x25519_trace_x3_init
    .if X25519_TRACE
    mov QWORD PTR [rip + x25519_trace_snapshot_frame], rsp
    lea rax, [rsp + 272]
    mov QWORD PTR [rip + x25519_trace_snapshot_x3_address], rax
    mov rax, QWORD PTR [rsp + 272]
    mov QWORD PTR [rip + x25519_trace_init_after], rax
    .endif
    mov r15d, 254
.Lxladder:
    mov eax, r15d
    shr eax, 3
    movzx edx, BYTE PTR [rsp + rax]
    mov eax, r15d
    and eax, 7
    mov ecx, eax
    shr edx, cl
    and edx, 1
    mov DWORD PTR [rsp + 1404], edx
    xor edx, DWORD PTR [rsp + 1400]
    mov r11, rdx
    neg r11
    X_TRACE_FIRST_STAGE 112, x25519_trace_x2_pre
    X_TRACE_FIRST_STAGE 272, x25519_trace_x3_pre
    X_TRACE_BOUNDARY X_TRACE_PRE_CSWAP
    X_CSWAP 112, 272
    X_CSWAP 192, 352
    X_TRACE_FIRST_STAGE 112, x25519_trace_x2_post
    X_TRACE_FIRST_STAGE 272, x25519_trace_x3_post
      X_TRACE_BOUNDARY X_TRACE_POST_CSWAP
      mov edx, DWORD PTR [rsp + 1404]
    mov DWORD PTR [rsp + 1400], edx
      X_SNAPSHOT 112, 1728
    X_SNAPSHOT 192, 1808
    lea rdi, [rsp + 112]
    lea rsi, [rsp + 192]
    lea rdx, [rsp + 432]
    call field_add
     X_TRACE_NAMED 0, 0, 432
    X_TRACE_FIRST_CAPTURE 432, 0
    lea rdi, [rsp + 112]
    lea rsi, [rsp + 192]
    lea rdx, [rsp + 512]
    call field_sub
     X_TRACE_NAMED 1, 1, 512
    X_SNAPSHOT 432, 1408
    X_SNAPSHOT 512, 1488
    lea rdi, [rsp + 432]
    call field_reduce
    lea rdi, [rsp + 512]
    call field_reduce
    X_TRACE_FIRST_CAPTURE 512, 160
    lea rdi, [rsp + 272]
    lea rsi, [rsp + 352]
    lea rdx, [rsp + 592]
    call field_add
     X_TRACE_NAMED 2, 2, 592
    X_TRACE_FIRST_CAPTURE 592, 400
    lea rdi, [rsp + 592]
    call field_reduce
    lea rdi, [rsp + 272]
    lea rsi, [rsp + 352]
    lea rdx, [rsp + 672]
    call field_sub
     X_TRACE_NAMED 3, 3, 672
    lea rdi, [rsp + 672]
    call field_reduce
    X_TRACE_FIRST_CAPTURE 672, 480
    lea rdi, [rsp + 672]
    lea rsi, [rsp + 432]
    lea rdx, [rsp + 752]
    call field_mul
     X_TRACE_NAMED 4, 4, 752
    X_TRACE_FIRST_CAPTURE 752, 560
    lea rdi, [rsp + 592]
    lea rsi, [rsp + 512]
    lea rdx, [rsp + 832]
    call field_mul
     X_TRACE_NAMED 5, 5, 832
    X_TRACE_FIRST_CAPTURE 832, 640
    lea rdi, [rsp + 752]
    lea rsi, [rsp + 832]
    lea rdx, [rsp + 1152]
     call field_add
     X_TRACE_NAMED 6, 6, 1152
    lea rdi, [rsp + 1152]
    call field_reduce
    lea rdi, [rsp + 1152]
    lea rsi, [rsp + 1152]
    lea rdx, [rsp + 272]
     call field_sqr
     X_TRACE_NAMED 7, 7, 272
    X_TRACE_FIRST_CAPTURE 272, 720
    lea rdi, [rsp + 752]
    lea rsi, [rsp + 832]
    lea rdx, [rsp + 1232]
     call field_sub
     X_TRACE_NAMED 8, 8, 1232
    lea rdi, [rsp + 1232]
    call field_reduce
    X_TRACE_FIRST_CAPTURE 1232, 1120
    lea rdi, [rsp + 1232]
    lea rsi, [rsp + 1232]
    lea rdx, [rsp + 352]
     call field_sqr
     X_TRACE_NAMED 9, 9, 352
    lea rdi, [rsp + 32]
    lea rsi, [rsp + 352]
    lea rdx, [rsp + 352]
     call field_mul
     X_TRACE_NAMED 10, 10, 352
    lea rdi, [rsp + 432]
    lea rsi, [rsp + 432]
    lea rdx, [rsp + 992]
     call field_sqr
     X_TRACE_NAMED 11, 11, 992
    lea rdi, [rsp + 512]
    lea rsi, [rsp + 512]
    lea rdx, [rsp + 1072]
     call field_sqr
     X_TRACE_NAMED 12, 12, 1072
    X_SNAPSHOT 992, 1568
    X_SNAPSHOT 1072, 1648
    lea rdi, [rsp + 992]
     lea rsi, [rsp + 1072]
     lea rdx, [rsp + 1232]
     call field_sub
     X_TRACE_NAMED 13, 13, 1232
     lea rdi, [rsp + 1232]
      call field_reduce
    lea rdi, [rsp + 992]
    lea rsi, [rsp + 1072]
    lea rdx, [rsp + 112]
     call field_mul
     X_TRACE_NAMED 14, 14, 112
    lea rdi, [rsp + 992]
    lea rsi, [rsp + 1232]
    mov edx, 121665
    xor eax, eax
.Lxconst:
    mov QWORD PTR [rsp + 432 + rax*8], 0
    inc eax
    cmp eax, 10
    jb .Lxconst
    mov QWORD PTR [rsp + 432], rdx
    lea rdi, [rsp + 1232]
    lea rsi, [rsp + 432]
    lea rdx, [rsp + 1152]
     call field_mul
     X_TRACE_NAMED 15, 15, 1152
    lea rdi, [rsp + 992]
    lea rsi, [rsp + 1152]
    lea rdx, [rsp + 992]
     call field_add
    lea rdi, [rsp + 992]
    call field_reduce
    lea rdi, [rsp + 1232]
    lea rsi, [rsp + 992]
    lea rdx, [rsp + 192]
     call field_mul
     X_TRACE_NAMED 16, 16, 192
     X_TRACE_FIRST_CAPTURE 192, 960
     X_TRACE
     X_TRACE_BOUNDARY X_TRACE_BIT_END
     dec r15d
    jns .Lxladder
    mov r11, 0
    X_CSWAP 112, 272
    X_CSWAP 192, 352

    .if X25519_TRACE
    mov QWORD PTR [rsp + 1384], 0
    .endif
.Lxinv_start:
    # z2^(p-2), with a fixed public exponent
    xor ecx, ecx
.Lxinv_init:
    mov QWORD PTR [rsp + 1152 + rcx*8], 0
    inc ecx
    cmp ecx, 10
    jb .Lxinv_init
    mov QWORD PTR [rsp + 1152], 1
    mov rax, QWORD PTR [rsp + 192]
    mov QWORD PTR [rsp + 1232], rax
    mov rax, QWORD PTR [rsp + 200]
    mov QWORD PTR [rsp + 1240], rax
    mov rax, QWORD PTR [rsp + 208]
    mov QWORD PTR [rsp + 1248], rax
    mov rax, QWORD PTR [rsp + 216]
    mov QWORD PTR [rsp + 1256], rax
    mov rax, QWORD PTR [rsp + 224]
    mov QWORD PTR [rsp + 1264], rax
    mov rax, QWORD PTR [rsp + 232]
    mov QWORD PTR [rsp + 1272], rax
    mov rax, QWORD PTR [rsp + 240]
    mov QWORD PTR [rsp + 1280], rax
    mov rax, QWORD PTR [rsp + 248]
    mov QWORD PTR [rsp + 1288], rax
    mov rax, QWORD PTR [rsp + 256]
    mov QWORD PTR [rsp + 1296], rax
    mov rax, QWORD PTR [rsp + 264]
    mov QWORD PTR [rsp + 1304], rax
    mov r15d, 254
    lea rbx, [rip + x25519_exp]
.Lxinv:
     X_TRACE_INV_BEFORE
    lea rdi, [rsp + 1152]
    lea rsi, [rsp + 1152]
    lea rdx, [rsp + 1072]
     call field_sqr
     .if X25519_TRACE
      mov QWORD PTR [rsp + 1392], 0
     .endif
    mov eax, r15d
    shr eax, 3
    movzx edx, BYTE PTR [rbx + rax]
    mov eax, r15d
    and eax, 7
    mov ecx, eax
    shr edx, cl
      and edx, 1
      .if X25519_TRACE
      mov QWORD PTR [rsp + 1400], rdx
      .endif
     test edx, edx
     jz .Lxinv_square_only
     .if X25519_TRACE
      mov QWORD PTR [rsp + 1392], 1
     .endif
    lea rdi, [rsp + 1072]
    lea rsi, [rsp + 1232]
    lea rdx, [rsp + 1152]
     call field_mul
    jmp .Lxinv_skip
.Lxinv_square_only:
    xor ecx, ecx
.Lxinv_square_copy:
    mov rax, QWORD PTR [rsp + 1072 + rcx*8]
    mov QWORD PTR [rsp + 1152 + rcx*8], rax
    inc ecx
    cmp ecx, 10
    jb .Lxinv_square_copy
.Lxinv_skip:
     X_TRACE_INV_AFTER
     dec r15d
    jns .Lxinv
    .if X25519_TRACE
    cmp QWORD PTR [rsp + 1384], 1
    je .Lxinv_debug_return
    .endif
    lea rdi, [rsp + 112]
    lea rsi, [rsp + 1152]
    lea rdx, [rsp + 1072]
    call field_mul

    # Select h-p without a data-dependent branch.
    mov rax, QWORD PTR [rsp + 1072]
    sub rax, 67108845
    mov QWORD PTR [rsp + 992], rax
    mov rax, QWORD PTR [rsp + 1080]
    sbb rax, 67108863
    mov QWORD PTR [rsp + 1000], rax
    mov rax, QWORD PTR [rsp + 1088]
    sbb rax, 67108863
    mov QWORD PTR [rsp + 1008], rax
    mov rax, QWORD PTR [rsp + 1096]
    sbb rax, 67108863
    mov QWORD PTR [rsp + 1016], rax
    mov rax, QWORD PTR [rsp + 1104]
    sbb rax, 67108863
    mov QWORD PTR [rsp + 1024], rax
    mov rax, QWORD PTR [rsp + 1112]
    sbb rax, 67108863
    mov QWORD PTR [rsp + 1032], rax
    mov rax, QWORD PTR [rsp + 1120]
    sbb rax, 67108863
    mov QWORD PTR [rsp + 1040], rax
    mov rax, QWORD PTR [rsp + 1128]
    sbb rax, 67108863
    mov QWORD PTR [rsp + 1048], rax
    mov rax, QWORD PTR [rsp + 1136]
    sbb rax, 67108863
    mov QWORD PTR [rsp + 1056], rax
    mov rax, QWORD PTR [rsp + 1144]
    sbb rax, 33554431
    mov QWORD PTR [rsp + 1064], rax
    xor r11, r11
    sbb r11, r11
    xor ecx, ecx
.Lxcanon:
    mov rax, QWORD PTR [rsp + 1072 + rcx*8]
    xor rax, QWORD PTR [rsp + 992 + rcx*8]
    and rax, r11
    xor rax, QWORD PTR [rsp + 1072 + rcx*8]
    mov QWORD PTR [rsp + 1072 + rcx*8], rax
    inc ecx
    cmp ecx, 10
    jb .Lxcanon

    mov rax, QWORD PTR [rsp + 1072]
    mov QWORD PTR [rsp + 1312], rax
    mov rax, QWORD PTR [rsp + 1080]
    mov QWORD PTR [rsp + 1320], rax
    mov rax, QWORD PTR [rsp + 1088]
    mov QWORD PTR [rsp + 1328], rax
    mov rax, QWORD PTR [rsp + 1096]
    mov QWORD PTR [rsp + 1336], rax
    mov rax, QWORD PTR [rsp + 1104]
    mov QWORD PTR [rsp + 1344], rax
    mov rax, QWORD PTR [rsp + 1112]
    mov QWORD PTR [rsp + 1352], rax
    mov rax, QWORD PTR [rsp + 1120]
    mov QWORD PTR [rsp + 1360], rax
    mov rax, QWORD PTR [rsp + 1128]
    mov QWORD PTR [rsp + 1368], rax
    mov rax, QWORD PTR [rsp + 1136]
    mov QWORD PTR [rsp + 1376], rax
    mov rax, QWORD PTR [rsp + 1144]
    mov QWORD PTR [rsp + 1384], rax
    mov eax, DWORD PTR [rsp + 1072]
    mov ecx, DWORD PTR [rsp + 1080]
    shl rcx, 26
    or rax, rcx
    mov DWORD PTR [r12], eax
    mov eax, DWORD PTR [rsp + 1080]
    shr eax, 6
    mov ecx, DWORD PTR [rsp + 1088]
    shl ecx, 20
    or eax, ecx
    mov DWORD PTR [r12 + 4], eax
    mov eax, DWORD PTR [rsp + 1088]
    shr eax, 12
    mov ecx, DWORD PTR [rsp + 1096]
    shl ecx, 14
    or eax, ecx
    mov DWORD PTR [r12 + 8], eax
    mov eax, DWORD PTR [rsp + 1096]
    shr eax, 18
    mov ecx, DWORD PTR [rsp + 1104]
    shl ecx, 8
    or eax, ecx
    mov DWORD PTR [r12 + 12], eax
    mov eax, DWORD PTR [rsp + 1104]
    shr eax, 24
    mov ecx, DWORD PTR [rsp + 1112]
    shl ecx, 2
    or eax, ecx
    mov ecx, DWORD PTR [rsp + 1120]
    shl ecx, 28
    or eax, ecx
    mov DWORD PTR [r12 + 16], eax
    mov eax, DWORD PTR [rsp + 1112]
    shr eax, 30
    mov ecx, DWORD PTR [rsp + 1120]
    shr ecx, 4
    or eax, ecx
    mov ecx, DWORD PTR [rsp + 1128]
    shl ecx, 22
    or eax, ecx
    mov DWORD PTR [r12 + 20], eax
    mov eax, DWORD PTR [rsp + 1128]
    shr eax, 10
    mov ecx, DWORD PTR [rsp + 1136]
    shl ecx, 16
    or eax, ecx
    mov DWORD PTR [r12 + 24], eax
    mov eax, DWORD PTR [rsp + 1136]
    shr eax, 16
    mov ecx, DWORD PTR [rsp + 1144]
    shl ecx, 10
    or eax, ecx
    mov DWORD PTR [r12 + 28], eax
    add rsp, 2048
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.if X25519_TRACE
.global x25519_trace_buffer
.global x25519_debug_invert
# x25519_debug_invert(out, input) uses the inline inversion frame and loop.
x25519_debug_invert:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 2048
    mov r12, rdi
    mov QWORD PTR [rsp + 1384], 1
    mov QWORD PTR [rip + x25519_trace_inv_count], 0
    xor ecx, ecx
.Lxinv_debug_copy:
    mov rax, QWORD PTR [rsi + rcx*8]
    mov QWORD PTR [rsp + 192 + rcx*8], rax
    inc ecx
    cmp ecx, 10
    jb .Lxinv_debug_copy
    jmp .Lxinv_start
.Lxinv_debug_return:
    xor ecx, ecx
.Lxinv_debug_output:
    mov rax, QWORD PTR [rsp + 1152 + rcx*8]
    mov QWORD PTR [r12 + rcx*8], rax
    inc ecx
    cmp ecx, 10
    jb .Lxinv_debug_output
    add rsp, 2048
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.global x25519_trace_count
.global x25519_trace_named
.global x25519_trace_boundary_buffer
.global x25519_trace_boundary_count
.global x25519_trace_inv_buffer
.global x25519_trace_inv_count
x25519_trace_record:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13d, esi
    mov r14d, edx
    mov rax, QWORD PTR [rip + x25519_trace_count]
    cmp rax, 255
    jae .Lxtrace_done
    imul r15, rax, 576
    lea rbx, [rip + x25519_trace_buffer]
    add rbx, r15
    mov QWORD PTR [rbx], r13
    mov QWORD PTR [rbx + 8], r14
    lea r8, [r12 + 1408]
    lea r9, [rbx + 16]
    mov ecx, 10
.Lxtrace_x2:
    mov rax, QWORD PTR [r8]
    mov QWORD PTR [r9], rax
    add r8, 8
    add r9, 8
    dec ecx
    jnz .Lxtrace_x2
    lea r8, [r12 + 1568]
    lea r9, [rbx + 96]
    mov ecx, 10
.Lxtrace_z2:
    mov rax, QWORD PTR [r8]
    mov QWORD PTR [r9], rax
    add r8, 8
    add r9, 8
    dec ecx
    jnz .Lxtrace_z2
    lea r8, [r12 + 1488]
    lea r9, [rbx + 176]
    mov ecx, 10
.Lxtrace_x3:
    mov rax, QWORD PTR [r8]
    mov QWORD PTR [r9], rax
    add r8, 8
    add r9, 8
    dec ecx
    jnz .Lxtrace_x3
    lea r8, [r12 + 1648]
    lea r9, [rbx + 256]
    mov ecx, 10
.Lxtrace_z3:
    mov rax, QWORD PTR [r8]
    mov QWORD PTR [r9], rax
    add r8, 8
    add r9, 8
    dec ecx
    jnz .Lxtrace_z3
    lea r8, [r12 + 112]
    lea r9, [rbx + 336]
    mov ecx, 10
.Lxtrace_x2_final:
    mov rax, QWORD PTR [r8]
    mov QWORD PTR [r9], rax
    add r8, 8
    add r9, 8
    dec ecx
    jnz .Lxtrace_x2_final
    lea r8, [r12 + 1728]
    lea r9, [rbx + 416]
    mov ecx, 10
.Lxtrace_x2_input:
    mov rax, QWORD PTR [r8]
    mov QWORD PTR [r9], rax
    add r8, 8
    add r9, 8
    dec ecx
    jnz .Lxtrace_x2_input
    lea r8, [r12 + 1808]
    lea r9, [rbx + 496]
    mov ecx, 10
.Lxtrace_z2_input:
    mov rax, QWORD PTR [r8]
    mov QWORD PTR [r9], rax
    add r8, 8
    add r9, 8
    dec ecx
    jnz .Lxtrace_z2_input
    inc QWORD PTR [rip + x25519_trace_count]
.Lxtrace_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
x25519_trace_boundary:
    push r11
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13d, esi
    mov r14d, edx
    mov rax, QWORD PTR [rip + x25519_trace_boundary_count]
    cmp rax, 765
    jae .Lxtrace_boundary_done
    imul r15, rax, X_TRACE_BOUNDARY_RECORD_SIZE
    lea rbx, [rip + x25519_trace_boundary_buffer]
    add rbx, r15
    mov QWORD PTR [rbx], r13
    mov QWORD PTR [rbx + 8], r14
    mov QWORD PTR [rbx + 16], rcx
    mov QWORD PTR [rbx + 24], 0
    mov QWORD PTR [rbx + 32], 1
    mov QWORD PTR [rbx + 40], 2
    mov QWORD PTR [rbx + 48], 3
    lea r8, [r12 + 112]
    lea r9, [rbx + 56]
    mov ecx, 10
.Lxtrace_boundary_x2:
    mov rax, QWORD PTR [r8]
    mov QWORD PTR [r9], rax
    add r8, 8
    add r9, 8
    dec ecx
    jnz .Lxtrace_boundary_x2
    lea r8, [r12 + 192]
    lea r9, [rbx + 136]
    mov ecx, 10
.Lxtrace_boundary_z2:
    mov rax, QWORD PTR [r8]
    mov QWORD PTR [r9], rax
    add r8, 8
    add r9, 8
    dec ecx
    jnz .Lxtrace_boundary_z2
    lea r8, [r12 + 272]
    lea r9, [rbx + 216]
    mov ecx, 10
.Lxtrace_boundary_x3:
    mov rax, QWORD PTR [r8]
    mov QWORD PTR [r9], rax
    add r8, 8
    add r9, 8
    dec ecx
    jnz .Lxtrace_boundary_x3
    lea r8, [r12 + 352]
    lea r9, [rbx + 296]
    mov ecx, 10
.Lxtrace_boundary_z3:
    mov rax, QWORD PTR [r8]
    mov QWORD PTR [r9], rax
    add r8, 8
    add r9, 8
    dec ecx
    jnz .Lxtrace_boundary_z3
    inc QWORD PTR [rip + x25519_trace_boundary_count]
.Lxtrace_boundary_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop r11
    ret
.section .bss
.align 8
x25519_trace_count: .quad 0
x25519_trace_buffer: .zero 146880
x25519_trace_boundary_count: .quad 0
x25519_trace_boundary_buffer: .zero 287640
x25519_trace_input: .zero 32
x25519_trace_decoded: .zero 80
x25519_trace_x3_init: .zero 80
x25519_trace_x2_pre: .zero 80
x25519_trace_x3_pre: .zero 80
x25519_trace_x2_post: .zero 80
x25519_trace_x3_post: .zero 80
x25519_trace_init_u0: .zero 8
x25519_trace_init_x3_address: .zero 8
x25519_trace_init_ranges: .zero 40
x25519_trace_init_events: .zero 320
x25519_trace_init_after: .zero 8
x25519_trace_init_frame: .zero 8
x25519_trace_snapshot_frame: .zero 8
x25519_trace_snapshot_x3_address: .zero 8
x25519_mul_trace: .zero 1368
x25519_mul_trace_folded: .zero 152
x25519_mul_trace_carry0: .zero 152
x25519_mul_trace_carry1: .zero 152
x25519_mul_trace_carry2: .zero 152
x25519_mul_trace_carry3: .zero 152
x25519_mul_trace_carry4: .zero 152
x25519_mul_trace_carry5: .zero 152
x25519_mul_trace_carry6: .zero 152
x25519_trace_sq_count: .zero 8
x25519_trace_sq_active: .zero 8
x25519_trace_sq_a: .zero 8
x25519_trace_sq_b: .zero 8
x25519_trace_sq_dest: .zero 8
x25519_trace_sq_input: .zero 80
x25519_trace_mul_dest: .zero 8
x25519_trace_mul_src1: .zero 8
x25519_trace_mul_src2: .zero 8
x25519_trace_mul_input: .zero 80
x25519_trace_mul_input2: .zero 80
x25519_trace_sq_output: .zero 80
x25519_trace_ops: .zero 1440
x25519_trace_named: .zero 450840
x25519_trace_inv_count: .quad 0
x25519_trace_inv_buffer: .zero 108120
.section .text
.endif

.section .rodata
x25519_exp:
    .byte 0xeb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    .byte 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    .byte 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    .byte 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
x25519_prime:
    .quad 67108845, 67108863, 67108863, 67108863, 67108863
    .quad 67108863, 67108863, 67108863, 67108863, 2097151
