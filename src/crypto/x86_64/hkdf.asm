.intel_syntax noprefix
.include "common.inc"

# HKDF-SHA256 / HKDF-SHA384 / HKDF-SHA512 extract + expand (RFC 5869)
# for x86-64. See ../hkdf.inc for the shared API notes.
# Expansion is a loop of HMAC calls so OKM can be as large as 255 * L.

.section .text

# Extract is exactly HMAC(salt, ikm)
.macro HKDF_EXTRACT name, hmacfn
.global \name
\name:
    jmp \hmacfn
.endm

# HKDF-Expand for one hash. Parameters:
#   name      exported symbol: (rdi=prk, rsi=info, rdx=infolen, rcx=okm, r8=okmlen)
#   hmacfn    hmac entry point with the matching digest length L
#   L         hash output length in bytes
.macro HKDF_EXPAND name, hmacfn, L
.global \name
\name:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    cld
    mov rbx, rdi
    mov r13, rsi
    mov r14, rdx
    mov r12, rcx
    mov r15, r8
    test r15, r15
    jz 9f
    # Keep the call-site stack aligned after six saved registers.
    lea rax, [r14 + 3*\L + 24]
    and rax, -16
    add rax, 8
    sub rsp, rax
    mov rbp, rsp
    mov qword ptr [rbp + r14 + 3*\L + 9], 0
    mov byte ptr [rbp + r14 + 3*\L + 1], 1
2:
    # msg = T[..tlen) || info || counter
    mov rsi, rbp
    mov rcx, [rbp + r14 + 3*\L + 9]
    lea rdi, [rbp + \L]
    rep movsb
    mov rsi, r13
    mov rcx, r14
    rep movsb
    movzx rax, byte ptr [rbp + r14 + 3*\L + 1]
    mov [rdi], al
    inc byte ptr [rbp + r14 + 3*\L + 1]

    # T(i) = HMAC(prk, msg, tlen + infolen + 1)
    mov rdi, rbx
    mov rsi, \L
    lea rdx, [rbp + \L]
    mov rcx, [rbp + r14 + 3*\L + 9]
    add rcx, r14
    add rcx, 1
    lea r8, [rbp + r14 + 2*\L + 1]
    call \hmacfn

    # copy min(L, remaining) bytes into okm
    mov rcx, \L
    cmp r15, rcx
    jae 1f
    mov rcx, r15
1:
    mov r9, rcx
    lea rsi, [rbp + r14 + 2*\L + 1]
    mov rdi, r12
    rep movsb
    add r12, r9
    sub r15, r9

    # keep the full block as T for the next round
    lea rsi, [rbp + r14 + 2*\L + 1]
    mov rdi, rbp
    mov rcx, \L
    rep movsb
    mov qword ptr [rbp + r14 + 3*\L + 9], \L
    test r15, r15
    jnz 2b

    lea rax, [r14 + 3*\L + 24]
    and rax, -16
    add rax, 8
    add rsp, rax
9:
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.endm

# HKDF-Expand-Label (RFC 8446 7.1): builds
#   HkdfLabel = u16(outlen) || "tls13 " || label || u8(constextlen) || context
# and feeds it to the hash's expand step. Parameters:
#   name        exported symbol: (rdi=secret, rsi=label, rdx=labellen,
#                 rcx=context, r8=contextlen, r9=out, outlen=[rsp+8])
#   expandfn    hkdf expand for the matching hash
.macro HKDF_EL name, expandfn
.global \name
\name:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    cld
    mov rbx, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    mov r12, r8
    lea rax, [r14 + r12 + 24]
    and rax, -16
    sub rsp, rax
    mov rbp, rsp
    mov r8, [rsp + rax + 56]
    mov rdx, r8
    shr rdx, 8
    mov [rbp], dl
    mov [rbp + 1], r8b
    mov word ptr [rbp + 2], 0x6c74
    mov dword ptr [rbp + 4], 0x20333173
    lea rdi, [rbp + 8]
    mov rsi, r13
    mov rcx, r14
    rep movsb
    mov [rdi], r12b
    inc rdi
    mov rsi, r15
    mov rcx, r12
    rep movsb
    mov rdi, rbx
    lea rsi, [rbp]
    lea rdx, [r14 + r12 + 9]
    mov rcx, r9
    call \expandfn
    lea rax, [r14 + r12 + 24]
    and rax, -16
    add rsp, rax
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.endm

.macro HKDF_DS name, expandlabelfn, L
.global \name
\name:
    push \L
    call \expandlabelfn
    add rsp, 8
    ret
.endm

HKDF_EXTRACT hkdf_sha256_extract, hmac_sha256
HKDF_EXPAND  hkdf_sha256_expand, hmac_sha256, 32
HKDF_EXTRACT hkdf_sha384_extract, hmac_sha384
HKDF_EXPAND  hkdf_sha384_expand, hmac_sha384, 48
HKDF_EXTRACT hkdf_sha512_extract, hmac_sha512
HKDF_EXPAND  hkdf_sha512_expand, hmac_sha512, 64

HKDF_EL hkdf_expand_label_sha256, hkdf_sha256_expand
HKDF_DS hkdf_derive_secret_sha256, hkdf_expand_label_sha256, 32
HKDF_EL hkdf_expand_label_sha384, hkdf_sha384_expand
HKDF_DS hkdf_derive_secret_sha384, hkdf_expand_label_sha384, 48
HKDF_EL hkdf_expand_label_sha512, hkdf_sha512_expand
HKDF_DS hkdf_derive_secret_sha512, hkdf_expand_label_sha512, 64
