.intel_syntax noprefix
.include "common.inc"

# HMAC-SHA256 / HMAC-SHA384 / HMAC-SHA512 (RFC 2104) for x86-64.
# See ../hmac.inc for the shared API notes.

.section .text

# One instantiation per hash. Parameters:
#   name    exported symbol: hmac(rdi=key, rsi=keylen, rdx=msg, rcx=msglen, r8=mac)
#   initfn / updfn / finfn   hash entry points
#   B       hash block size in bytes
#   L       digest size in bytes
#   CTX     hash context size in bytes
.macro HMAC_IMPL name, initfn, updfn, finfn, B, L, CTX
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
    mov r12, rsi
    mov r13, rdx
    mov r14, rcx
    mov r15, r8
    sub rsp, 2*\CTX + 3*\B + \L
    mov rbp, rsp

    # K = key, or H(key) when keylen > B
    cmp r12, \B
    jbe 1f
    lea rdi, [rbp]
    call \initfn
    lea rdi, [rbp]
    mov rsi, rbx
    mov rdx, r12
    call \updfn
    lea rdi, [rbp]
    lea rsi, [rbp + 2*\CTX]
    call \finfn
    mov r12, \L
    jmp 2f
1:
    lea rdi, [rbp + 2*\CTX]
    mov rsi, rbx
    mov rcx, r12
    rep movsb
2:
    # zero-pad K to block size
    xor eax, eax
    mov rcx, \B
    sub rcx, r12
    lea rdi, [rbp + 2*\CTX]
    add rdi, r12
    rep stosb

    # ipad = K ^ 0x36, opad = K ^ 0x5c
    lea r12, [rbp + 2*\CTX]
    lea rbx, [rbp + 2*\CTX + \B]
    lea rcx, [rbp + 2*\CTX + 2*\B]
    mov r8, \B
3:
    test r8, r8
    jz 4f
    movzx rax, byte ptr [r12]
    mov rdx, rax
    xor al, 0x36
    xor dl, 0x5c
    mov [rbx], al
    mov [rcx], dl
    inc r12
    inc rbx
    inc rcx
    dec r8
    jmp 3b
4:
    # inner digest = H(i_pad || msg)
    lea rdi, [rbp]
    call \initfn
    lea rdi, [rbp]
    lea rsi, [rbp + 2*\CTX + \B]
    mov rdx, \B
    call \updfn
    lea rdi, [rbp]
    mov rsi, r13
    mov rdx, r14
    call \updfn
    lea rdi, [rbp]
    lea rsi, [rbp + 2*\CTX + 3*\B]
    call \finfn

    # mac = H(o_pad || inner_digest)
    lea rdi, [rbp + \CTX]
    call \initfn
    lea rdi, [rbp + \CTX]
    lea rsi, [rbp + 2*\CTX + 2*\B]
    mov rdx, \B
    call \updfn
    lea rdi, [rbp + \CTX]
    lea rsi, [rbp + 2*\CTX + 3*\B]
    mov rdx, \L
    call \updfn
    lea rdi, [rbp + \CTX]
    mov rsi, r15
    call \finfn

    add rsp, 2*\CTX + 3*\B + \L
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.endm

HMAC_IMPL hmac_sha256, sha256_init, sha256_update, sha256_final, 64, 32, 112
HMAC_IMPL hmac_sha384, sha384_init, sha512_update, sha512_final, 128, 48, 216
HMAC_IMPL hmac_sha512, sha512_init, sha512_update, sha512_final, 128, 64, 216
