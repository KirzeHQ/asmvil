# Shared testing signature IDs
.equ ASM_TEST_SIG_BUFFER_TO_BUFFER,             1
.equ ASM_TEST_SIG_CONTEXT_BUFFER_TO_BUFFER,     2
.equ ASM_TEST_SIG_KEY_BUFFER_TO_BUFFER,         3
.equ ASM_TEST_SIG_CONTEXT_KEY_NONCE,            4
.equ ASM_TEST_SIG_CONTEXT_INPUT_OUTPUT_LENGTH,  5
.equ ASM_TEST_SIG_BIGINT_BINARY,                6
.equ ASM_TEST_SIG_BIGINT_SHIFT,                 7
.equ ASM_TEST_SIG_X25519,                       8

.equ ASM_TEST_VERSION,                          1
.equ ASM_TEST_RECORD_SIZE,                      56

.equ ASM_TEST_FLAG_CPU_AESNI,                  (1 << 0)
.equ ASM_TEST_FLAG_CPU_PCLMUL,                 (1 << 1)
.equ ASM_TEST_FLAG_CPU_SSSE3,                  (1 << 2)
.equ ASM_TEST_FLAG_CPU_ARM_AES,                (1 << 3)
.equ ASM_TEST_FLAG_CPU_ARM_PMULL,              (1 << 4)
.equ ASM_TEST_FLAG_EXPERIMENTAL,               (1 << 5)

.equ ASM_TEST_OK,                               0
.equ ASM_TEST_INVALID_FRAME,                    1
.equ ASM_TEST_ARGS_TOO_SMALL,                   2
.equ ASM_TEST_OUT_TOO_SMALL,                    3
.equ ASM_TEST_INVALID_ARGUMENT,                 4
.equ ASM_TEST_INVALID_ALIGNMENT,                5
.equ ASM_TEST_UNSUPPORTED,                      6
.equ ASM_TEST_PRIMITIVE_FAILURE,                7
