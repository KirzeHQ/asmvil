.include "testing/signatures.inc"

.ifdef ASMVIL_TESTING

.weak x25519

.macro ASM_TEST_ARCHES architectures:vararg
.endm

.macro ASM_FUNC name, signature, flags, source_dir, source_name
    .section .rodata
.Lasmvil_test_name_\@:
    .asciz "\name"
.Lasmvil_test_name_end_\@:
    .pushsection asmvil_test_registry,"a",@progbits
    .balign 8
    .long ASM_TEST_VERSION
    .long ASM_TEST_RECORD_SIZE
    .quad \signature
    .quad \flags
    .quad .Lasmvil_test_name_\@
    .quad .Lasmvil_test_name_end_\@ - .Lasmvil_test_name_\@ - 1
    .quad \name
    .quad 0
    .popsection
.endm

.include "testing/tests.inc"

.global asmvil_test_registry_version
.global asmvil_test_registry_begin
.global asmvil_test_registry_end

.section .text
asmvil_test_registry_version:
    mov x0, ASM_TEST_VERSION
    ret

asmvil_test_registry_begin:
    adrp x0, __start_asmvil_test_registry
    add x0, x0, :lo12:__start_asmvil_test_registry
    ret

asmvil_test_registry_end:
    adrp x0, __stop_asmvil_test_registry
    add x0, x0, :lo12:__stop_asmvil_test_registry
    ret

.section .asmvil_test_registry,"a",@progbits
.balign 8
__start_asmvil_test_registry:
__stop_asmvil_test_registry:
.endif
