name := "asmvil"
build_dir := "build"
src_dir := "src"

default: build

native-arch:
    #!/usr/bin/env bash
    case "$(uname -m)" in
        x86_64|amd64) echo "x86_64" ;;
        aarch64|arm64) echo "aarch64" ;;
        *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
    esac

build: 
    #!/usr/bin/env bash
    set -euo pipefail
    case "$(uname -m)" in
        x86_64|amd64)
            just build-x86_64
            ;;
        aarch64|arm64)
            just build-aarch64
            ;;
        *)
            echo "Unsupported architecture: $(uname -m)" >&2
            exit 1
            ;;
    esac

build-all: build-x86_64 build-aarch64

build-x86_64:
    #!/usr/bin/env bash
    set -euo pipefail
    out="{{build_dir}}/{{name}}_x86_64"
    mkdir -p "$out"
    as --64 -I include/x86_64 -o "$out/{{name}}.o" {{src_dir}}/main.asm
    as --64 -I include/x86_64 -o "$out/start.o" {{src_dir}}/x86_64/start.asm
    ld -m elf_x86_64 -z noexecstack -o "$out/{{name}}" "$out/{{name}}.o" "$out/start.o"
    echo "Built: $out/{{name}}"

build-aarch64:
    #!/usr/bin/env bash
    set -euo pipefail
    out="{{build_dir}}/{{name}}_aarch64"
    mkdir -p "$out"
    as -march=armv8-a -I include/aarch64 -o "$out/{{name}}.o" {{src_dir}}/main.asm
    as -march=armv8-a -I include/aarch64 -o "$out/start.o" {{src_dir}}/aarch64/start.asm
    ld -m aarch64linux -z noexecstack -o "$out/{{name}}" "$out/{{name}}.o" "$out/start.o"
    echo "Built: $out/{{name}}"

run: build
    ./{{build_dir}}/{{name}}_$(uname -m)/{{name}}

clean:
    rm -rf {{build_dir}}
    echo "Cleaned build directory"

test:
    #!/usr/bin/env bash
    set -euo pipefail
    case "$(uname -m)" in
        x86_64|amd64)
            arch=x86_64
            asflags="--64"
            ldflags="-m elf_x86_64"
            ;;
        aarch64|arm64)
            arch=aarch64
            asflags="-march=armv8-a"
            ldflags="-m aarch64linux"
            ;;
        *)
            echo "Unsupported architecture: $(uname -m)" >&2
            exit 1
            ;;
    esac
    testdir="tests/$arch"
    if [ ! -d "$testdir" ] || [ -z "$(ls -A "$testdir" 2>/dev/null)" ]; then
        echo "No tests found in $testdir/"
        exit 0
    fi

    # Build the crypto library for the native arch.
    mkdir -p /tmp/asmvil_crypto
    extra_objs=""
    for src in {{src_dir}}/crypto/$arch/*.asm; do
        [ -e "$src" ] || continue
        obj="/tmp/asmvil_crypto/$(basename "$src" .asm).o"
        as $asflags -I "include/$arch" -I src -o "$obj" "$src" || exit 1
        extra_objs="$extra_objs $obj"
    done

    for test in $(find "$testdir" -name '*.asm' | sort); do
        echo "Testing: $test"
        as $asflags -I "include/$arch" -o /tmp/test.o "$test" || exit 1
        ld $ldflags -z noexecstack -o /tmp/test /tmp/test.o $extra_objs || exit 1
        /tmp/test
        echo "PASS: $test"
        rm -f /tmp/test /tmp/test.o
    done
    rm -rf /tmp/asmvil_crypto
    echo "All tests passed"

fmt:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "fmt is not configured for assembly yet"

lint:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "lint is not configured for assembly yet"
