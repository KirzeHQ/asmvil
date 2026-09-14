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
    cargo test --manifest-path tests/Cargo.toml

fmt:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "fmt is not configured for assembly yet"

lint:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "lint is not configured for assembly yet"
