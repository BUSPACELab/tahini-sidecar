# Tahini Sidecar
# Requires: SGX_SDK in environment (e.g. /opt/intel/sgxsdk), SGX_MODE optional (SIM|HW).

load("@rules_shell//shell:sh_binary.bzl", "sh_binary")

# Trusted code
genrule(
    name = "edl_gen",
    srcs = ["sidecar.edl"],
    outs = [
        "sidecar_u.c",
        "sidecar_u.h",
        "sidecar_t.c",
        "sidecar_t.h",
    ],
    cmd = """
        set -e
        SDK="$$SGX_SDK"
        [ -z "$$SDK" ] && { echo "SGX_SDK must be set (e.g. /opt/intel/sgxsdk)"; exit 1; }
        "$$SDK/bin/x64/sgx_edger8r" --untrusted "$(location sidecar.edl)" --search-path "$$SDK/include" --untrusted-dir "$(@D)"
        "$$SDK/bin/x64/sgx_edger8r" --trusted "$(location sidecar.edl)" --search-path "$$SDK/include" --trusted-dir "$(@D)"
    """,
    message = "Generating SGX bridge code from EDL",
)

# Untrusted code
genrule(
    name = "sidecar_bin",
    srcs = [
        ":edl_gen",
        "sidecar.h",
        "u_attest.c",
        "u_attest.h",
        "u_main.c",
        "u_util.c",
        "u_util.h",
    ],
    outs = ["sidecar"],
    cmd = """
        set -e
        SDK="$$SGX_SDK"
        [ -z "$$SDK" ] && { echo "SGX_SDK must be set"; exit 1; }
        EDL_FILES="$(locations :edl_gen)"
        EDL_DIR="$$(dirname "$$(echo "$$EDL_FILES" | awk '{print $$1}')")"
        ROOT="$$(dirname $(location sidecar.h))"
        if [ "$$SGX_MODE" = "HW" ]; then URTS=sgx_urts; else URTS=sgx_urts_sim; fi
        DCAP_HOME="$${DCAP_HOME:-/usr}"
        DCAP_INC="$$DCAP_HOME/include"
        DCAP_LIB="$$DCAP_HOME/lib64"
        [ -d "$$DCAP_HOME/lib/x86_64-linux-gnu" ] && DCAP_LIB="$$DCAP_HOME/lib/x86_64-linux-gnu"
        CC="$${CC:-gcc}"
        $$CC -m64 -fPIC -Wno-attributes -I"$$SDK/include" -I"$$DCAP_INC" -I"$$ROOT" -I"$$EDL_DIR" -c "$$EDL_DIR/sidecar_u.c" -o "$(@D)/sidecar_u.o"
        $$CC -m64 -fPIC -Wno-attributes -I"$$SDK/include" -I"$$DCAP_INC" -I"$$ROOT" -I"$$EDL_DIR" -c "$(location u_main.c)" -o "$(@D)/u_main.o"
        $$CC -m64 -fPIC -Wno-attributes -I"$$SDK/include" -I"$$DCAP_INC" -I"$$ROOT" -I"$$EDL_DIR" -c "$(location u_util.c)" -o "$(@D)/u_util.o"
        $$CC -m64 -fPIC -Wno-attributes -I"$$SDK/include" -I"$$DCAP_INC" -I"$$ROOT" -I"$$EDL_DIR" -c "$(location u_attest.c)" -o "$(@D)/u_attest.o"
        $$CC -m64 -o "$@" "$(@D)/sidecar_u.o" "$(@D)/u_main.o" "$(@D)/u_util.o" "$(@D)/u_attest.o" -L"$$SDK/lib64" -L"$$DCAP_LIB" -l$$URTS -lsgx_dcap_ql -lpthread
    """,
    message = "Building untrusted sidecar binary",
)

# ---- Trusted enclave (enclave.so) ----
genrule(
    name = "enclave_so",
    srcs = [
        ":edl_gen",
        "e_sidecar.c",
        "sidecar.h",
        "sidecar.lds",
    ],
    outs = ["enclave.so"],
    cmd = """
        set -e
        SDK="$$SGX_SDK"
        [ -z "$$SDK" ] && { echo "SGX_SDK must be set"; exit 1; }
        EDL_FILES="$(locations :edl_gen)"
        EDL_DIR="$$(dirname "$$(echo "$$EDL_FILES" | awk '{print $$1}')")"
        ROOT="$$(dirname $(location sidecar.h))"
        if [ "$$SGX_MODE" = "HW" ]; then
            TRTS=sgx_trts; TSVC=sgx_tservice
        else
            TRTS=sgx_trts_sim; TSVC=sgx_tservice_sim
        fi
        CC="$${CC:-gcc}"
        $$CC -m64 -nostdinc -fvisibility=hidden -fpie -fstack-protector \\
            -I"$$SDK/include" -I"$$SDK/include/tlibc" -I"$$ROOT" -I"$$EDL_DIR" \\
            -c "$$EDL_DIR/sidecar_t.c" -o "$(@D)/sidecar_t.o"
        $$CC -m64 -nostdinc -fvisibility=hidden -fpie -fstack-protector \\
            -I"$$SDK/include" -I"$$SDK/include/tlibc" -I"$$ROOT" -I"$$EDL_DIR" \\
            -c "$(location e_sidecar.c)" -o "$(@D)/e_sidecar.o"
        $$CC -m64 -nostdlib -nodefaultlibs -nostartfiles \\
            "$(@D)/sidecar_t.o" "$(@D)/e_sidecar.o" \\
            -L"$$SDK/lib64" -Wl,--no-undefined \\
            -Wl,--whole-archive -l$$TRTS -Wl,--no-whole-archive \\
            -Wl,--start-group -lsgx_tstdc -lsgx_tcrypto -l$$TSVC -Wl,--end-group \\
            -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \\
            -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \\
            -Wl,--defsym,__ImageBase=0 \\
            -Wl,--version-script="$(location sidecar.lds)" \\
            -o "$@"
    """,
    message = "Building enclave shared object",
)

# ---- Signing key (generated; use a fixed key in repo for reproducible signing) ----
genrule(
    name = "signing_key",
    outs = ["sidecar_private.pem"],
    # A generated key gives the enclave a different MRSIGNER on every build, so
    # nothing can pin who signed it. Two builds of the same commit were confirmed
    # to produce identical MRENCLAVE and different MRSIGNER, which is exactly this.
    #
    # Point TAHINI_SIGNING_KEY at a PEM to sign with a fixed key and get a stable
    # MRSIGNER. Generating one remains the default so a fresh clone builds without
    # setup; that is fine for development, where the code identity is what matters,
    # and not fine for anything a verifier is expected to trust.
    #
    # SGX requires RSA-3072 with public exponent 3:
    #   openssl genrsa -out sidecar_private.pem -3 3072
    cmd = """
        set -e
        if [ -n "$${TAHINI_SIGNING_KEY:-}" ]; then
            if [ ! -f "$${TAHINI_SIGNING_KEY:-}" ]; then
                echo "TAHINI_SIGNING_KEY=$${TAHINI_SIGNING_KEY:-} does not exist" >&2
                exit 1
            fi
            cp "$${TAHINI_SIGNING_KEY:-}" $@
        else
            echo "note: no TAHINI_SIGNING_KEY; generating a throwaway key, MRSIGNER will not be stable" >&2
            openssl genrsa -out $@ -3 3072
        fi
    """,
    message = "Preparing enclave signing key",
)

# ---- Signed enclave (enclave.signed.so) ----
genrule(
    name = "enclave_signed",
    srcs = [
        ":enclave_so",
        ":signing_key",
        "sidecar.config.xml",
    ],
    outs = ["enclave.signed.so"],
    cmd = """
        set -e
        SDK="$$SGX_SDK"
        [ -z "$$SDK" ] && { echo "SGX_SDK must be set"; exit 1; }
        "$$SDK/bin/x64/sgx_sign" sign -key "$(location :signing_key)" -enclave "$(location :enclave_so)" -out "$@" -config "$(location sidecar.config.xml)"
    """,
    message = "Signing enclave",
)

exports_files([
    "sidecar.config.xml",
    "sidecar.lds",
])

# Build everything (sidecar binary + signed enclave)
alias(
    name = "all",
    actual = ":sidecar_bin",
    visibility = ["//visibility:public"],
)

# Sync repo to a remote host (e.g. Linode): bazel run //:sync -- <ip_address>
sh_binary(
    name = "sync",
    srcs = ["infra/sync.sh"],
    visibility = ["//visibility:public"],
)

# Docker (x86_64 Linux)
sh_binary(
    name = "docker_build",
    srcs = ["scripts/docker-build.sh"],
    visibility = ["//visibility:public"],
)

sh_binary(
    name = "docker_run",
    srcs = ["scripts/docker-run.sh"],
    visibility = ["//visibility:public"],
)

# End-to-end demo (SGX HW mode): bazel run //:demo
sh_binary(
    name = "demo",
    srcs = ["scripts/demo.sh"],
    data = [
        "Dockerfile.client",
        "Dockerfile.server",
        "docker-compose.sgx.yml",
        "docker-compose.yml",
    ],
    visibility = ["//visibility:public"],
)

# Tear down demo containers + shared volume: bazel run //:demo_down
sh_binary(
    name = "demo_down",
    srcs = ["scripts/demo-down.sh"],
    data = [
        "docker-compose.sgx.yml",
        "docker-compose.yml",
    ],
    visibility = ["//visibility:public"],
)
