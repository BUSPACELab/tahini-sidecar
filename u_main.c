#include "sidecar_u.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/syscall.h>
#include <errno.h>
#include <sgx_urts.h>
#include <sgx_report.h>
#include <sgx_dcap_ql_wrapper.h>
#include "sidecar.h"
#include "u_util.h"

static void usage(const char* prog) {
    fprintf(stderr,
        "usage: %s [options] <service-binary> [service-args...]\n"
        "\n"
        "options:\n"
        "  --tahini-dc <path>       server delegated credential JSON\n"
        "  --tahini-dc-cert <path>  parent TLS certificate (public)\n"
        "  --tahini-dc-sig <path>   client verification info JSON\n"
        "  --tahini-quote-out <path> write attestation JSON for client verification\n",
        prog);
}

int main(int argc, char* argv[]) {
    const char* dc_server_path = NULL;
    const char* dc_cert_path = NULL;
    const char* dc_sig_path = NULL;
    const char* quote_out_path = NULL;

    static struct option long_options[] = {
        {"tahini-dc",        required_argument, NULL, 'd'},
        {"tahini-dc-cert",   required_argument, NULL, 'c'},
        {"tahini-dc-sig",    required_argument, NULL, 's'},
        {"tahini-quote-out", required_argument, NULL, 'q'},
        {NULL, 0, NULL, 0}
    };

    // '+' stops getopt at the first non-option arg (the service binary)
    int opt;
    while ((opt = getopt_long(argc, argv, "+", long_options, NULL)) != -1) {
        switch (opt) {
            case 'd': dc_server_path = optarg; break;
            case 'c': dc_cert_path   = optarg; break;
            case 's': dc_sig_path    = optarg; break;
            case 'q': quote_out_path = optarg; break;
            default:
                usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    if (optind >= argc) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char* service_binary = argv[optind];
    int service_args_start = optind + 1;

    if (!validate_user()) {
        fprintf(stderr, "error: permission denied (must be in group %s)\n", TAHINI_SIDECAR_OWNERS_GROUP);
        return EXIT_FAILURE;
    }

    sgx_enclave_id_t eid = 0;
    sgx_status_t ret = sgx_create_enclave(TAHINI_ENCLAVE_FILE, SGX_DEBUG_FLAG, NULL, NULL, &eid, NULL);
    if (ret != SGX_SUCCESS) {
        fprintf(stderr, "failed to create enclave (0x%x)\n", ret);
        return EXIT_FAILURE;
    }

    // Step 1: hash the service binary into a memfd (TOCTOU-safe)
    int binary_fd = -1;
    sgx_status_t retval;
    ret = ecall_hash_binary(eid, &retval, service_binary, &binary_fd);
    if (ret != SGX_SUCCESS || retval != SGX_SUCCESS || binary_fd < 0) {
        fprintf(stderr, "ecall_hash_binary failed (ret=0x%x retval=0x%x)\n", ret, retval);
        sgx_destroy_enclave(eid);
        return EXIT_FAILURE;
    }

    // Step 2: generate ECDH credentials inside the enclave
    uint8_t secret_key[TAHINI_KEY_SIZE];
    uint8_t public_key[TAHINI_PUBKEY_SIZE];
    ret = ecall_generate_credentials(eid, &retval, secret_key, TAHINI_KEY_SIZE, public_key, TAHINI_PUBKEY_SIZE);
    if (ret != SGX_SUCCESS || retval != SGX_SUCCESS) {
        fprintf(stderr, "ecall_generate_credentials failed (ret=0x%x retval=0x%x)\n", ret, retval);
        sgx_destroy_enclave(eid);
        return EXIT_FAILURE;
    }

    // Step 3: get QE3 target info (DCAP) so the report targets the Quoting Enclave
    sgx_target_info_t qe_target_info;
    memset(&qe_target_info, 0, sizeof(qe_target_info));
    quote3_error_t qe3_ret = sgx_qe_get_target_info(&qe_target_info);
    if (qe3_ret != SGX_QL_SUCCESS) {
        fprintf(stderr, "sgx_qe_get_target_info failed (0x%x)\n", (unsigned)qe3_ret);
        sgx_destroy_enclave(eid);
        return EXIT_FAILURE;
    }

    // Step 4: create attestation report targeting QE3, binding binary hash + public key
    sgx_report_t report;
    uint8_t binary_hash[TAHINI_HASH_SIZE];
    uint8_t pubkey_out[TAHINI_PUBKEY_SIZE];
    ret = ecall_get_attestation_report(eid, &retval, &qe_target_info, &report,
                                       binary_hash, TAHINI_HASH_SIZE,
                                       pubkey_out, TAHINI_PUBKEY_SIZE);
    if (ret != SGX_SUCCESS || retval != SGX_SUCCESS) {
        fprintf(stderr, "ecall_get_attestation_report failed (ret=0x%x retval=0x%x)\n", ret, retval);
        sgx_destroy_enclave(eid);
        return EXIT_FAILURE;
    }

    sgx_destroy_enclave(eid);

    // Step 5: generate ECDSA/DCAP quote from the report
    struct enclave_quote eq = get_enclave_quote(&report);
    if (eq.error != 0) {
        fprintf(stderr, "get_enclave_quote failed\n");
        return EXIT_FAILURE;
    }

    // Print attestation artifacts to stderr so service stdout is clean
    char hash_hex[TAHINI_HASH_SIZE * 2 + 1];
    bin_to_hex(binary_hash, TAHINI_HASH_SIZE, hash_hex);
    fprintf(stderr, "tahini binary hash: %s\n", hash_hex);

    char* quote_hex = malloc((size_t)eq.quote_size * 2 + 1);
    if (!quote_hex) {
        fprintf(stderr, "failed to allocate quote hex buffer\n");
        free_enclave_quote(&eq);
        return EXIT_FAILURE;
    }
    bin_to_hex(eq.quote, eq.quote_size, quote_hex);
    fprintf(stderr, "tahini quote (%u bytes): %s\n", eq.quote_size, quote_hex);
    free(quote_hex);

    if (quote_out_path) {
        if (write_attestation_json(quote_out_path, eq.quote, eq.quote_size,
                                   binary_hash, TAHINI_HASH_SIZE,
                                   pubkey_out, TAHINI_PUBKEY_SIZE) != 0) {
            fprintf(stderr, "failed to write attestation JSON to %s\n", quote_out_path);
            free_enclave_quote(&eq);
            return EXIT_FAILURE;
        }
        fprintf(stderr, "tahini attestation written to %s\n", quote_out_path);
    }

    free_enclave_quote(&eq);

    if (dc_sig_path) {
        fprintf(stderr, "tahini dc verification info: ");
        dump_file_to_stream(dc_sig_path, stderr);
        fprintf(stderr, "\n");
    }

    // Step 6: exec the service binary from the memfd (exact bytes we hashed)
    char secret_hex[TAHINI_KEY_SIZE * 2 + 1];
    bin_to_hex(secret_key, TAHINI_KEY_SIZE, secret_hex);

    // Count how many extra DC args we need to forward
    int dc_extra = 0;
    if (dc_server_path) dc_extra += 2;
    if (dc_cert_path)   dc_extra += 2;

    int svc_extra_args = argc - service_args_start;
    int svc_total = 1 + 2 + dc_extra + svc_extra_args + 1; // binary + secret pair + dc pairs + extra + NULL
    char** svc_argv = malloc((size_t)svc_total * sizeof(char*));
    if (!svc_argv) {
        fprintf(stderr, "failed to allocate argv\n");
        return EXIT_FAILURE;
    }

    int idx = 0;
    svc_argv[idx++] = (char*)service_binary;
    svc_argv[idx++] = "--tahini-secret";
    svc_argv[idx++] = secret_hex;
    if (dc_server_path) {
        svc_argv[idx++] = "--tahini-dc";
        svc_argv[idx++] = (char*)dc_server_path;
    }
    if (dc_cert_path) {
        svc_argv[idx++] = "--tahini-dc-cert";
        svc_argv[idx++] = (char*)dc_cert_path;
    }
    for (int i = service_args_start; i < argc; i++) {
        svc_argv[idx++] = argv[i];
    }
    svc_argv[idx] = NULL;

    lseek(binary_fd, 0, SEEK_SET);
    syscall(SYS_execveat, binary_fd, "", svc_argv, NULL, AT_EMPTY_PATH);
    fprintf(stderr, "execveat failed: %s\n", strerror(errno));
    free(svc_argv);
    return EXIT_FAILURE;
}
