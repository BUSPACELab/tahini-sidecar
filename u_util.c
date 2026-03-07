#include "u_util.h"
#include <stdlib.h>
#include <unistd.h>
#include <grp.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>

#include <sgx_report.h>
#include <sgx_dcap_ql_wrapper.h>

long ocall_syscall(long syscall_number, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6) {
    return syscall(syscall_number, arg1, arg2, arg3, arg4, arg5, arg6);
}

void ocall_copy_byte(void* dest, uint8_t byte) {
    *((char*)dest) = (char)byte;
}

void bin_to_hex(const uint8_t* bin, size_t len, char* hex) {
    const char hc[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        hex[i*2]     = hc[(bin[i] >> 4) & 0x0F];
        hex[i*2 + 1] = hc[bin[i] & 0x0F];
    }
    hex[len*2] = '\0';
}


int validate_user(void) {
    const char* error_prefix = "error in validate_user: ";

    struct group* gr = getgrnam(TAHINI_SIDECAR_OWNERS_GROUP);
    if (!gr) {
        fprintf(stderr, "%s user group %s not found\n", error_prefix, TAHINI_SIDECAR_OWNERS_GROUP);
        return 0;
    }

    gid_t want = gr->gr_gid;

    // getegid() is the effective group ID of the current process
    if (getegid() == want) return 1;

    // check if the process has any supplementary group IDs
    int n = getgroups(0, NULL);

    if (n <= 0) {
        fprintf(stderr, "%s failed to get groups\n", error_prefix);
        return 0;
    }

    gid_t* list = malloc((size_t)n * sizeof(gid_t));
    if (!list) {
        fprintf(stderr, "%s failed to allocate memory for groups list\n", error_prefix);
        return 0;
    }

    n = getgroups(n, list);
    if (n <= 0) {
        fprintf(stderr, "%s failed to get groups\n", error_prefix);
        free(list);
        return 0;
    }

    int found = 0;

    int i;
    for (i = 0; i < n; i++) {
        // check if the process is in any of the supplementary group IDs
        if (list[i] == want) {
            found = 1;
            break;
        }
    }

    free(list);
    return found;
}


struct enclave_quote get_enclave_quote(const sgx_report_t* report) {
    const char* error_prefix = "error in get_enclave_quote: ";

    struct enclave_quote quote = {0};

    if (!report) {
        fprintf(stderr, "%s report is NULL\n", error_prefix);
        quote.error = -1;
        return quote;
    }

    uint32_t quote_size = 0;
    quote3_error_t qe = sgx_qe_get_quote_size(&quote_size);

    if (qe != SGX_QL_SUCCESS) {
        fprintf(stderr, "%s DCAP sgx_qe_get_quote_size failed (0x%x)\n", error_prefix, (unsigned)qe);
        quote.error = -1;
        return quote;
    }

    quote.quote_size = quote_size;
    quote.quote = malloc(quote_size);
    if (!quote.quote) {
        fprintf(stderr, "%s failed to allocate memory for quote\n", error_prefix);
        quote.error = -1;
        return quote;
    }

    qe = sgx_qe_get_quote(report, quote_size, quote.quote);
    if (qe != SGX_QL_SUCCESS) {
        fprintf(stderr, "%s DCAP sgx_qe_get_quote failed (0x%x)\n", error_prefix, (unsigned)qe);
        free(quote.quote);
        quote.quote = NULL;
        quote.quote_size = 0;
        quote.error = -1;
        return quote;
    }

    quote.error = 0;
    return quote;
}

void free_enclave_quote(struct enclave_quote* quote) {
    if (!quote) {
        fprintf(stderr, "error in free_enclave_quote: quote is NULL\n");
        return;
    }

    free(quote->quote);
    quote->quote = NULL;
    quote->quote_size = 0;
    quote->error = 0;
}

static const char b64url_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// base64url_encode encodes the given data into a base64url string. The joys of 
// working in C where the standard library gives us essentially nothing.
static char* base64url_encode(const uint8_t* data, size_t len, size_t* out_len) {
    size_t olen = 4 * ((len + 2) / 3);
    char* out = malloc(olen + 1);
    if (!out) return NULL;

    size_t i, j;
    for (i = 0, j = 0; i + 2 < len; i += 3, j += 4) {
        uint32_t v = ((uint32_t)data[i] << 16) | ((uint32_t)data[i+1] << 8) | data[i+2];
        out[j]   = b64url_table[(v >> 18) & 0x3F];
        out[j+1] = b64url_table[(v >> 12) & 0x3F];
        out[j+2] = b64url_table[(v >> 6)  & 0x3F];
        out[j+3] = b64url_table[v & 0x3F];
    }
    if (i < len) {
        uint32_t v = (uint32_t)data[i] << 16;
        if (i + 1 < len) v |= (uint32_t)data[i+1] << 8;
        out[j++] = b64url_table[(v >> 18) & 0x3F];
        out[j++] = b64url_table[(v >> 12) & 0x3F];
        if (i + 1 < len) out[j++] = b64url_table[(v >> 6) & 0x3F];
    }
    out[j] = '\0';
    if (out_len) *out_len = j;
    return out;
}

int write_attestation_json(const char* path,
                           const uint8_t* quote, uint32_t quote_size,
                           const uint8_t* binary_hash, size_t hash_size,
                           const uint8_t* public_key, size_t pubkey_size) {
    FILE* f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, "error: failed to open %s for writing\n", path);
        return -1;
    }

    size_t b64_len = 0;
    char* quote_b64 = base64url_encode(quote, quote_size, &b64_len);
    if (!quote_b64) {
        fprintf(stderr, "error: failed to base64url-encode quote\n");
        fclose(f);
        return -1;
    }

    char hash_hex[hash_size * 2 + 1];
    bin_to_hex(binary_hash, hash_size, hash_hex);

    char pubkey_hex[pubkey_size * 2 + 1];
    bin_to_hex(public_key, pubkey_size, pubkey_hex);

    fprintf(f,
        "{\n"
        "  \"quote\": \"%s\",\n"
        "  \"binary_hash\": \"%s\",\n"
        "  \"public_key\": \"%s\"\n"
        "}\n",
        quote_b64, hash_hex, pubkey_hex);

    free(quote_b64);
    fclose(f);
    return 0;
}

int dump_file_to_stream(const char* path, FILE* stream) {
    FILE* f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "error: failed to open %s\n", path);
        return -1;
    }
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        fwrite(buf, 1, n, stream);
    }
    fclose(f);
    return 0;
}