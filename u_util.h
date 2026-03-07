#ifndef TAHINI_U_UTIL_H
#define TAHINI_U_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sgx_report.h>

#define TAHINI_SIDECAR_OWNERS_GROUP "sidecar-owners"

// AT_EMPTY_PATH is a flag for execveat syscall to indicate that the path is empty
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

// SYS_execveat is the syscall number for execveat
#ifndef SYS_execveat
#define SYS_execveat 322
#endif

// Returns 1 if the current process is in the TAHINI_SIDECAR_OWNERS_GROUP, 0 otherwise.
int validate_user(void);

struct enclave_quote {
    uint8_t* quote;
    uint32_t quote_size;
    int error;
};

// Returns the enclave quote. On success returns 0; on failure returns -1 and quote is NULL.
// Note that the quote is allocated on the heap and must be freed by the caller.
struct enclave_quote get_enclave_quote(const sgx_report_t* report);

// Frees the enclave quote.
void free_enclave_quote(struct enclave_quote* quote);

// Note(jadidbourbaki): These two functions are used to bridge the enclave to the untrusted side.

// ocall_syscall is a wrapper around the syscall function.
// It is used to call syscalls from the enclave to the untrusted side.
long ocall_syscall(long syscall_number, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6);

// ocall_copy_byte is a wrapper around the memcpy function.
// It is used to copy bytes from the enclave to the untrusted side.
void ocall_copy_byte(void* dest, uint8_t byte);

// bin_to_hex converts len bytes of bin into a null-terminated hex string. hex must be at least len*2+1 bytes.
void bin_to_hex(const uint8_t* bin, size_t len, char* hex);

// dump_file_to_stream reads a file and writes its contents to the given FILE* stream.
// Returns 0 on success, -1 on failure.
int dump_file_to_stream(const char* path, FILE* stream);

// write_attestation_json writes attestation artifacts as JSON to the given path.
// The JSON contains base64url-encoded quote, hex binary hash, and hex public key.
// Returns 0 on success, -1 on failure.
int write_attestation_json(const char* path,
                           const uint8_t* quote, uint32_t quote_size,
                           const uint8_t* binary_hash, size_t hash_size,
                           const uint8_t* public_key, size_t pubkey_size);

#endif /* TAHINI_U_UTIL_H */
