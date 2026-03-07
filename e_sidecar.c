#include "sidecar_t.h"
#include <sgx_tcrypto.h>
#include <sgx_trts.h>
#include <sgx_report.h>
#include <sgx_utils.h> 
#include <string.h>

#include "sidecar.h"

// stored_hash is the hash of the binary
static uint8_t stored_hash[TAHINI_HASH_SIZE] = {0};
// public_key_commitment is the hash of the full public key for attestation report
static uint8_t public_key_commitment[TAHINI_HASH_SIZE] = {0};
// full_public_key is the full public key (64 bytes: x + y)
static sgx_ec256_public_t full_public_key = {0};
// private_key is the private key
static sgx_ec256_private_t private_key = {0};
// initialized is a flag to indicate if the enclave is initialized
static int initialized = 0;

// e_malloc_cpy allocates size bytes in untrusted memory (mmap). If src is non-NULL, copies from enclave; if src is NULL, allocates only (no copy).
static void* e_malloc_cpy(const void* src, size_t size) {
    if (size == 0) {
        return NULL;
    }
    long mmap_result;
    sgx_status_t ocall_ret = ocall_syscall(&mmap_result, TAHINI_SYSCALL_MMAP,
        0, (long)size,
        TAHINI_MMAP_PROT_READ | TAHINI_MMAP_PROT_WRITE,
        TAHINI_MMAP_MAP_PRIVATE | TAHINI_MMAP_MAP_ANONYMOUS, -1, 0);
    if (ocall_ret != SGX_SUCCESS || mmap_result == (long)TAHINI_MMAP_MAP_FAILED) {
        return NULL;
    }
    void* dest = (void*)mmap_result;
    if (src) {
        const uint8_t* s = (const uint8_t*)src;
        for (size_t i = 0; i < size; i++) {
            ocall_copy_byte((char*)dest + i, s[i]);
        }
    }
    return dest;
}

// ecall_hash_binary reads the binary through untrusted memory, snapshots each chunk into
// the enclave for hashing, then writes the enclave copy to a memfd. The caller execs that
// memfd, so the executed bytes are exactly the bytes the enclave hashed. This prevents TOCTOU attacks.
sgx_status_t ecall_hash_binary(const char* binary_path, int* binary_fd) {
    if (!binary_path || !binary_fd) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    *binary_fd = -1;

    sgx_sha_state_handle_t sha_handle;
    sgx_status_t ret = sgx_sha256_init(&sha_handle);
    if (ret != SGX_SUCCESS) {
        return ret;
    }

    // The `binary_path` as received from the caller is in enclave memory (EDL [in] copy). 
    // Since the Linux kernel can't read EPC, we copy it to untrusted memory so the open() syscall can read it.
    // However, the *path* to the binary was never a sensitive value, it was the binary itself that was sensitive.
    // Therefore, this is not a concern in terms of our trust model. We trust the caller to give us the correct path.
    size_t path_len = 0;
    while (binary_path[path_len] != '\0') path_len++;
    path_len++;
    void* upath = e_malloc_cpy(binary_path, path_len);
    if (!upath) {
        sgx_sha256_close(sha_handle);
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    long fd_long;
    sgx_status_t ocall_ret = ocall_syscall(&fd_long, TAHINI_SYSCALL_OPEN, (long)upath, TAHINI_FILE_OPEN_FLAG_RDONLY, 0, 0, 0, 0);
    if (ocall_ret != SGX_SUCCESS) {
        sgx_sha256_close(sha_handle);
        return ocall_ret;
    }
    int file_fd = (int)fd_long;
    if (file_fd < 0) {
        sgx_sha256_close(sha_handle);
        return SGX_ERROR_UNEXPECTED;
    }

    void* memfd_name = e_malloc_cpy("", 1);
    if (!memfd_name) {
        ocall_syscall(&fd_long, TAHINI_SYSCALL_CLOSE, file_fd, 0, 0, 0, 0, 0);
        sgx_sha256_close(sha_handle);
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    ocall_ret = ocall_syscall(&fd_long, TAHINI_SYSCALL_MEMFD_CREATE, (long)memfd_name, 0, 0, 0, 0, 0);
    if (ocall_ret != SGX_SUCCESS || fd_long < 0) {
        ocall_syscall(&fd_long, TAHINI_SYSCALL_CLOSE, file_fd, 0, 0, 0, 0, 0);
        sgx_sha256_close(sha_handle);
        return SGX_ERROR_UNEXPECTED;
    }
    int memfd_fd = (int)fd_long;

    void* write_buf = e_malloc_cpy(NULL, TAHINI_CHUNK_SIZE);
    if (!write_buf) {
        ocall_syscall(&fd_long, TAHINI_SYSCALL_CLOSE, memfd_fd, 0, 0, 0, 0, 0);
        ocall_syscall(&fd_long, TAHINI_SYSCALL_CLOSE, file_fd, 0, 0, 0, 0, 0);
        sgx_sha256_close(sha_handle);
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    uint8_t buffer[TAHINI_CHUNK_SIZE];
    size_t file_offset = 0;
    size_t bytes_read = 0;

    // In this loop, each byte of the binary goes through the following steps:
    // 1. The byte is read from the file on disk into the sidecar's memory.
    // 2. The byte is copied from the sidecar's memory into the enclave's memory. This is where the hash is computed.
    // 3. The byte is copied back from the enclave's memory into the sidecar's memory.
    // 4. The byte is written from the sidecar's memory to the memfd. This is where the binary is stored. This 
    //    prevents TOCTOU attacks by ensuring the binary that was executed is the same binary that was hashed.
    do {
        bytes_read = 0;
        long lseek_result;
        ocall_ret = ocall_syscall(&lseek_result, TAHINI_SYSCALL_LSEEK, file_fd, file_offset, TAHINI_FILE_OPEN_FLAG_SEEK_SET, 0, 0, 0);
        if (ocall_ret != SGX_SUCCESS || lseek_result < 0) {
            ocall_syscall(&fd_long, TAHINI_SYSCALL_CLOSE, memfd_fd, 0, 0, 0, 0, 0);
            ocall_syscall(&fd_long, TAHINI_SYSCALL_CLOSE, file_fd, 0, 0, 0, 0, 0);
            sgx_sha256_close(sha_handle);
            return SGX_ERROR_UNEXPECTED;
        }

        long read_result;
        ocall_ret = ocall_syscall(&read_result, TAHINI_SYSCALL_READ, file_fd, (long)write_buf, TAHINI_CHUNK_SIZE, 0, 0, 0);
        if (ocall_ret != SGX_SUCCESS) {
            ocall_syscall(&fd_long, TAHINI_SYSCALL_CLOSE, memfd_fd, 0, 0, 0, 0, 0);
            ocall_syscall(&fd_long, TAHINI_SYSCALL_CLOSE, file_fd, 0, 0, 0, 0, 0);
            sgx_sha256_close(sha_handle);
            return ocall_ret;
        }

        if (read_result > 0) {
            bytes_read = (size_t)read_result;
            // Snapshot into enclave memory: hash and memfd write both use this copy,
            // so a malicious host can't race between the two.
            memcpy(buffer, write_buf, bytes_read);
            ret = sgx_sha256_update(buffer, bytes_read, sha_handle);
            if (ret != SGX_SUCCESS) {
                ocall_syscall(&fd_long, TAHINI_SYSCALL_CLOSE, memfd_fd, 0, 0, 0, 0, 0);
                ocall_syscall(&fd_long, TAHINI_SYSCALL_CLOSE, file_fd, 0, 0, 0, 0, 0);
                sgx_sha256_close(sha_handle);
                return ret;
            }
            for (size_t i = 0; i < bytes_read; i++) {
                ocall_copy_byte((char*)write_buf + i, buffer[i]);
            }
            long write_result;
            ocall_ret = ocall_syscall(&write_result, TAHINI_SYSCALL_WRITE, memfd_fd, (long)write_buf, bytes_read, 0, 0, 0);
            if (ocall_ret != SGX_SUCCESS || write_result != (long)bytes_read) {
                ocall_syscall(&fd_long, TAHINI_SYSCALL_CLOSE, memfd_fd, 0, 0, 0, 0, 0);
                ocall_syscall(&fd_long, TAHINI_SYSCALL_CLOSE, file_fd, 0, 0, 0, 0, 0);
                sgx_sha256_close(sha_handle);
                return SGX_ERROR_UNEXPECTED;
            }
            file_offset += bytes_read;
        }
    } while (bytes_read == TAHINI_CHUNK_SIZE);

    ocall_syscall(&fd_long, TAHINI_SYSCALL_CLOSE, file_fd, 0, 0, 0, 0, 0);

    ret = sgx_sha256_get_hash(sha_handle, (sgx_sha256_hash_t*)stored_hash);
    sgx_sha256_close(sha_handle);
    if (ret != SGX_SUCCESS) {
        ocall_syscall(&fd_long, TAHINI_SYSCALL_CLOSE, memfd_fd, 0, 0, 0, 0, 0);
        return ret;
    }

    initialized = 1;
    *binary_fd = memfd_fd;
    return SGX_SUCCESS;
}

// ecall_generate_credentials generates ECDH key pair and sends to caller
// secret_key_out is the output secret key (32 bytes)
// secret_key_len is the length of the secret key (32 bytes)
// public_key_out is the output public key (64 bytes: x + y)
// public_key_len is the length of the public key (64 bytes)
sgx_status_t ecall_generate_credentials(
    uint8_t* secret_key_out,
    size_t secret_key_len,
    uint8_t* public_key_out,
    size_t public_key_len
) {
    if (!initialized) {
        return SGX_ERROR_UNEXPECTED;
    }
    
    if (secret_key_len != TAHINI_KEY_SIZE || public_key_len != TAHINI_PUBKEY_SIZE) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    
    // Open ECC context for NIST P-256
    sgx_ecc_state_handle_t ecc_handle = NULL;
    sgx_status_t ret = sgx_ecc256_open_context(&ecc_handle);
    if (ret != SGX_SUCCESS) {
        return ret;
    }
    
    // Generate ECDH key pair (NIST P-256)
    ret = sgx_ecc256_create_key_pair(&private_key, &full_public_key, ecc_handle);
    if (ret != SGX_SUCCESS) {
        sgx_ecc256_close_context(ecc_handle);
        return ret;
    }
    
    sgx_ecc256_close_context(ecc_handle);
    
    // Compute hash of full public key for attestation report binding
    // The sgx_report_data_t structure is 64 bytes total. We use:
    // - 32 bytes for the binary hash (stored_hash)
    // - 32 bytes for the public key commitment (hash of full public key)
    // This cryptographically binds the full 64-byte public key in the report
    // while fitting within the 64-byte report_data constraint
    ret = sgx_sha256_msg((const uint8_t*)&full_public_key, sizeof(sgx_ec256_public_t), 
                          (sgx_sha256_hash_t*)public_key_commitment);
    if (ret != SGX_SUCCESS) {
        return ret;
    }
    
    // Serialize private key (32 bytes) - copy directly
    memcpy(secret_key_out, private_key.r, TAHINI_KEY_SIZE);
    
    // Return full public key (64 bytes: x + y coordinates)
    // Serialize: first 32 bytes are x-coordinate, next 32 bytes are y-coordinate
    memcpy(public_key_out, full_public_key.gx, TAHINI_KEY_SIZE);
    memcpy(public_key_out + TAHINI_KEY_SIZE, full_public_key.gy, TAHINI_KEY_SIZE);
    
    return SGX_SUCCESS;
}

// ecall_get_attestation_report gets attestation report with hash + public key for remote attestation
// target_info is the target information
// report is the output report
// binary_hash_out is the output binary hash (32 bytes)
// hash_len is the length of the binary hash (32 bytes)
// public_key_out is the output public key (64 bytes: x + y)
// pubkey_len is the length of the public key (64 bytes)
sgx_status_t ecall_get_attestation_report(
    const sgx_target_info_t* target_info,
    sgx_report_t* report,
    uint8_t* binary_hash_out,
    size_t hash_len,
    uint8_t* public_key_out,
    size_t pubkey_len
) {
    if (!initialized) {
        return SGX_ERROR_UNEXPECTED;
    }
    
    if (hash_len != TAHINI_HASH_SIZE || pubkey_len != TAHINI_PUBKEY_SIZE) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    
    // Copy hash and public key commitment to report data
    // sgx_report_data_t is 64 bytes total, structured as:
    // - report_data.d[0..31]: binary hash (32 bytes)
    // - report_data.d[32..63]: public key commitment (32 bytes, hash of full 64-byte public key)
    // We can't fit the full 64-byte public key because we need 32 bytes for the binary hash,
    // leaving only 32 bytes remaining. Using a hash commitment cryptographically binds the
    // full public key in the attestation report. The full 64-byte public key is returned separately.
    sgx_report_data_t report_data = {0};
    memcpy(report_data.d, stored_hash, TAHINI_HASH_SIZE);
    memcpy(report_data.d + TAHINI_HASH_SIZE, public_key_commitment, TAHINI_HASH_SIZE);
    
    // Generate attestation report
    sgx_status_t ret = sgx_create_report(target_info, &report_data, report);
    if (ret != SGX_SUCCESS) {
        return ret;
    }
    
    // Copy hash and public key to output parameters
    memcpy(binary_hash_out, stored_hash, TAHINI_HASH_SIZE);
    memcpy(public_key_out, full_public_key.gx, TAHINI_KEY_SIZE);
    memcpy(public_key_out + TAHINI_KEY_SIZE, full_public_key.gy, TAHINI_KEY_SIZE);
    
    return SGX_SUCCESS;
}

// bin_to_hex converts a binary string to a hex string
// bin is the binary string to convert
// len is the length of the binary string
// hex is the output hex string
static void bin_to_hex(const uint8_t* bin, size_t len, char* hex) {
    const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        hex[i*2] = hex_chars[(bin[i] >> 4) & 0x0F];
        hex[i*2 + 1] = hex_chars[bin[i] & 0x0F];
    }
    hex[len*2] = '\0';
}

// ecall_launch_service handles all logic including argument parsing, hashing, credential generation, and execve
// argc is the argument count (including program name)
// argv is the argument array (argv[1] is the service binary path, argv[2..] are service args)
sgx_status_t ecall_launch_service(int argc, size_t argv_buffer_size, const char* argv_buffer) {
    if (argc < 2 || !argv_buffer) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    
    // Parse argv_buffer to find argv[1] (service binary path)
    // argv_buffer format: argv[0]\0argv[1]\0...argv[argc-1]\0
    const char* binary_path = NULL;
    size_t offset = 0;
    int current_arg = 0;
    
    // Skip argv[0] which is just the tahini sidecar binary name
    while (current_arg < 1 && offset < argv_buffer_size && argv_buffer[offset] != '\0') {
        offset++;
    }
    if (offset < argv_buffer_size && argv_buffer[offset] == '\0') {
        offset++; // skip the null terminator
        current_arg++;
    }
    
    // now offset points to argv[1] which is the service binary path
    if (current_arg == 1 && offset < argv_buffer_size) {
        binary_path = argv_buffer + offset;
    }
    
    if (!binary_path) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    
    // hash the binary and stream into a memfd; we exec that fd so we run exactly the bytes we hashed (no TOCTOU)
    int binary_fd = -1;
    sgx_status_t ret = ecall_hash_binary(binary_path, &binary_fd);
    if (ret != SGX_SUCCESS || binary_fd < 0) {
        return ret != SGX_SUCCESS ? ret : SGX_ERROR_UNEXPECTED;
    }
    
    // generate credentials
    uint8_t secret_key[TAHINI_KEY_SIZE];
    uint8_t public_key[TAHINI_PUBKEY_SIZE];
    ret = ecall_generate_credentials(secret_key, TAHINI_KEY_SIZE, public_key, TAHINI_PUBKEY_SIZE);
    if (ret != SGX_SUCCESS) {
        return ret;
    }
    
    // convert the secret key to hex
    char secret_hex[TAHINI_KEY_SIZE * 2 + 1];
    bin_to_hex(secret_key, TAHINI_KEY_SIZE, secret_hex);
    
    // find the start of argv[2] for service arguments
    // we already parsed to argv[1], so continue from there
    size_t argv2_offset = offset; // continue from where we found argv[1]

    while (argv2_offset < argv_buffer_size && argv_buffer[argv2_offset] != '\0') {
        argv2_offset++;
    }
    if (argv2_offset < argv_buffer_size && argv_buffer[argv2_offset] == '\0') {
        argv2_offset++; // skip the null terminator which now points to argv[2]
    }
    
    size_t arg_count = 0;
    if (argc > 2) {
        arg_count = argc - 2; // the number of service arguments is argc - 2 (argv[2..argc-1])
    }
    
    // construct the argv array in untrusted memory
    // the total number of arguments is 3 + arg_count (binary_path, "--tahini-secret", secret_hex, + parsed args)
    #define MAX_ARGS 256
    if (3 + arg_count > MAX_ARGS) {
        return SGX_ERROR_INVALID_PARAMETER; // the number of arguments is too large
    }
    
    // calculate the length of the binary path including the null terminator
    size_t binary_path_len = 0;
    while (binary_path[binary_path_len] != '\0') {
        binary_path_len++;
    }
    binary_path_len++; // add the null terminator
    
    // allocate and copy the binary path using mmap syscall + minimal copy ocall
    void* binary_path_ptr = e_malloc_cpy(binary_path, binary_path_len);
    if (!binary_path_ptr) {
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    
    // allocate and copy the secret key to hex using mmap syscall + minimal copy ocall
    void* secret_hex_ptr = e_malloc_cpy(secret_hex, TAHINI_KEY_SIZE * 2 + 1);
    if (!secret_hex_ptr) {
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    
    // allocate and copy the "--tahini-secret" flag using mmap syscall + minimal copy ocall
    const char* flag_str = "--tahini-secret";
    // "--tahini-secret" is 15 characters, need 16 bytes including null terminator
    void* tahini_secret_flag = e_malloc_cpy(flag_str, 16);
    if (!tahini_secret_flag) {
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    
    // parse the arguments from argv_buffer and copy each to untrusted memory
    // the service arguments are starting at argv2_offset
    void* arg_ptrs[MAX_ARGS];
    size_t current_offset = argv2_offset;
    for (size_t i = 0; i < arg_count; i++) {
        if (current_offset >= argv_buffer_size) {
            return SGX_ERROR_INVALID_PARAMETER;
        }

        // find the length of this argument
        size_t arg_start = current_offset;
        while (current_offset < argv_buffer_size && argv_buffer[current_offset] != '\0') {
            current_offset++;
        }
        size_t arg_len = current_offset - arg_start;
        if (current_offset < argv_buffer_size) {
            current_offset++; // skip the null terminator
        }
        
        // allocate and copy the argument string using mmap syscall + minimal copy ocall
        arg_ptrs[i] = e_malloc_cpy(argv_buffer + arg_start, arg_len + 1);
        if (!arg_ptrs[i]) {
            return SGX_ERROR_OUT_OF_MEMORY;
        }
    }
    
    // build the argv array structure in enclave memory first
    // NOTE(jadidbourbaki): all of these pointers are now in untrusted memory
    void* argv_array_local[MAX_ARGS];
    argv_array_local[0] = binary_path_ptr;
    argv_array_local[1] = tahini_secret_flag;
    argv_array_local[2] = secret_hex_ptr;
    for (size_t i = 0; i < arg_count; i++) {
        argv_array_local[3 + i] = arg_ptrs[i];
    }
    argv_array_local[3 + arg_count] = NULL;
    
    // allocate and copy the argv array using mmap syscall + minimal copy ocall
    size_t argv_array_size = (3 + arg_count + 1) * sizeof(void*);
    void* argv_array = e_malloc_cpy(argv_array_local, argv_array_size);
    if (!argv_array) {
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    
    // exec the memfd (exact bytes we hashed). rewind fd then execveat with AT_EMPTY_PATH
    long lseek_result;
    sgx_status_t ocall_ret = ocall_syscall(&lseek_result, TAHINI_SYSCALL_LSEEK, binary_fd, 0, TAHINI_FILE_OPEN_FLAG_SEEK_SET, 0, 0, 0);
    if (ocall_ret != SGX_SUCCESS || lseek_result != 0) {
        return SGX_ERROR_UNEXPECTED;
    }
    void* empty_path = e_malloc_cpy("", 1);
    if (!empty_path) {
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    long execve_result = 0;
    ocall_ret = ocall_syscall(&execve_result, TAHINI_SYSCALL_EXECVEAT,
        (long)binary_fd, (long)empty_path, (long)argv_array, (long)NULL,
        (long)TAHINI_AT_EMPTY_PATH, 0);
    if (ocall_ret != SGX_SUCCESS) {
        return ocall_ret;
    }
    // execveat on success never returns
    return SGX_ERROR_UNEXPECTED;
}
