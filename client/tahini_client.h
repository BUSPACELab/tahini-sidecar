#ifndef TAHINI_CLIENT_H
#define TAHINI_CLIENT_H

#include <stdint.h>

// Caller-side API for attesting a service before connecting to it.
//
// The caller gives an address and gets back the service's binary hash and the
// delegated credential it will serve TLS with. The intended sequence is:
//
//   1. fetch the document from the sidecar guarding the service
//   2. submit `quote` to an attestation service, establishing that this is a
//      genuine enclave running the measured code
//   3. check `binary_hash` against the approved manifest
//   4. connect to the service, verifying its handshake against
//      `verification_info`
//
// Steps 2 and 3 are the caller's policy and are deliberately not done here: this
// library retrieves the material, it does not decide what is acceptable. What it
// does guarantee is that the three pieces come from one document, so the hash
// checked against the manifest and the credential used for the handshake are the
// ones the quote covers.
//
// Designed to be called over FFI, so every field is a plain C string owned by the
// struct and released by tahini_attestation_free.

#ifdef __cplusplus
extern "C" {
#endif

// The mock reports this instead of a real protocol version, so a caller can tell
// at runtime that it is not talking to a sidecar.
#define TAHINI_ATTEST_MOCK_VERSION 0

typedef struct {
    int version;              // protocol version the sidecar reported
    char* binary_hash;        // hex SHA-256 of the service binary
    char* quote;              // base64url DCAP quote
    char* verification_info;  // delegated credential's public half, as JSON
} tahini_attestation;

// Error codes. Negative so a caller can test `< 0` without knowing the set.
#define TAHINI_OK                 0
#define TAHINI_ERR_ARGS          -1
#define TAHINI_ERR_CONNECT       -2
#define TAHINI_ERR_READ          -3
#define TAHINI_ERR_PROTOCOL      -4
#define TAHINI_ERR_MEMORY        -5

// tahini_fetch_attestation connects to the sidecar at ip:port and fills `out`.
// Returns TAHINI_OK, or one of the codes above. On failure `out` is zeroed and
// tahini_last_error() describes what happened.
//
// timeout_ms bounds the whole exchange; pass 0 for a default. A sidecar that
// accepts the connection and then stalls must not hang the caller's startup.
int tahini_fetch_attestation(const char* ip, uint16_t port, uint32_t timeout_ms,
                             tahini_attestation* out);

// Frees the strings in `out` and zeroes it. Safe on an already-zeroed struct.
void tahini_attestation_free(tahini_attestation* out);

// Describes the most recent failure on this thread. Never NULL.
const char* tahini_last_error(void);

#ifdef __cplusplus
}
#endif

#endif /* TAHINI_CLIENT_H */
