#ifndef TAHINI_U_ATTEST_H
#define TAHINI_U_ATTEST_H

#include <stddef.h>
#include <stdint.h>

// The attestation endpoint a caller talks to before trusting a service.
//
// The protocol is one exchange: the caller connects, sends nothing, and reads a
// single JSON document until end of stream.
//
//   {"version":1,
//    "binary_hash":"<hex>",
//    "quote":"<base64url>",
//    "verification_info":{...}}
//
// `quote` is the DCAP quote, which the caller submits to an attestation service
// to establish that this is a genuine enclave running the code it claims.
// `binary_hash` is what the caller checks against its approved manifest.
// `verification_info` is the delegated credential's public half, which the caller
// uses to verify the TLS handshake with the service itself.
//
// Everything served here is public. The quote is meant to be handed to a verifier,
// the binary hash is a measurement, and the verification info is the half of the
// credential a client needs — the private half never leaves the service. So this
// endpoint needs no transport security of its own: an attacker who tampers with
// the document produces a quote that fails verification or a hash that fails the
// manifest check, and one who merely reads it learns nothing secret.
#define TAHINI_ATTEST_PROTOCOL_VERSION 1

// tahini_serve_attestation forks a child to serve the document above on
// listen_addr ("ip:port") for as long as the service runs, and returns in the
// parent so it can go on to launch the service.
//
// A fork is needed because the launcher ends in execveat: the process image is
// replaced by the service, so without a separate process there is nobody left to
// answer a caller. The child keeps only the public material below, never the
// credential's private half.
//
// Returns 0 if the socket was bound and the child started, -1 otherwise. Failure
// to serve is fatal to the caller's ability to attest, so the launcher treats it
// as an error rather than launching a service nobody can verify.
int tahini_serve_attestation(const char* listen_addr,
                             const uint8_t* quote, uint32_t quote_size,
                             const uint8_t* binary_hash, size_t hash_size,
                             const char* verification_info_json);

#endif /* TAHINI_U_ATTEST_H */
