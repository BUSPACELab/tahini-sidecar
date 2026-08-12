#include "tahini_client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// A stand-in for tahini_client.c that talks to no sidecar.
//
// Link this instead of the real client to develop and test a caller on a machine
// with no SGX. It is a drop-in: same header, same ownership rules, so the caller
// under test is the same code that will run against real hardware.
//
// What it deliberately does NOT do is pretend to attest. The quote is obvious
// filler, so anything that actually verifies it will reject it. That is the point:
// a caller wired up against this mock and then shipped would fail at the
// verification step rather than silently accepting an unattested peer.
//
// TAHINI_MOCK_BINARY_HASH overrides the hash, so a test can exercise both the
// manifest-match and manifest-mismatch paths.
// TAHINI_MOCK_FAIL set to a code name makes the call fail, for error handling:
//   connect | read | protocol
#define MOCK_HASH_DEFAULT \
    "0000000000000000000000000000000000000000000000000000000000000000"

#define MOCK_QUOTE "TU9DSy1RVU9URS1OT1QtVkFMSUQ"  /* "MOCK-QUOTE-NOT-VALID" */

static char g_error[256] = "no error";

const char* tahini_last_error(void) { return g_error; }

void tahini_attestation_free(tahini_attestation* out) {
    if (!out) return;
    free(out->binary_hash);
    free(out->quote);
    free(out->verification_info);
    memset(out, 0, sizeof(*out));
}

static char* dup_or_null(const char* s) {
    size_t n = strlen(s) + 1;
    char* p = malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

int tahini_fetch_attestation(const char* ip, uint16_t port, uint32_t timeout_ms,
                             tahini_attestation* out) {
    (void)timeout_ms;
    if (!ip || !out || port == 0) {
        snprintf(g_error, sizeof(g_error), "bad arguments");
        return TAHINI_ERR_ARGS;
    }
    memset(out, 0, sizeof(*out));

    const char* forced = getenv("TAHINI_MOCK_FAIL");
    if (forced) {
        if (strcmp(forced, "connect") == 0) {
            snprintf(g_error, sizeof(g_error), "mock: connect %s:%u refused", ip, (unsigned)port);
            return TAHINI_ERR_CONNECT;
        }
        if (strcmp(forced, "read") == 0) {
            snprintf(g_error, sizeof(g_error), "mock: read failed");
            return TAHINI_ERR_READ;
        }
        if (strcmp(forced, "protocol") == 0) {
            snprintf(g_error, sizeof(g_error), "mock: document missing verification_info");
            return TAHINI_ERR_PROTOCOL;
        }
        snprintf(g_error, sizeof(g_error), "mock: unknown TAHINI_MOCK_FAIL '%s'", forced);
        return TAHINI_ERR_ARGS;
    }

    const char* hash = getenv("TAHINI_MOCK_BINARY_HASH");
    if (!hash || !*hash) hash = MOCK_HASH_DEFAULT;

    // A syntactically real VerificationInfo, so a caller that deserializes it into
    // fizz_rs::VerificationInfo succeeds and the failure lands where it belongs —
    // at quote verification or the handshake.
    char vinfo[512];
    snprintf(vinfo, sizeof(vinfo),
             "{\"service_name\":\"mock-%u\","
             "\"valid_time\":604800,"
             "\"expected_verify_scheme\":1027,"
             "\"public_key_der\":\"3059301306072a8648ce3d020106082a8648ce3d0301070342000400\","
             "\"expires_at\":0}",
             (unsigned)port);

    out->version = TAHINI_ATTEST_MOCK_VERSION;
    out->binary_hash = dup_or_null(hash);
    out->quote = dup_or_null(MOCK_QUOTE);
    out->verification_info = dup_or_null(vinfo);
    if (!out->binary_hash || !out->quote || !out->verification_info) {
        tahini_attestation_free(out);
        snprintf(g_error, sizeof(g_error), "out of memory");
        return TAHINI_ERR_MEMORY;
    }

    fprintf(stderr, "tahini client: MOCK attestation for %s:%u — not a real quote\n",
            ip, (unsigned)port);
    return TAHINI_OK;
}
