#include "u_attest.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "u_util.h"

// Splits "ip:port" in place. Returns 0 on success.
static int split_addr(const char* addr, char* host, size_t host_cap, uint16_t* port) {
    const char* colon = strrchr(addr, ':');
    if (!colon || colon == addr) return -1;
    size_t hlen = (size_t)(colon - addr);
    if (hlen + 1 > host_cap) return -1;
    memcpy(host, addr, hlen);
    host[hlen] = '\0';
    char* end = NULL;
    long p = strtol(colon + 1, &end, 10);
    if (!end || *end != '\0' || p <= 0 || p > 65535) return -1;
    *port = (uint16_t)p;
    return 0;
}

// Builds the document described in u_attest.h. Returns a malloc'd string.
//
// verification_info_json is spliced in as raw JSON rather than a quoted string, so
// a caller can parse it as a nested object instead of unescaping a payload out of
// a string field.
static char* render_document(const uint8_t* quote, uint32_t quote_size,
                             const uint8_t* binary_hash, size_t hash_size,
                             const char* verification_info_json) {
    char* quote_b64 = base64url_encode(quote, quote_size, NULL);
    if (!quote_b64) return NULL;

    char* hash_hex = malloc(hash_size * 2 + 1);
    if (!hash_hex) { free(quote_b64); return NULL; }
    bin_to_hex(binary_hash, hash_size, hash_hex);

    const char* vinfo = verification_info_json ? verification_info_json : "null";
    const char* fmt =
        "{\n"
        "  \"version\": %d,\n"
        "  \"binary_hash\": \"%s\",\n"
        "  \"quote\": \"%s\",\n"
        "  \"verification_info\": %s\n"
        "}\n";

    int n = snprintf(NULL, 0, fmt, TAHINI_ATTEST_PROTOCOL_VERSION, hash_hex, quote_b64, vinfo);
    char* doc = (n > 0) ? malloc((size_t)n + 1) : NULL;
    if (doc) snprintf(doc, (size_t)n + 1, fmt, TAHINI_ATTEST_PROTOCOL_VERSION, hash_hex, quote_b64, vinfo);

    free(quote_b64);
    free(hash_hex);
    return doc;
}

static void serve_forever(int listen_fd, const char* doc, size_t doc_len) {
    // A caller that disappears mid-write would otherwise kill this process with
    // SIGPIPE and take the endpoint down with it.
    signal(SIGPIPE, SIG_IGN);

    for (;;) {
        int fd = accept(listen_fd, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR) continue;
            // The listening socket is unusable; nothing to recover to.
            break;
        }

        // Bound how long one stuck caller can hold the loop. The document is a
        // few kilobytes, so anything slower than this is not making progress.
        struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        size_t off = 0;
        while (off < doc_len) {
            ssize_t w = write(fd, doc + off, doc_len - off);
            if (w > 0) { off += (size_t)w; continue; }
            if (w < 0 && errno == EINTR) continue;
            break;
        }
        close(fd);
    }
    close(listen_fd);
    _exit(EXIT_FAILURE);
}

int tahini_serve_attestation(const char* listen_addr,
                             const uint8_t* quote, uint32_t quote_size,
                             const uint8_t* binary_hash, size_t hash_size,
                             const char* verification_info_json) {
    char host[64];
    uint16_t port = 0;
    if (split_addr(listen_addr, host, sizeof(host), &port) != 0) {
        fprintf(stderr, "tahini attest: cannot parse listen address '%s' (want ip:port)\n",
                listen_addr);
        return -1;
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
        fprintf(stderr, "tahini attest: '%s' is not an IPv4 address\n", host);
        return -1;
    }

    char* doc = render_document(quote, quote_size, binary_hash, hash_size,
                                verification_info_json);
    if (!doc) {
        fprintf(stderr, "tahini attest: failed to build the attestation document\n");
        return -1;
    }
    size_t doc_len = strlen(doc);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "tahini attest: socket: %s\n", strerror(errno));
        free(doc);
        return -1;
    }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    if (bind(fd, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
        fprintf(stderr, "tahini attest: bind %s: %s\n", listen_addr, strerror(errno));
        close(fd);
        free(doc);
        return -1;
    }
    if (listen(fd, 16) != 0) {
        fprintf(stderr, "tahini attest: listen: %s\n", strerror(errno));
        close(fd);
        free(doc);
        return -1;
    }

    // Bind before forking, so a port already in use is reported to the operator
    // rather than failing silently in a child nobody is watching.
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "tahini attest: fork: %s\n", strerror(errno));
        close(fd);
        free(doc);
        return -1;
    }

    if (pid == 0) {
        serve_forever(fd, doc, doc_len);
        _exit(EXIT_FAILURE); /* not reached */
    }

    // Parent goes on to exec the service, so it keeps neither the socket nor a
    // second copy of the document.
    close(fd);
    free(doc);
    fprintf(stderr, "tahini attest: serving attestation on %s (pid %d)\n",
            listen_addr, (int)pid);
    return 0;
}
