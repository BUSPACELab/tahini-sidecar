# Remote Attestation Flow

The control flow is essentially the following. The sidecar produces an SGX report inside the enclave and the untrusted layer turns it into an ECDSA quote via Intel SGX DCAP. A remote client verifies the quote using a collateral, which is the TCB info, CRLs, and the PCK certificate chain.

Here is what the untrusted part of the sidecar does, step by step:

1. Hash the binary with `ecall_hash_binary` by streaming the service binary into a memfd while computing SHA-256 inside the enclave.
2. Generate credentials using `ecall_generate_credentials` by creating an ECDH key pair inside the enclave.
3. Get Quoting Enclave v3 (QE3) target info using the untrusted side calls from Intel SGX's DCAP attestation API, i.e., `sgx_qe_get_target_info()` to obtain the Quoting Enclave's identity.
4. Create the Intel SGX report with `ecall_get_attestation_report` which calls `sgx_create_report(qe_target_info, report_data)` where `report_data` = binary hash (32 B) || key commitment (32 B). The report targets QE3.
5. Generate the ECDSA quote using untrusted side calls from Intel SGX's DCAP attestation API with `sgx_qe_get_quote(&report)`. The DCAP Quote Library loads the Quoting Enclave (QE3), verifies the report, and produces an ECDSA-P256 quote.
6. Print the quote, essentially, the hex-encoded quote and binary hash are printed to stderr.
7. Execute the underlying service. `execveat(memfd, ...)` replaces the process with the service, passing the secret via `--tahini-secret`.

## Channel Binding

Pass `--tahini-dc-pubkey <hex>` and the key commitment covers the delegated credential the service serves TLS with, rather than the ECDH key from step 2 that nothing in the TLS path consumes. Lift the hex out of the client verification info:

```bash
--tahini-dc-pubkey "$(jq -r .public_key_der fizz_client.json)"
```

This is what makes the attestation say something about a connection. Without it the quote proves "a binary measuring H runs in a genuine enclave" and the handshake proves "my peer holds credential D's private key", but nothing joins the two: a relay can serve a genuine quote for the real binary while terminating TLS with its own credential, and the client only learns that the right code exists somewhere. With the commitment over D, the quote reads "the binary measuring H serves with credential D", which composes with the handshake into "the peer on this channel is the attested code".

The launcher warns when the flag is absent, and a client that checks the commitment against its own verification info will reject such a quote.

## Client Verification

The client receives the quote and verifies it using collateral. On Azure confidential VMs, collateral comes from [Azure Trusted Hardware Identity Management](https://learn.microsoft.com/en-us/azure/security/fundamentals/trusted-hardware-identity-management). The `az-dcap-client` QPL (installed in the docker image when `AZURE=1`) handles this transparently.

`examples/rpc-client` does the full check: it submits the quote to Azure Attestation, then compares `report_data` against the binary hash and against `H(public_key_der)` taken from the verification info driving its own handshake. Taking the key from that side matters — hashing the key the sidecar ships next to the quote would only show the sidecar agrees with itself.

## Running End-to-End on Azure

Set up a confidential Intel SGX VM using this [guide](https://learn.microsoft.com/en-us/azure/confidential-computing/quick-create-portal) from Microsoft Azure. Clone this repository in the VM.

Then build the docker:

```bash
bazel run //:docker_build -- --build-arg SGX_MODE=HW --build-arg AZURE=1
```

And then run the docker. We have a script, `docker-run.sh`, that auto-detects SGX devices.

```bash
bazel run //:docker_run
```

Inside the docker, you can build the sidecar (and optionally a hello world example):

```bash
bazel build //:sidecar_bin //:enclave_signed //examples:hello
```

Then you can run the hello world example with the sidecar:

```bash
./bazel-bin/sidecar ./bazel-bin/examples/hello
```