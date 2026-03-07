# Tahini Sidecar

<img src="share/cover.png" width="150"></img>

A lightweight attestation sidecar that is part of the [Tahini Project](https://space.babman.io/projects/compliance.html) led by Dr. Kinan Albab's
[SPACE Lab](https://space.babman.io/index.html) at Boston University. 

## Setup and running with Docker

The sidecar requires the **Intel SGX SDK** (x86_64 Linux). The easiest way to build and run is with the provided Docker image, which includes the SDK in simulation mode.

### 1. Build the Docker image

From the repo root:

```bash
bazel run //:docker_build
```

### 2. Run the container

Your repo is mounted at `/workspace` so you can edit locally and build inside the container.

```bash
bazel run //:docker_run
```

### 3. Inside the container: build with Bazel

The container has `SGX_SDK` and `SGX_MODE=SIM` set. Build the sidecar, signed enclave, and example:

```bash
bazel build //:sidecar_bin //:enclave_signed //examples:hello
```

### 4. Run the sidecar with the example service

From the container shell (you’re in `/workspace`):

```bash
./bazel-bin/sidecar ./bazel-bin/examples/hello
```

You should see something like:

```
tahini secret: 82569dba350c98ea4189a31eb9191fc9147a1428055034cfd8475ccd76a8c9ea
hello, world!
```

To run the sidecar with another binary, pass its path as the first argument:

```bash
./bazel-bin/sidecar /path/to/your/service/binary
```

## Sync to a remote host

To sync the repo to a remote x86_64 host (e.g. a Linode instance) for building or running there:

```bash
bazel run //:sync -- <ip_address>
```

This rsyncs the repo to `/root/tahini-sidecar` on the remote. Run the sync from your local repo root so the script can find the git root.

**On the remote host**, use the **exact synced path** (e.g. `cd /root/tahini-sidecar`) so `MODULE.bazel` is present—then run `./infra/install.sh` and Bazel. Otherwise Bazel will report “not invoked from within a workspace”:

```bash
ssh root@<ip_address>
cd /root/tahini-sidecar
./infra/install.sh
bazel run //:docker_build
# or: bazel build //:sidecar_bin //:enclave_signed //examples:hello
```

`infra/install.sh` installs Docker (`apt install docker.io`) and Bazelisk to `/usr/local/bin/bazel` (uses `sudo`). Sync verifies `MODULE.bazel` exists locally and on the remote so the workspace is valid.

## Example: changing the service changes the secret

The sidecar hashes the service binary and binds it to the attestation. If you change the example and rebuild, the secret and reported hash change. Try editing `examples/hello.c` (e.g. change the printed string), then:

```bash
bazel build //examples:hello //:sidecar_bin //:enclave_signed
./bazel-bin/sidecar ./bazel-bin/examples/hello
```

You’ll get a different `tahini secret` and hash, so clients can detect that the binary changed.

## Convention

We prefix all untrusted code with `u_` and all enclave code with `e_`. Other than that,
`sidecar.edl` is the enclave definition language file that defines the interface,
`sidecar.lds` is the linker script for the enclave, and `sidecar.config.xml` is the
configuration of the enclave. The project is built with **Bazel** (see `BUILD`, `MODULE.bazel`, and `WORKSPACE`).

## Execution mode

The Docker image runs in simulation mode (`SGX_MODE=SIM`) by default. To run on SGX hardware, build with `SGX_MODE=HW`:

```bash
bazel run //:docker_build -- --build-arg SGX_MODE=HW
```

Attestation uses `ECDSA/DCAP` via `libsgx-dcap-ql`. Quote generation requires SGX hardware. In simulation mode the quote step will fail. See `docs/ATTESTATION.md` for the full flow and client verification.

### Azure DCsv3

On Azure confidential VMs (DCsv3), build with the Azure QPL:

```bash
bazel run //:docker_build -- --build-arg SGX_MODE=HW --build-arg AZURE=1
```

This installs `az-dcap-client` which routes collateral requests to Azure THIM instead of Intel PCS. The run script auto-detects SGX devices and the AESM socket. See `docs/ATTESTATION.md` for details.

## End to End Demonstration with Delegated TLS and fizz-rs

This requires a Microsoft Azure confidential VM. You can provision one with Terraform (see above) or set it up manually using this [guide](https://learn.microsoft.com/en-us/azure/confidential-computing/quick-create-portal) from Microsoft Azure. Clone this repository in the VM.

The sidecar can launch an RPC server that uses [delegated credentials](https://datatracker.ietf.org/doc/rfc9345/) (RFC 9345) for TLS, providing two trust layers. The first layer is the SGX attestation, which proves to the RPC client that the right code / binary is running for the RPC server. The second layer, Delegated TLS, proves that the communication channel can be trusted, i.e., it is encrypted with a short-lived credential signed by a trusted certificate authority (CA). This second part uses [fizz-rs](https://github.com/BUSPACELab/fizz-rs) which is included as a submodule at `third_party/fizz-rs`.

To set up, first ensure that the submodule is added and up to date:

```bash
git submodule update --init --recursive
```

The demo runs two containers. A server composed of the SGX sidecar and the RPC server with delegated TLS, and a client which connects and verifies the delegated credential. To build these containers on an Azure confidential VM, first run

```bash
SGX_MODE=HW AZURE=1 docker compose -f docker-compose.yml -f docker-compose.sgx.yml up --build
```

Here is what happens:

1. The server container generates a TLS certificate with the delegated credential extension.
2. The fizz-sidecar which is developed in C++ generates a delegated credential i.e short-lived cert and verification info.
3. The tahini sidecar hashes the RPC server binary, does SGX attestation, and launches it via `execveat`.
4. The RPC server starts listening on port 8443 with the delegated credential.
5. The client container reads the verification info from a shared volume and connects over delegated TLS.
6. The client verifies the delegated credential during the TLS handshake.

What to observe: the server container's stderr shows the SGX attestation output including the binary hash, the DCAP quote, and the verification info. The client container's stderr shows the successful TLS handshake and message exchange.

### Sidecar DC flags

The sidecar accepts optional flags for delegated credential integration:

```bash
./sidecar [--tahini-dc <server.json>] [--tahini-dc-cert <cert.pem>] [--tahini-dc-sig <client.json>] <service> [args...]
```

- `--tahini-dc`: path to the server delegated credential JSON (forwarded to the service binary)
- `--tahini-dc-cert`: path to the parent TLS certificate (forwarded to the service binary)
- `--tahini-dc-sig`: path to client verification info JSON (printed to stderr for clients)


## Provisioning an Azure SGX VM with Terraform

Instead of manually creating a VM, you can also use the provided Terraform configuration:

```bash
cd infra/terraform
terraform init
terraform apply
```

This provisions a `Standard_DC1s_v3` (SGX-capable) VM with Ubuntu 22.04, Docker, Bazelisk, and the Intel SGX DCAP libraries pre-installed via cloud-init.

After `terraform apply`, use the printed outputs to connect and sync:

```bash
ssh -i ~/.ssh/tahini-sidecar_key.pem azureuser@$(terraform output -raw public_ip)
```

Or sync the repo from your local machine

```bash
bazel run //:sync -- $(terraform output -raw public_ip)
```

To tear everything down:

```bash
terraform destroy
```