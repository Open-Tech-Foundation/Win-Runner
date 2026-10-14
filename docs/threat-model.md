# Threat model

Win-Runner is a **compatibility runtime, not a security sandbox**.
This page states the model plainly and gives isolation recipes to use
until the built-in sandbox lands.

## What the runtime does

- Guest x86-64 code executes **directly on the host CPU** (Linux x86-64
  backend). There is no instruction emulator standing between guest code
  and the processor.
- Guest programs run **with Win-Runner's OS privileges** (your uid) and can
  issue **host Linux system calls** directly. Nothing filters, namespaces,
  or virtualizes raw syscalls today.
- Windows API behavior comes from **host-side shims** (Rust code): files via
  WinFS/host fs, sockets via host sockets, threads via host threads. Shims
  constrain programs that *use the Windows API*, but a program can bypass
  shims with a direct syscall.

## What is NOT protected

| Threat | Status |
|---|---|
| Malicious/buggy guest reading/writing host files outside mounts | **Not prevented.** Run untrusted binaries isolated (recipes below). |
| Guest opening network connections to anywhere the host can reach | **Not prevented.** Filter with netns / firewall. |
| Guest exhausting host CPU/RAM/disk via direct syscalls | **Not prevented.** Use cgroup / rlimit / disk quotas. |
| Malicious package content from `wpkg` mirrors | **Mitigated, not eliminated.** Archives are SHA-256-checked against bundled manifests, but manifests pin upstream binaries you still trust. |
| Malicious snapshot (`.winfs`) contents | **Not verified.** Snapshots are data you trust like any disk image. |
| Control listener abuse | **Narrowed.** Binds loopback only; per-session random token in the URL path; unauthenticated handshakes expire after 2s (max 64 pending). Still: anyone on the host who learns the URL controls the shell. |
| Writable host mounts (`--mount=Z:/…`) | Write through to the host by design. Prefer `--mount-ro` when the guest only reads. |

Consequences in practice: `WinFS` and read-only mounts are **organization
tools, not isolation boundaries**. A read-only mount stops polite programs
from writing; it does not stop hostile ones.

## Recommended isolation (until the sandbox lands)

### Option A: `bwrap` (bubblewrap), no root needed

```bash
# Guest sees: read-only system, private /tmp, only ./work shared.
# No network. Adjust --ro-bind paths to your distro as needed.
bwrap \
  --unshare-all --share-net \
  --die-with-parent \
  --ro-bind /usr /usr \
  --ro-bind /etc/resolv.conf /etc/resolv.conf \
  --tmpfs /tmp \
  --bind "$PWD/work" /work \
  --setenv PATH /usr/bin:/bin \
  --chdir /work \
  /path/to/winrun --mount-ro=Z:/work shell
```

Drop `--share-net` (keep `--unshare-net`) to deny network entirely:

```bash
bwrap \
  --unshare-all --unshare-net \
  --die-with-parent \
  --ro-bind /usr /usr \
  --tmpfs /tmp \
  --bind "$PWD/work" /work \
  --chdir /work \
  /path/to/winrun --mount-ro=Z:/work shell
```

Notes:

- Keep the `winrun` binary and its temp/session dir (`$TMPDIR`, default
  `/tmp`) inside the sandbox so session blobs stay contained.
- Snapshots written with `--save` land wherever you point them — keep that
  path inside `/work` if you want to inspect the result afterwards.
- `bwrap` limits syscalls only via the namespaces you request; add
  `--seccomp` / cgroup limits per your distro's tooling for CPU/RAM caps.

### Option B: container (Docker/Podman)

```dockerfile
FROM debian:stable-slim
COPY winrun /usr/local/bin/winrun
RUN useradd -m runner
USER runner
WORKDIR /work
ENTRY rop
ENTRYPOINT ["winrun"]
```

```bash
# No network, only ./work mounted, memory-capped:
docker run --rm -it --network none --memory 2g --cpus 2 \
  -v "$PWD/work:/work:ro" winrun-image --mount-ro=Z:/work shell
```

### CI checklist

- Run one job per container; start from a clean snapshot each time.
- Use `--mount-ro` for sources; collect artifacts from a writable path you
  control, or from a saved snapshot you diff before trusting.
- Never print the headless control URL into logs; it carries the session token.
- Pin `winrun` and `wpkg` package versions; record them with the build.

## Supply-chain notes

- `wpkg` verifies every downloaded archive against the SHA-256 in its bundled
  manifest before install, and keeps a host-side content-addressed cache
  (`~/.cache/winrun/wpkg`, overridable via `$WINRUN_CACHE_DIR`) that is
  re-verified on use.
- TLS from the guest (built-in `curl`, `Invoke-WebRequest`, Python `ssl`/pip)
  verifies against the **guest** ROOT store, seeded from the Mozilla CA bundle
  pinned in `resources/cacert.pem` — not the host's CA files.
- Releases ship checksums plus build provenance attestation (see README).

## Reporting

Security-sensitive issues: please report privately to the maintainers (see
project contact channels) rather than filing a public issue. The built-in
sandbox is tracked as in-progress work; this page will be updated when its
guarantees can be stated and tested.
