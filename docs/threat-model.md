# Threat model

Win-Runner is a **compatibility runtime, not a security sandbox**.
Isolation recipes below apply until the built-in sandbox lands.

## What the runtime does

- Guest code runs **directly on the host CPU** — no emulator in between.
- Guests run **with your uid** and can issue **host syscalls** directly. Nothing filters them.
- Windows APIs are **host-side shims** (files, sockets, threads). Polite programs stay
  inside them; hostile ones can bypass them with a raw syscall.

## What is NOT protected

| Threat | Status |
|---|---|
| Host file access outside mounts | **Not prevented.** Isolate untrusted binaries (below). |
| Network to anywhere the host reaches | **Not prevented.** Filter with netns / firewall. |
| CPU/RAM/disk exhaustion | **Not prevented.** Use cgroup / rlimit / quotas. |
| Malicious `wpkg` content | **Mitigated.** SHA-256-checked, but you still trust upstream binaries. |
| Malicious snapshots (`.winfs`) | **Not verified.** Trust like any disk image. |
| Control URL leak | **Narrowed.** Loopback-only + per-session token; still, URL = shell access. |
| Writable mounts | Write through by design. Prefer `--mount-ro` for reads. |

WinFS and read-only mounts are **organization, not isolation**. Read-only stops
polite programs, not hostile ones.

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

- Keep the binary + `$TMPDIR` session dir inside the sandbox so blobs stay contained.
- Keep `--save` snapshot paths inside `/work` to inspect results after.
- Add `--seccomp` / cgroup limits for CPU/RAM caps.

### Option B: container (Docker/Podman)

```dockerfile
FROM debian:stable-slim
COPY winrun /usr/local/bin/winrun
RUN useradd -m runner
USER runner
WORKDIR /work
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

- `wpkg` SHA-256-checks every archive (host cache in `~/.cache/winrun/wpkg` re-verified on use).
- Guest TLS verifies against the **guest** ROOT store (pinned Mozilla bundle), not host CAs.
- Releases ship checksums + build provenance.

## Reporting

Security issues: report privately to the maintainers, not via public issues.
