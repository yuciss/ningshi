[中文](README.zh.md)

# Ningshi

**Version 0.4.3**

Ningshi (凝时) is a KernelSU module. It helps you scroll less and keeps apps from running in the background.

## Features

- **Kill at launch.** App code is stopped before it runs.
- **Rules.** Always-on, lock-screen block, time windows (per weekday), duration limit + cooldown; per-app and shared-pool groups.
- **WebUI.** Configure everything in the browser.

## Usage

Each app (or group) can combine four rules:

- **Always on** — block it all the time.
- **Lock screen** — block while the screen is off.
- **Time windows** — pick the hours and the weekdays. A window means "usable only inside it" by default; switch the policy to *Block in windows* to invert it. No weekday selected = every day. A window that crosses midnight belongs to the day it starts on (Monday 22:00-07:00 covers Monday night into Tuesday morning).
- **Duration** — allow a limited usage time; once used up, it resets the next day, or blocks for a **cooldown** period and then resets automatically.

The **+5 / +20** buttons grant a temporary **extension** (capped daily) for when you really need the app.

## Requirements

- KernelSU, arm64 device
- Kernel with kprobe enabled and the `binder_transaction` symbol in `/proc/kallsyms`

## Screenshots

![Screenshot 1](screenshots/screenshot-1.webp) ![Screenshot 2](screenshots/screenshot-2.webp)

## Development

### Layout

```
.
├── module/                 # flashable module (packaging just zips this directory)
│   ├── module.prop
│   ├── customize.sh        # install checks (arch + symbol)
│   ├── service.sh          # boot watchdog that starts the daemon
│   ├── uninstall.sh        # kills the daemon on uninstall
│   ├── bin/                # built binary (copied in at build time)
│   └── webroot/            # KernelSU WebUI
│       ├── index.html
│       └── config.json
├── daemon/                 # core program (Rust daemon + eBPF)
│   ├── src/                # engine, gate, detection, socket, ...
│   ├── bpf/gate.bpf.c      # kprobe / kretprobe hooks
│   ├── build.sh            # build BPF + cross-compile the daemon
│   └── rules.example.json  # example rules
└── scripts/package.sh      # one-shot build + package
```

### Build

Requires `clang` (for BPF), the Rust toolchain with the `aarch64-unknown-linux-musl` target, and `cargo-zigbuild`.

```bash
cd daemon
./build.sh
# output: target/aarch64-unknown-linux-musl/release/ningshi
```

### Packaging

`scripts/package.sh` does it all: builds the daemon, places the binary in `module/bin/`, and zips `module/` into `ningshi-vX.Y.Z.zip` (`module.prop` sits at the zip root; packaging needs the `zip` command).

### Device testing

```bash
adb push module/bin/ningshi /data/local/tmp/
adb shell su -c 'pkill -9 ningshi; sleep 1; cp /data/local/tmp/ningshi /data/adb/modules/ningshi/bin/ningshi && chmod 755 /data/adb/modules/ningshi/bin/ningshi'
# the watchdog restarts the new binary ~5s later
```

CLI:

```bash
ningshi status                       # status JSON (blocked uids / usage / kill counts / gate health)
ningshi reload                       # reload rules.json
ningshi apply <file>                 # validate a rules file, then make it live
ningshi extension <key> <minutes>    # grant a temporary extension
ningshi version
ningshi clear_log
```

### Rules file

`/data/adb/ningshi/rules.json` is the single data contract shared by the WebUI and the daemon; see `daemon/rules.example.json`. Unknown fields are ignored when parsing, for forward compatibility.

Writes go through `ningshi apply`: the daemon parses the candidate file first and only then replaces the live one, so a bad write can never disarm the module. The last file that parsed cleanly is kept as `rules.json.ok` and is used (loudly, in the log) if the live file becomes unreadable. A file claiming a newer schema version than the daemon supports is refused instead of being misread.

### Key design

- **Interception**: two independent kernel anchors, either of which is enough, and which symbols they use is decided by probing what the running kernel actually has (visible as `status.gate.uid_switch_symbol`). A kretprobe on `commit_creds` reports a process that just switched to a blocked uid - every credential change in Linux goes through it, whichever syscall or namespace mechanism Android uses; it falls back to the generated `__arm64_sys_setresuid` wrapper. A kprobe/kretprobe pair on `binder_transaction` reports the first non-zero-handle transaction of a new process. The userspace killer waits for the process to become foreground (`oom_score_adj == 0`, i.e. the attach handshake is complete) and only then sends `SIGKILL` through a pidfd, so a recycled pid can never redirect the kill, and it re-checks the block list first because a kernel-side mark can outlive the rule that created it.
- **Identity**: the kernel only answers "a process of a blocked uid appeared". Before signalling, the killer reads that process's own `/proc/<pid>/cmdline` and requires it to carry one of the package names the user blocked for that uid - a name the process itself was given, not something read out of a system file. `/data/system/packages.list` is therefore only a lookup table for uids, never the authority on who a process is, so a uid recycled by a newly installed app can never be hit (such skips are counted in `status.gate.identity_skipped`).
- **Detection**: foreground / screen state / package-to-uid are read from kernel filesystems (cpuset / DRM / `packages.list`); a pid's uid comes from `/proc/<pid>` ownership - one stat instead of parsing the status file of every process (verified identical on the test device).
- **Adaptive scheduling**: the daemon sleeps until the next moment something can actually change: the next window edge, the next extension/cooldown expiry, local midnight, or the 60s sweep interval while any app is blocked. With nothing time-dependent configured it idles for ~5 minutes, and `/data/system` events other than `packages.list` are ignored. Blocking a launch happens in the kernel, so a long sleep never weakens enforcement.
- **Single instance**: the daemon holds an `flock` and exits when another instance owns it; two instances would attach two sets of probes with two conflicting block maps.
- **Fail-open**: every failed detection lets the app through. A periodic sweep covers any process the gate missed.
- **Health**: `status.gate` reports which anchors are attached plus the kernel-side counters (marks, events, ring-buffer drops, skipped kills), and `rules_source` says whether the running rules came from the file, the fallback copy or the built-in default.
