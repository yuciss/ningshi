// Ningshi daemon entry point.
// No args = daemon mode. CLI: ningshi status|reload|extension|apply|version|clear_log.

mod clear;
mod config;
mod engine;
mod fg;
mod gate;
mod pm;
mod proc;
mod rules;
mod socket;

use std::collections::HashMap;
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex};

use config::{ensure_data_dir, log, socket_path};
use engine::Engine;
use gate::Gate;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("status") | Some("reload") | Some("extension") | Some("apply") => return cli(&args),
        Some("clear_log") => {
            config::clear_log()?;
            println!("ok");
            return Ok(());
        }
        Some("--version") | Some("version") => {
            println!("ningshi v{}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        _ => {}
    }
    run_daemon()
}

fn cli(args: &[String]) -> anyhow::Result<()> {
    let cmd = args[1].as_str();
    let mut req = socket::Request {
        v: socket::PROTOCOL_VERSION,
        cmd: cmd.to_string(),
        key: None,
        minutes: None,
        path: None,
    };
    match cmd {
        "extension" => {
            req.key = args.get(2).cloned();
            req.minutes = args.get(3).and_then(|s| s.parse().ok());
        }
        "apply" => req.path = args.get(2).cloned(),
        _ => {}
    }
    let resp = socket::request(&socket_path(), &req)?;
    println!("{}", serde_json::to_string_pretty(&resp.data)?);
    if !resp.ok {
        if let Some(e) = resp.error {
            eprintln!("error: {e}");
        }
        std::process::exit(1);
    }
    // A daemon from a different build means a stale binary was copied in (or the
    // daemon was never restarted): say so instead of behaving oddly.
    if let Some(v) = resp.data.get("version").and_then(|v| v.as_str()) {
        if v != env!("CARGO_PKG_VERSION") {
            eprintln!(
                "warning: daemon is v{v}, this binary is v{}; reinstall the module",
                env!("CARGO_PKG_VERSION")
            );
        }
    }
    Ok(())
}

/// Only one daemon may run: two instances would attach two sets of probes with
/// two conflicting block maps, and which one wins would be undefined. The lock
/// is taken before any probe is attached and released when the process exits.
fn lock_daemon() -> anyhow::Result<std::fs::File> {
    let path = config::lock_path();
    let file = std::fs::OpenOptions::new().create(true).write(true).open(&path)?;
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        anyhow::bail!("another ningshi daemon already holds {path}");
    }
    Ok(file)
}

// Watch /data/system so package install/uninstall (packages.list rewrite)
// is picked up immediately instead of waiting for the next tick.
fn setup_inotify() -> anyhow::Result<i32> {
    let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
    if fd < 0 {
        anyhow::bail!("inotify_init1 failed");
    }
    let path = b"/data/system\0";
    let wd = unsafe {
        libc::inotify_add_watch(
            fd,
            path.as_ptr() as *const libc::c_char,
            libc::IN_MOVED_TO | libc::IN_CLOSE_WRITE | libc::IN_DELETE | libc::IN_CREATE,
        )
    };
    if wd < 0 {
        unsafe { libc::close(fd) };
        anyhow::bail!("inotify_add_watch /data/system failed");
    }
    log("[engine] watching /data/system for package changes");
    Ok(fd)
}

/// Drain pending inotify events. Returns true only when packages.list itself
/// changed. Everything else written into /data/system (battery stats, dropbox,
/// appops, ...) is ignored on purpose: waking the engine for it would cost power
/// and change nothing.
fn drain_inotify(fd: i32) -> bool {
    let hdr = std::mem::size_of::<libc::inotify_event>();
    let mut buf = [0u8; 4096];
    let mut changed = false;
    // The fd is non-blocking, so this ends with EAGAIN once everything is read.
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            break;
        }
        let n = n as usize;
        let mut off = 0usize;
        while off + hdr <= n {
            let ev = unsafe { &*(buf.as_ptr().add(off) as *const libc::inotify_event) };
            let len = ev.len as usize;
            if off + hdr + len > n {
                break;
            }
            if len > 0 {
                let raw = &buf[off + hdr..off + hdr + len];
                let name = raw.split(|b| *b == 0).next().unwrap_or(&[]);
                if name == b"packages.list" {
                    changed = true;
                }
            }
            off += hdr + len;
        }
    }
    changed
}

fn run_daemon() -> anyhow::Result<()> {
    ensure_data_dir()?;
    // Held for the whole process lifetime; dropped (released) on exit.
    let _lock = match lock_daemon() {
        Ok(f) => f,
        Err(e) => {
            log(&format!("[ningshi] not starting: {e}"));
            return Ok(());
        }
    };

    log(&format!("[ningshi] daemon v{}", env!("CARGO_PKG_VERSION")));

    let kill_count: Arc<Mutex<HashMap<u32, u64>>> = Arc::new(Mutex::new(HashMap::new()));
    let gate = Gate::start(Arc::clone(&kill_count))?;
    let mut engine = Engine::new(gate, kill_count)?;

    // Apply the initial block map right away: the first poll below can wait for
    // a long idle interval, and until the first tick the BPF block map is empty
    // (blocked apps would launch freely after every daemon restart).
    if let Err(e) = engine.tick() {
        log(&format!("[engine] initial tick error: {e}"));
    }

    let listener = socket::listen(&socket_path())?;
    let fd = listener.as_raw_fd();
    log(&format!("[ningshi] listening on {}", socket_path()));

    let ino_fd = setup_inotify().unwrap_or(-1);

    // Adaptive wake schedule: sleep until the next moment something can change
    // (window edge, usage accounting, sweep, expiry) instead of ticking on a
    // fixed cadence. Blocking a launch is kernel-side, so a longer sleep never
    // weakens enforcement.
    let mut next_tick = std::time::Instant::now();
    loop {
        let now = std::time::Instant::now();
        let wait_ms = if next_tick > now {
            (next_tick - now).as_millis().min(i32::MAX as u128) as i32
        } else {
            0
        };
        let mut pfds = [
            libc::pollfd { fd, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: ino_fd, events: libc::POLLIN, revents: 0 },
        ];
        let nfds: libc::nfds_t = if ino_fd >= 0 { 2 } else { 1 };
        let r = unsafe { libc::poll(pfds.as_mut_ptr(), nfds, wait_ms) };

        let mut changed = false;
        if r > 0 {
            if (pfds[0].revents & libc::POLLIN) != 0 {
                if let Ok((stream, _)) = listener.accept() {
                    changed |= socket::handle(stream, &mut engine);
                }
            }
            if nfds == 2 && (pfds[1].revents & libc::POLLIN) != 0 {
                changed |= drain_inotify(ino_fd);
            }
        }

        // Tick when the schedule says so, or immediately when a request changed
        // something (rules reload, extension, package install).
        if std::time::Instant::now() >= next_tick || changed {
            if let Err(e) = engine.tick() {
                log(&format!("[engine] tick error: {e}"));
            }
            let secs = engine.tick_interval_secs();
            next_tick = std::time::Instant::now() + std::time::Duration::from_secs(secs);
        }
    }
}
