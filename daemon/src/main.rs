// Ningshi daemon entry point.
// No args = daemon mode. CLI: ningshi status|reload|extension|version|clear_log.

mod clear;
mod config;
mod engine;
mod fg;
mod gate;
mod pm;
mod rules;
mod socket;

use std::collections::HashMap;
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex};

use config::{ensure_data_dir, log, rules_path, socket_path};
use engine::Engine;
use gate::Gate;
use rules::Rules;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("status") | Some("reload") | Some("extension") => return cli(&args),
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
        cmd: cmd.to_string(),
        key: None,
        minutes: None,
    };
    if cmd == "extension" {
        req.key = args.get(2).cloned();
        req.minutes = args.get(3).and_then(|s| s.parse().ok());
    }
    let resp = socket::request(&socket_path(), &req)?;
    println!("{}", serde_json::to_string_pretty(&resp.data)?);
    if !resp.ok {
        if let Some(e) = resp.error {
            eprintln!("error: {e}");
        }
        std::process::exit(1);
    }
    Ok(())
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

fn drain_inotify(fd: i32) {
    let mut buf = [0u8; 4096];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 || (n as usize) < buf.len() {
            break;
        }
    }
}

fn run_daemon() -> anyhow::Result<()> {
    let rules = match Rules::load(std::path::Path::new(&rules_path())) {
        Ok(r) => r,
        Err(e) => {
            log(&format!("[ningshi] rules.json load failed: {e}"));
            Rules::default()
        }
    };

    if rules.settings.clear_log_on_boot {
        let _ = config::clear_log();
    }

    ensure_data_dir()?;

    log(&format!("[ningshi] daemon v{}", env!("CARGO_PKG_VERSION")));

    let kill_count: Arc<Mutex<HashMap<u32, u64>>> = Arc::new(Mutex::new(HashMap::new()));
    let gate = Gate::start(Arc::clone(&kill_count))?;
    let mut engine = Engine::new(gate, rules, kill_count)?;

    // Apply the initial block map right away: the first poll in the loop below
    // can wait up to 15s, and until the first tick the BPF block map is empty
    // (blocked apps would launch freely after every daemon restart).
    if let Err(e) = engine.tick() {
        log(&format!("[engine] initial tick error: {e}"));
    }

    let listener = socket::listen(&socket_path())?;
    let fd = listener.as_raw_fd();
    log(&format!("[ningshi] listening on {}", socket_path()));

    let ino_fd = setup_inotify().unwrap_or(-1);

    loop {
        let mut pfds = [
            libc::pollfd { fd, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: ino_fd, events: libc::POLLIN, revents: 0 },
        ];
        let nfds: libc::nfds_t = if ino_fd >= 0 { 2 } else { 1 };
        let r = unsafe { libc::poll(pfds.as_mut_ptr(), nfds, 15000) };
        if r > 0 {
            if (pfds[0].revents & libc::POLLIN) != 0 {
                if let Ok((stream, _)) = listener.accept() {
                    socket::handle(stream, &mut engine);
                }
            }
            if nfds == 2 && (pfds[1].revents & libc::POLLIN) != 0 {
                drain_inotify(ino_fd);
                if let Err(e) = engine.sync_packages() {
                    log(&format!("[engine] package sync error: {e}"));
                }
            }
        }
        if let Err(e) = engine.tick() {
            log(&format!("[engine] tick error: {e}"));
        }
    }
}
