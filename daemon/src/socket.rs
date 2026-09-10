// Unix socket + CLI protocol (root and WebUI only).
// Requests and responses are single-line JSON, tagged with a protocol version.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};

use serde::{Deserialize, Serialize};

use crate::config::log;
use crate::engine::Engine;

/// Bumped whenever the request or response shape changes. An unknown version is
/// refused with a clear message instead of being misread: a stale binary talking
/// to a newer daemon must be visible, not mysterious.
pub const PROTOCOL_VERSION: u32 = 2;

#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    /// Protocol version; 0 means a client from before versioning existed.
    #[serde(default)]
    pub v: u32,
    pub cmd: String,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub minutes: Option<u32>,
    /// File to validate and install (`apply`).
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    #[serde(default)]
    pub v: u32,
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub data: serde_json::Value,
}

/// Server: listen on the socket (root only).
pub fn listen(path: &str) -> anyhow::Result<UnixListener> {
    let _ = std::fs::remove_file(path);
    let l = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(l)
}

/// Server: handle one connection (blocking, single command).
/// Returns true when the request changed daemon state, so the main loop knows
/// whether an immediate tick is needed.
pub fn handle(mut stream: UnixStream, engine: &mut Engine) -> bool {
    // A client that connects and never sends would otherwise block the
    // single-threaded poll loop here forever. Bound the read.
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
    let mut buf = [0u8; 8192];
    let n = match stream.read(&mut buf) {
        Ok(n) => n,
        Err(_) => return false,
    };
    let req: Request = match serde_json::from_slice(&buf[..n]) {
        Ok(r) => r,
        Err(e) => {
            write_resp(&mut stream, &Response {
                v: PROTOCOL_VERSION,
                ok: false,
                error: Some(e.to_string()),
                data: serde_json::json!({}),
            });
            return false;
        }
    };

    // 0 = client predates versioning; anything else must match exactly.
    if req.v != 0 && req.v != PROTOCOL_VERSION {
        write_resp(&mut stream, &Response {
            v: PROTOCOL_VERSION,
            ok: false,
            error: Some(format!(
                "protocol v{} is not supported by this daemon (v{}); reinstall the module",
                req.v, PROTOCOL_VERSION
            )),
            data: serde_json::json!({}),
        });
        return false;
    }

    let (resp, changed) = match req.cmd.as_str() {
        "reload" => match engine.reload() {
            Ok(()) => (ok_resp(serde_json::json!({})), true),
            Err(e) => (err_resp(&e.to_string()), false),
        },
        "status" => {
            // Read-only snapshot: never tick here. A status query is what the
            // WebUI polls, and ticking would let opening the WebUI kill
            // processes as a side effect.
            (ok_resp(engine.status()), false)
        }
        "extension" => {
            let key = req.key.unwrap_or_default();
            let minutes = req.minutes.unwrap_or(5);
            match engine.add_extension(&key, minutes) {
                Ok(mins) => (ok_resp(serde_json::json!({ "minutes": mins })), true),
                Err(e) => (err_resp(&e.to_string()), false),
            }
        }
        // Validate a candidate rules file and only then make it live. The WebUI
        // uses this instead of overwriting rules.json, so a bad payload is
        // refused here while the running configuration keeps enforcing.
        "apply" => {
            let path = req.path.unwrap_or_default();
            if path.is_empty() {
                (err_resp("apply needs a file path"), false)
            } else {
                match engine.apply_rules_file(&path) {
                    Ok(apps) => (
                        ok_resp(serde_json::json!({ "apps": apps, "rules_source": "file" })),
                        true,
                    ),
                    Err(e) => (err_resp(&e.to_string()), false),
                }
            }
        }
        other => (err_resp(&format!("unknown cmd: {other}")), false),
    };

    write_resp(&mut stream, &resp);
    log(&format!("[socket] handled '{}'", req.cmd));
    changed
}

fn ok_resp(data: serde_json::Value) -> Response {
    Response { v: PROTOCOL_VERSION, ok: true, error: None, data }
}

fn err_resp(msg: &str) -> Response {
    Response {
        v: PROTOCOL_VERSION,
        ok: false,
        error: Some(msg.to_string()),
        data: serde_json::json!({}),
    }
}

fn write_resp(stream: &mut UnixStream, resp: &Response) {
    if let Ok(line) = serde_json::to_string(resp) {
        let _ = stream.write_all((line + "\n").as_bytes());
    }
}

/// Client: used by CLI mode (`ningshi status` / `reload` / `extension` /
/// `apply`).
pub fn request(path: &str, req: &Request) -> anyhow::Result<Response> {
    let mut s = UnixStream::connect(path)?;
    let line = serde_json::to_string(req)?;
    s.write_all((line + "\n").as_bytes())?;
    let mut buf = String::new();
    s.read_to_string(&mut buf)?;
    Ok(serde_json::from_str(&buf)?)
}
