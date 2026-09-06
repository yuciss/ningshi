// Unix socket + CLI protocol (root and WebUI only).
// Requests and responses are single-line JSON.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};

use serde::{Deserialize, Serialize};

use crate::config::log;
use crate::engine::Engine;

#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    pub cmd: String,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub minutes: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
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
pub fn handle(mut stream: UnixStream, engine: &mut Engine) {
    // A client that connects and never sends would otherwise block the
    // single-threaded poll loop here forever. Bound the read.
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
    let mut buf = [0u8; 8192];
    let n = match stream.read(&mut buf) {
        Ok(n) => n,
        Err(_) => return,
    };
    let req: Request = match serde_json::from_slice(&buf[..n]) {
        Ok(r) => r,
        Err(e) => {
            write_resp(&mut stream, &Response {
                ok: false,
                error: Some(e.to_string()),
                data: serde_json::json!({}),
            });
            return;
        }
    };

    let resp = match req.cmd.as_str() {
        "reload" => match engine.reload() {
            Ok(()) => ok_resp(serde_json::json!({})),
            Err(e) => err_resp(&e.to_string()),
        },
        "status" => {
            // Refresh on demand so the WebUI always gets up-to-date state.
            if let Err(e) = engine.tick() {
                log(&format!("[socket] tick error: {e}"));
            }
            ok_resp(engine.status())
        }
        "extension" => {
            let key = req.key.unwrap_or_default();
            let minutes = req.minutes.unwrap_or(5);
            match engine.add_extension(&key, minutes) {
                Ok(mins) => ok_resp(serde_json::json!({ "minutes": mins })),
                Err(e) => err_resp(&e.to_string()),
            }
        }
        other => err_resp(&format!("unknown cmd: {other}")),
    };

    write_resp(&mut stream, &resp);
    log(&format!("[socket] handled '{}'", req.cmd));
}

fn ok_resp(data: serde_json::Value) -> Response {
    Response { ok: true, error: None, data }
}

fn err_resp(msg: &str) -> Response {
    Response { ok: false, error: Some(msg.to_string()), data: serde_json::json!({}) }
}

fn write_resp(stream: &mut UnixStream, resp: &Response) {
    if let Ok(line) = serde_json::to_string(resp) {
        let _ = stream.write_all((line + "\n").as_bytes());
    }
}

/// Client: used by CLI mode (`ningshi status` / `reload` / `extension`).
pub fn request(path: &str, req: &Request) -> anyhow::Result<Response> {
    let mut s = UnixStream::connect(path)?;
    let line = serde_json::to_string(req)?;
    s.write_all((line + "\n").as_bytes())?;
    let mut buf = String::new();
    s.read_to_string(&mut buf)?;
    Ok(serde_json::from_str(&buf)?)
}
