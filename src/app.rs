//! `mnemosyne app`: a local web interface for the backups.
//!
//! Safeguards (the same model as the author's password manager, Sphinx):
//! - binds 127.0.0.1 only and checks the Host header (DNS rebinding);
//! - every API call needs a random per-run token in a custom header, which other web
//!   pages cannot send without a CORS preflight that this server never approves; the
//!   token travels in the URL fragment, which browsers never send to servers;
//! - strict Content-Security-Policy, no inline scripts, no external resources;
//! - starts locked; the repository key lives in memory only while unlocked, is dropped
//!   after 10 idle minutes, and the server exits when the window stops pinging;
//! - wrong passwords: after 5 in a row, unlocking pauses for 30 s;
//! - read-only: it lists, compares, verifies and downloads, but never deletes, prunes
//!   or writes into a repository (verification only updates the status file).

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};
use zeroize::Zeroizing;

use crate::maintain::{self, ReadData};
use crate::repo::Repo;
use crate::snapshot::{EntryKind, Snapshot};
use crate::status;
use crate::{diff, human_bytes};

const INDEX_HTML: &str = include_str!("../assets/index.html");
const APP_JS: &str = include_str!("../assets/app.js");
const APP_CSS: &str = include_str!("../assets/app.css");
pub const ICON_SVG: &str = include_str!("../assets/icon.svg");

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; \
                   img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
const MAX_BODY: u64 = 16 * 1024;
const MAX_FAILED: u32 = 5;
const PAUSE: Duration = Duration::from_secs(30);
const HEARTBEAT: Duration = Duration::from_secs(45);
pub const IDLE_LOCK: Duration = Duration::from_secs(10 * 60);
/// Downloads go through the browser's memory: keep them to a sane size.
const MAX_DOWNLOAD: u64 = 1 << 30;
const MAX_LIST: usize = 2000;

type Resp = Response<std::io::Cursor<Vec<u8>>>;

struct Unlocked {
    repo: Repo,
    root: String,
    /// The last snapshot opened, with a parent -> children index for browsing.
    cached: Option<(Snapshot, BTreeMap<String, Vec<usize>>)>,
}

struct State {
    token: String,
    port: u16,
    unlocked: Option<Unlocked>,
    failed: u32,
    paused_until: Option<Instant>,
    last_ping: Instant,
    password_file: Option<PathBuf>,
}

fn new_token() -> Result<String, String> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|_| "random number generation failed".to_string())?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

fn respond(content_type: &str, status: u16, body: Vec<u8>) -> Resp {
    let mut r = Response::from_data(body).with_status_code(StatusCode(status));
    for (k, v) in [
        ("Content-Type", content_type),
        ("Cache-Control", "no-store"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
        ("Content-Security-Policy", CSP),
    ] {
        if let Ok(h) = Header::from_bytes(k.as_bytes(), v.as_bytes()) {
            r.add_header(h);
        }
    }
    r
}

fn json_ok(v: Value) -> Resp {
    respond(
        "application/json; charset=utf-8",
        200,
        v.to_string().into_bytes(),
    )
}

fn json_err(status: u16, msg: &str) -> Resp {
    respond(
        "application/json; charset=utf-8",
        status,
        json!({ "error": msg }).to_string().into_bytes(),
    )
}

fn header(req: &Request, name: &'static str) -> Option<String> {
    req.headers()
        .iter()
        .find(|h| h.field.equiv(name))
        .map(|h| h.value.as_str().to_string())
}

fn query(url: &str) -> BTreeMap<String, String> {
    url.split_once('?')
        .map(|(_, q)| {
            q.split('&')
                .filter_map(|kv| kv.split_once('='))
                .map(|(k, v)| (decode(k), decode(v)))
                .collect()
        })
        .unwrap_or_default()
}

/// Percent-decoding for query values (UTF-8; invalid sequences become U+FFFD). Works on
/// bytes, so a stray '%' next to a multi-byte character can never split it.
fn decode(s: &str) -> String {
    fn hex(b: u8) -> Option<u8> {
        (b as char).to_digit(16).map(|d| d as u8)
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' => match (
                bytes.get(i + 1).copied().and_then(hex),
                bytes.get(i + 2).copied().and_then(hex),
            ) {
                (Some(h), Some(l)) => {
                    out.push(h * 16 + l);
                    i += 2;
                }
                _ => out.push(b'%'),
            },
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn body_json(req: &mut Request) -> Result<Value, String> {
    let mut buf = Vec::new();
    req.as_reader()
        .take(MAX_BODY + 1)
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    if buf.len() as u64 > MAX_BODY {
        return Err("request too large".into());
    }
    serde_json::from_slice(&buf).map_err(|_| "send JSON".to_string())
}

fn canonical(p: &str) -> String {
    std::fs::canonicalize(p)
        .map(|c| c.display().to_string())
        .unwrap_or_else(|_| p.to_string())
}

/// Repositories the status file knows, plus $MNEMOSYNE_REPO.
fn known_repos() -> Vec<String> {
    let mut repos: Vec<String> = status::load().repos.keys().cloned().collect();
    if let Ok(r) = std::env::var("MNEMOSYNE_REPO") {
        let r = canonical(&r);
        if !repos.contains(&r) {
            repos.push(r);
        }
    }
    repos
}

/// The saved password file, only if it is private (mode 600), like the CLI requires.
fn usable_password_file(p: &Option<PathBuf>) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let p = p.as_ref()?;
    let meta = std::fs::metadata(p).ok()?;
    (meta.is_file() && meta.permissions().mode() & 0o077 == 0).then(|| p.clone())
}

impl State {
    fn overview(&self) -> Value {
        let st = status::load();
        let repos: Vec<Value> = known_repos()
            .into_iter()
            .map(|r| {
                let s = st.repos.get(&r).cloned().unwrap_or_default();
                json!({
                    "path": r,
                    "exists": Path::new(&r).join("config.json").exists(),
                    "snapshots": s.snapshots,
                    "repo_bytes": s.repo_bytes,
                    "last_backup": s.last_backup,
                    "last_good_backup": s.last_good_backup,
                    "last_check": s.last_check,
                })
            })
            .collect();
        json!({
            "version": env!("CARGO_PKG_VERSION"),
            "repos": repos,
            "unlocked": self.unlocked.as_ref().map(|u| u.root.clone()),
            "password_file": usable_password_file(&self.password_file).is_some(),
            "paused_s": self.paused_until.map(|t| t.saturating_duration_since(Instant::now()).as_secs()).unwrap_or(0),
        })
    }

    fn unlock(&mut self, body: &Value) -> Resp {
        if let Some(until) = self.paused_until {
            if Instant::now() < until {
                return json_err(
                    429,
                    &format!(
                        "too many wrong passwords; wait {} s",
                        until.duration_since(Instant::now()).as_secs() + 1
                    ),
                );
            }
            self.paused_until = None;
        }
        let Some(root) = body.get("repo").and_then(Value::as_str) else {
            return json_err(400, "which repository?");
        };
        if !known_repos().iter().any(|r| r == root) {
            return json_err(400, "unknown repository");
        }
        let password: Zeroizing<String> =
            if body.get("use_file").and_then(Value::as_bool) == Some(true) {
                let Some(path) = usable_password_file(&self.password_file) else {
                    return json_err(400, "no private (mode 600) password file");
                };
                match std::fs::read_to_string(path) {
                    Ok(t) => Zeroizing::new(t.trim_end_matches(['\n', '\r']).to_string()),
                    Err(e) => return json_err(500, &e.to_string()),
                }
            } else {
                Zeroizing::new(
                    body.get("password")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                )
            };
        match Repo::open(Path::new(root), &password) {
            Ok(repo) => {
                self.failed = 0;
                self.unlocked = Some(Unlocked {
                    repo,
                    root: root.to_string(),
                    cached: None,
                });
                json_ok(json!({ "ok": true }))
            }
            Err(crate::Error::WrongPassword) => {
                self.failed += 1;
                if self.failed >= MAX_FAILED {
                    self.failed = 0;
                    self.paused_until = Some(Instant::now() + PAUSE);
                }
                json_err(401, "wrong password")
            }
            Err(e) => json_err(400, &e.to_string()),
        }
    }
}

impl Unlocked {
    fn snapshot(
        &mut self,
        wanted: &str,
    ) -> Result<&(Snapshot, BTreeMap<String, Vec<usize>>), Resp> {
        let name = self
            .repo
            .resolve(wanted)
            .map_err(|e| json_err(404, &e.to_string()))?;
        if self
            .cached
            .as_ref()
            .map(|(s, _)| s.name != name)
            .unwrap_or(true)
        {
            let snap = self
                .repo
                .load_snapshot(&name)
                .map_err(|e| json_err(500, &e.to_string()))?;
            let mut index: BTreeMap<String, Vec<usize>> = BTreeMap::new();
            for (i, e) in snap.entries.iter().enumerate() {
                let p = e.display();
                let parent = Path::new(&p)
                    .parent()
                    .map(|x| x.display().to_string())
                    .unwrap_or_default();
                index.entry(parent).or_default().push(i);
            }
            self.cached = Some((snap, index));
        }
        Ok(self.cached.as_ref().expect("just cached"))
    }
}

fn entry_json(e: &crate::snapshot::Entry) -> Value {
    json!({
        "path": e.display(),
        "name": Path::new(&e.display()).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| e.display()),
        "kind": match e.kind { EntryKind::Dir => "dir", EntryKind::File => "file", EntryKind::Symlink => "link" },
        "size": e.size,
        "mtime": e.mtime,
        "mode": format!("{:04o}", e.mode & 0o7777),
        "chunks": e.chunks.len(),
    })
}

fn snapshot_list(u: &mut Unlocked) -> Resp {
    let names = match u.repo.snapshot_names() {
        Ok(n) => n,
        Err(e) => return json_err(500, &e.to_string()),
    };
    let mut out = Vec::new();
    for n in names {
        match u.repo.load_snapshot(&n) {
            Ok(s) => out.push(json!({
                "name": s.name, "time": s.time, "host": s.host, "paths": s.paths, "tags": s.tags,
                "summary": s.summary, "warnings": s.warnings.len(),
            })),
            Err(e) => out.push(json!({ "name": n, "error": e.to_string() })),
        }
    }
    json_ok(json!({ "repo": u.root, "snapshots": out, "disk_bytes": u.repo.disk_usage() }))
}

fn tree(u: &mut Unlocked, q: &BTreeMap<String, String>) -> Resp {
    let snap_name = q.get("snap").cloned().unwrap_or_else(|| "latest".into());
    let dir = q.get("dir").cloned().unwrap_or_default();
    let (snap, index) = match u.snapshot(&snap_name) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let rows: Vec<Value> = if dir.is_empty() {
        // the backed-up roots
        snap.entries
            .iter()
            .filter(|e| snap.paths.contains(&e.display()))
            .map(entry_json)
            .collect()
    } else {
        index
            .get(&dir)
            .map(|ids| ids.iter().map(|&i| entry_json(&snap.entries[i])).collect())
            .unwrap_or_default()
    };
    json_ok(
        json!({ "snapshot": snap.name, "dir": dir, "entries": rows.into_iter().take(MAX_LIST).collect::<Vec<_>>() }),
    )
}

fn search(u: &mut Unlocked, q: &BTreeMap<String, String>) -> Resp {
    let needle = q.get("q").map(|s| s.to_lowercase()).unwrap_or_default();
    if needle.chars().count() < 2 {
        return json_err(400, "type at least 2 characters");
    }
    let snap_name = q.get("snap").cloned().unwrap_or_else(|| "latest".into());
    let (snap, _) = match u.snapshot(&snap_name) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let hits: Vec<Value> = snap
        .entries
        .iter()
        .filter(|e| {
            let p = e.display();
            Path::new(&p)
                .file_name()
                .is_some_and(|n| n.to_string_lossy().to_lowercase().contains(&needle))
        })
        .take(200)
        .map(entry_json)
        .collect();
    json_ok(json!({ "snapshot": snap.name, "query": needle, "entries": hits }))
}

fn download(u: &mut Unlocked, q: &BTreeMap<String, String>) -> Resp {
    let snap_name = q.get("snap").cloned().unwrap_or_else(|| "latest".into());
    let Some(path) = q.get("path").cloned() else {
        return json_err(400, "which file?");
    };
    let entry = {
        let (snap, _) = match u.snapshot(&snap_name) {
            Ok(x) => x,
            Err(r) => return r,
        };
        // A lookup in the snapshot's own list: nothing on disk is ever opened by path.
        match snap
            .entries
            .iter()
            .find(|e| e.kind == EntryKind::File && e.display() == path)
        {
            Some(e) => e.clone(),
            None => return json_err(404, "no such file in this snapshot"),
        }
    };
    if entry.size > MAX_DOWNLOAD {
        return json_err(
            413,
            &format!(
                "{} is too big for the browser; use mnemosyne restore",
                human_bytes(entry.size)
            ),
        );
    }
    let mut data = Vec::with_capacity(entry.size as usize);
    for id in &entry.chunks {
        match u.repo.get_chunk(id) {
            Ok(c) => data.extend_from_slice(&c),
            Err(e) => return json_err(500, &e.to_string()),
        }
    }
    let mut r = respond("application/octet-stream", 200, data);
    let name: String = Path::new(&path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".into())
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "._- ".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    if let Ok(h) = Header::from_bytes(
        &b"Content-Disposition"[..],
        format!("attachment; filename=\"{name}\"").as_bytes(),
    ) {
        r.add_header(h);
    }
    r
}

fn snapshot_diff(u: &mut Unlocked, q: &BTreeMap<String, String>) -> Resp {
    let (Some(a), Some(b)) = (q.get("a"), q.get("b")) else {
        return json_err(400, "give a and b");
    };
    let load = |u: &Unlocked, n: &str| -> Result<Snapshot, Resp> {
        let name = u
            .repo
            .resolve(n)
            .map_err(|e| json_err(404, &e.to_string()))?;
        u.repo
            .load_snapshot(&name)
            .map_err(|e| json_err(500, &e.to_string()))
    };
    let (old, new) = match (load(u, a), load(u, b)) {
        (Ok(x), Ok(y)) => (x, y),
        (Err(r), _) | (_, Err(r)) => return r,
    };
    let (changes, summary) = diff::diff(&old, &new, false);
    let total = changes.len();
    json_ok(json!({
        "old": old.name, "new": new.name, "summary": summary, "total": total,
        "changes": changes.into_iter().take(MAX_LIST).collect::<Vec<_>>(),
    }))
}

fn verify(u: &mut Unlocked, body: &Value) -> Resp {
    let pct = body
        .get("percent")
        .and_then(Value::as_u64)
        .unwrap_or(10)
        .clamp(1, 100) as u8;
    let mode = if pct == 100 {
        ReadData::All
    } else {
        ReadData::Percent(pct)
    };
    let started = Instant::now();
    let report = match maintain::check(&u.repo, mode, &mut |_| {}) {
        Ok(r) => r,
        Err(e) => return json_err(500, &e.to_string()),
    };
    let outcome = status::Outcome {
        time: crate::now_rfc3339(),
        ok: report.ok(),
        error: report
            .errors
            .first()
            .map(|e| format!("{} problem(s), first: {e}", report.errors.len())),
        bytes: report.bytes_read,
        duration_ms: started.elapsed().as_millis() as u64,
        read_data: Some(if pct == 100 {
            "all".into()
        } else {
            format!("{pct}%")
        }),
        ..Default::default()
    };
    let key = canonical(&u.root);
    status::update(&key, |s| s.last_check = Some(outcome));
    json_ok(json!({ "ok": report.ok(), "report": report }))
}

fn handle(req: &mut Request, st: &mut State) -> Resp {
    let host = header(req, "Host").unwrap_or_default();
    if host != format!("127.0.0.1:{}", st.port) && host != format!("localhost:{}", st.port) {
        return json_err(403, "forbidden host");
    }
    let url = req.url().to_string();
    let path = url.split('?').next().unwrap_or("/").to_string();
    let method = req.method().clone();
    match (&method, path.as_str()) {
        (Method::Get, "/") => {
            return respond(
                "text/html; charset=utf-8",
                200,
                INDEX_HTML.as_bytes().to_vec(),
            )
        }
        (Method::Get, "/app.js") => {
            return respond(
                "text/javascript; charset=utf-8",
                200,
                APP_JS.as_bytes().to_vec(),
            )
        }
        (Method::Get, "/app.css") => {
            return respond("text/css; charset=utf-8", 200, APP_CSS.as_bytes().to_vec())
        }
        (Method::Get, "/icon.svg") => {
            return respond("image/svg+xml", 200, ICON_SVG.as_bytes().to_vec())
        }
        _ => {}
    }
    if !path.starts_with("/api/") {
        return json_err(404, "not found");
    }
    if !same(
        &header(req, "X-Mnemosyne-Token").unwrap_or_default(),
        &st.token,
    ) {
        return json_err(401, "missing or wrong token");
    }
    let q = query(&url);
    match (&method, path.as_str()) {
        (Method::Get, "/api/ping") => {
            st.last_ping = Instant::now();
            json_ok(json!({ "ok": true }))
        }
        (Method::Get, "/api/overview") => json_ok(st.overview()),
        (Method::Post, "/api/unlock") => match body_json(req) {
            Ok(b) => st.unlock(&b),
            Err(e) => json_err(400, &e),
        },
        (Method::Post, "/api/lock") => {
            st.unlocked = None;
            json_ok(json!({ "ok": true }))
        }
        _ => {
            let body = if method == Method::Post {
                match body_json(req) {
                    Ok(b) => b,
                    Err(e) => return json_err(400, &e),
                }
            } else {
                Value::Null
            };
            let Some(u) = st.unlocked.as_mut() else {
                return json_err(423, "locked");
            };
            match (&method, path.as_str()) {
                (Method::Get, "/api/snapshots") => snapshot_list(u),
                (Method::Get, "/api/tree") => tree(u, &q),
                (Method::Get, "/api/search") => search(u, &q),
                (Method::Get, "/api/download") => download(u, &q),
                (Method::Get, "/api/diff") => snapshot_diff(u, &q),
                (Method::Post, "/api/verify") => verify(u, &body),
                _ => json_err(404, "not found"),
            }
        }
    }
}

pub struct Options {
    pub port: u16,
    pub open_window: bool,
    pub password_file: Option<PathBuf>,
}

pub fn run(opts: Options) -> Result<(), String> {
    let server =
        Server::http(("127.0.0.1", opts.port)).map_err(|e| format!("cannot listen: {e}"))?;
    let port = server
        .server_addr()
        .to_ip()
        .map(|a| a.port())
        .ok_or("no port")?;
    let mut st = State {
        token: new_token()?,
        port,
        unlocked: None,
        failed: 0,
        paused_until: None,
        last_ping: Instant::now(),
        password_file: opts.password_file,
    };
    let url = format!("http://127.0.0.1:{port}/#t={}", st.token);
    if opts.open_window {
        if let Err(e) = crate::desktop::open_app_window(&url) {
            eprintln!("{e}\nOpen this link yourself: {url}");
        }
    } else {
        eprintln!(
            "Mnemosyne is running: {url}\n(locks after {} idle minutes; Ctrl+C stops it)",
            IDLE_LOCK.as_secs() / 60
        );
    }
    let mut last_activity = Instant::now();
    loop {
        if st.unlocked.is_some() && last_activity.elapsed() >= IDLE_LOCK {
            st.unlocked = None; // the key is wiped when the Repo is dropped
        }
        if opts.open_window && st.last_ping.elapsed() >= HEARTBEAT {
            break; // the window was closed
        }
        let mut req = match server.recv_timeout(Duration::from_millis(500)) {
            Ok(Some(r)) => r,
            Ok(None) => continue,
            Err(e) => return Err(format!("server error: {e}")),
        };
        if req.url() != "/api/ping" {
            last_activity = Instant::now();
        }
        let resp = handle(&mut req, &mut st);
        let _ = req.respond(resp);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_decoding() {
        let q = query("/api/tree?snap=latest&dir=%2Fhome%2Fuser%2Fa%20b&x=%zz");
        assert_eq!(q["dir"], "/home/user/a b");
        assert_eq!(q["snap"], "latest");
        assert_eq!(q["x"], "%zz");
        assert_eq!(decode("caf%C3%A9+x"), "café x");
    }

    #[test]
    fn tokens_compare_in_constant_time() {
        assert!(same("abc", "abc") && !same("abc", "abd") && !same("abc", "ab"));
    }
}
