//! `mnemosyne app` end to end: the real binary, raw HTTP on loopback.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command, Stdio};

struct App {
    child: Child,
    port: u16,
    token: String,
}

impl Drop for App {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start(dir: &std::path::Path) -> App {
    let mut child = Command::new(env!("CARGO_BIN_EXE_mnemosyne"))
        .args(["app", "--no-window"])
        .env("MNEMOSYNE_REPO", dir.join("repo"))
        .env("MNEMOSYNE_PASSWORD_FILE", dir.join("pw"))
        .env("MNEMOSYNE_STATUS", dir.join("status.json"))
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stderr.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    // "Mnemosyne is running: http://127.0.0.1:PORT/#t=TOKEN"
    let url = line
        .split_whitespace()
        .find(|w| w.starts_with("http://"))
        .unwrap()
        .to_string();
    let port = url
        .trim_start_matches("http://127.0.0.1:")
        .split('/')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let token = url.split("#t=").nth(1).unwrap().to_string();
    App { child, port, token }
}

fn http(
    app: &App,
    method: &str,
    path: &str,
    body: Option<&str>,
    token: bool,
    host: Option<&str>,
) -> (u16, Vec<u8>) {
    let mut s = TcpStream::connect(("127.0.0.1", app.port)).unwrap();
    let host = host
        .map(String::from)
        .unwrap_or_else(|| format!("127.0.0.1:{}", app.port));
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    if token {
        req += &format!("X-Mnemosyne-Token: {}\r\n", app.token);
    }
    if let Some(b) = body {
        req += &format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{b}",
            b.len()
        );
    } else {
        req += "\r\n";
    }
    s.write_all(req.as_bytes()).unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    let mut body = raw[split + 4..].to_vec();
    if head.to_lowercase().contains("transfer-encoding: chunked") {
        body = dechunk(&body);
    }
    (status, body)
}

fn dechunk(mut b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let end = b.windows(2).position(|w| w == b"\r\n").unwrap();
        let size =
            usize::from_str_radix(std::str::from_utf8(&b[..end]).unwrap().trim(), 16).unwrap();
        if size == 0 {
            return out;
        }
        out.extend_from_slice(&b[end + 2..end + 2 + size]);
        b = &b[end + 4 + size..];
    }
}

fn json(b: &[u8]) -> serde_json::Value {
    serde_json::from_slice(b).unwrap()
}

#[test]
fn browse_download_diff_verify_and_guards() {
    let d = tempfile::tempdir().unwrap();
    fs::write(d.path().join("pw"), "app password 12345").unwrap();
    fs::set_permissions(d.path().join("pw"), fs::Permissions::from_mode(0o600)).unwrap();
    let src = d.path().join("src");
    fs::create_dir_all(src.join("notes")).unwrap();
    let report: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    fs::write(src.join("notes/report.bin"), &report).unwrap();
    fs::write(src.join("todo.txt"), "first").unwrap();
    let cli = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_mnemosyne"))
            .args(args)
            .env("MNEMOSYNE_REPO", d.path().join("repo"))
            .env("MNEMOSYNE_PASSWORD_FILE", d.path().join("pw"))
            .env("MNEMOSYNE_STATUS", d.path().join("status.json"))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    cli(&["init"]);
    cli(&["backup", src.to_str().unwrap()]);
    fs::write(src.join("todo.txt"), "second, longer").unwrap();
    cli(&["backup", src.to_str().unwrap()]);
    let root = fs::canonicalize(&src).unwrap().display().to_string();
    let repo = fs::canonicalize(d.path().join("repo"))
        .unwrap()
        .display()
        .to_string();

    let app = start(d.path());
    // guards
    assert_eq!(
        http(&app, "GET", "/api/overview", None, false, None).0,
        401,
        "token required"
    );
    assert_eq!(
        http(
            &app,
            "GET",
            "/api/overview",
            None,
            true,
            Some("evil.example")
        )
        .0,
        403,
        "Host checked"
    );
    assert_eq!(
        http(&app, "GET", "/", None, false, None).0,
        200,
        "the page itself needs no token"
    );
    assert_eq!(
        http(&app, "GET", "/api/snapshots", None, true, None).0,
        423,
        "locked at start"
    );
    let o = json(&http(&app, "GET", "/api/overview", None, true, None).1);
    assert!(o["repos"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["path"] == repo));
    assert_eq!(o["password_file"], true);

    // wrong passwords pause unlocking
    let bad = format!(r#"{{"repo":"{repo}","password":"nope nope nope"}}"#);
    for _ in 0..5 {
        assert_eq!(
            http(&app, "POST", "/api/unlock", Some(&bad), true, None).0,
            401
        );
    }
    let good = format!(r#"{{"repo":"{repo}","password":"app password 12345"}}"#);
    assert_eq!(
        http(&app, "POST", "/api/unlock", Some(&good), true, None).0,
        429,
        "paused after 5 wrong"
    );
    let unknown = r#"{"repo":"/etc","password":"x"}"#;
    assert_eq!(
        http(&app, "POST", "/api/unlock", Some(unknown), true, None).0,
        429,
        "still paused"
    );
    drop(app);

    let app = start(d.path());
    let via_file = format!(r#"{{"repo":"{repo}","use_file":true}}"#);
    assert_eq!(
        http(&app, "POST", "/api/unlock", Some(&via_file), true, None).0,
        200
    );
    let snaps = json(&http(&app, "GET", "/api/snapshots", None, true, None).1);
    let names: Vec<String> = snaps["snapshots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(names.len(), 2);

    let top = json(&http(&app, "GET", "/api/tree?snap=latest", None, true, None).1);
    assert_eq!(top["entries"][0]["path"], root);
    let notes = format!("{root}/notes").replace('/', "%2F");
    let inside = json(
        &http(
            &app,
            "GET",
            &format!("/api/tree?snap=latest&dir={notes}"),
            None,
            true,
            None,
        )
        .1,
    );
    assert_eq!(inside["entries"][0]["name"], "report.bin");
    let found = json(
        &http(
            &app,
            "GET",
            "/api/search?snap=latest&q=REPO",
            None,
            true,
            None,
        )
        .1,
    );
    assert_eq!(
        found["entries"].as_array().unwrap().len(),
        1,
        "case-insensitive name search"
    );

    let file = format!("{root}/notes/report.bin").replace('/', "%2F");
    let (code, got) = http(
        &app,
        "GET",
        &format!("/api/download?snap=latest&path={file}"),
        None,
        true,
        None,
    );
    assert_eq!((code, got.len()), (200, report.len()));
    assert_eq!(
        got, report,
        "the downloaded file is byte for byte the original"
    );
    let (code, old) = http(
        &app,
        "GET",
        &format!(
            "/api/download?snap={}&path={}",
            names[0],
            format!("{root}/todo.txt").replace('/', "%2F")
        ),
        None,
        true,
        None,
    );
    assert_eq!(
        (code, old.as_slice()),
        (200, &b"first"[..]),
        "any snapshot, not only the latest"
    );
    let etc = "%2Fetc%2Fpasswd";
    assert_eq!(
        http(
            &app,
            "GET",
            &format!("/api/download?snap=latest&path={etc}"),
            None,
            true,
            None
        )
        .0,
        404,
        "only files in the snapshot"
    );

    let diff = json(
        &http(
            &app,
            "GET",
            &format!("/api/diff?a={}&b={}", names[0], names[1]),
            None,
            true,
            None,
        )
        .1,
    );
    assert_eq!(diff["summary"]["modified"], 1);
    assert_eq!(diff["changes"][0]["path"], format!("{root}/todo.txt"));

    let v = json(
        &http(
            &app,
            "POST",
            "/api/verify",
            Some(r#"{"percent":100}"#),
            true,
            None,
        )
        .1,
    );
    assert_eq!(v["ok"], true);
    assert!(v["report"]["chunks_read"].as_u64().unwrap() >= 2);
    let status = fs::read_to_string(d.path().join("status.json")).unwrap();
    assert!(
        status.contains("\"read_data\": \"all\""),
        "the check is recorded for dashboards"
    );

    assert_eq!(
        http(&app, "POST", "/api/lock", Some("{}"), true, None).0,
        200
    );
    assert_eq!(
        http(&app, "GET", "/api/snapshots", None, true, None).0,
        423,
        "locked again"
    );
}
