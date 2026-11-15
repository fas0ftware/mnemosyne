//! End to end through the real binary, with the real (default) key derivation.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Env {
    dir: tempfile::TempDir,
}

impl Env {
    fn new() -> Env {
        let env = Env {
            dir: tempfile::tempdir().unwrap(),
        };
        fs::write(env.pw(), "correct horse battery").unwrap();
        fs::set_permissions(env.pw(), fs::Permissions::from_mode(0o600)).unwrap();
        env
    }
    fn p(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }
    fn pw(&self) -> PathBuf {
        self.p("pw")
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_mnemosyne"))
            .args(args)
            .env("MNEMOSYNE_REPO", self.p("repo"))
            .env("MNEMOSYNE_PASSWORD_FILE", self.pw())
            .env("MNEMOSYNE_STATUS", self.p("status.json"))
            .output()
            .unwrap()
    }
    fn ok(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }
}

fn tree(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = vec![];
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            let rel = p.strip_prefix(root).unwrap().display().to_string();
            let m = fs::symlink_metadata(&p).unwrap();
            if m.is_dir() {
                stack.push(p);
                out.push((rel, vec![]));
            } else if m.file_type().is_symlink() {
                out.push((
                    rel,
                    fs::read_link(&p)
                        .unwrap()
                        .display()
                        .to_string()
                        .into_bytes(),
                ));
            } else {
                out.push((rel, fs::read(&p).unwrap()));
            }
        }
    }
    out.sort();
    out
}

#[test]
fn full_cycle() {
    let env = Env::new();
    let src = env.p("src");
    fs::create_dir_all(src.join("project/node_modules/pkg")).unwrap();
    fs::create_dir_all(src.join("project/src")).unwrap();
    fs::write(src.join("project/src/main.rs"), "fn main() {}\n").unwrap();
    fs::write(src.join("project/node_modules/pkg/index.js"), "x").unwrap();
    let blob: Vec<u8> = (0..5_000_000u32)
        .map(|i| (i.wrapping_mul(0x9E3779B1) >> 24) as u8)
        .collect();
    fs::write(src.join("project/data.bin"), &blob).unwrap();
    std::os::unix::fs::symlink("src/main.rs", src.join("project/link")).unwrap();

    assert!(env.ok(&["init"]).contains("Created repository"));
    let first = env.ok(&["backup", src.to_str().unwrap(), "--exclude", "node_modules"]);
    assert!(first.contains("2 files, 3 dirs"), "{first}");
    let second = env.ok(&["backup", src.to_str().unwrap(), "--exclude", "node_modules"]);
    assert!(second.contains("0 read, 0 B added"), "{second}");

    let list = env.ok(&["snapshots"]);
    assert_eq!(list.lines().count(), 3, "{list}");
    let ls = env.ok(&["ls", "latest"]);
    assert!(ls.contains("main.rs") && !ls.contains("node_modules"));

    let out = env.p("out");
    env.ok(&["restore", "latest", "--target", out.to_str().unwrap()]);
    let canon = fs::canonicalize(&src).unwrap();
    let restored = out.join(canon.strip_prefix("/").unwrap());
    let mut want = tree(&src);
    want.retain(|(p, _)| !p.contains("node_modules"));
    assert_eq!(tree(&restored), want);

    assert!(env
        .ok(&["check", "--read-data"])
        .contains("no problems found"));
    let status: serde_json::Value =
        serde_json::from_slice(&fs::read(env.p("status.json")).unwrap()).unwrap();
    let repo_status = status["repos"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap();
    assert_eq!(repo_status["last_backup"]["ok"], true);
    assert_eq!(repo_status["last_check"]["read_data"], "all");
    assert_eq!(repo_status["snapshots"], 2);

    let forget = env.ok(&["forget", "--keep-last", "1", "--prune"]);
    assert!(forget.contains("1 kept, 1 removed"), "{forget}");
    assert!(env
        .ok(&["check", "--read-data"])
        .contains("no problems found"));
}

#[test]
fn passwords_and_damage() {
    let env = Env::new();
    env.ok(&["init"]);

    fs::write(env.p("bad"), "not the password").unwrap();
    fs::set_permissions(env.p("bad"), fs::Permissions::from_mode(0o600)).unwrap();
    let out = env.run(&[
        "--password-file",
        env.p("bad").to_str().unwrap(),
        "snapshots",
    ]);
    assert_eq!(out.status.code(), Some(3), "wrong password exit code");

    fs::set_permissions(env.pw(), fs::Permissions::from_mode(0o644)).unwrap();
    let out = env.run(&["snapshots"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("chmod 600"));
    fs::set_permissions(env.pw(), fs::Permissions::from_mode(0o600)).unwrap();

    let src = env.p("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("f"), "important").unwrap();
    env.ok(&["backup", src.to_str().unwrap()]);
    // damage one stored chunk: the structure check passes, the data check does not
    let data = env.p("repo/data");
    let sub = fs::read_dir(&data).unwrap().next().unwrap().unwrap().path();
    let chunk = fs::read_dir(sub).unwrap().next().unwrap().unwrap().path();
    let mut bytes = fs::read(&chunk).unwrap();
    bytes[40] ^= 1;
    fs::write(&chunk, bytes).unwrap();
    assert!(env.run(&["check"]).status.success());
    let out = env.run(&["check", "--read-data"]);
    assert_eq!(out.status.code(), Some(5));
    let status = fs::read_to_string(env.p("status.json")).unwrap();
    assert!(status.contains("\"ok\": false"));
    // and a restore refuses to write damaged data
    let out = env.run(&[
        "restore",
        "latest",
        "--target",
        env.p("out").to_str().unwrap(),
    ]);
    assert!(!out.status.success());
}

#[test]
fn usage_errors() {
    let env = Env::new();
    let out = Command::new(env!("CARGO_BIN_EXE_mnemosyne"))
        .args(["snapshots"])
        .env_remove("MNEMOSYNE_REPO")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let out = env.run(&["snapshots"]);
    assert!(String::from_utf8_lossy(&out.stderr).contains("not a Mnemosyne repository"));
    // a backup into a repository that cannot be opened is recorded as failed
    assert!(!env
        .run(&["backup", env.p("pw").to_str().unwrap()])
        .status
        .success());
    let status = fs::read_to_string(env.p("status.json")).unwrap();
    assert!(
        status.contains("\"ok\": false") && status.contains("not a Mnemosyne repository"),
        "{status}"
    );
    env.ok(&["init"]);
    assert_eq!(
        env.run(&["init"]).status.code(),
        Some(2),
        "second init refused"
    );
    assert_eq!(
        env.run(&["forget"]).status.code(),
        Some(2),
        "empty policy refused"
    );
    assert!(env.ok(&["status"]).contains("never") || env.ok(&["status"]).contains("no backups"));
}
