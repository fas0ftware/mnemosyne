use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use mnemosyne::maintain::{self, Policy, ReadData};
use mnemosyne::repo::{Lock, Repo};
use mnemosyne::snapshot::EntryKind;
use mnemosyne::status::{self, Outcome};
use mnemosyne::{backup, human_bytes, restore, Error, Result};

#[derive(Parser)]
#[command(
    name = "mnemosyne",
    version,
    about = "Encrypted, deduplicating backups that test their own restores"
)]
struct Cli {
    /// Repository directory
    #[arg(short, long, global = true, env = "MNEMOSYNE_REPO")]
    repo: Option<PathBuf>,
    /// Read the password from this file (mode 600) instead of asking; for timers
    #[arg(long, global = true, env = "MNEMOSYNE_PASSWORD_FILE")]
    password_file: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a repository (asks for a new password)
    Init {
        /// Also store the password in this file (mode 600) so timers can run backups
        #[arg(long)]
        save_password: Option<PathBuf>,
    },
    /// Back up files and directories
    Backup {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Glob to skip: a name anywhere (node_modules, *.pyc) or a path (/home/*/Downloads)
        #[arg(short, long)]
        exclude: Vec<String>,
        /// Read more exclude patterns from a file, one per line (# comments)
        #[arg(long)]
        exclude_file: Vec<PathBuf>,
        /// Skip the contents of directories marked with a CACHEDIR.TAG
        #[arg(long)]
        exclude_caches: bool,
        #[arg(long)]
        tag: Vec<String>,
        /// Print every file that is read
        #[arg(short, long)]
        verbose: bool,
    },
    /// List snapshots
    Snapshots {
        #[arg(long)]
        json: bool,
    },
    /// List the files of a snapshot
    Ls {
        /// Snapshot name, a unique part of it, or "latest"
        snapshot: String,
        /// Only paths under this one
        path: Option<PathBuf>,
    },
    /// What changed between two snapshots (by chunk ids; nothing is decrypted but the lists)
    Diff {
        /// Older snapshot (name, unique part of it)
        old: String,
        /// Newer snapshot (default: latest)
        #[arg(default_value = "latest")]
        new: String,
        /// Also list files whose mode or modification time changed
        #[arg(long)]
        metadata: bool,
        #[arg(long)]
        json: bool,
    },
    /// Restore a snapshot into a directory
    Restore {
        snapshot: String,
        #[arg(short, long)]
        target: PathBuf,
        /// Only these paths (absolute, as listed by `ls`)
        #[arg(short, long)]
        include: Vec<PathBuf>,
        /// Replace files that already exist in the target
        #[arg(long)]
        overwrite: bool,
    },
    /// Verify the repository; --read-data decrypts and verifies every chunk
    Check {
        #[arg(long, conflicts_with = "read_data_subset")]
        read_data: bool,
        /// Verify this percentage of chunks, picked at random
        #[arg(long, value_parser = clap::value_parser!(u8).range(1..=100))]
        read_data_subset: Option<u8>,
    },
    /// Delete snapshots that the keep rules do not keep
    Forget {
        #[arg(long, default_value_t = 0)]
        keep_last: usize,
        #[arg(long, default_value_t = 0)]
        keep_daily: usize,
        #[arg(long, default_value_t = 0)]
        keep_weekly: usize,
        #[arg(long, default_value_t = 0)]
        keep_monthly: usize,
        #[arg(long, default_value_t = 0)]
        keep_yearly: usize,
        /// Then delete the data no snapshot uses any more
        #[arg(long)]
        prune: bool,
        #[arg(short = 'n', long)]
        dry_run: bool,
    },
    /// Delete data that no snapshot uses
    Prune {
        #[arg(short = 'n', long)]
        dry_run: bool,
    },
    /// Change the repository password
    Passwd,
    /// Remove a lock left behind by a crashed run
    Unlock,
    /// Repository size and snapshot count
    Stats,
    /// Open the backups in a window: browse, compare, verify, download a file (local only)
    App {
        /// Port on 127.0.0.1 (0 = any free port)
        #[arg(long, default_value_t = 0)]
        port: u16,
        /// Do not open a window; print the link instead
        #[arg(long)]
        no_window: bool,
    },
    /// Put Mnemosyne into the application menu
    InstallApp,
    /// Show the last backup and check of every repository (no password needed)
    Status {
        #[arg(long)]
        json: bool,
    },
}

fn read_password(file: &Option<PathBuf>, prompt: &str) -> Result<Zeroizing<String>> {
    if let Some(path) = file {
        let meta =
            fs::metadata(path).map_err(|e| Error::Usage(format!("{}: {e}", path.display())))?;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(Error::Usage(format!(
                "{} can be read by other users; run: chmod 600 {}",
                path.display(),
                path.display()
            )));
        }
        let text = Zeroizing::new(fs::read_to_string(path)?);
        return Ok(Zeroizing::new(
            text.trim_end_matches(['\n', '\r']).to_string(),
        ));
    }
    rpassword::prompt_password(prompt)
        .map(Zeroizing::new)
        .map_err(|e| {
            Error::Usage(format!(
                "cannot ask for the password ({e}); use --password-file"
            ))
        })
}

fn repo_path(cli: &Cli) -> Result<PathBuf> {
    cli.repo.clone().ok_or_else(|| {
        Error::Usage("which repository? give --repo DIR or set MNEMOSYNE_REPO".into())
    })
}

fn open(cli: &Cli) -> Result<Repo> {
    let root = repo_path(cli)?;
    let pw = read_password(&cli.password_file, "Repository password: ")?;
    Repo::open(&root, &pw)
}

fn status_key(repo: &Repo) -> String {
    path_key(&repo.root)
}

fn path_key(root: &std::path::Path) -> String {
    fs::canonicalize(root)
        .unwrap_or_else(|_| root.to_path_buf())
        .display()
        .to_string()
}

/// Open for a backup or check, recording a failure to open (disk not mounted, wrong
/// password file) in the status file too: a dashboard must see that, not old good news.
fn open_recorded(cli: &Cli, check: bool) -> Result<Repo> {
    open(cli).inspect_err(|e| {
        if let Ok(root) = repo_path(cli) {
            let outcome = Outcome {
                time: mnemosyne::now_rfc3339(),
                ok: false,
                error: Some(e.to_string()),
                ..Default::default()
            };
            status::update(&path_key(&root), |st| {
                if check {
                    st.last_check = Some(outcome);
                } else {
                    st.last_backup = Some(outcome);
                }
            });
        }
    })
}

fn exclude_patterns(exclude: &[String], files: &[PathBuf]) -> Result<Vec<String>> {
    let mut out = exclude.to_vec();
    for f in files {
        let text =
            fs::read_to_string(f).map_err(|e| Error::Usage(format!("{}: {e}", f.display())))?;
        out.extend(
            text.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(String::from),
        );
    }
    Ok(out)
}

fn print_table(rows: &[Vec<String>]) {
    let widths: Vec<usize> = (0..rows[0].len())
        .map(|c| rows.iter().map(|r| r[c].chars().count()).max().unwrap_or(0))
        .collect();
    for r in rows {
        let line: Vec<String> = r
            .iter()
            .zip(&widths)
            .map(|(cell, w)| format!("{cell:<w$}"))
            .collect();
        println!("{}", line.join("  ").trim_end());
    }
}

fn run(cli: Cli) -> Result<()> {
    match &cli.command {
        Command::Init { save_password } => {
            let root = repo_path(&cli)?;
            let pw = match &cli.password_file {
                Some(_) => read_password(&cli.password_file, "")?,
                None => {
                    eprintln!(
                        "Choose the repository password. Without it the backups cannot be read:"
                    );
                    eprintln!("write it down somewhere that is not on this computer.");
                    let a = read_password(&None, "New password: ")?;
                    mnemosyne::repo::check_password_strength(&a)?;
                    let b = read_password(&None, "Repeat: ")?;
                    if *a != *b {
                        return Err(Error::Usage("the passwords differ".into()));
                    }
                    a
                }
            };
            let repo = Repo::init(&root, &pw)?;
            if let Some(path) = save_password {
                if let Some(dir) = path.parent() {
                    fs::create_dir_all(dir)?;
                }
                let mut f = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
                    .map_err(|e| Error::Usage(format!("{}: {e}", path.display())))?;
                f.write_all(pw.as_bytes())?;
                println!("Password saved to {} (mode 600)", path.display());
            }
            println!(
                "Created repository {} (id {})",
                root.display(),
                &repo.id[..8]
            );
        }
        Command::Backup {
            paths,
            exclude,
            exclude_file,
            exclude_caches,
            tag,
            verbose,
        } => {
            let repo = open_recorded(&cli, false)?;
            let key = status_key(&repo);
            let opts = backup::Options {
                excludes: exclude_patterns(exclude, exclude_file)?,
                exclude_caches: *exclude_caches,
                tags: tag.clone(),
            };
            let verbose = *verbose;
            let started = Instant::now();
            let result = backup::backup(&repo, paths, &opts, &mut |line| {
                if verbose || line.starts_with("warning") {
                    eprintln!("{line}");
                }
            });
            match result {
                Ok(snap) => {
                    let s = &snap.summary;
                    println!(
                        "snapshot {}: {} files, {} dirs, {} ({} read, {} added)",
                        snap.name,
                        s.files,
                        s.dirs,
                        human_bytes(s.bytes),
                        s.files_read,
                        human_bytes(s.added_bytes)
                    );
                    if s.skipped > 0 {
                        println!("{} item(s) skipped, see the warnings above", s.skipped);
                    }
                    let outcome = Outcome {
                        time: snap.time.clone(),
                        ok: true,
                        snapshot: Some(snap.name.clone()),
                        files: s.files,
                        bytes: s.bytes,
                        added_bytes: s.added_bytes,
                        warnings: s.skipped,
                        duration_ms: s.duration_ms,
                        ..Default::default()
                    };
                    let (count, size) = (
                        repo.snapshot_names().map(|n| n.len()).unwrap_or(0),
                        repo.disk_usage(),
                    );
                    status::update(&key, |st| {
                        st.last_backup = Some(outcome.clone());
                        st.last_good_backup = Some(outcome);
                        st.snapshots = count;
                        st.repo_bytes = size;
                    });
                }
                Err(e) => {
                    let outcome = Outcome {
                        time: mnemosyne::now_rfc3339(),
                        ok: false,
                        error: Some(e.to_string()),
                        duration_ms: started.elapsed().as_millis() as u64,
                        ..Default::default()
                    };
                    status::update(&key, |st| st.last_backup = Some(outcome));
                    return Err(e);
                }
            }
        }
        Command::Snapshots { json } => {
            let repo = open(&cli)?;
            let mut list = vec![];
            for name in repo.snapshot_names()? {
                let mut s = repo.load_snapshot(&name)?;
                s.entries.clear();
                list.push(s);
            }
            if *json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&list).map_err(|e| Error::Usage(e.to_string()))?
                );
            } else if list.is_empty() {
                println!("no snapshots yet");
            } else {
                let mut rows = vec![vec![
                    "NAME".into(),
                    "TIME".into(),
                    "HOST".into(),
                    "FILES".into(),
                    "SIZE".into(),
                    "PATHS".into(),
                ]];
                for s in &list {
                    rows.push(vec![
                        s.name.clone(),
                        s.time.clone(),
                        s.host.clone(),
                        s.summary.files.to_string(),
                        human_bytes(s.summary.bytes),
                        s.paths.join(", "),
                    ]);
                }
                print_table(&rows);
            }
        }
        Command::Ls { snapshot, path } => {
            let repo = open(&cli)?;
            let snap = repo.load_snapshot(&repo.resolve(snapshot)?)?;
            for e in &snap.entries {
                let p = e.path()?;
                if path.as_ref().is_some_and(|w| !p.starts_with(w)) {
                    continue;
                }
                let kind = match e.kind {
                    EntryKind::Dir => 'd',
                    EntryKind::File => '-',
                    EntryKind::Symlink => 'l',
                };
                println!(
                    "{kind}{:04o} {:>10}  {}",
                    e.mode & 0o7777,
                    e.size,
                    p.display()
                );
            }
        }
        Command::Diff {
            old,
            new,
            metadata,
            json,
        } => {
            let repo = open(&cli)?;
            let a = repo.load_snapshot(&repo.resolve(old)?)?;
            let b = repo.load_snapshot(&repo.resolve(new)?)?;
            let (changes, s) = mnemosyne::diff::diff(&a, &b, *metadata);
            if *json {
                let out = serde_json::json!({"old": a.name, "new": b.name, "summary": s, "changes": changes});
                println!(
                    "{}",
                    serde_json::to_string_pretty(&out).map_err(|e| Error::Usage(e.to_string()))?
                );
                return Ok(());
            }
            for c in &changes {
                let size = match c.kind {
                    mnemosyne::diff::Kind::Modified => {
                        format!("{} -> {}", human_bytes(c.old_size), human_bytes(c.new_size))
                    }
                    mnemosyne::diff::Kind::Removed => human_bytes(c.old_size),
                    _ => human_bytes(c.new_size),
                };
                let suffix = if c.entry == "file" {
                    format!("  ({size})")
                } else {
                    format!("  [{}]", c.entry)
                };
                println!("{} {}{}", c.kind.symbol(), c.path, suffix);
            }
            let sign = if s.bytes_delta < 0 { "-" } else { "+" };
            println!(
                "{} -> {}: {} added, {} removed, {} modified, {} replaced{}, {}{}",
                a.name,
                b.name,
                s.added,
                s.removed,
                s.modified,
                s.replaced,
                if *metadata {
                    format!(", {} metadata only", s.metadata)
                } else {
                    String::new()
                },
                sign,
                human_bytes(s.bytes_delta.unsigned_abs())
            );
        }
        Command::Restore {
            snapshot,
            target,
            include,
            overwrite,
        } => {
            let repo = open(&cli)?;
            let snap = repo.load_snapshot(&repo.resolve(snapshot)?)?;
            let opts = restore::Options {
                include: include.clone(),
                overwrite: *overwrite,
            };
            let r = restore::restore(&repo, &snap, target, &opts, &mut |l| eprintln!("{l}"))?;
            println!(
                "restored {} files, {} dirs, {} links ({}) into {}{}",
                r.files,
                r.dirs,
                r.symlinks,
                human_bytes(r.bytes),
                target.display(),
                if r.skipped_existing > 0 {
                    format!(
                        "; {} existing kept (--overwrite replaces them)",
                        r.skipped_existing
                    )
                } else {
                    String::new()
                }
            );
        }
        Command::Check {
            read_data,
            read_data_subset,
        } => {
            let repo = open_recorded(&cli, true)?;
            let mode = match (read_data, read_data_subset) {
                (true, _) => ReadData::All,
                (_, Some(p)) => ReadData::Percent(*p),
                _ => ReadData::None,
            };
            let started = Instant::now();
            let report = maintain::check(&repo, mode, &mut |l| eprintln!("{l}"))?;
            for e in &report.errors {
                eprintln!("error: {e}");
            }
            println!(
                "{} snapshots, {} chunks used, {} stored ({} unused), {} chunks read and verified ({})",
                report.snapshots, report.chunks_referenced, report.chunks_stored, report.chunks_unused, report.chunks_read, human_bytes(report.bytes_read)
            );
            let label = match mode {
                ReadData::None => "structure".to_string(),
                ReadData::All => "all".to_string(),
                ReadData::Percent(p) => format!("{p}%"),
            };
            let outcome = Outcome {
                time: mnemosyne::now_rfc3339(),
                ok: report.ok(),
                error: report
                    .errors
                    .first()
                    .map(|e| format!("{} problem(s), first: {e}", report.errors.len())),
                bytes: report.bytes_read,
                duration_ms: started.elapsed().as_millis() as u64,
                read_data: Some(label),
                ..Default::default()
            };
            let (count, size) = (report.snapshots, repo.disk_usage());
            status::update(&status_key(&repo), |st| {
                st.last_check = Some(outcome);
                st.snapshots = count;
                st.repo_bytes = size;
            });
            if !report.ok() {
                return Err(Error::Corrupt(format!(
                    "{} problem(s) found",
                    report.errors.len()
                )));
            }
            println!("no problems found");
        }
        Command::Forget {
            keep_last,
            keep_daily,
            keep_weekly,
            keep_monthly,
            keep_yearly,
            prune,
            dry_run,
        } => {
            let repo = open(&cli)?;
            let policy = Policy {
                last: *keep_last,
                daily: *keep_daily,
                weekly: *keep_weekly,
                monthly: *keep_monthly,
                yearly: *keep_yearly,
            };
            let (keep, drop) = maintain::forget(&repo, policy, *dry_run)?;
            let verb = if *dry_run { "would remove" } else { "removed" };
            for n in &drop {
                println!("{verb} {n}");
            }
            println!("{} kept, {} {verb}", keep.len(), drop.len());
            if *prune {
                let r = maintain::prune(&repo, *dry_run)?;
                println!(
                    "prune: {} chunks, {} {}",
                    r.chunks_removed,
                    human_bytes(r.bytes_freed),
                    if *dry_run { "would be freed" } else { "freed" }
                );
            }
            let (count, size) = (repo.snapshot_names()?.len(), repo.disk_usage());
            status::update(&status_key(&repo), |st| {
                st.snapshots = count;
                st.repo_bytes = size;
            });
        }
        Command::Prune { dry_run } => {
            let repo = open(&cli)?;
            let r = maintain::prune(&repo, *dry_run)?;
            println!(
                "{} unused chunks, {} {}",
                r.chunks_removed,
                human_bytes(r.bytes_freed),
                if *dry_run { "would be freed" } else { "freed" }
            );
        }
        Command::Passwd => {
            let repo = open(&cli)?;
            let _lock = Lock::acquire(&repo, "passwd")?;
            let a = read_password(&None, "New password: ")?;
            mnemosyne::repo::check_password_strength(&a)?;
            let b = read_password(&None, "Repeat: ")?;
            if *a != *b {
                return Err(Error::Usage("the passwords differ".into()));
            }
            repo.change_password(&a)?;
            println!("Password changed. Update any --password-file used by timers.");
        }
        Command::Unlock => {
            let repo = open(&cli)?;
            println!(
                "{}",
                if Lock::force_remove(&repo)? {
                    "lock removed"
                } else {
                    "the repository was not locked"
                }
            );
        }
        Command::Stats => {
            let repo = open(&cli)?;
            let names = repo.snapshot_names()?;
            println!("repository  {}", repo.root.display());
            println!("id          {}", repo.id);
            println!("snapshots   {}", names.len());
            println!("chunks      {}", repo.chunk_ids()?.len());
            println!("size        {}", human_bytes(repo.disk_usage()));
        }
        Command::App { port, no_window } => {
            // The saved password file (as used by the timers) can unlock it with one click.
            let file = cli.password_file.clone().or_else(|| {
                std::env::var_os("HOME")
                    .map(|h| PathBuf::from(h).join(".config/mnemosyne/password"))
            });
            mnemosyne::app::run(mnemosyne::app::Options {
                port: *port,
                open_window: !*no_window,
                password_file: file,
            })
            .map_err(Error::Usage)?;
        }
        Command::InstallApp => {
            mnemosyne::desktop::install_app().map_err(Error::Usage)?;
        }
        Command::Status { json } => {
            let st = status::load();
            if *json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&st).map_err(|e| Error::Usage(e.to_string()))?
                );
                return Ok(());
            }
            if st.repos.is_empty() {
                println!("no backups recorded yet");
            }
            for (repo, s) in &st.repos {
                println!("{repo}");
                let show = |label: &str, o: &Option<Outcome>| match o {
                    Some(o) => println!(
                        "  {label:<12} {}  {}{}",
                        o.time,
                        if o.ok { "ok" } else { "FAILED" },
                        o.error
                            .as_ref()
                            .map(|e| format!(": {e}"))
                            .unwrap_or_default()
                    ),
                    None => println!("  {label:<12} never"),
                };
                show("last backup", &s.last_backup);
                show("last check", &s.last_check);
                println!(
                    "  {:<12} {} snapshots, {}",
                    "repository",
                    s.snapshots,
                    human_bytes(s.repo_bytes)
                );
            }
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mnemosyne: {e}");
            ExitCode::from(match e {
                Error::Usage(_) => 2,
                Error::WrongPassword => 3,
                Error::Locked(_) => 4,
                Error::Corrupt(_) => 5,
                _ => 1,
            })
        }
    }
}
