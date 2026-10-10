//! The console's shell: a login shell on a pseudo-terminal, carried over a WebSocket to
//! xterm.js. The console runs as root, so the shell is root's. Every byte it shows is
//! recorded, one file per session.

use std::{
    io::{Read, Write},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::PathBuf,
    process::Stdio,
};

use anyhow::{bail, Context, Result};
use axum::extract::ws::{Message, WebSocket};

/// A pseudo-terminal pair with the shell on its far end.
struct Pty {
    master: std::fs::File,
    child: std::process::Child,
}

fn set_size(fd: i32, cols: u16, rows: u16) {
    let ws = libc::winsize { ws_row: rows.max(2), ws_col: cols.max(10), ws_xpixel: 0, ws_ypixel: 0 };
    // SAFETY: TIOCSWINSZ reads the winsize we pass; fd is the open master.
    unsafe {
        libc::ioctl(fd, libc::TIOCSWINSZ, &ws);
    }
}

fn spawn(cols: u16, rows: u16) -> Result<Pty> {
    let (mut master, mut slave) = (0, 0);
    // SAFETY: openpty fills both descriptors; the null pointers ask for defaults.
    if unsafe { libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null(), std::ptr::null()) } != 0 {
        bail!("openpty: {}", std::io::Error::last_os_error());
    }
    // SAFETY: both were just opened and are ours alone.
    let (master, slave) = unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
    set_size(master.as_raw_fd(), cols, rows);
    let shell = std::env::var("SHELL").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "/bin/bash".into());
    let mut cmd = std::process::Command::new(&shell);
    cmd.arg("-l")
        .env("TERM", "xterm-256color")
        .env("PVS_CONSOLE", "1")
        .stdin(Stdio::from(slave.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave));
    if let Some(home) = home_dir() {
        cmd.current_dir(&home).env("HOME", home);
    }
    use std::os::unix::process::CommandExt;
    // SAFETY: only async-signal-safe calls between fork and exec - a new session, with the
    // terminal on stdin as its controlling terminal.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = cmd.spawn().with_context(|| format!("starting {shell}"))?;
    Ok(Pty { master: std::fs::File::from(master), child })
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from).filter(|p| p.is_dir()).or_else(|| Some(PathBuf::from("/root")).filter(|p| p.is_dir()))
}

/// Where sessions are recorded: root's log folder in the container, the data folder in a
/// development run.
fn record_dir(data_dir: &std::path::Path) -> PathBuf {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 { PathBuf::from("/var/log/pve-vm-studio/console-shell") } else { data_dir.join("console-shell") }
}

/// Runs one session until either side closes. Input frames are text: "i" + keystrokes, or
/// "r<cols>x<rows>" for a resize. Output frames are binary, as the terminal wrote them.
pub async fn session(mut ws: WebSocket, data_dir: PathBuf, from: String, cols: u16, rows: u16) {
    let pty = match spawn(cols, rows) {
        Ok(p) => p,
        Err(e) => {
            let _ = ws.send(Message::Text(format!("\r\nThe shell did not start: {e:#}\r\n").into())).await;
            return;
        }
    };
    let dir = record_dir(&data_dir);
    let _ = std::fs::create_dir_all(&dir);
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    let stamp = chrono::Local::now().format("%Y-%m-%d_%H%M%S");
    let rec_path = dir.join(format!("{stamp}_{}.log", from.replace([':', '/'], "_")));
    let mut record = std::fs::OpenOptions::new().create(true).append(true).open(&rec_path).ok();
    tracing::info!("console: shell opened from {from}, recorded to {}", rec_path.display());

    let Pty { master, mut child } = pty;
    let master_fd = master.as_raw_fd();
    let mut reader = match master.try_clone() {
        Ok(r) => r,
        Err(e) => {
            let _ = ws.send(Message::Text(format!("\r\n{e}\r\n").into())).await;
            return;
        }
    };
    let mut writer = master;
    // The terminal's output, read on a thread of its own (a pty master blocks).
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    loop {
        tokio::select! {
            out = rx.recv() => match out {
                Some(bytes) => {
                    if let Some(r) = record.as_mut() {
                        let _ = r.write_all(&bytes);
                    }
                    if ws.send(Message::Binary(bytes.into())).await.is_err() {
                        break;
                    }
                }
                // The shell ended (exit, logout).
                None => break,
            },
            msg = ws.recv() => match msg {
                Some(Ok(Message::Text(t))) => {
                    let t = t.as_str();
                    if let Some(keys) = t.strip_prefix('i') {
                        if writer.write_all(keys.as_bytes()).is_err() {
                            break;
                        }
                    } else if let Some(size) = t.strip_prefix('r')
                        && let Some((c, r)) = size.split_once('x')
                        && let (Ok(c), Ok(r)) = (c.parse::<u16>(), r.parse::<u16>())
                    {
                        set_size(master_fd, c, r);
                    }
                }
                Some(Ok(Message::Binary(b))) => {
                    if writer.write_all(&b).is_err() {
                        break;
                    }
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                Some(Ok(_)) => {}
            },
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    let _ = ws.send(Message::Close(None)).await;
    tracing::info!("console: shell from {from} closed");
}
