//! The log and its level. The level is a setting (the maintenance console's Debug tools),
//! read by the studio and the console alike and changed while they run: "" is the
//! recommended one. RUST_LOG, when set, wins over the setting.

use std::sync::OnceLock;

use tracing_subscriber::{prelude::*, reload, EnvFilter, Registry};

static HANDLE: OnceLock<reload::Handle<EnvFilter, Registry>> = OnceLock::new();

/// The levels the console offers, the recommended one first.
pub const LEVELS: [&str; 4] = ["info", "warn", "debug", "trace"];
pub const RECOMMENDED: &str = "info";

#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct LogSettings {
    /// One of LEVELS; empty is the recommended one.
    pub level: String,
}

impl LogSettings {
    pub fn effective(&self) -> &str {
        if LEVELS.contains(&self.level.as_str()) { &self.level } else { RECOMMENDED }
    }
}

/// The filter for a level: the studio's own lines at it, the chatty libraries held back.
fn filter(level: &str) -> EnvFilter {
    let spec = match level {
        "warn" => "warn",
        "debug" => "debug,sqlx=warn,hyper=info,hyper_util=info,reqwest=info,rustls=info,h2=info,tungstenite=info",
        "trace" => "trace,sqlx=info,hyper=info,hyper_util=info,rustls=info,h2=info,tungstenite=info",
        _ => "info,sqlx=warn",
    };
    EnvFilter::new(spec)
}

pub fn init() {
    let env = std::env::var("RUST_LOG").ok().filter(|v| !v.is_empty());
    let f = match &env {
        Some(v) => EnvFilter::new(v),
        None => filter(RECOMMENDED),
    };
    let (layer, handle) = reload::Layer::new(f);
    tracing_subscriber::registry().with(layer).with(tracing_subscriber::fmt::layer()).init();
    if env.is_none() {
        let _ = HANDLE.set(handle);
    }
}

/// Switches the running process to this level (no-op under RUST_LOG).
pub fn apply(level: &str) {
    if let Some(h) = HANDLE.get() {
        let _ = h.reload(filter(level));
    }
}
