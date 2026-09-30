//! The job runner. Everything slow - bakes, deploys - is a job: a tokio task with a log
//! that streams to every browser watching it, a row in `jobs`, and a file on disk that
//! outlives the process.

use std::{collections::HashMap, path::PathBuf, sync::Arc};

use anyhow::Result;
use chrono::{Local, Utc};
use serde::Serialize;
use sqlx::SqlitePool;
use tokio::{
    io::AsyncWriteExt,
    sync::{broadcast, Mutex, RwLock},
};

/// What a browser receives while watching a job.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Event {
    Line { n: usize, text: String },
    /// The step running now and how far it got (None: no percentage to give). Not
    /// logged - a progress bar, not history. `done` clears it.
    Progress { label: String, pct: Option<f64>, detail: String, done: bool },
    Status { status: String, error: Option<String> },
}

/// The log tags of the PowerShell studio (Write-Log): lower case, five wide, so the
/// message column starts in the same place on every line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tag {
    Start,
    Get,
    Run,
    Info,
    Warn,
    Ok,
    Error,
    Debug,
    End,
}

impl Tag {
    pub fn shown(self) -> &'static str {
        match self {
            Tag::Start => "start",
            Tag::Get => "get",
            Tag::Run => "run",
            Tag::Info => "info",
            Tag::Warn => "warn",
            Tag::Ok => "o.k.",
            Tag::Error => "error",
            Tag::Debug => "debug",
            Tag::End => "end",
        }
    }
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct JobRow {
    pub id: String,
    pub kind: String,
    pub title: String,
    pub status: String,
    pub created_by: String,
    pub params: String,
    pub error: Option<String>,
    pub created_at: String,
    pub started_at: Option<String>,
    pub ended_at: Option<String>,
}

/// The handle a job's body writes through.
#[derive(Clone)]
pub struct JobLog {
    live: Arc<Live>,
}

struct Live {
    /// Lines so far and the file, under one lock so a new watcher's snapshot and its
    /// subscription never miss or double a line.
    inner: Mutex<LiveInner>,
    tx: broadcast::Sender<Event>,
    /// Keeps background lines (line_now) in the order they were given.
    order: Arc<Mutex<()>>,
    /// The last progress event, for a browser that starts watching mid-step.
    progress: std::sync::Mutex<Option<Event>>,
}

struct LiveInner {
    lines: Vec<String>,
    file: tokio::fs::File,
}

impl JobLog {
    /// Same layout as the PowerShell logs: date and time, the tag, the message.
    pub async fn tag(&self, tag: Tag, text: impl Into<String>) {
        let text = format!("{} [ {:<5} ] {}", Local::now().format("%Y-%m-%d %H:%M:%S"), tag.shown(), text.into());
        let mut inner = self.live.inner.lock().await;
        let _ = inner.file.write_all(format!("{text}\n").as_bytes()).await;
        let n = inner.lines.len();
        inner.lines.push(text.clone());
        let _ = self.live.tx.send(Event::Line { n, text });
    }

    pub async fn line(&self, text: impl Into<String>) {
        self.tag(Tag::Info, text).await
    }
    pub async fn get(&self, text: impl Into<String>) {
        self.tag(Tag::Get, text).await
    }
    pub async fn run(&self, text: impl Into<String>) {
        self.tag(Tag::Run, text).await
    }
    pub async fn warn(&self, text: impl Into<String>) {
        self.tag(Tag::Warn, text).await
    }
    pub async fn ok(&self, text: impl Into<String>) {
        self.tag(Tag::Ok, text).await
    }
    pub async fn debug(&self, text: impl Into<String>) {
        self.tag(Tag::Debug, text).await
    }

    /// For code that cannot await (a callback): the line is written in the background,
    /// in order with the others.
    pub fn tag_now(&self, tag: Tag, text: impl Into<String>) {
        let this = self.clone();
        let text = text.into();
        let order = self.live.order.clone();
        tokio::spawn(async move {
            let _turn = order.lock().await;
            this.tag(tag, text).await;
        });
    }

    /// The progress bar: what runs now, how far (0-100) when that is known.
    pub fn progress(&self, label: impl Into<String>, pct: Option<f64>, detail: impl Into<String>) {
        let ev = Event::Progress { label: label.into(), pct, detail: detail.into(), done: false };
        *self.live.progress.lock().unwrap() = Some(ev.clone());
        let _ = self.live.tx.send(ev);
    }

    pub fn progress_done(&self) {
        let ev = Event::Progress { label: String::new(), pct: None, detail: String::new(), done: true };
        *self.live.progress.lock().unwrap() = None;
        let _ = self.live.tx.send(ev);
    }
}

pub type Watch = (Vec<String>, Option<Event>, Option<broadcast::Receiver<Event>>);

#[derive(Clone)]
pub struct Jobs {
    db: SqlitePool,
    dir: PathBuf,
    running: Arc<RwLock<HashMap<String, Arc<Live>>>>,
}

impl Jobs {
    /// A job that was running when the process stopped is not running any more.
    pub async fn new(db: SqlitePool, dir: PathBuf) -> Result<Self> {
        tokio::fs::create_dir_all(&dir).await?;
        sqlx::query(
            "UPDATE jobs SET status = 'interrupted', ended_at = ?, \
             error = 'the studio stopped while this job ran' \
             WHERE status IN ('queued', 'running')",
        )
        .bind(now())
        .execute(&db)
        .await?;
        Ok(Self { db, dir, running: Default::default() })
    }

    /// Records the job and starts it. Returns its id at once; the work runs on.
    pub async fn spawn<F, Fut>(
        &self,
        kind: &str,
        title: &str,
        created_by: &str,
        params: serde_json::Value,
        body: F,
    ) -> Result<String>
    where
        F: FnOnce(JobLog) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO jobs (id, kind, title, status, created_by, params, created_at, started_at) \
             VALUES (?, ?, ?, 'running', ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(kind)
        .bind(title)
        .bind(created_by)
        .bind(params.to_string())
        .bind(now())
        .bind(now())
        .execute(&self.db)
        .await?;

        let file = tokio::fs::File::create(self.log_path(&id)).await?;
        let (tx, _) = broadcast::channel(8192);
        let live = Arc::new(Live {
            inner: Mutex::new(LiveInner { lines: Vec::new(), file }),
            tx,
            order: Arc::new(Mutex::new(())),
            progress: std::sync::Mutex::new(None),
        });
        self.running.write().await.insert(id.clone(), live.clone());

        let this = self.clone();
        let job_id = id.clone();
        let job_title = title.to_owned();
        tokio::spawn(async move {
            let log = JobLog { live: live.clone() };
            log.tag(Tag::Start, &job_title).await;
            // A panic in the body must still end the job, so run it as its own task.
            let outcome = tokio::spawn(body(log.clone())).await;
            let (status, error) = match outcome {
                Ok(Ok(())) => ("succeeded", None),
                Ok(Err(e)) => ("failed", Some(format!("{e:#}"))),
                Err(e) => ("failed", Some(format!("job crashed: {e}"))),
            };
            log.progress_done();
            match &error {
                Some(e) => log.tag(Tag::Error, e).await,
                None => log.tag(Tag::End, format!("{job_title}: done")).await,
            }
            let _ = sqlx::query("UPDATE jobs SET status = ?, error = ?, ended_at = ? WHERE id = ?")
                .bind(status)
                .bind(&error)
                .bind(now())
                .bind(&job_id)
                .execute(&this.db)
                .await;
            {
                let _guard = live.inner.lock().await;
                let _ = live.tx.send(Event::Status { status: status.into(), error });
            }
            this.running.write().await.remove(&job_id);
        });
        Ok(id)
    }

    pub async fn list(&self, limit: i64) -> Result<Vec<JobRow>> {
        Ok(sqlx::query_as("SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?")
            .bind(limit)
            .fetch_all(&self.db)
            .await?)
    }

    pub async fn get(&self, id: &str) -> Result<Option<JobRow>> {
        Ok(sqlx::query_as("SELECT * FROM jobs WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.db)
            .await?)
    }

    /// Everything logged so far, the current progress, and - while the job runs - a feed
    /// of what comes next.
    pub async fn watch(&self, id: &str) -> Result<Watch> {
        if let Some(live) = self.running.read().await.get(id).cloned() {
            let inner = live.inner.lock().await;
            let progress = live.progress.lock().unwrap().clone();
            return Ok((inner.lines.clone(), progress, Some(live.tx.subscribe())));
        }
        let text = tokio::fs::read_to_string(self.log_path(id)).await.unwrap_or_default();
        Ok((text.lines().map(str::to_owned).collect(), None, None))
    }

    fn log_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.log"))
    }
}

fn now() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
