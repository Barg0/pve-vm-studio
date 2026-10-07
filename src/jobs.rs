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
    /// `step`: how far the current stage got (0-100) - the running step's own percentage,
    /// where `pct` is the whole job's.
    Progress { label: String, pct: Option<f64>, step: Option<f64>, detail: String, done: bool },
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
    /// Who asked the job to stop; the job ends at its next check (JobLog::check_abort).
    abort: std::sync::Mutex<Option<String>>,
    /// <id>.steps: when each progress stage began - the mail's step times.
    steps: PathBuf,
}

struct LiveInner {
    lines: Vec<String>,
    file: tokio::fs::File,
}

impl JobLog {
    /// Err once someone pressed Abort - the long waits call this, so the job fails the normal
    /// way and its own cleanup (bake and worker VMs) still runs.
    pub fn check_abort(&self) -> Result<()> {
        match self.live.abort.lock().unwrap().as_ref() {
            Some(who) => anyhow::bail!("cancelled by {who}"),
            None => Ok(()),
        }
    }

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

    /// A progress stage begins: its name and the time, one line in <id>.steps. Small and
    /// synchronous - Progress::stage is called from code that does not await.
    /// Where the jobs' .steps files are (progress.rs reads earlier runs from there).
    pub fn steps_dir(&self) -> Option<std::path::PathBuf> {
        self.live.steps.parent().map(|p| p.to_path_buf())
    }

    pub fn mark_step(&self, name: &str) {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&self.live.steps) {
            let _ = writeln!(f, "{}\t{}", chrono::Utc::now().to_rfc3339(), name.replace(['\t', '\n'], " "));
        }
    }

    /// The progress bar: what runs now, how far (0-100) when that is known.
    pub fn progress(&self, label: impl Into<String>, pct: Option<f64>, detail: impl Into<String>) {
        self.progress_step(label, pct, None, detail)
    }

    pub fn progress_step(&self, label: impl Into<String>, pct: Option<f64>, step: Option<f64>, detail: impl Into<String>) {
        let ev = Event::Progress { label: label.into(), pct, step, detail: detail.into(), done: false };
        *self.live.progress.lock().unwrap() = Some(ev.clone());
        let _ = self.live.tx.send(ev);
    }

    pub fn progress_done(&self) {
        let ev = Event::Progress { label: String::new(), pct: None, step: None, detail: String::new(), done: true };
        *self.live.progress.lock().unwrap() = None;
        let _ = self.live.tx.send(ev);
    }
}

pub type Watch = (Vec<String>, Option<Event>, Option<broadcast::Receiver<Event>>);

/// Told the id of every job that ends (the notifications).
pub type EndHook = Arc<dyn Fn(String) + Send + Sync>;

#[derive(Clone)]
pub struct Jobs {
    db: SqlitePool,
    dir: PathBuf,
    running: Arc<RwLock<HashMap<String, Arc<Live>>>>,
    on_end: Arc<std::sync::OnceLock<EndHook>>,
    /// The jobs the last stop cut off: (id, title).
    pub interrupted: Arc<Vec<(String, String)>>,
    /// A set number of jobs at a time per lane (the ISO builds share the work volume).
    lanes: Arc<std::sync::Mutex<HashMap<String, Lane>>>,
}

/// A lane: its slots (tokio's semaphore - first come, first served), how many there are,
/// and the titles of the jobs holding one.
struct Lane {
    slots: Arc<tokio::sync::Semaphore>,
    limit: usize,
    holders: Vec<(String, String)>,
}

impl Lane {
    fn new() -> Self {
        Self { slots: Arc::new(tokio::sync::Semaphore::new(1)), limit: 1, holders: Vec::new() }
    }
}

impl Jobs {
    /// A job that was running when the process stopped is not running any more.
    pub async fn new(db: SqlitePool, dir: PathBuf) -> Result<Self> {
        tokio::fs::create_dir_all(&dir).await?;
        // Their logs get the closing line too - a log ends with [ end ] or [ error ], always.
        let cut: Vec<(String, String)> = sqlx::query_as("SELECT id, title FROM jobs WHERE status IN ('queued', 'running')").fetch_all(&db).await?;
        for (id, _) in &cut {
            use tokio::io::AsyncWriteExt;
            if let Ok(mut f) = tokio::fs::OpenOptions::new().append(true).open(dir.join(format!("{id}.log"))).await {
                let line = format!("{} [ {:<5} ] interrupted - the studio stopped while this job ran\n", Local::now().format("%Y-%m-%d %H:%M:%S"), "error");
                let _ = f.write_all(line.as_bytes()).await;
            }
        }
        sqlx::query(
            "UPDATE jobs SET status = 'interrupted', ended_at = ?, \
             error = 'the studio stopped while this job ran' \
             WHERE status IN ('queued', 'running')",
        )
        .bind(now())
        .execute(&db)
        .await?;
        Ok(Self { db, dir, running: Default::default(), on_end: Default::default(), interrupted: Arc::new(cut), lanes: Default::default() })
    }

    /// Set once, at start.
    pub fn on_end(&self, hook: EndHook) {
        let _ = self.on_end.set(hook);
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
        self.spawn_in(None, kind, title, created_by, params, body).await
    }

    /// How many jobs of `lane` may run at a time (1 when never set). Fewer than now: the
    /// running ones finish, the queue waits until the number is under the new limit.
    pub fn set_lane_limit(&self, lane: &str, limit: usize) {
        let limit = limit.max(1);
        let mut lanes = self.lanes.lock().unwrap();
        let l = lanes.entry(lane.to_owned()).or_insert_with(Lane::new);
        if limit > l.limit {
            l.slots.add_permits(limit - l.limit);
        } else if limit < l.limit {
            // Slots taken back as they come free.
            let (slots, n) = (l.slots.clone(), (l.limit - limit) as u32);
            tokio::spawn(async move {
                if let Ok(p) = slots.acquire_many_owned(n).await {
                    p.forget();
                }
            });
        }
        l.limit = limit;
    }

    /// Like spawn, but only the lane's limit of jobs runs at a time: a later one is queued
    /// and starts when a slot comes free, in the order they were asked for.
    pub async fn spawn_in_lane<F, Fut>(
        &self,
        lane: &str,
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
        self.spawn_in(Some(lane), kind, title, created_by, params, body).await
    }

    async fn spawn_in<F, Fut>(
        &self,
        lane: Option<&str>,
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
        // A slot of the lane, taken right here when one is free - so two asked for at once
        // cannot both find the last one free - or waited for in the job's task.
        let lane = lane.map(|l| {
            let mut lanes = self.lanes.lock().unwrap();
            let lane = lanes.entry(l.to_owned()).or_insert_with(Lane::new);
            match lane.slots.clone().try_acquire_owned() {
                Ok(g) => {
                    lane.holders.push((id.clone(), title.to_owned()));
                    (l.to_owned(), lane.slots.clone(), Some(g), Vec::new())
                }
                Err(_) => (l.to_owned(), lane.slots.clone(), None, lane.holders.iter().map(|h| h.1.clone()).collect()),
            }
        });
        let queued = lane.as_ref().is_some_and(|l| l.2.is_none());
        sqlx::query(
            "INSERT INTO jobs (id, kind, title, status, created_by, params, created_at, started_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(kind)
        .bind(title)
        .bind(if queued { "queued" } else { "running" })
        .bind(created_by)
        .bind(params.to_string())
        .bind(now())
        .bind(if queued { None } else { Some(now()) })
        .execute(&self.db)
        .await?;

        let file = tokio::fs::File::create(self.log_path(&id)).await?;
        let (tx, _) = broadcast::channel(8192);
        let live = Arc::new(Live {
            inner: Mutex::new(LiveInner { lines: Vec::new(), file }),
            tx,
            order: Arc::new(Mutex::new(())),
            progress: std::sync::Mutex::new(None),
            abort: std::sync::Mutex::new(None),
            steps: self.dir.join(format!("{id}.steps")),
        });
        self.running.write().await.insert(id.clone(), live.clone());

        let this = self.clone();
        let job_id = id.clone();
        let job_title = title.to_owned();
        tokio::spawn(async move {
            let log = JobLog { live: live.clone() };
            log.tag(Tag::Start, &job_title).await;
            // Queued: wait for the lane, cancellable while waiting. The guard lives until the
            // job ends.
            let mut _lane_guard = None;
            let mut cancelled = None;
            let lane_name = lane.as_ref().map(|l| l.0.clone());
            if let Some((name, slots, guard, before)) = lane {
                match guard {
                    Some(g) => _lane_guard = Some(g),
                    None => {
                        let before = match before.as_slice() {
                            [] => "the job before it".to_owned(),
                            [one] => one.clone(),
                            many => format!("one of {} has", many.join(", ")),
                        };
                        let before = if before.starts_with("one of ") { before } else { format!("{before} has") };
                        log.tag(Tag::Info, format!("Queued - starts when {before} finished")).await;
                        log.progress("Queued", None, String::new());
                        // One wait for a slot the whole time - first come, first served - with
                        // a look at Cancel every two seconds beside it.
                        let wait = slots.acquire_owned();
                        tokio::pin!(wait);
                        let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
                        loop {
                            tokio::select! {
                                g = &mut wait => {
                                    _lane_guard = g.ok();
                                    break;
                                }
                                _ = tick.tick() => {
                                    if let Err(e) = log.check_abort() {
                                        cancelled = Some(e);
                                        break;
                                    }
                                }
                            }
                        }
                        if cancelled.is_none() {
                            if let Some(l) = this.lanes.lock().unwrap().get_mut(&name) {
                                l.holders.push((job_id.clone(), job_title.clone()));
                            }
                            let _ = sqlx::query("UPDATE jobs SET status = 'running', started_at = ? WHERE id = ?").bind(now()).bind(&job_id).execute(&this.db).await;
                            log.progress_done();
                            log.run("Starting - the work volume is free").await;
                        }
                    }
                }
            }
            // A panic in the body must still end the job, so run it as its own task.
            let outcome = match cancelled {
                Some(e) => Ok(Err(e)),
                None => tokio::spawn(body(log.clone())).await,
            };
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
            if let Some(name) = &lane_name
                && let Some(l) = this.lanes.lock().unwrap().get_mut(name)
            {
                l.holders.retain(|h| h.0 != job_id);
            }
            drop(_lane_guard);
            if let Some(hook) = this.on_end.get() {
                hook(job_id);
            }
        });
        Ok(id)
    }

    pub async fn list(&self, limit: i64) -> Result<Vec<JobRow>> {
        Ok(sqlx::query_as("SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?")
            .bind(limit)
            .fetch_all(&self.db)
            .await?)
    }

    /// The progress bar of every running job that has one, by job id - what the
    /// dashboard shows without opening an event stream per job.
    pub async fn progress(&self) -> std::collections::HashMap<String, Event> {
        self.running
            .read()
            .await
            .iter()
            .filter_map(|(id, live)| live.progress.lock().unwrap().clone().map(|p| (id.clone(), p)))
            .collect()
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

    /// No job runs - the work folder holds nothing anyone needs.
    pub async fn idle(&self) -> bool {
        self.running.read().await.is_empty()
    }

    /// Asks a running job to stop. False when it is not running here.
    pub async fn abort(&self, id: &str, who: &str) -> bool {
        let Some(live) = self.running.read().await.get(id).cloned() else { return false };
        let first = live.abort.lock().unwrap().replace(who.to_owned()).is_none();
        if first {
            JobLog { live }.warn(format!("Cancel requested by {who} - stopping at the next safe point, then cleaning up")).await;
        }
        true
    }

    /// Whether the job is running in this process right now.
    /// The jobs running in this process now.
    pub async fn running_ids(&self) -> Vec<String> {
        self.running.read().await.keys().cloned().collect()
    }

    /// Waits for a job to end; its final row.
    pub async fn wait(&self, id: &str) -> Result<JobRow> {
        loop {
            if !self.is_running(id).await {
                return self.get(id).await?.ok_or_else(|| anyhow::anyhow!("job {id} is gone"));
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    }

    pub async fn is_running(&self, id: &str) -> bool {
        self.running.read().await.contains_key(id)
    }

    /// Drops a finished job: its row and its log file.
    pub async fn delete(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM jobs WHERE id = ? AND status NOT IN ('queued', 'running')").bind(id).execute(&self.db).await?;
        let _ = tokio::fs::remove_file(self.log_path(id)).await;
        let _ = tokio::fs::remove_file(self.dir.join(format!("{id}.steps"))).await;
        Ok(())
    }

/// The log's last `n` lines that say something - no debug lines, no closing [ end ] -
    /// for the mail of a job that failed.
    pub async fn log_tail(&self, id: &str, n: usize) -> Vec<String> {
        let text = tokio::fs::read_to_string(self.log_path(id)).await.unwrap_or_default();
        let lines: Vec<&str> = text.lines().filter(|l| !l.contains("[ debug") && !l.contains("[ end") && !l.trim().is_empty()).collect();
        // Time of day only - the mail says the date.
        lines[lines.len().saturating_sub(n)..].iter().map(|l| l.get(11..).unwrap_or(l).to_owned()).collect()
    }

    /// A job's stages with when each began (<id>.steps), oldest first.
    pub async fn steps(&self, id: &str) -> Vec<(chrono::DateTime<chrono::FixedOffset>, String)> {
        let text = tokio::fs::read_to_string(self.dir.join(format!("{id}.steps"))).await.unwrap_or_default();
        text.lines()
            .filter_map(|l| l.split_once('\t'))
            .filter_map(|(at, name)| Some((chrono::DateTime::parse_from_rfc3339(at).ok()?, name.to_owned())))
            .collect()
    }

    fn log_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.log"))
    }
}

fn now() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
