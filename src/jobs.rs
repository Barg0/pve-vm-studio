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
    /// The catalog image the job's gold is of - its own gold, or the gold of the VM it
    /// built. Read from the golds table, which keeps a removed gold's row, so the job
    /// list can colour a gold or VM by what it is long after the gold is gone.
    #[sqlx(default)]
    pub image: Option<String>,
    /// The queue's order (a queued job starts before the ones with a higher number).
    #[sqlx(default)]
    pub seq: i64,
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
    id: String,
}

struct LiveInner {
    lines: Vec<String>,
    file: tokio::fs::File,
}

impl JobLog {
    /// The job's own id.
    pub fn id(&self) -> &str {
        &self.live.id
    }

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

/// Studio settings → Job queue.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[serde(default)]
pub struct QueueSettings {
    /// Jobs at a time, over every kind; 0: no limit.
    pub limit: u32,
}

impl Default for QueueSettings {
    fn default() -> Self {
        Self { limit: 3 }
    }
}

tokio::task_local! {
    /// Set while a queued job is started again after a restart: its id and place.
    static RESTORE: (String, i64);
}

#[derive(Clone)]
pub struct Jobs {
    db: SqlitePool,
    dir: PathBuf,
    /// Every job of this process that has not ended - queued or running: its live log.
    running: Arc<RwLock<HashMap<String, Arc<Live>>>>,
    on_end: Arc<std::sync::OnceLock<EndHook>>,
    /// The jobs the last stop cut off: (id, title).
    pub interrupted: Arc<Vec<(String, String)>>,
    /// The jobs that were queued when the process stopped, in queue order - started again
    /// by the studio (requeue) once it is up.
    pending: Arc<std::sync::Mutex<Vec<JobRow>>>,
    sched: Arc<std::sync::Mutex<Sched>>,
}

/// The queue: what waits, in which order, and what may start. Every job goes through it.
struct Sched {
    /// Jobs at a time over all kinds (Studio settings → Job queue); 0: no limit.
    limit: usize,
    /// A lane's own limit - the ISO builds share the work volume (Image settings).
    lanes: HashMap<String, usize>,
    /// Why nothing starts right now (the studio has just started, PVE does not answer),
    /// and since when.
    hold: Option<(String, String)>,
    waiting: Vec<Wait>,
    running: Vec<Slot>,
    next_seq: i64,
}

struct Wait {
    id: String,
    title: String,
    lane: Option<String>,
    exclusive: bool,
    seq: i64,
    /// The job this one waits for (params "after"): it starts only once that one succeeded,
    /// and is skipped when that one fails.
    after: Option<String>,
    go: Option<tokio::sync::oneshot::Sender<Go>>,
}

/// What a waiting job is told.
enum Go {
    Start,
    /// It never starts: the job it waited for did not succeed.
    Skip(String),
}

struct Slot {
    id: String,
    title: String,
    lane: Option<String>,
    exclusive: bool,
}

impl Sched {
    fn lane_limit(&self, lane: &str) -> usize {
        self.lanes.get(lane).copied().unwrap_or(1).max(1)
    }

    /// The job `id` is still to finish - queued or running.
    fn pending(&self, id: &str) -> bool {
        self.waiting.iter().any(|w| w.id == id) || self.running.iter().any(|r| r.id == id)
    }

    fn title_of(&self, id: &str) -> String {
        self.waiting.iter().map(|w| (&w.id, &w.title)).chain(self.running.iter().map(|r| (&r.id, &r.title))).find(|(i, _)| *i == id).map(|(_, t)| t.clone()).unwrap_or_default()
    }

    /// The jobs that start now, taken off the waiting list in queue order. A job whose lane
    /// is full lets the ones behind it pass; the studio's update starts alone, and nothing
    /// passes it while it waits.
    fn pump(&mut self) -> Vec<Wait> {
        let mut out = Vec::new();
        if self.hold.is_some() || self.running.iter().any(|r| r.exclusive) {
            return out;
        }
        self.waiting.sort_by_key(|w| w.seq);
        if let Some(i) = self.waiting.iter().position(|w| w.exclusive) {
            if self.running.is_empty() {
                let w = self.waiting.remove(i);
                self.running.push(Slot { id: w.id.clone(), title: w.title.clone(), lane: w.lane.clone(), exclusive: true });
                out.push(w);
            }
            return out;
        }
        let mut i = 0;
        while i < self.waiting.len() {
            if self.limit > 0 && self.running.len() >= self.limit {
                break;
            }
            let full = self.waiting[i]
                .lane
                .as_deref()
                .is_some_and(|l| self.running.iter().filter(|r| r.lane.as_deref() == Some(l)).count() >= self.lane_limit(l));
            let blocked = self.waiting[i].after.as_deref().is_some_and(|a| self.pending(a));
            if full || blocked {
                i += 1;
                continue;
            }
            let w = self.waiting.remove(i);
            self.running.push(Slot { id: w.id.clone(), title: w.title.clone(), lane: w.lane.clone(), exclusive: w.exclusive });
            out.push(w);
        }
        out
    }

    /// Why a waiting job waits, in a few words.
    fn why(&self, id: &str) -> String {
        if let Some((why, _)) = &self.hold {
            return why.clone();
        }
        let Some(w) = self.waiting.iter().find(|w| w.id == id) else { return String::new() };
        if self.running.iter().any(|r| r.exclusive) || self.waiting.iter().any(|x| x.exclusive && x.id != id) {
            return "the studio's update goes first".into();
        }
        if w.exclusive {
            return format!("{} running job(s) finish first", self.running.len());
        }
        if let Some(a) = w.after.as_deref().filter(|a| self.pending(a)) {
            let t = self.title_of(a);
            // "Build Windows Server 2022 20348.5622 media (en-US)" -> its ISO, by name.
            return match t.strip_prefix("Build ").and_then(|r| r.split(" media").next()).filter(|_| t.contains(" media")) {
                Some(iso) => format!("waits for its ISO - {iso}"),
                None => format!("waits for {t}"),
            };
        }
        if let Some(l) = w.lane.as_deref() {
            let busy: Vec<&str> = self.running.iter().filter(|r| r.lane.as_deref() == Some(l)).map(|r| r.title.as_str()).collect();
            if busy.len() >= self.lane_limit(l) {
                return format!("starts when {} has finished", busy.join(" or "));
            }
        }
        let ahead = self.waiting.iter().filter(|x| x.seq < w.seq).count();
        let all = format!("{} of {} at a time running", self.running.len(), self.limit);
        if ahead == 0 { format!("next - {all}") } else { format!("{ahead} ahead of it - {all}") }
    }
}

impl Jobs {
    /// A job that was running when the process stopped is not running any more; one that
    /// was queued waits again (requeue starts it, in its place).
    pub async fn new(db: SqlitePool, dir: PathBuf) -> Result<Self> {
        tokio::fs::create_dir_all(&dir).await?;
        // Their logs get the closing line too - a log ends with [ end ] or [ error ], always.
        let cut: Vec<(String, String)> = sqlx::query_as("SELECT id, title FROM jobs WHERE status = 'running'").fetch_all(&db).await?;
        for (id, _) in &cut {
            if let Ok(mut f) = tokio::fs::OpenOptions::new().append(true).open(dir.join(format!("{id}.log"))).await {
                let line = format!("{} [ {:<5} ] interrupted - the studio stopped while this job ran\n", Local::now().format("%Y-%m-%d %H:%M:%S"), "error");
                let _ = f.write_all(line.as_bytes()).await;
            }
        }
        sqlx::query(
            "UPDATE jobs SET status = 'interrupted', ended_at = ?, \
             error = 'the studio stopped while this job ran' \
             WHERE status = 'running'",
        )
        .bind(now())
        .execute(&db)
        .await?;
        let pending: Vec<JobRow> = sqlx::query_as("SELECT *, NULL AS image FROM jobs WHERE status = 'queued' ORDER BY seq, created_at").fetch_all(&db).await?;
        let (max,): (i64,) = sqlx::query_as("SELECT COALESCE(MAX(seq), 0) FROM jobs").fetch_one(&db).await?;
        let sched = Sched {
            limit: QueueSettings::default().limit as usize,
            lanes: HashMap::new(),
            hold: Some(("the studio is starting".into(), now())),
            waiting: Vec::new(),
            running: Vec::new(),
            next_seq: max,
        };
        Ok(Self {
            db,
            dir,
            running: Default::default(),
            on_end: Default::default(),
            interrupted: Arc::new(cut),
            pending: Arc::new(std::sync::Mutex::new(pending)),
            sched: Arc::new(std::sync::Mutex::new(sched)),
        })
    }

    /// Set once, at start.
    pub fn on_end(&self, hook: EndHook) {
        let _ = self.on_end.set(hook);
    }

    /// Records the job and queues it; it starts at once when the queue has room. Returns its
    /// id at once; the work runs on.
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

    /// Like spawn, but within the queue only the lane's limit of jobs runs at a time.
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

    /// The jobs that were queued when the process stopped - taken once.
    pub fn take_pending(&self) -> Vec<JobRow> {
        std::mem::take(&mut *self.pending.lock().unwrap())
    }

    /// Starts a job that was queued before the restart again, under its own id and in its
    /// own place. `body` is what the job's kind builds from its saved settings.
    pub async fn restore<F, Fut>(&self, row: &JobRow, lane: Option<&str>, body: F) -> Result<String>
    where
        F: FnOnce(JobLog) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        let params: serde_json::Value = serde_json::from_str(&row.params).unwrap_or_default();
        RESTORE.scope((row.id.clone(), row.seq), self.spawn_in(lane, &row.kind, &row.title, &row.created_by, params, body)).await
    }

    /// A queued job that cannot be started again after the restart: interrupted, with why.
    pub async fn give_up(&self, row: &JobRow, why: &str) {
        if let Ok(mut f) = tokio::fs::OpenOptions::new().append(true).open(self.log_path(&row.id)).await {
            let line = format!("{} [ {:<5} ] {why}\n", Local::now().format("%Y-%m-%d %H:%M:%S"), "error");
            let _ = f.write_all(line.as_bytes()).await;
        }
        let _ = sqlx::query("UPDATE jobs SET status = 'interrupted', ended_at = ?, error = ? WHERE id = ? AND status = 'queued'")
            .bind(now())
            .bind(why)
            .bind(&row.id)
            .execute(&self.db)
            .await;
    }

    /// Jobs at a time over all kinds; 0: no limit. Fewer than now: the running ones finish,
    /// the queue waits until the number is under the new limit.
    pub fn set_limit(&self, limit: usize) {
        self.sched.lock().unwrap().limit = limit;
        self.kick();
    }

    /// How many jobs of `lane` may run at a time (1 when never set).
    pub fn set_lane_limit(&self, lane: &str, limit: usize) {
        self.sched.lock().unwrap().lanes.insert(lane.to_owned(), limit.max(1));
        self.kick();
    }

    /// Nothing new starts until release - with why (shown on every queued job).
    pub fn hold(&self, why: &str) {
        let mut s = self.sched.lock().unwrap();
        if s.hold.as_ref().is_none_or(|h| h.0 != why) {
            let since = s.hold.as_ref().map(|h| h.1.clone()).unwrap_or_else(now);
            s.hold = Some((why.to_owned(), since));
        }
    }

    pub fn release(&self) {
        self.sched.lock().unwrap().hold = None;
        self.kick();
    }

    /// Starts what the queue has room for.
    fn kick(&self) {
        let started = self.sched.lock().unwrap().pump();
        for mut w in started {
            if let Some(go) = w.go.take() {
                let _ = go.send(Go::Start);
            }
        }
    }

    /// The queue's state for the pages: the limit, why it holds, and each queued job's
    /// place and reason, in order.
    pub fn queue(&self) -> serde_json::Value {
        let s = self.sched.lock().unwrap();
        let mut waiting: Vec<&Wait> = s.waiting.iter().collect();
        waiting.sort_by_key(|w| w.seq);
        serde_json::json!({
            "limit": s.limit,
            "running": s.running.len(),
            "hold": s.hold.as_ref().map(|h| serde_json::json!({ "why": h.0, "since": h.1 })),
            "lanes": s.lanes,
            "queued": waiting.iter().enumerate().map(|(i, w)| serde_json::json!({ "id": w.id, "place": i + 1, "why": s.why(&w.id), "lane": w.lane, "after": w.after.as_ref().filter(|a| s.pending(a)) })).collect::<Vec<_>>(),
        })
    }

    /// A new order for the queued jobs: `ids` first, in that order, the others after them
    /// as they were. Saved, so a restart keeps it.
    pub async fn reorder(&self, ids: &[String]) -> Result<()> {
        let changes: Vec<(String, i64)> = {
            let mut s = self.sched.lock().unwrap();
            s.waiting.sort_by_key(|w| w.seq);
            let mut seqs: Vec<i64> = s.waiting.iter().map(|w| w.seq).collect();
            seqs.sort();
            let mut order: Vec<String> = ids.iter().filter(|id| s.waiting.iter().any(|w| &w.id == *id)).cloned().collect();
            for w in &s.waiting {
                if !order.contains(&w.id) {
                    order.push(w.id.clone());
                }
            }
            // A job never goes before the queued job it waits for: it lands right behind it.
            for w in s.waiting.iter().filter(|w| w.after.is_some()) {
                let a = w.after.as_deref().unwrap_or_default();
                let (Some(me), Some(dep)) = (order.iter().position(|x| *x == w.id), order.iter().position(|x| x == a)) else { continue };
                if me < dep {
                    let id = order.remove(me);
                    order.insert(dep, id);
                }
            }
            // Places that tie (jobs of before this order existed) get numbers of their own.
            for i in 1..seqs.len() {
                if seqs[i] <= seqs[i - 1] {
                    seqs[i] = seqs[i - 1] + 1;
                }
            }
            if let Some(last) = seqs.last() {
                s.next_seq = s.next_seq.max(*last);
            }
            let changes: Vec<(String, i64)> = order.into_iter().zip(seqs).collect();
            for (id, seq) in &changes {
                if let Some(w) = s.waiting.iter_mut().find(|w| &w.id == id) {
                    w.seq = *seq;
                }
            }
            changes
        };
        for (id, seq) in &changes {
            sqlx::query("UPDATE jobs SET seq = ? WHERE id = ?").bind(seq).bind(id).execute(&self.db).await?;
        }
        self.kick();
        Ok(())
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
        let restore = RESTORE.try_with(|r| r.clone()).ok();
        let id = restore.as_ref().map(|r| r.0.clone()).unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        // The job it waits for: still to finish here, done, or gone without success.
        let after = params["after"].as_str().filter(|a| !a.is_empty()).map(str::to_owned);
        let mut skip = None;
        if let Some(a) = &after
            && !self.sched.lock().unwrap().pending(a)
        {
            let st: Option<(String,)> = sqlx::query_as("SELECT status FROM jobs WHERE id = ?").bind(a).fetch_optional(&self.db).await?;
            if st.as_ref().is_none_or(|(st,)| st != "succeeded") {
                skip = Some(format!("not started - the job it waited for {}", st.map(|(s,)| format!("is {s}")).unwrap_or_else(|| "is gone".into())));
            }
        }
        // The studio's own update restarts it: it runs alone.
        let exclusive = kind == "update";
        let (go_tx, mut go_rx) = tokio::sync::oneshot::channel::<Go>();
        let (seq, started_now) = {
            let mut s = self.sched.lock().unwrap();
            let seq = match &restore {
                Some((_, seq)) => *seq,
                None => {
                    s.next_seq += 1;
                    s.next_seq
                }
            };
            match skip.take() {
                // Never queued: told at once that it is skipped.
                Some(why) => {
                    let _ = go_tx.send(Go::Skip(why));
                    (seq, false)
                }
                None => {
                    s.waiting.push(Wait { id: id.clone(), title: title.to_owned(), lane: lane.map(str::to_owned), exclusive, seq, after, go: Some(go_tx) });
                    let started = s.pump();
                    let now_too = started.iter().any(|w| w.id == id);
                    for mut w in started {
                        if let Some(go) = w.go.take() {
                            let _ = go.send(Go::Start);
                        }
                    }
                    (seq, now_too)
                }
            }
        };
        let status = if started_now { "running" } else { "queued" };
        if restore.is_some() {
            sqlx::query("UPDATE jobs SET status = ?, started_at = ? WHERE id = ?")
                .bind(status)
                .bind(if started_now { Some(now()) } else { None })
                .bind(&id)
                .execute(&self.db)
                .await?;
        } else {
            sqlx::query(
                "INSERT INTO jobs (id, kind, title, status, created_by, params, created_at, started_at, seq) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&id)
            .bind(kind)
            .bind(title)
            .bind(status)
            .bind(created_by)
            .bind(params.to_string())
            .bind(now())
            .bind(if started_now { Some(now()) } else { None })
            .bind(seq)
            .execute(&self.db)
            .await?;
        }

        let file = if restore.is_some() {
            tokio::fs::OpenOptions::new().create(true).append(true).open(self.log_path(&id)).await?
        } else {
            tokio::fs::File::create(self.log_path(&id)).await?
        };
        let (tx, _) = broadcast::channel(8192);
        let lines = if restore.is_some() {
            tokio::fs::read_to_string(self.log_path(&id)).await.unwrap_or_default().lines().map(str::to_owned).collect()
        } else {
            Vec::new()
        };
        let live = Arc::new(Live {
            inner: Mutex::new(LiveInner { lines, file }),
            tx,
            order: Arc::new(Mutex::new(())),
            progress: std::sync::Mutex::new(None),
            abort: std::sync::Mutex::new(None),
            steps: self.dir.join(format!("{id}.steps")),
            id: id.clone(),
        });
        self.running.write().await.insert(id.clone(), live.clone());

        let this = self.clone();
        let job_id = id.clone();
        let job_title = title.to_owned();
        let restored = restore.is_some();
        tokio::spawn(async move {
            let log = JobLog { live: live.clone() };
            if restored {
                log.tag(Tag::Info, "The studio restarted - back in the queue, in its place").await;
            } else {
                log.tag(Tag::Start, &job_title).await;
            }
            // Queued: wait for the queue, cancellable while waiting.
            let mut cancelled = None;
            let mut skipped = None;
            if !started_now {
                let why = this.sched.lock().unwrap().why(&job_id);
                if !why.is_empty() {
                    log.tag(Tag::Info, format!("Queued - {why}")).await;
                    log.progress("Queued", None, why);
                }
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
                loop {
                    tokio::select! {
                        go = &mut go_rx => {
                            if let Ok(Go::Skip(why)) = go {
                                skipped = Some(why);
                            }
                            break;
                        }
                        _ = tick.tick() => {
                            if let Err(e) = log.check_abort() {
                                let mut s = this.sched.lock().unwrap();
                                // Started in the same moment: it runs, and stops at its first check.
                                if let Some(i) = s.waiting.iter().position(|w| w.id == job_id) {
                                    s.waiting.remove(i);
                                    cancelled = Some(e);
                                }
                                break;
                            }
                            let why = this.sched.lock().unwrap().why(&job_id);
                            log.progress("Queued", None, why);
                        }
                    }
                }
                if cancelled.is_none() && skipped.is_none() {
                    let _ = sqlx::query("UPDATE jobs SET status = 'running', started_at = ? WHERE id = ?").bind(now()).bind(&job_id).execute(&this.db).await;
                    log.progress_done();
                    log.run("Starting - the queue has room").await;
                }
            }
            // A panic in the body must still end the job, so run it as its own task.
            let never_ran = cancelled.is_some() || skipped.is_some();
            // Started: whatever it kept for a restart is in memory now.
            let _ = tokio::fs::remove_file(this.secret_path(&job_id)).await;
            let (status, error) = if let Some(why) = skipped {
                ("skipped", Some(why))
            } else {
                let outcome = match cancelled {
                    Some(e) => Ok(Err(e)),
                    None => tokio::spawn(body(log.clone())).await,
                };
                match outcome {
                    Ok(Ok(())) => ("succeeded", None),
                    Ok(Err(e)) => ("failed", Some(format!("{e:#}"))),
                    Err(e) => ("failed", Some(format!("job crashed: {e}"))),
                }
            };
            if never_ran {
                // Its gold or VM record was made when it was asked for; nothing was built.
                let _ = sqlx::query("UPDATE golds SET status = 'failed' WHERE job_id = ? AND status = 'baking'").bind(&job_id).execute(&this.db).await;
                let _ = sqlx::query("UPDATE vms SET status = 'failed' WHERE job_id = ? AND status = 'building'").bind(&job_id).execute(&this.db).await;
            }
            let _ = tokio::fs::remove_file(this.secret_path(&job_id)).await;
            log.progress_done();
            match &error {
                Some(e) if status == "skipped" => log.tag(Tag::End, format!("Skipped - {e}")).await,
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
            // What waited for it: starts now, or - when it did not succeed - is skipped.
            let dependents: Vec<Wait> = {
                let mut s = this.sched.lock().unwrap();
                s.running.retain(|r| r.id != job_id);
                if status == "succeeded" {
                    Vec::new()
                } else {
                    let (gone, keep): (Vec<Wait>, Vec<Wait>) = std::mem::take(&mut s.waiting).into_iter().partition(|w| w.after.as_deref() == Some(job_id.as_str()));
                    s.waiting = keep;
                    gone
                }
            };
            for mut w in dependents {
                let why = format!("not started - {job_title} {}", if status == "skipped" { "was skipped" } else { "did not succeed" });
                if let Some(go) = w.go.take() {
                    let _ = go.send(Go::Skip(why));
                }
            }
            this.kick();
            if let Some(hook) = this.on_end.get() {
                hook(job_id);
            }
        });
        Ok(id)
    }

    /// What a queued job needs again after a restart but never keeps in its params (a
    /// deploy's passwords): a file only the studio reads, gone when the job ends.
    pub fn secret_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.secret"))
    }

    pub async fn keep_secret(&self, id: &str, value: &serde_json::Value) -> Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        let path = self.secret_path(id);
        let mut f = std::fs::OpenOptions::new().create(true).truncate(true).write(true).mode(0o600).open(&path)?;
        std::io::Write::write_all(&mut f, value.to_string().as_bytes())?;
        Ok(())
    }

    pub async fn secret(&self, id: &str) -> Option<serde_json::Value> {
        tokio::fs::read(self.secret_path(id)).await.ok().and_then(|b| serde_json::from_slice(&b).ok())
    }

    pub async fn list(&self, limit: i64) -> Result<Vec<JobRow>> {
        Ok(sqlx::query_as(
            "SELECT j.*, COALESCE(g.image_id, gv.image_id) AS image FROM jobs j \
             LEFT JOIN golds g ON g.id = CASE WHEN json_valid(j.params) THEN json_extract(j.params, '$.gold') END \
             LEFT JOIN vms v ON v.id = CASE WHEN json_valid(j.params) THEN json_extract(j.params, '$.vm') END \
             LEFT JOIN golds gv ON gv.id = v.gold_id \
             ORDER BY j.created_at DESC LIMIT ?",
        )
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

    /// No job runs - the work folder holds nothing anyone needs. Queued ones have not
    /// begun (a media build that is continued keeps its folder by its checkpoint).
    pub async fn idle(&self) -> bool {
        self.sched.lock().unwrap().running.is_empty()
    }

    /// Asks a running job to stop. False when it is not running here.
    pub async fn abort(&self, id: &str, who: &str) -> bool {
        let Some(live) = self.running.read().await.get(id).cloned() else { return false };
        let first = live.abort.lock().unwrap().replace(who.to_owned()).is_none();
        let queued = self.sched.lock().unwrap().waiting.iter().any(|w| w.id == id);
        if first {
            let text = if queued { format!("Cancelled by {who} - it leaves the queue") } else { format!("Cancel requested by {who} - stopping at the next safe point, then cleaning up") };
            JobLog { live }.warn(text).await;
        }
        true
    }

    /// The jobs running in this process now - started, not queued.
    pub async fn running_ids(&self) -> Vec<String> {
        self.sched.lock().unwrap().running.iter().map(|r| r.id.clone()).collect()
    }

    /// The jobs waiting in the queue now.
    pub async fn queued_ids(&self) -> Vec<String> {
        self.sched.lock().unwrap().waiting.iter().map(|w| w.id.clone()).collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sched(limit: usize) -> Sched {
        Sched { limit, lanes: HashMap::from([("media".to_owned(), 1)]), hold: None, waiting: Vec::new(), running: Vec::new(), next_seq: 0 }
    }

    fn wait(s: &mut Sched, id: &str, lane: Option<&str>, exclusive: bool) {
        s.next_seq += 1;
        s.waiting.push(Wait { id: id.into(), title: id.into(), lane: lane.map(str::to_owned), exclusive, seq: s.next_seq, after: None, go: None });
    }

    fn ids(v: Vec<Wait>) -> Vec<String> {
        v.into_iter().map(|w| w.id).collect()
    }

    #[test]
    fn the_limit_and_a_full_lane() {
        let mut s = sched(3);
        wait(&mut s, "iso1", Some("media"), false);
        wait(&mut s, "iso2", Some("media"), false);
        wait(&mut s, "bake1", None, false);
        wait(&mut s, "bake2", None, false);
        wait(&mut s, "bake3", None, false);
        // One ISO at a time: the second lets the bakes behind it pass; three at a time in all.
        assert_eq!(ids(s.pump()), ["iso1", "bake1", "bake2"]);
        assert_eq!(s.why("iso2"), "starts when iso1 has finished");
        s.running.retain(|r| r.id != "bake1");
        assert_eq!(ids(s.pump()), ["bake3"]);
        s.running.retain(|r| r.id != "iso1");
        assert_eq!(ids(s.pump()), ["iso2"]);
    }

    #[test]
    fn the_update_goes_alone() {
        let mut s = sched(3);
        wait(&mut s, "a", None, false);
        assert_eq!(ids(s.pump()), ["a"]);
        wait(&mut s, "update", None, true);
        wait(&mut s, "b", None, false);
        // b waits behind the update, which waits for a.
        assert!(s.pump().is_empty());
        assert_eq!(s.why("b"), "the studio's update goes first");
        s.running.clear();
        assert_eq!(ids(s.pump()), ["update"]);
        assert!(s.pump().is_empty());
    }

    #[test]
    fn a_bake_waits_for_its_iso() {
        let mut s = sched(3);
        wait(&mut s, "iso", Some("media"), false);
        wait(&mut s, "bake", None, false);
        s.waiting[1].after = Some("iso".into());
        wait(&mut s, "web", None, false);
        // The bake waits while its ISO runs; the job behind it passes.
        assert_eq!(ids(s.pump()), ["iso", "web"]);
        assert_eq!(s.why("bake"), "waits for iso");
        s.running.retain(|r| r.id != "iso");
        assert_eq!(ids(s.pump()), ["bake"]);
    }

    async fn jobs() -> (Jobs, tempfile_dir::Dir) {
        let dir = tempfile_dir::Dir::new();
        let db = sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!().run(&db).await.unwrap();
        let j = Jobs::new(db, dir.0.clone()).await.unwrap();
        j.release();
        (j, dir)
    }

    async fn status(j: &Jobs, id: &str) -> String {
        for _ in 0..100 {
            let s = j.get(id).await.unwrap().unwrap().status;
            if s != "queued" && s != "running" {
                return s;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        "still going".into()
    }

    #[tokio::test]
    async fn a_failed_iso_skips_its_bakes() {
        let (j, _d) = jobs().await;
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let iso = j.spawn_in_lane("media", "media", "Build ISO media (en-US)", "t", serde_json::json!({}), move |_| async move {
            let _ = rx.await;
            anyhow::bail!("DISM failed")
        }).await.unwrap();
        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let r = ran.clone();
        let bake = j.spawn("bake", "Bake", "t", serde_json::json!({ "after": iso }), move |_| async move {
            r.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }).await.unwrap();
        assert!(j.queue()["queued"][0]["why"].as_str().unwrap().starts_with("waits for its ISO - ISO"));
        let _ = tx.send(());
        assert_eq!(status(&j, &iso).await, "failed");
        assert_eq!(status(&j, &bake).await, "skipped");
        assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn a_good_iso_starts_its_bakes() {
        let (j, _d) = jobs().await;
        let iso = j.spawn_in_lane("media", "media", "Build ISO media (en-US)", "t", serde_json::json!({}), |_| async { Ok(()) }).await.unwrap();
        let bake = j.spawn("bake", "Bake", "t", serde_json::json!({ "after": iso }), |_| async { Ok(()) }).await.unwrap();
        assert_eq!(status(&j, &iso).await, "succeeded");
        assert_eq!(status(&j, &bake).await, "succeeded");
        // Asked for after its ISO is through: it starts at once.
        let late = j.spawn("bake", "Bake", "t", serde_json::json!({ "after": iso }), |_| async { Ok(()) }).await.unwrap();
        assert_eq!(status(&j, &late).await, "succeeded");
    }

    /// A temporary folder for a test's job logs, removed afterwards.
    mod tempfile_dir {
        pub struct Dir(pub std::path::PathBuf);
        impl Dir {
            pub fn new() -> Self {
                let p = std::env::temp_dir().join(format!("pvs-jobs-test-{}", uuid::Uuid::new_v4()));
                std::fs::create_dir_all(&p).unwrap();
                Self(p)
            }
        }
        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    #[test]
    fn a_hold_and_no_limit() {
        let mut s = sched(0);
        s.hold = Some(("the studio is starting".into(), String::new()));
        for i in 0..5 {
            wait(&mut s, &format!("j{i}"), None, false);
        }
        assert!(s.pump().is_empty());
        s.hold = None;
        assert_eq!(s.pump().len(), 5);
    }
}
