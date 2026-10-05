//! Login is PVE login: the user's credentials go to PVE, the ticket stays on the server,
//! and the browser gets an opaque session cookie. The user's PVE privileges decide what
//! the studio lets them do; the studio's own token only does the work.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    extract::{FromRef, FromRequestParts},
    http::{request::Parts, Method, StatusCode},
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use tokio::sync::RwLock;

use crate::{error::ApiError, pve::Ticket, AppState};

pub const COOKIE: &str = "pvs_session";
/// Every request that changes something must carry this header with the session's value.
/// A cross-site form cannot set a header, so this stops CSRF without a token dance.
pub const CSRF_HEADER: &str = "x-pvs-csrf";

/// PVE tickets are valid for two hours; renew well before that.
const RENEW_AFTER: Duration = Duration::from_secs(60 * 60);
/// A session nobody used for this long is gone.
const IDLE_LIMIT: Duration = Duration::from_secs(8 * 60 * 60);

#[derive(Clone)]
pub struct Session {
    pub user: String,
    pub csrf: String,
    ticket: Ticket,
    ticket_at: Instant,
    last_seen: Instant,
}

impl Session {
    pub fn ticket(&self) -> &Ticket {
        &self.ticket
    }
}

/// The sessions, kept in a file of the studio's own (root only, beside the PVE token it
/// already keeps) so an update of the studio does not sign everyone out.
#[derive(Clone, Default)]
pub struct Sessions(Arc<RwLock<HashMap<String, Session>>>, Option<Arc<std::path::PathBuf>>);

#[derive(serde::Serialize, serde::Deserialize)]
struct Saved {
    id: String,
    user: String,
    csrf: String,
    ticket: Ticket,
    /// Unix seconds.
    ticket_at: u64,
    last_seen: u64,
}

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl Sessions {
    /// The sessions the last run left behind; the ones idle too long are dropped.
    pub fn load(path: std::path::PathBuf) -> Self {
        let now = unix_now();
        let back = |t: u64| Instant::now().checked_sub(Duration::from_secs(now.saturating_sub(t))).unwrap_or_else(Instant::now);
        let saved: Vec<Saved> = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        let map: HashMap<String, Session> = saved
            .into_iter()
            .filter(|s| now.saturating_sub(s.last_seen) < IDLE_LIMIT.as_secs())
            .map(|s| (s.id, Session { user: s.user, csrf: s.csrf, ticket: s.ticket, ticket_at: back(s.ticket_at), last_seen: back(s.last_seen) }))
            .collect();
        Self(Arc::new(RwLock::new(map)), Some(Arc::new(path)))
    }

    async fn save(&self) {
        let Some(path) = &self.1 else { return };
        let now = unix_now();
        let ago = |i: Instant| now.saturating_sub(i.elapsed().as_secs());
        let saved: Vec<Saved> = self
            .0
            .read()
            .await
            .iter()
            .map(|(id, s)| Saved { id: id.clone(), user: s.user.clone(), csrf: s.csrf.clone(), ticket: s.ticket.clone(), ticket_at: ago(s.ticket_at), last_seen: ago(s.last_seen) })
            .collect();
        let Ok(bytes) = serde_json::to_vec(&saved) else { return };
        let tmp = path.with_extension("tmp");
        use std::os::unix::fs::OpenOptionsExt;
        let ok = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp).and_then(|mut f| std::io::Write::write_all(&mut f, &bytes));
        if ok.is_ok() {
            let _ = std::fs::rename(&tmp, path.as_ref());
        }
    }

    pub async fn create(&self, ticket: Ticket) -> (String, Session) {
        let id = random_token();
        let now = Instant::now();
        let session = Session {
            user: ticket.username.clone(),
            csrf: random_token(),
            ticket,
            ticket_at: now,
            last_seen: now,
        };
        let mut map = self.0.write().await;
        map.retain(|_, s| s.last_seen.elapsed() < IDLE_LIMIT);
        map.insert(id.clone(), session.clone());
        drop(map);
        self.save().await;
        (id, session)
    }

    pub async fn remove(&self, id: &str) {
        self.0.write().await.remove(id);
        self.save().await;
    }

    async fn touch(&self, id: &str) -> Option<Session> {
        let mut map = self.0.write().await;
        let s = map.get_mut(id)?;
        if s.last_seen.elapsed() >= IDLE_LIMIT {
            map.remove(id);
            return None;
        }
        s.last_seen = Instant::now();
        Some(s.clone())
    }

    async fn store_ticket(&self, id: &str, ticket: Ticket) {
        if let Some(s) = self.0.write().await.get_mut(id) {
            s.ticket = ticket;
            s.ticket_at = Instant::now();
        }
        self.save().await;
    }
}

/// 256 bits from the OS RNG (two v4 UUIDs), hex without dashes.
fn random_token() -> String {
    format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple())
}

pub fn session_cookie(id: String, secure: bool) -> Cookie<'static> {
    Cookie::build((COOKIE, id))
        .path("/")
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Strict)
        // Kept across a browser restart; the server's idle limit (8 h unused) still ends it.
        .max_age(time::Duration::days(7))
        .build()
}

/// The logged-in user. Taking this as a handler argument is what makes a route private.
pub struct User {
    pub session_id: String,
    pub session: Session,
}

impl<S> FromRequestParts<S> for User
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app = AppState::from_ref(state);
        let jar = CookieJar::from_headers(&parts.headers);
        let id = jar
            .get(COOKIE)
            .map(|c| c.value().to_owned())
            .ok_or_else(unauthorized)?;
        let mut session = app.sessions.touch(&id).await.ok_or_else(unauthorized)?;

        if parts.method != Method::GET && parts.method != Method::HEAD {
            let sent = parts.headers.get(CSRF_HEADER).and_then(|v| v.to_str().ok());
            if sent != Some(session.csrf.as_str()) {
                return Err(ApiError::new(StatusCode::FORBIDDEN, "missing or wrong CSRF header"));
            }
        }

        if session.ticket_at.elapsed() >= RENEW_AFTER {
            match app.pve.renew(&session.ticket).await {
                Ok(t) => {
                    app.sessions.store_ticket(&id, t.clone()).await;
                    session.ticket = t;
                }
                Err(_) => {
                    // PVE no longer accepts the ticket (user disabled, password changed,
                    // cluster restarted with a new key...). Back to the login page.
                    app.sessions.remove(&id).await;
                    return Err(unauthorized());
                }
            }
        }

        Ok(User { session_id: id, session })
    }
}

fn unauthorized() -> ApiError {
    ApiError::new(StatusCode::UNAUTHORIZED, "not logged in")
}

impl User {
    /// True when PVE grants `privilege` on `path` or on a parent that propagates.
    pub async fn can(&self, app: &AppState, path: &str, privilege: &str) -> Result<bool, ApiError> {
        let perms = app.pve.permissions(self.session.ticket()).await?;
        let mut p = path.trim_end_matches('/').to_owned();
        loop {
            let key = if p.is_empty() { "/" } else { p.as_str() };
            // /access/permissions already folds inheritance in, so an entry on the exact
            // path counts either way; a parent's counts only if it propagates.
            if let Some(&propagate) = perms.get(key).and_then(|p| p.get(privilege))
                && (key == path || propagate == 1)
            {
                return Ok(true);
            }
            if key == "/" {
                return Ok(false);
            }
            p.truncate(p.rfind('/').unwrap_or(0));
        }
    }

    pub async fn require(&self, app: &AppState, path: &str, privilege: &str) -> Result<(), ApiError> {
        if self.can(app, path, privilege).await? {
            Ok(())
        } else {
            Err(ApiError::new(
                StatusCode::FORBIDDEN,
                format!("{} lacks {privilege} on {path}", self.session.user),
            ))
        }
    }
}
