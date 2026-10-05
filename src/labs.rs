//! Labs: the studio's designs, kept on the server. The Hyper-V studio lived in one
//! browser tab and a state token; here the same state is saved as it is edited.

use anyhow::Result;
use serde::Serialize;
use sqlx::SqlitePool;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct LabRow {
    pub id: String,
    pub name: String,
    pub state: String,
    pub revision: i64,
    pub updated_by: String,
    pub updated_at: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct LabSummary {
    pub id: String,
    pub name: String,
    pub revision: i64,
    pub updated_by: String,
    pub updated_at: String,
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

pub async fn list(db: &SqlitePool) -> Result<Vec<LabSummary>> {
    Ok(sqlx::query_as("SELECT id, name, revision, updated_by, updated_at FROM labs ORDER BY updated_at DESC").fetch_all(db).await?)
}

pub async fn get(db: &SqlitePool, id: &str) -> Result<Option<LabRow>> {
    Ok(sqlx::query_as("SELECT * FROM labs WHERE id = ?").bind(id).fetch_optional(db).await?)
}

pub async fn create(db: &SqlitePool, name: &str, state: &str, user: &str) -> Result<LabRow> {
    let id = uuid::Uuid::new_v4().to_string();
    let t = now();
    sqlx::query("INSERT INTO labs (id, name, state, revision, updated_by, updated_at, created_at) VALUES (?, ?, ?, 1, ?, ?, ?)")
        .bind(&id)
        .bind(name)
        .bind(state)
        .bind(user)
        .bind(&t)
        .bind(&t)
        .execute(db)
        .await?;
    Ok(get(db, &id).await?.expect("just inserted"))
}

/// Saves when `revision` is still the stored one; None means someone saved in between.
pub async fn save(db: &SqlitePool, id: &str, name: &str, state: &str, revision: i64, user: &str) -> Result<Option<i64>> {
    let r = sqlx::query("UPDATE labs SET name = ?, state = ?, revision = revision + 1, updated_by = ?, updated_at = ? WHERE id = ? AND revision = ?")
        .bind(name)
        .bind(state)
        .bind(user)
        .bind(now())
        .bind(id)
        .bind(revision)
        .execute(db)
        .await?;
    Ok((r.rows_affected() == 1).then_some(revision + 1))
}

pub async fn delete(db: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM labs WHERE id = ?").bind(id).execute(db).await?;
    Ok(())
}
