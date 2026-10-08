use std::{path::Path, sync::{Mutex, MutexGuard}, time::Duration};

use axum::{
    Json,
    extract::{Path as RoutePath, Query, State},
    http::{HeaderMap, StatusCode},
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{ApiError, ApiResult, AppState, admin, authed, now_ms, rate_limit};

pub struct Support {
    db: Mutex<Connection>,
}

impl Support {
    pub fn open(path: &Path) -> Result<Self, String> {
        let db = Connection::open(path).map_err(|error| error.to_string())?;
        db.busy_timeout(Duration::from_secs(3)).map_err(|error| error.to_string())?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS tickets (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 wallet TEXT NOT NULL,
                 subject TEXT NOT NULL,
                 category TEXT NOT NULL,
                 status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','waiting','closed')),
                 created_at INTEGER NOT NULL,
                 updated_at INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS tickets_wallet_updated ON tickets(wallet, updated_at DESC);
             CREATE INDEX IF NOT EXISTS tickets_status_updated ON tickets(status, updated_at DESC);
             CREATE TABLE IF NOT EXISTS ticket_messages (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 ticket_id INTEGER NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
                 author_wallet TEXT NOT NULL,
                 author_role TEXT NOT NULL CHECK(author_role IN ('player','admin')),
                 body TEXT NOT NULL,
                 created_at INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS ticket_messages_ticket ON ticket_messages(ticket_id, id);",
        )
        .map_err(|error| error.to_string())?;
        Ok(Self { db: Mutex::new(db) })
    }

    fn db(&self) -> MutexGuard<'_, Connection> {
        self.db.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn fail(status: StatusCode, message: &str) -> ApiError { ApiError::new(status, message) }
fn db_error(_: rusqlite::Error) -> ApiError { fail(StatusCode::INTERNAL_SERVER_ERROR, "Support data is unavailable.") }

fn clean_text(text: &str, limit: usize) -> String {
    text.chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\t'))
        .take(limit)
        .collect::<String>()
        .trim()
        .to_owned()
}

fn require_player(headers: &HeaderMap, state: &AppState) -> Result<String, ApiError> {
    rate_limit(state)?;
    Ok(authed(headers, state)?.wallet)
}

#[derive(Deserialize)]
pub struct CreateTicket {
    subject: String,
    category: String,
    message: String,
}

pub async fn create(State(state): State<AppState>, headers: HeaderMap, Json(body): Json<CreateTicket>) -> ApiResult {
    let wallet = require_player(&headers, &state)?;
    let subject = clean_text(&body.subject, 120);
    let message = clean_text(&body.message, 5000);
    if !(5..=120).contains(&subject.chars().count()) {
        return Err(fail(StatusCode::BAD_REQUEST, "Subject must be 5 to 120 characters."));
    }
    if !matches!(body.category.as_str(), "account" | "billing" | "gameplay" | "bug" | "other") {
        return Err(fail(StatusCode::BAD_REQUEST, "Choose a valid support category."));
    }
    if !(10..=5000).contains(&message.chars().count()) {
        return Err(fail(StatusCode::BAD_REQUEST, "Message must be 10 to 5,000 characters."));
    }
    let db = state.support.db();
    let open_count: i64 = db
        .query_row("SELECT COUNT(*) FROM tickets WHERE wallet=?1 AND status!='closed'", [&wallet], |row| row.get(0))
        .map_err(db_error)?;
    if open_count >= 25 {
        return Err(fail(StatusCode::TOO_MANY_REQUESTS, "You have too many open tickets."));
    }
    let now = now_ms() as i64;
    let tx = db.unchecked_transaction().map_err(db_error)?;
    tx.execute(
        "INSERT INTO tickets(wallet,subject,category,status,created_at,updated_at) VALUES(?1,?2,?3,'open',?4,?4)",
        params![wallet, subject, body.category, now],
    )
    .map_err(db_error)?;
    let id = tx.last_insert_rowid();
    tx.execute(
        "INSERT INTO ticket_messages(ticket_id,author_wallet,author_role,body,created_at) VALUES(?1,?2,'player',?3,?4)",
        params![id, wallet, message, now],
    )
    .map_err(db_error)?;
    tx.commit().map_err(db_error)?;
    Ok(Json(json!({ "id": id, "status": "open" })))
}

pub async fn mine(State(state): State<AppState>, headers: HeaderMap) -> ApiResult {
    let wallet = require_player(&headers, &state)?;
    ticket_list(&state, Some(wallet), None)
}

fn ticket_list(state: &AppState, wallet: Option<String>, status: Option<String>) -> ApiResult {
    let db = state.support.db();
    let mut stmt = db.prepare(
        "SELECT t.id,t.wallet,t.subject,t.category,t.status,t.created_at,t.updated_at,
         COALESCE((SELECT body FROM ticket_messages m WHERE m.ticket_id=t.id ORDER BY m.id DESC LIMIT 1),'')
         FROM tickets t WHERE (?1 IS NULL OR t.wallet=?1) AND (?2 IS NULL OR t.status=?2)
         ORDER BY t.updated_at DESC LIMIT 200",
    ).map_err(db_error)?;
    let rows = stmt
        .query_map(params![wallet, status], |row| {
            Ok(json!({
                "id": row.get::<_, i64>(0)?, "wallet": row.get::<_, String>(1)?,
                "subject": row.get::<_, String>(2)?, "category": row.get::<_, String>(3)?,
                "status": row.get::<_, String>(4)?, "created_at": row.get::<_, i64>(5)?,
                "updated_at": row.get::<_, i64>(6)?, "last_message": row.get::<_, String>(7)?,
            }))
        })
        .map_err(db_error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(db_error)?;
    Ok(Json(json!({ "tickets": rows })))
}

fn ticket_detail(support: &Support, id: i64, wallet: Option<&str>) -> Result<Value, ApiError> {
    let db = support.db();
    let ticket = db
        .query_row(
            "SELECT id,wallet,subject,category,status,created_at,updated_at FROM tickets WHERE id=?1 AND (?2 IS NULL OR wallet=?2)",
            params![id, wallet],
            |row| Ok(json!({
                "id": row.get::<_, i64>(0)?, "wallet": row.get::<_, String>(1)?,
                "subject": row.get::<_, String>(2)?, "category": row.get::<_, String>(3)?,
                "status": row.get::<_, String>(4)?, "created_at": row.get::<_, i64>(5)?,
                "updated_at": row.get::<_, i64>(6)?,
            })),
        )
        .optional()
        .map_err(db_error)?
        .ok_or_else(|| fail(StatusCode::NOT_FOUND, "Ticket not found."))?;
    let mut stmt = db
        .prepare("SELECT id,author_wallet,author_role,body,created_at FROM ticket_messages WHERE ticket_id=?1 ORDER BY id")
        .map_err(db_error)?;
    let messages = stmt
        .query_map([id], |row| {
            Ok(json!({
                "id": row.get::<_, i64>(0)?, "wallet": row.get::<_, String>(1)?,
                "role": row.get::<_, String>(2)?, "body": row.get::<_, String>(3)?,
                "created_at": row.get::<_, i64>(4)?,
            }))
        })
        .map_err(db_error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(db_error)?;
    Ok(json!({ "ticket": ticket, "messages": messages }))
}

pub async fn detail(State(state): State<AppState>, headers: HeaderMap, RoutePath(id): RoutePath<i64>) -> ApiResult {
    let wallet = require_player(&headers, &state)?;
    Ok(Json(ticket_detail(&state.support, id, Some(&wallet))?))
}

#[derive(Deserialize)]
pub struct Reply {
    message: String,
}

fn insert_reply(state: &AppState, id: i64, author: &str, role: &str, message: &str, owner: Option<&str>) -> Result<(), ApiError> {
    let db = state.support.db();
    let now = now_ms() as i64;
    let tx = db.unchecked_transaction().map_err(db_error)?;
    let changed = if owner.is_some() {
        tx.execute("UPDATE tickets SET status='open',updated_at=?3 WHERE id=?1 AND wallet=?2", params![id, owner, now])
    } else {
        tx.execute("UPDATE tickets SET status='waiting',updated_at=?2 WHERE id=?1", params![id, now])
    }.map_err(db_error)?;
    if changed == 0 {
        return Err(fail(StatusCode::NOT_FOUND, "Ticket not found."));
    }
    tx.execute(
        "INSERT INTO ticket_messages(ticket_id,author_wallet,author_role,body,created_at) VALUES(?1,?2,?3,?4,?5)",
        params![id, author, role, message, now],
    )
    .map_err(db_error)?;
    tx.commit().map_err(db_error)
}

pub async fn player_reply(State(state): State<AppState>, headers: HeaderMap, RoutePath(id): RoutePath<i64>, Json(body): Json<Reply>) -> ApiResult {
    let wallet = require_player(&headers, &state)?;
    let message = clean_text(&body.message, 5000);
    if !(2..=5000).contains(&message.chars().count()) {
        return Err(fail(StatusCode::BAD_REQUEST, "Reply must be 2 to 5,000 characters."));
    }
    insert_reply(&state, id, &wallet, "player", &message, Some(&wallet))?;
    Ok(Json(json!({ "updated": true })))
}

#[derive(Deserialize)]
pub struct TicketFilter {
    status: Option<String>,
}

pub async fn admin_list(State(state): State<AppState>, headers: HeaderMap, Query(filter): Query<TicketFilter>) -> ApiResult {
    admin::admin_session(&headers, &state)?;
    if filter.status.as_deref().is_some_and(|status| !matches!(status, "open" | "waiting" | "closed")) {
        return Err(fail(StatusCode::BAD_REQUEST, "Invalid ticket status."));
    }
    ticket_list(&state, None, filter.status)
}

pub async fn admin_detail(State(state): State<AppState>, headers: HeaderMap, RoutePath(id): RoutePath<i64>) -> ApiResult {
    admin::admin_session(&headers, &state)?;
    Ok(Json(ticket_detail(&state.support, id, None)?))
}

pub async fn admin_reply(State(state): State<AppState>, headers: HeaderMap, RoutePath(id): RoutePath<i64>, Json(body): Json<Reply>) -> ApiResult {
    let admin = admin::admin_session(&headers, &state)?;
    let message = clean_text(&body.message, 5000);
    if !(2..=5000).contains(&message.chars().count()) {
        return Err(fail(StatusCode::BAD_REQUEST, "Reply must be 2 to 5,000 characters."));
    }
    insert_reply(&state, id, &admin.wallet, "admin", &message, None)?;
    admin::audit(&state, &admin.wallet, "support_reply", json!({ "ticket_id": id }));
    Ok(Json(json!({ "updated": true })))
}

#[derive(Deserialize)]
pub struct StatusUpdate {
    status: String,
}

pub async fn admin_status(State(state): State<AppState>, headers: HeaderMap, RoutePath(id): RoutePath<i64>, Json(body): Json<StatusUpdate>) -> ApiResult {
    let admin = admin::admin_session(&headers, &state)?;
    if !matches!(body.status.as_str(), "open" | "waiting" | "closed") {
        return Err(fail(StatusCode::BAD_REQUEST, "Invalid ticket status."));
    }
    let changed = state.support.db().execute(
        "UPDATE tickets SET status=?2,updated_at=?3 WHERE id=?1",
        params![id, body.status, now_ms() as i64],
    ).map_err(db_error)?;
    if changed == 0 {
        return Err(fail(StatusCode::NOT_FOUND, "Ticket not found."));
    }
    admin::audit(&state, &admin.wallet, "support_status", json!({ "ticket_id": id, "status": body.status }));
    Ok(Json(json!({ "updated": true })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn ticket_threads_are_wallet_scoped() {
        let path = std::env::temp_dir().join(format!("rh-support-{}.db", rand::random::<u64>()));
        let support = Support::open(&path).unwrap();
        let id = {
            let db = support.db();
            db.execute(
                "INSERT INTO tickets(wallet,subject,category,status,created_at,updated_at) VALUES('wallet-a','Help','gameplay','open',1,1)",
                [],
            )
            .unwrap();
            db.last_insert_rowid()
        };
        assert_eq!(ticket_detail(&support, id, Some("wallet-b")).unwrap_err().0, StatusCode::NOT_FOUND);
        let own = ticket_detail(&support, id, Some("wallet-a")).unwrap();
        assert_eq!(own["ticket"]["wallet"], "wallet-a");
        assert_eq!(ticket_detail(&support, id, None).unwrap()["ticket"]["id"], id);
        drop(support);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("db-wal"));
        let _ = fs::remove_file(path.with_extension("db-shm"));
    }
}