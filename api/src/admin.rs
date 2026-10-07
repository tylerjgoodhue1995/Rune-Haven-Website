use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs,
    io::Write,
    path::Path as FsPath,
    time::Duration,
};

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::{
    ApiError, ApiResult, AppState, Session, authed, character_list, game_online, game_uuid, now_ms, rate_limit, run_db,
    valid_wallet, wallet_balance,
};

const MAX_APPROVED: usize = 5000;
const MAX_IMPORT: usize = 1000;
const MAX_LABEL: usize = 60;
const MAX_NOTE: usize = 500;

fn internal(message: &str) -> ApiError { ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, message) }

fn clean(text: &str, max: usize) -> String {
    text.chars().filter(|c| !c.is_control()).collect::<String>().trim().chars().take(max).collect()
}

/// The shared alpha-access file, read by the game server on every login. Unknown fields are preserved.
struct Access(Map<String, Value>);

impl Access {
    fn load(path: &FsPath) -> Result<Self, ApiError> {
        match fs::read(path) {
            Ok(bytes) => match serde_json::from_slice::<Value>(&bytes) {
                Ok(Value::Object(map)) => Ok(Self(map)),
                _ => Err(internal("The alpha access file is unreadable; refusing to overwrite it.")),
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut map = Map::new();
                map.insert("maintenance_mode".into(), Value::Bool(true));
                map.insert("allowed_wallets".into(), json!([]));
                Ok(Self(map))
            },
            Err(_) => Err(internal("The alpha access file could not be read.")),
        }
    }

    fn invite_only(&self) -> bool { self.0.get("maintenance_mode").and_then(Value::as_bool).unwrap_or(true) }

    fn wallets(&self) -> Vec<String> {
        self.0
            .get("allowed_wallets")
            .and_then(Value::as_array)
            .map(|list| list.iter().filter_map(|entry| entry.as_str().map(str::to_owned)).collect())
            .unwrap_or_default()
    }

    fn set_wallets(&mut self, wallets: Vec<String>) { self.0.insert("allowed_wallets".into(), json!(wallets)); }

    fn set_invite_only(&mut self, invite_only: bool) { self.0.insert("maintenance_mode".into(), Value::Bool(invite_only)); }

    fn save(&self, path: &FsPath) -> Result<(), ApiError> {
        write_atomic(path, &serde_json::to_vec_pretty(&self.0).map_err(|_| internal("Could not save access list."))?)
    }
}

// Rename can briefly fail on Windows while the game server has the file open.
fn write_atomic(path: &FsPath, data: &[u8]) -> Result<(), ApiError> {
    let temp = path.with_extension("tmp");
    fs::write(&temp, data).map_err(|_| internal("Could not save changes."))?;
    for attempt in 0..8 {
        if fs::rename(&temp, path).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(40 * (attempt + 1)));
    }
    let _ = fs::remove_file(&temp);
    Err(internal("Could not save changes. Try again."))
}

#[derive(Clone, Default)]
struct Member {
    label: String,
    note: String,
    added_at: u64,
    added_by: String,
}

fn load_members(path: &FsPath) -> Result<BTreeMap<String, Member>, ApiError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(_) => return Err(internal("The member notes file could not be read.")),
    };
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| internal("The member notes file is unreadable; refusing to overwrite it."))?;
    let text = |entry: &Value, key: &str| entry.get(key).and_then(Value::as_str).unwrap_or_default().to_owned();
    Ok(value
        .get("wallets")
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .map(|(wallet, entry)| {
                    (wallet.clone(), Member {
                        label: text(entry, "label"),
                        note: text(entry, "note"),
                        added_at: entry.get("added_at").and_then(Value::as_u64).unwrap_or(0),
                        added_by: text(entry, "added_by"),
                    })
                })
                .collect()
        })
        .unwrap_or_default())
}

fn save_members(path: &FsPath, members: &BTreeMap<String, Member>) -> Result<(), ApiError> {
    let wallets: Map<String, Value> = members
        .iter()
        .map(|(wallet, m)| {
            (wallet.clone(), json!({ "label": m.label, "note": m.note, "added_at": m.added_at, "added_by": m.added_by }))
        })
        .collect();
    write_atomic(path, &serde_json::to_vec_pretty(&json!({ "wallets": wallets })).map_err(|_| internal("Could not save notes."))?)
}

fn audit(state: &AppState, admin: &str, action: &str, detail: Value) {
    let line = json!({ "at": now_ms() as u64, "admin": admin, "action": action, "detail": detail }).to_string();
    let result = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&state.cfg.audit_path)
        .and_then(|mut file| writeln!(file, "{line}"));
    if let Err(error) = result {
        eprintln!("audit log write failed: {error}");
    }
}

fn read_audit(path: &FsPath, limit: usize) -> Vec<Value> {
    fs::read_to_string(path)
        .map(|text| text.lines().rev().filter_map(|line| serde_json::from_str(line).ok()).take(limit).collect())
        .unwrap_or_default()
}

fn admin_session(headers: &HeaderMap, state: &AppState) -> Result<Session, ApiError> {
    rate_limit(state)?;
    let session = authed(headers, state)?;
    if !state.cfg.admin_wallets.contains(&session.wallet) {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "Admin access required."));
    }
    Ok(session)
}

// All file changes run serialized so concurrent admin actions cannot overwrite each other.
async fn serialized<T: Send + 'static>(
    state: &AppState,
    job: impl FnOnce(&AppState) -> Result<T, ApiError> + Send + 'static,
) -> Result<T, ApiError> {
    let state = state.clone();
    tokio::task::spawn_blocking(move || {
        let _guard = state.admin_lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        job(&state)
    })
    .await
    .map_err(|_| internal("Admin task failed."))?
}

#[derive(Deserialize)]
pub struct NewMember {
    wallet: String,
    #[serde(default)]
    label: String,
    #[serde(default)]
    note: String,
}

fn apply_additions(
    wallets: &mut Vec<String>,
    members: &mut BTreeMap<String, Member>,
    entries: Vec<NewMember>,
    admin: &str,
    now: u64,
) -> (Vec<String>, Vec<Value>) {
    let mut known: HashSet<String> = wallets.iter().cloned().collect();
    let mut added = Vec::new();
    let mut skipped = Vec::new();
    for entry in entries {
        let wallet = entry.wallet.trim().to_owned();
        let reason = if !valid_wallet(&wallet) {
            Some("not a valid Solana address")
        } else if known.contains(&wallet) {
            Some("already approved")
        } else if wallets.len() >= MAX_APPROVED {
            Some("approved list is full")
        } else {
            None
        };
        if let Some(reason) = reason {
            skipped.push(json!({ "wallet": wallet, "reason": reason }));
            continue;
        }
        known.insert(wallet.clone());
        wallets.push(wallet.clone());
        members.insert(wallet.clone(), Member {
            label: clean(&entry.label, MAX_LABEL),
            note: clean(&entry.note, MAX_NOTE),
            added_at: now,
            added_by: admin.to_owned(),
        });
        added.push(wallet);
    }
    (added, skipped)
}

pub async fn overview(State(state): State<AppState>, headers: HeaderMap) -> ApiResult {
    admin_session(&headers, &state)?;
    let online = game_online(&state.cfg).await;
    let characters = run_db(&state, |conn| conn.query_row("SELECT COUNT(*) FROM character", [], |row| row.get::<_, i64>(0)))
        .await
        .ok();
    let (approved, invite_only, recent) = serialized(&state, |st| {
        let access = Access::load(&st.cfg.alpha_access_path)?;
        Ok((access.wallets().len(), access.invite_only(), read_audit(&st.cfg.audit_path, 5)))
    })
    .await?;
    let sessions = state.sessions.lock().unwrap().values().filter(|s| s.expires_at > now_ms()).count();
    Ok(Json(json!({
        "game_online": online,
        "version": state.cfg.game_version,
        "alpha_open": !invite_only,
        "approved_count": approved,
        "characters": characters,
        "active_sessions": sessions,
        "recent_activity": recent,
    })))
}

pub async fn members(State(state): State<AppState>, headers: HeaderMap) -> ApiResult {
    admin_session(&headers, &state)?;
    let (wallets, notes, invite_only) = serialized(&state, |st| {
        let access = Access::load(&st.cfg.alpha_access_path)?;
        Ok((access.wallets(), load_members(&st.cfg.members_path)?, access.invite_only()))
    })
    .await?;
    let uuids: Vec<(String, String)> = wallets.iter().map(|w| (w.clone(), game_uuid(w).to_string())).collect();
    let counts: HashMap<String, i64> = run_db(&state, move |conn| {
        let mut stmt = conn.prepare("SELECT COUNT(*) FROM character WHERE player_uuid = ?1")?;
        let mut counts = HashMap::new();
        for (wallet, uuid) in &uuids {
            counts.insert(wallet.clone(), stmt.query_row([uuid], |row| row.get::<_, i64>(0))?);
        }
        Ok(counts)
    })
    .await
    .unwrap_or_default();

    let mut list: Vec<Value> = wallets
        .iter()
        .map(|wallet| {
            let note = notes.get(wallet).cloned().unwrap_or_default();
            json!({
                "wallet": wallet,
                "label": note.label,
                "note": note.note,
                "added_at": note.added_at,
                "added_by": note.added_by,
                "game_account": game_uuid(wallet).to_string(),
                "characters": counts.get(wallet),
            })
        })
        .collect();
    list.sort_by(|a, b| b["added_at"].as_u64().cmp(&a["added_at"].as_u64()).then_with(|| a["wallet"].as_str().cmp(&b["wallet"].as_str())));
    Ok(Json(json!({ "alpha_open": !invite_only, "members": list })))
}

#[derive(Deserialize)]
pub struct AddBody {
    entries: Vec<NewMember>,
}

pub async fn add(State(state): State<AppState>, headers: HeaderMap, Json(body): Json<AddBody>) -> ApiResult {
    let admin = admin_session(&headers, &state)?.wallet;
    if body.entries.is_empty() || body.entries.len() > MAX_IMPORT {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, format!("Provide between 1 and {MAX_IMPORT} wallets at a time.")));
    }
    let (added, skipped, total) = serialized(&state, move |st| {
        let mut access = Access::load(&st.cfg.alpha_access_path)?;
        let mut members = load_members(&st.cfg.members_path)?;
        let mut wallets = access.wallets();
        let (added, skipped) = apply_additions(&mut wallets, &mut members, body.entries, &admin, now_ms() as u64);
        if !added.is_empty() {
            let total = wallets.len();
            access.set_wallets(wallets);
            save_members(&st.cfg.members_path, &members)?;
            access.save(&st.cfg.alpha_access_path)?;
            audit(st, &admin, "add_wallets", json!({ "added": added, "skipped": skipped.len() }));
            return Ok((added, skipped, total));
        }
        Ok((added, skipped, wallets.len()))
    })
    .await?;
    Ok(Json(json!({ "added": added, "skipped": skipped, "approved_count": total })))
}

#[derive(Deserialize)]
pub struct NoteBody {
    #[serde(default)]
    label: String,
    #[serde(default)]
    note: String,
}

pub async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(wallet): Path<String>,
    Json(body): Json<NoteBody>,
) -> ApiResult {
    let admin = admin_session(&headers, &state)?.wallet;
    serialized(&state, move |st| {
        let access = Access::load(&st.cfg.alpha_access_path)?;
        if !access.wallets().contains(&wallet) {
            return Err(ApiError::new(StatusCode::NOT_FOUND, "That wallet is not on the approved list."));
        }
        let mut members = load_members(&st.cfg.members_path)?;
        let entry = members.entry(wallet.clone()).or_default();
        entry.label = clean(&body.label, MAX_LABEL);
        entry.note = clean(&body.note, MAX_NOTE);
        save_members(&st.cfg.members_path, &members)?;
        audit(st, &admin, "edit_wallet_note", json!({ "wallet": wallet }));
        Ok(Json(json!({ "ok": true })))
    })
    .await
}

pub async fn remove(State(state): State<AppState>, headers: HeaderMap, Path(wallet): Path<String>) -> ApiResult {
    let admin = admin_session(&headers, &state)?.wallet;
    serialized(&state, move |st| {
        let mut access = Access::load(&st.cfg.alpha_access_path)?;
        let mut wallets = access.wallets();
        let before = wallets.len();
        wallets.retain(|entry| entry != &wallet);
        if wallets.len() == before {
            return Err(ApiError::new(StatusCode::NOT_FOUND, "That wallet is not on the approved list."));
        }
        access.set_wallets(wallets.clone());
        access.save(&st.cfg.alpha_access_path)?;
        let mut members = load_members(&st.cfg.members_path)?;
        if members.remove(&wallet).is_some() {
            save_members(&st.cfg.members_path, &members)?;
        }
        audit(st, &admin, "remove_wallet", json!({ "wallet": wallet }));
        Ok(Json(json!({ "approved_count": wallets.len() })))
    })
    .await
}

#[derive(Deserialize)]
pub struct SettingsBody {
    alpha_open: bool,
}

pub async fn settings(State(state): State<AppState>, headers: HeaderMap, Json(body): Json<SettingsBody>) -> ApiResult {
    let admin = admin_session(&headers, &state)?.wallet;
    serialized(&state, move |st| {
        let mut access = Access::load(&st.cfg.alpha_access_path)?;
        access.set_invite_only(!body.alpha_open);
        access.save(&st.cfg.alpha_access_path)?;
        audit(st, &admin, "set_alpha_open", json!({ "alpha_open": body.alpha_open }));
        Ok(Json(json!({ "alpha_open": body.alpha_open })))
    })
    .await
}

pub async fn audit_log(State(state): State<AppState>, headers: HeaderMap, Query(query): Query<HashMap<String, String>>) -> ApiResult {
    admin_session(&headers, &state)?;
    let limit = query.get("limit").and_then(|value| value.parse::<usize>().ok()).unwrap_or(50).clamp(1, 200);
    let entries = serialized(&state, move |st| Ok(read_audit(&st.cfg.audit_path, limit))).await?;
    Ok(Json(json!({ "entries": entries })))
}

pub async fn lookup(State(state): State<AppState>, headers: HeaderMap, Path(wallet): Path<String>) -> ApiResult {
    admin_session(&headers, &state)?;
    let wallet = wallet.trim().to_owned();
    if !valid_wallet(&wallet) {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "That is not a valid Solana address."));
    }
    let lookup_wallet = wallet.clone();
    let (approved, note) = serialized(&state, move |st| {
        let access = Access::load(&st.cfg.alpha_access_path)?;
        let notes = load_members(&st.cfg.members_path)?;
        Ok((access.wallets().contains(&lookup_wallet), notes.get(&lookup_wallet).cloned()))
    })
    .await?;
    let characters = character_list(&state, &wallet).await.ok();
    let balance = wallet_balance(&state, &wallet).await.ok().map(|json| json.0);
    Ok(Json(json!({
        "wallet": wallet,
        "game_account": game_uuid(&wallet).to_string(),
        "approved": approved || state.cfg.admin_wallets.contains(&wallet),
        "is_admin": state.cfg.admin_wallets.contains(&wallet),
        "label": note.as_ref().map(|m| m.label.clone()),
        "note": note.as_ref().map(|m| m.note.clone()),
        "added_at": note.as_ref().map(|m| m.added_at),
        "characters": characters,
        "balance": balance,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "EiL5hGfzLAyCah2GMrxFz47HPLwgK6CQtS1CL1gWxQF8";
    const B: &str = "11111111111111111111111111111112";

    fn entry(wallet: &str, label: &str) -> NewMember {
        NewMember { wallet: wallet.into(), label: label.into(), note: String::new() }
    }

    #[test]
    fn additions_skip_invalid_and_duplicates_and_keep_notes() {
        let mut wallets = vec![];
        let mut members = BTreeMap::new();
        let entries = vec![entry(A, "  Tyler\u{7}  "), entry("nope", ""), entry(A, "again"), entry(B, "Bob")];
        let (added, skipped) = apply_additions(&mut wallets, &mut members, entries, "admin", 42);
        assert_eq!(added, vec![A.to_string(), B.to_string()]);
        assert_eq!(wallets.len(), 2);
        assert_eq!(skipped.len(), 2);
        assert_eq!(skipped[0]["reason"], "not a valid Solana address");
        assert_eq!(skipped[1]["reason"], "already approved");
        assert_eq!(members[A].label, "Tyler");
        assert_eq!(members[A].added_by, "admin");
    }

    #[test]
    fn additions_respect_the_approved_limit() {
        let mut wallets: Vec<String> = (0..MAX_APPROVED).map(|i| format!("w{i}")).collect();
        let mut members = BTreeMap::new();
        let (added, skipped) = apply_additions(&mut wallets, &mut members, vec![entry(A, "")], "admin", 1);
        assert!(added.is_empty());
        assert_eq!(skipped[0]["reason"], "approved list is full");
    }

    #[test]
    fn access_file_preserves_unknown_fields_and_fails_closed() {
        let dir = std::env::temp_dir().join(format!("rh-admin-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("alpha-access.json");
        fs::write(&path, r#"{"maintenance_mode":false,"allowed_wallets":["x"],"extra":7}"#).unwrap();
        let mut access = Access::load(&path).unwrap();
        assert!(!access.invite_only());
        access.set_wallets(vec!["x".into(), "y".into()]);
        access.save(&path).unwrap();
        let saved: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(saved["extra"], 7);
        assert_eq!(saved["allowed_wallets"], json!(["x", "y"]));

        fs::write(&path, "{ not json").unwrap();
        assert!(Access::load(&path).is_err());
        assert!(Access::load(&dir.join("missing.json")).unwrap().invite_only());
        fs::remove_dir_all(&dir).unwrap();
    }
}
