use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::OnceLock,
    time::Duration,
};

use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
};
use serde::Deserialize;
use serde_json::json;
use tokio::net::TcpStream;

use crate::{ApiError, ApiResult, AppState, admin::{self, admin_session}, game_online};

fn fail(status: StatusCode, message: impl Into<String>) -> ApiError { ApiError::new(status, message) }

fn normalize_log_line(line: &str) -> &str {
    let Some(end) = line.find("] ") else { return line };
    let rest = &line[end + 2..];
    let bytes = rest.as_bytes();
    if bytes.len() >= 11
        && bytes.get(4) == Some(&b'-')
        && bytes.get(7) == Some(&b'-')
        && bytes.get(10) == Some(&b'T')
    {
        rest
    } else {
        line
    }
}

fn control_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

fn run_task(verb: &'static str, task: &'static str) -> Result<(), String> {
    let output = Command::new("schtasks.exe")
        .args([verb, "/TN", task])
        .output()
        .map_err(|error| format!("Could not run Task Scheduler: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let detail = String::from_utf8_lossy(&output.stderr);
        let detail = detail.trim();
        Err(if detail.is_empty() { format!("Task Scheduler rejected {verb} for {task}.") } else { detail.to_owned() })
    }
}

async fn schedule(verb: &'static str, task: &'static str) -> Result<(), ApiError> {
    tokio::task::spawn_blocking(move || run_task(verb, task))
        .await
        .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "Task control worker failed."))?
        .map_err(|error| fail(StatusCode::BAD_GATEWAY, error))
}

async fn auth_online() -> bool {
    tokio::time::timeout(Duration::from_secs(2), TcpStream::connect("127.0.0.1:19253"))
        .await
        .is_ok_and(|result| result.is_ok())
}

async fn ensure_auth() -> Result<(), ApiError> {
    if !auth_online().await {
        schedule("/Run", "RuneHaven-Auth").await?;
        for _ in 0..20 {
            if auth_online().await { return Ok(()) }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        return Err(fail(StatusCode::GATEWAY_TIMEOUT, "Auth service did not start; game server was not started."));
    }
    Ok(())
}

async fn stop_game(state: &AppState) -> Result<(), ApiError> {
    if !game_online(&state.cfg).await { return Ok(()) }
    schedule("/End", "RuneHaven-Game-Server").await?;
    for _ in 0..40 {
        if !game_online(&state.cfg).await { return Ok(()) }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(fail(StatusCode::GATEWAY_TIMEOUT, "Game server did not stop before timeout."))
}

pub async fn status(State(state): State<AppState>, headers: axum::http::HeaderMap) -> ApiResult {
    admin_session(&headers, &state)?;
    Ok(Json(json!({
        "online": game_online(&state.cfg).await,
        "auth_online": auth_online().await,
        "version": state.cfg.game_version,
    })))
}

#[derive(Deserialize)]
pub struct ControlRequest {
    action: String,
}

pub async fn control(State(state): State<AppState>, headers: axum::http::HeaderMap, Json(body): Json<ControlRequest>) -> ApiResult {
    let admin = admin_session(&headers, &state)?;
    if !matches!(body.action.as_str(), "start" | "stop" | "restart") {
        return Err(fail(StatusCode::BAD_REQUEST, "Action must be start, stop or restart."));
    }
    let _guard = control_lock().lock().await;
    match body.action.as_str() {
        "start" => {
            if game_online(&state.cfg).await {
                return Ok(Json(json!({ "online": true, "message": "Game server is already running." })));
            }
            ensure_auth().await?;
            schedule("/Run", "RuneHaven-Game-Server").await?;
        },
        "stop" => stop_game(&state).await?,
        "restart" => {
            stop_game(&state).await?;
            ensure_auth().await?;
            schedule("/Run", "RuneHaven-Game-Server").await?;
        },
        _ => unreachable!(),
    }
    admin::audit(&state, &admin.wallet, "server_control", json!({ "action": body.action }));
    Ok(Json(json!({
        "action": body.action,
        "online": game_online(&state.cfg).await,
        "message": match body.action.as_str() {
            "start" => "Game server start requested.",
            "stop" => "Game server stopped.",
            _ => "Game server restart requested.",
        },
    })))
}

#[derive(Deserialize)]
pub struct LogQuery {
    lines: Option<usize>,
}

pub async fn logs(State(state): State<AppState>, headers: axum::http::HeaderMap, Query(query): Query<LogQuery>) -> ApiResult {
    admin_session(&headers, &state)?;
    let limit = query.lines.unwrap_or(200).clamp(1, 500);
    let directory = &state.cfg.game_log_dir;
    let mut files: Vec<_> = fs::read_dir(directory)
        .map_err(|_| fail(StatusCode::NOT_FOUND, "No game logs yet. Start the server to create a log."))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.file_name().and_then(|name| name.to_str()).is_some_and(|name| name.starts_with("server-") && name.ends_with(".log")))
        .collect();
    files.sort_by_key(|path| fs::metadata(path).and_then(|metadata| metadata.modified()).ok());
    let path: PathBuf = files.pop().ok_or_else(|| fail(StatusCode::NOT_FOUND, "No game logs yet. Start the server to create a log."))?;
    let content = fs::read_to_string(&path).map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "Could not read the game log."))?;
    let lines: Vec<&str> = content
        .lines()
        .rev()
        .take(limit)
        .map(normalize_log_line)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    Ok(Json(json!({
        "file": path.file_name().and_then(|name| name.to_str()).unwrap_or_default(),
        "lines": lines,
    })))
}

#[cfg(test)]
mod tests {
    use super::normalize_log_line;

    #[test]
    fn strips_only_duplicate_launcher_timestamps() {
        assert_eq!(
            normalize_log_line("[2026-10-08 03:16:16.661Z] 2026-10-08T03:16:16.661908Z INFO server ready"),
            "2026-10-08T03:16:16.661908Z INFO server ready"
        );
        assert_eq!(normalize_log_line("plain log line"), "plain log line");
    }
}
