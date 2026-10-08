use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use ed25519_dalek::{Signature, VerifyingKey};
use rusqlite::{Connection, OpenFlags};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

mod admin;
mod market;

const SPL_TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const SESSION_TTL_MS: u128 = 12 * 60 * 60 * 1000;
const CHALLENGE_TTL_MS: u128 = 5 * 60 * 1000;

struct Config {
    game_db: PathBuf,
    parcels_path: PathBuf,
    buildings_path: PathBuf,
    alpha_access_path: PathBuf,
    members_path: PathBuf,
    audit_path: PathBuf,
    admin_wallets: HashSet<String>,
    game_addr: String,
    rpc_url: String,
    vgld_mint: Option<String>,
    market_db: PathBuf,
    market_key_file: PathBuf,
    market_fee_bps: u64,
    market_treasury: Option<String>,
    game_key: Option<String>,
    game_version: String,
}

impl Config {
    fn from_env() -> Self {
        let var = |name: &str, default: &str| std::env::var(name).unwrap_or_else(|_| default.to_string());
        Self {
            game_db: var("SITE_GAME_DB", "userdata/server/saves/db.sqlite").into(),
            parcels_path: var("SITE_PARCELS_PATH", "userdata/server/property_parcels.json").into(),
            buildings_path: var("SITE_BUILDINGS_PATH", "userdata/server/property_buildings.json").into(),
            alpha_access_path: var("SITE_ALPHA_ACCESS_PATH", "alpha-access.json").into(),
            members_path: var("SITE_MEMBERS_PATH", "alpha-members.json").into(),
            audit_path: var("SITE_AUDIT_PATH", "admin-audit.jsonl").into(),
            admin_wallets: var("SITE_ADMIN_WALLETS", "")
                .split(',')
                .map(str::trim)
                .filter(|wallet| !wallet.is_empty())
                .map(str::to_owned)
                .collect(),
            game_addr: var("SITE_GAME_ADDR", "127.0.0.1:14004"),
            rpc_url: var("SITE_SOLANA_RPC_URL", "https://api.devnet.solana.com"),
            vgld_mint: std::env::var("SITE_VGLD_MINT").ok().filter(|mint| !mint.is_empty()),
            market_db: var("SITE_MARKET_DB", "market.db").into(),
            market_key_file: var("SITE_MARKET_KEY_FILE", "market-key.hex").into(),
            market_fee_bps: var("SITE_MARKET_FEE_BPS", "250").parse().unwrap_or(250).min(2000),
            market_treasury: std::env::var("SITE_MARKET_TREASURY").ok().filter(|wallet| valid_wallet(wallet)),
            game_key: std::env::var("SITE_GAME_KEY").ok().filter(|key| key.len() >= 24),
            game_version: var("SITE_GAME_VERSION", "alpha"),
        }
    }
}

struct Challenge {
    wallet: String,
    message: String,
    expires_at: u128,
}

#[derive(Clone)]
struct Session {
    wallet: String,
    expires_at: u128,
}

#[derive(Clone)]
struct AppState {
    cfg: Arc<Config>,
    market: Arc<market::Market>,
    http: reqwest::Client,
    challenges: Arc<Mutex<HashMap<String, Challenge>>>,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    requests: Arc<Mutex<VecDeque<Instant>>>,
    admin_lock: Arc<Mutex<()>>,
}

#[derive(Debug)]
struct ApiError(StatusCode, String);

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self { Self(status, message.into()) }

    fn unauthorized(message: &str) -> Self { Self::new(StatusCode::UNAUTHORIZED, message) }

    fn bad_gateway(message: &str) -> Self { Self::new(StatusCode::BAD_GATEWAY, message) }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response { (self.0, Json(json!({ "message": self.1 }))).into_response() }
}

type ApiResult = Result<Json<Value>, ApiError>;

fn now_ms() -> u128 { SystemTime::now().duration_since(UNIX_EPOCH).expect("clock before epoch").as_millis() }

fn random_hex() -> String {
    rand::random::<[u8; 32]>().iter().map(|byte| format!("{byte:02x}")).collect()
}

// Matches derive_uuid in the game server's login provider, so wallet logins map to the same account.
fn game_uuid(wallet: &str) -> Uuid {
    let mut state: u128 = 144066263297769815596495629667062367629;
    for byte in wallet.as_bytes() {
        state ^= *byte as u128;
        state = state.wrapping_mul(309485009821345068724781371);
    }
    Uuid::from_u128(state)
}

fn valid_wallet(wallet: &str) -> bool {
    bs58::decode(wallet).into_vec().is_ok_and(|bytes| bytes.len() == 32)
}

fn rate_limit(state: &AppState) -> Result<(), ApiError> {
    let mut requests = state.requests.lock().unwrap();
    let now = Instant::now();
    while requests.front().is_some_and(|at| now.duration_since(*at) > Duration::from_secs(60)) {
        requests.pop_front();
    }
    if requests.len() >= 600 {
        return Err(ApiError::new(StatusCode::TOO_MANY_REQUESTS, "Too many requests. Please slow down."));
    }
    requests.push_back(now);
    Ok(())
}

fn alpha_open(cfg: &Config) -> bool {
    fs::read(&cfg.alpha_access_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|value| value.get("maintenance_mode").and_then(Value::as_bool))
        .is_some_and(|invite_only| !invite_only)
}

fn alpha_access(cfg: &Config, wallet: &str) -> bool {
    if cfg.admin_wallets.contains(wallet) {
        return true;
    }
    let Some(value) = fs::read(&cfg.alpha_access_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
    else {
        return false;
    };
    if value.get("maintenance_mode").and_then(Value::as_bool) == Some(false) {
        return true;
    }
    value
        .get("allowed_wallets")
        .and_then(Value::as_array)
        .is_some_and(|wallets| wallets.iter().any(|entry| entry.as_str() == Some(wallet)))
}

fn authed(headers: &HeaderMap, state: &AppState) -> Result<Session, ApiError> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::unauthorized("Sign in with your wallet."))?;
    let mut sessions = state.sessions.lock().unwrap();
    let now = now_ms();
    sessions.retain(|_, session| session.expires_at > now);
    sessions
        .get(token)
        .cloned()
        .ok_or_else(|| ApiError::unauthorized("Session expired. Sign in again."))
}

fn alpha_session(headers: &HeaderMap, state: &AppState) -> Result<Session, ApiError> {
    rate_limit(state)?;
    let session = authed(headers, state)?;
    if !alpha_access(&state.cfg, &session.wallet) {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "This wallet is not approved for the alpha."));
    }
    Ok(session)
}

fn open_game_db(cfg: &Config) -> Result<Connection, ApiError> {
    let conn = Connection::open_with_flags(
        &cfg.game_db,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| ApiError::bad_gateway("Game data is unavailable right now."))?;
    let _ = conn.busy_timeout(Duration::from_secs(2));
    Ok(conn)
}

async fn run_db<T: Send + 'static>(
    state: &AppState,
    job: impl FnOnce(Connection) -> rusqlite::Result<T> + Send + 'static,
) -> Result<T, ApiError> {
    let cfg = Arc::clone(&state.cfg);
    tokio::task::spawn_blocking(move || {
        let conn = open_game_db(&cfg)?;
        job(conn).map_err(|_| ApiError::bad_gateway("Game data could not be read."))
    })
    .await
    .map_err(|_| ApiError::bad_gateway("Game data could not be read."))?
}

async fn rpc(state: &AppState, method: &str, params: Value) -> Result<Value, ApiError> {
    let response: Value = state
        .http
        .post(&state.cfg.rpc_url)
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
        .send()
        .await
        .map_err(|_| ApiError::bad_gateway("Solana network is unreachable."))?
        .json()
        .await
        .map_err(|_| ApiError::bad_gateway("Solana network returned an invalid response."))?;
    response
        .get("result")
        .cloned()
        .ok_or_else(|| ApiError::bad_gateway("Solana network request failed."))
}

fn parsed_token_accounts(result: &Value) -> Vec<(String, u64, u64)> {
    result
        .get("value")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            let info = entry.pointer("/account/data/parsed/info")?;
            let mint = info.get("mint")?.as_str()?.to_owned();
            let amount = info.pointer("/tokenAmount/amount")?.as_str()?.parse().ok()?;
            let decimals = info.pointer("/tokenAmount/decimals")?.as_u64()?;
            Some((mint, amount, decimals))
        })
        .collect()
}

async fn game_online(cfg: &Config) -> bool {
    matches!(
        tokio::time::timeout(Duration::from_millis(1500), tokio::net::TcpStream::connect(&cfg.game_addr)).await,
        Ok(Ok(_))
    )
}

async fn status(State(state): State<AppState>) -> ApiResult {
    rate_limit(&state)?;
    let online = game_online(&state.cfg).await;
    Ok(Json(json!({
        "online": online,
        "version": state.cfg.game_version,
        "alpha_open": alpha_open(&state.cfg),
        "checked_at": now_ms() as u64,
    })))
}

#[derive(Deserialize)]
struct ChallengeRequest {
    wallet: String,
}

async fn auth_challenge(State(state): State<AppState>, Json(body): Json<ChallengeRequest>) -> ApiResult {
    rate_limit(&state)?;
    if !valid_wallet(&body.wallet) {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "Invalid Solana wallet address."));
    }
    let nonce = random_hex();
    let expires_at = now_ms() + CHALLENGE_TTL_MS;
    let message = format!("Rune Haven Sign-In\nWallet: {}\nNonce: {nonce}\nExpires: {expires_at}", body.wallet);
    let mut challenges = state.challenges.lock().unwrap();
    let now = now_ms();
    challenges.retain(|_, challenge| challenge.expires_at > now);
    if challenges.len() > 5000 {
        return Err(ApiError::new(StatusCode::TOO_MANY_REQUESTS, "Too many pending sign-ins."));
    }
    challenges.insert(nonce.clone(), Challenge {
        wallet: body.wallet,
        message: message.clone(),
        expires_at,
    });
    Ok(Json(json!({ "nonce": nonce, "message": message })))
}

#[derive(Deserialize)]
struct VerifyRequest {
    wallet: String,
    nonce: String,
    signature: String,
}

async fn auth_verify(State(state): State<AppState>, Json(body): Json<VerifyRequest>) -> ApiResult {
    rate_limit(&state)?;
    let challenge = state
        .challenges
        .lock()
        .unwrap()
        .remove(&body.nonce)
        .ok_or_else(|| ApiError::unauthorized("Sign-in expired. Try again."))?;
    if challenge.wallet != body.wallet || challenge.expires_at <= now_ms() {
        return Err(ApiError::unauthorized("Sign-in expired. Try again."));
    }
    let key: [u8; 32] = bs58::decode(&body.wallet)
        .into_vec()
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "Invalid Solana wallet address."))?;
    let verifying_key = VerifyingKey::from_bytes(&key)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "Invalid Solana wallet address."))?;
    let signature = bs58::decode(&body.signature)
        .into_vec()
        .ok()
        .and_then(|bytes| Signature::from_slice(&bytes).ok())
        .ok_or_else(|| ApiError::unauthorized("Invalid wallet signature."))?;
    verifying_key
        .verify_strict(challenge.message.as_bytes(), &signature)
        .map_err(|_| ApiError::unauthorized("Wallet signature rejected."))?;

    let token = random_hex();
    state.sessions.lock().unwrap().insert(token.clone(), Session {
        wallet: body.wallet.clone(),
        expires_at: now_ms() + SESSION_TTL_MS,
    });
    Ok(Json(json!({
        "token": token,
        "wallet": body.wallet,
        "alpha_access": alpha_access(&state.cfg, &body.wallet),
        "is_admin": state.cfg.admin_wallets.contains(&body.wallet),
    })))
}

async fn me(State(state): State<AppState>, headers: HeaderMap) -> ApiResult {
    rate_limit(&state)?;
    let session = authed(&headers, &state)?;
    Ok(Json(json!({
        "wallet": session.wallet,
        "alpha_access": alpha_access(&state.cfg, &session.wallet),
        "is_admin": state.cfg.admin_wallets.contains(&session.wallet),
        "game_account": game_uuid(&session.wallet).to_string(),
    })))
}

async fn characters(State(state): State<AppState>, headers: HeaderMap) -> ApiResult {
    let session = alpha_session(&headers, &state)?;
    let list = character_list(&state, &session.wallet).await?;
    Ok(Json(json!({ "characters": list })))
}

async fn character_list(state: &AppState, wallet: &str) -> Result<Vec<Value>, ApiError> {
    let uuid = game_uuid(wallet).to_string();
    run_db(state, move |conn| {
        let mut stmt = conn.prepare("SELECT character_id, alias FROM character WHERE player_uuid = ?1 ORDER BY character_id")?;
        let rows = stmt
            .query_map([&uuid], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows
            .into_iter()
            .map(|(id, alias)| {
                let xp: Option<i64> = conn
                    .query_row(
                        "SELECT earned_exp FROM skill_group WHERE entity_id = ?1 AND skill_group_kind = 'General'",
                        [id],
                        |row| row.get(0),
                    )
                    .ok();
                json!({ "id": id, "name": alias, "general_xp": xp })
            })
            .collect::<Vec<_>>())
    })
    .await
}

fn inventory_rows(conn: &Connection, character_id: i64) -> rusqlite::Result<Vec<Value>> {
    let mut stmt = conn.prepare(
        "WITH RECURSIVE tree(item_id, container, def, stack) AS (
             SELECT item_id, CASE item_definition_id
                        WHEN 'veloren.core.pseudo_containers.loadout' THEN 'equipped' ELSE 'inventory' END,
                    item_definition_id, stack_size
             FROM item
             WHERE parent_container_item_id = ?1
               AND item_definition_id IN ('veloren.core.pseudo_containers.inventory',
                                          'veloren.core.pseudo_containers.loadout')
             UNION ALL
             SELECT i.item_id, t.container, i.item_definition_id, i.stack_size
             FROM item i JOIN tree t ON i.parent_container_item_id = t.item_id
         )
         SELECT container, def, stack FROM tree
         WHERE def NOT LIKE 'veloren.core.pseudo_containers.%'
         ORDER BY container, def",
    )?;
    stmt.query_map([character_id], |row| {
        Ok(json!({
            "container": row.get::<_, String>(0)?,
            "id": row.get::<_, String>(1)?,
            "count": row.get::<_, i64>(2)?,
        }))
    })?
    .collect()
}

async fn inventory(State(state): State<AppState>, headers: HeaderMap, Path(character_id): Path<i64>) -> ApiResult {
    let session = alpha_session(&headers, &state)?;
    let uuid = game_uuid(&session.wallet).to_string();
    let items = run_db(&state, move |conn| {
        let owned: bool = conn
            .query_row(
                "SELECT 1 FROM character WHERE character_id = ?1 AND player_uuid = ?2",
                rusqlite::params![character_id, uuid],
                |_| Ok(true),
            )
            .unwrap_or(false);
        if !owned {
            return Ok(None);
        }
        let rows = inventory_rows(&conn, character_id)?;
        Ok(Some(rows))
    })
    .await?;
    items
        .map(|items| Json(json!({ "items": items })))
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Character not found."))
}

async fn leaderboard(State(state): State<AppState>) -> ApiResult {
    rate_limit(&state)?;
    let rows = run_db(&state, |conn| {
        let mut stmt = conn.prepare(
            "SELECT c.alias, sg.earned_exp FROM character c
             JOIN skill_group sg ON sg.entity_id = c.character_id AND sg.skill_group_kind = 'General'
             ORDER BY sg.earned_exp DESC LIMIT 25",
        )?;
        stmt.query_map([], |row| Ok(json!({ "name": row.get::<_, String>(0)?, "general_xp": row.get::<_, i64>(1)? })))?
            .collect::<rusqlite::Result<Vec<_>>>()
    })
    .await?;
    Ok(Json(json!({ "players": rows })))
}

async fn balance(State(state): State<AppState>, headers: HeaderMap) -> ApiResult {
    let session = alpha_session(&headers, &state)?;
    wallet_balance(&state, &session.wallet).await
}

async fn wallet_balance(state: &AppState, wallet: &str) -> ApiResult {
    let lamports = rpc(state, "getBalance", json!([wallet]))
        .await?
        .get("value")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let vgld = match &state.cfg.vgld_mint {
        Some(mint) => {
            let result = rpc(
                state,
                "getTokenAccountsByOwner",
                json!([wallet, { "mint": mint }, { "encoding": "jsonParsed" }]),
            )
            .await?;
            let accounts = parsed_token_accounts(&result);
            let decimals = accounts.first().map_or(0, |entry| entry.2);
            let total: u64 = accounts.iter().map(|entry| entry.1).sum();
            json!({ "base_units": total.to_string(), "decimals": decimals })
        },
        None => Value::Null,
    };
    Ok(Json(json!({ "sol_lamports": lamports, "vgld": vgld })))
}

async fn land(State(state): State<AppState>, headers: HeaderMap) -> ApiResult {
    let session = alpha_session(&headers, &state)?;
    let parcels: Vec<Value> = fs::read(&state.cfg.parcels_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default();
    let result = rpc(
        &state,
        "getTokenAccountsByOwner",
        json!([session.wallet, { "programId": SPL_TOKEN_PROGRAM }, { "encoding": "jsonParsed" }]),
    )
    .await?;
    let held: HashSet<String> = parsed_token_accounts(&result)
        .into_iter()
        .filter(|(_, amount, decimals)| *amount == 1 && *decimals == 0)
        .map(|(mint, _, _)| mint)
        .collect();
    let owned: Vec<Value> = parcels
        .into_iter()
        .filter(|parcel| parcel.get("land_nft_id").and_then(Value::as_str).is_some_and(|id| held.contains(id)))
        .collect();
    Ok(Json(json!({ "parcels": owned })))
}

#[tokio::main]
async fn main() {
    let cfg = Config::from_env();
    let bind: SocketAddr = std::env::var("SITE_API_BIND")
        .unwrap_or_else(|_| "127.0.0.1:19260".to_string())
        .parse()
        .expect("SITE_API_BIND must be a socket address");
    let market = market::Market::open(&cfg.market_db, &cfg.market_key_file).expect("marketplace storage");
    let state = AppState {
        market: Arc::new(market),
        cfg: Arc::new(cfg),
        http: reqwest::Client::builder().timeout(Duration::from_secs(15)).build().expect("http client"),
        challenges: Arc::default(),
        sessions: Arc::default(),
        requests: Arc::default(),
        admin_lock: Arc::default(),
    };

    let app = Router::new()
        .route("/api/v1/status", get(status))
        .route("/api/v1/leaderboard", get(leaderboard))
        .route("/api/v1/auth/challenge", post(auth_challenge))
        .route("/api/v1/auth/verify", post(auth_verify))
        .route("/api/v1/me", get(me))
        .route("/api/v1/me/characters", get(characters))
        .route("/api/v1/me/characters/{id}/inventory", get(inventory))
        .route("/api/v1/me/balance", get(balance))
        .route("/api/v1/me/land", get(land))
        .route("/api/v1/market/listings", get(market::listings).post(market::create))
        .route("/api/v1/market/listings/{id}", axum::routing::delete(market::cancel))
        .route("/api/v1/market/listings/{id}/purchase", post(market::purchase))
        .route("/api/v1/market/listings/{id}/confirm", post(market::confirm))
        .route("/api/v1/market/listings/{id}/revoke", post(market::revoke))
        .route("/api/v1/market/owned", get(market::owned))
        .route("/api/v1/market/approve", post(market::prepare_approval))
        .route("/api/v1/game/deliveries", get(market::pending_deliveries))
        .route("/api/v1/game/entitlements/{wallet}", get(market::entitlements))
        .route("/api/v1/game/deliveries/{id}/ack", post(market::ack_delivery))
        .route("/api/v1/admin/market", get(market::market_info))
        .route("/api/v1/admin/market/assets", post(market::register_asset))
        .route("/api/v1/admin/market/mint-character", post(market::mint_character))
        .route("/api/v1/admin/market/mint-land", post(market::mint_land))
        .route("/api/v1/admin/market/mint-building", post(market::mint_building))
        .route("/api/v1/admin/overview", get(admin::overview))
        .route("/api/v1/admin/members", get(admin::members).post(admin::add))
        .route("/api/v1/admin/members/{wallet}", put(admin::update).delete(admin::remove))
        .route("/api/v1/admin/settings", put(admin::settings))
        .route("/api/v1/admin/audit", get(admin::audit_log))
        .route("/api/v1/admin/lookup/{wallet}", get(admin::lookup))
        .with_state(state);

    println!("Rune Haven site API listening on {bind}");
    let listener = tokio::net::TcpListener::bind(bind).await.expect("failed to bind site API");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .expect("site API failed");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_walks_nested_containers_and_skips_pseudo_items() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE item (item_id INTEGER PRIMARY KEY, parent_container_item_id INTEGER, item_definition_id TEXT, stack_size INTEGER, position TEXT, properties TEXT);
             INSERT INTO item VALUES (10, 1, 'veloren.core.pseudo_containers.inventory', 1, 'inventory', '{}');
             INSERT INTO item VALUES (11, 1, 'veloren.core.pseudo_containers.loadout', 1, 'loadout', '{}');
             INSERT INTO item VALUES (20, 10, 'common.items.armor.bag', 1, 'a', '{}');
             INSERT INTO item VALUES (21, 20, 'common.items.food.apple', 5, 'b', '{}');
             INSERT INTO item VALUES (22, 11, 'common.items.weapons.sword.starter', 1, 'c', '{}');
             INSERT INTO item VALUES (30, 2, 'common.items.food.other_character', 9, 'd', '{}');",
        )
        .unwrap();
        let rows = inventory_rows(&conn, 1).unwrap();
        let ids: Vec<_> = rows.iter().map(|r| r["id"].as_str().unwrap().to_owned()).collect();
        assert_eq!(rows.len(), 3);
        assert!(ids.contains(&"common.items.food.apple".to_owned()));
        assert!(!ids.iter().any(|id| id.contains("other_character")));
        let sword = rows.iter().find(|r| r["id"] == "common.items.weapons.sword.starter").unwrap();
        assert_eq!(sword["container"], "equipped");
    }

    #[test]
    fn game_uuid_is_stable() {
        assert_eq!(game_uuid("abc"), game_uuid("abc"));
        assert_ne!(game_uuid("abc"), game_uuid("abd"));
    }

    #[test]
    #[ignore = "needs SITE_GAME_DB pointing at a real save"]
    fn inventory_query_runs_on_real_save() {
        let path = std::env::var("SITE_GAME_DB").expect("SITE_GAME_DB");
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let ids: Vec<i64> = conn.prepare("SELECT character_id FROM character").unwrap().query_map([], |r| r.get(0)).unwrap().collect::<Result<_, _>>().unwrap();
        for id in &ids {
            let rows = inventory_rows(&conn, *id).unwrap();
            println!("character {id}: {} items", rows.len());
        }
        assert!(!ids.is_empty());
    }
}