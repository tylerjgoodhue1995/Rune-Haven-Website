//! Player marketplace: land, item and character NFTs sold for VGLD.
//!
//! Non-custodial: the seller approves the platform key as an SPL delegate for the single NFT, and a purchase is
//! one atomic transaction (buyer pays VGLD, delegate moves the NFT). No escrow wallet ever holds either side.

use std::{collections::HashSet, fs, path::Path as FsPath, sync::Mutex, time::Duration};

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
};
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    ApiError, ApiResult, AppState, SPL_TOKEN_PROGRAM, alpha_session, now_ms, rpc, valid_wallet,
    admin::{admin_session, audit},
};

const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
const MAX_PRICE: u64 = 1_000_000_000_000_000_000;

type Key = [u8; 32];

pub struct Market {
    key: SigningKey,
    db: Mutex<Connection>,
}

impl Market {
    pub fn open(db_path: &FsPath, key_file: &FsPath) -> Result<Self, String> {
        let seed: Key = match fs::read_to_string(key_file) {
            Ok(text) => {
                let bytes: Vec<u8> = (0..text.trim().len() / 2)
                    .map(|i| u8::from_str_radix(&text.trim()[i * 2..i * 2 + 2], 16))
                    .collect::<Result<_, _>>()
                    .map_err(|_| "market key file must be 64 hex characters")?;
                bytes.try_into().map_err(|_| "market key file must be 64 hex characters")?
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let seed: Key = rand::random();
                let hex: String = seed.iter().map(|byte| format!("{byte:02x}")).collect();
                fs::write(key_file, hex).map_err(|error| format!("could not write market key: {error}"))?;
                seed
            },
            Err(error) => return Err(format!("could not read market key: {error}")),
        };
        let conn = Connection::open(db_path).map_err(|error| format!("could not open market db: {error}"))?;
        let _ = conn.busy_timeout(Duration::from_secs(3));
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS assets(
                 mint TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('item','character')),
                 name TEXT NOT NULL, reference TEXT NOT NULL, created_at INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS listings(
                 id INTEGER PRIMARY KEY AUTOINCREMENT, mint TEXT NOT NULL, kind TEXT NOT NULL, name TEXT NOT NULL,
                 reference TEXT NOT NULL, seller TEXT NOT NULL, price INTEGER NOT NULL,
                 status TEXT NOT NULL DEFAULT 'active', buyer TEXT, signature TEXT UNIQUE,
                 created_at INTEGER NOT NULL, closed_at INTEGER);
             CREATE UNIQUE INDEX IF NOT EXISTS one_active_listing ON listings(mint) WHERE status = 'active';
             CREATE TABLE IF NOT EXISTS deliveries(
                 id INTEGER PRIMARY KEY AUTOINCREMENT, listing_id INTEGER NOT NULL UNIQUE, kind TEXT NOT NULL,
                 reference TEXT NOT NULL, mint TEXT NOT NULL, name TEXT NOT NULL, wallet TEXT NOT NULL,
                 status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL, delivered_at INTEGER);",
        )
        .map_err(|error| format!("could not prepare market db: {error}"))?;
        Ok(Self { key: SigningKey::from_bytes(&seed), db: Mutex::new(conn) })
    }

    fn delegate(&self) -> Key { self.key.verifying_key().to_bytes() }

    fn db(&self) -> std::sync::MutexGuard<'_, Connection> { self.db.lock().unwrap_or_else(|p| p.into_inner()) }
}

fn bad(message: impl Into<String>) -> ApiError { ApiError::new(StatusCode::BAD_REQUEST, message) }

fn db_err(_: rusqlite::Error) -> ApiError { ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Marketplace data could not be saved.") }

fn key(text: &str) -> Result<Key, ApiError> {
    bs58::decode(text).into_vec().ok().and_then(|bytes| bytes.try_into().ok()).ok_or_else(|| bad("Invalid address."))
}

fn konst(text: &str) -> Key { key(text).expect("constant address") }

fn b58(bytes: &[u8]) -> String { bs58::encode(bytes).into_string() }

fn find_pda(seeds: &[&[u8]], program: &Key) -> Key {
    for bump in (0..=255u8).rev() {
        let mut hasher = Sha256::new();
        for seed in seeds {
            hasher.update(seed);
        }
        hasher.update([bump]);
        hasher.update(program);
        hasher.update(b"ProgramDerivedAddress");
        let hash: Key = hasher.finalize().into();
        if VerifyingKey::from_bytes(&hash).is_err() {
            return hash;
        }
    }
    unreachable!("no valid program address bump")
}

fn ata(owner: &Key, mint: &Key) -> Key { find_pda(&[owner, &konst(SPL_TOKEN_PROGRAM), mint], &konst(ATA_PROGRAM)) }

struct Ix {
    program: Key,
    accounts: Vec<(Key, bool, bool)>, // (address, signer, writable)
    data: Vec<u8>,
}

fn compact(out: &mut Vec<u8>, mut value: usize) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Builds a legacy transaction message. Returns the message bytes and the ordered signer keys.
fn compile(payer: &Key, instructions: &[Ix], blockhash: &Key) -> (Vec<u8>, Vec<Key>) {
    let mut metas: Vec<(Key, bool, bool)> = vec![(*payer, true, true)];
    let mut touch = |address: Key, signer: bool, writable: bool| {
        if let Some(meta) = metas.iter_mut().find(|meta| meta.0 == address) {
            meta.1 |= signer;
            meta.2 |= writable;
        } else {
            metas.push((address, signer, writable));
        }
    };
    for ix in instructions {
        for (address, signer, writable) in &ix.accounts {
            touch(*address, *signer, *writable);
        }
        touch(ix.program, false, false);
    }
    let group = |signer: bool, writable: bool| metas.iter().filter(move |m| m.1 == signer && m.2 == writable).map(|m| m.0);
    let ordered: Vec<Key> = group(true, true)
        .chain(group(true, false))
        .chain(group(false, true))
        .chain(group(false, false))
        .collect();
    let signers = group(true, true).chain(group(true, false)).collect::<Vec<_>>();
    let mut message = vec![signers.len() as u8, group(true, false).count() as u8, group(false, false).count() as u8];
    compact(&mut message, ordered.len());
    for address in &ordered {
        message.extend_from_slice(address);
    }
    message.extend_from_slice(blockhash);
    compact(&mut message, instructions.len());
    let index = |address: &Key| ordered.iter().position(|a| a == address).expect("known account") as u8;
    for ix in instructions {
        message.push(index(&ix.program));
        compact(&mut message, ix.accounts.len());
        message.extend(ix.accounts.iter().map(|(address, ..)| index(address)));
        compact(&mut message, ix.data.len());
        message.extend_from_slice(&ix.data);
    }
    (message, signers)
}

fn serialize(market: &Market, payer: &Key, instructions: &[Ix], blockhash: &Key) -> String {
    let (message, signers) = compile(payer, instructions, blockhash);
    let mut tx = Vec::new();
    compact(&mut tx, signers.len());
    for signer in &signers {
        if *signer == market.delegate() {
            tx.extend_from_slice(&market.key.sign(&message).to_bytes());
        } else {
            tx.extend_from_slice(&[0u8; 64]);
        }
    }
    tx.extend_from_slice(&message);
    base64::engine::general_purpose::STANDARD.encode(tx)
}

fn create_ata_ix(payer: &Key, owner: &Key, mint: &Key) -> Ix {
    Ix {
        program: konst(ATA_PROGRAM),
        accounts: vec![
            (*payer, true, true),
            (ata(owner, mint), false, true),
            (*owner, false, false),
            (*mint, false, false),
            (konst(SYSTEM_PROGRAM), false, false),
            (konst(SPL_TOKEN_PROGRAM), false, false),
        ],
        data: vec![1],
    }
}

fn transfer_checked_ix(source: &Key, mint: &Key, dest: &Key, authority: &Key, amount: u64, decimals: u8) -> Ix {
    let mut data = vec![12];
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    Ix {
        program: konst(SPL_TOKEN_PROGRAM),
        accounts: vec![(*source, false, true), (*mint, false, false), (*dest, false, true), (*authority, true, false)],
        data,
    }
}

fn approve_checked_ix(source: &Key, mint: &Key, delegate: &Key, owner: &Key) -> Ix {
    let mut data = vec![13];
    data.extend_from_slice(&1u64.to_le_bytes());
    data.push(0);
    Ix {
        program: konst(SPL_TOKEN_PROGRAM),
        accounts: vec![(*source, false, true), (*mint, false, false), (*delegate, false, false), (*owner, true, false)],
        data,
    }
}

fn revoke_ix(source: &Key, owner: &Key) -> Ix {
    Ix { program: konst(SPL_TOKEN_PROGRAM), accounts: vec![(*source, false, true), (*owner, true, false)], data: vec![5] }
}

/// Splits a price into (seller proceeds, platform fee).
fn split_price(price: u64, fee_bps: u64) -> (u64, u64) {
    let fee = (price as u128 * fee_bps.min(10_000) as u128 / 10_000) as u64;
    (price - fee, fee)
}

async fn blockhash(state: &AppState) -> Result<Key, ApiError> {
    let result = rpc(state, "getLatestBlockhash", json!([{ "commitment": "finalized" }])).await?;
    result
        .pointer("/value/blockhash")
        .and_then(Value::as_str)
        .and_then(|text| key(text).ok())
        .ok_or_else(|| ApiError::bad_gateway("Could not fetch a Solana blockhash."))
}

struct Asset {
    kind: String,
    name: String,
    reference: String,
}

fn title(text: &str) -> String {
    text.split([' ', '_']).filter(|w| !w.is_empty()).map(|w| {
        let mut chars = w.chars();
        chars.next().map(|c| c.to_uppercase().collect::<String>() + chars.as_str()).unwrap_or_default()
    }).collect::<Vec<_>>().join(" ")
}

fn parcels(state: &AppState) -> Vec<Value> {
    fs::read(&state.cfg.parcels_path).ok().and_then(|bytes| serde_json::from_slice(&bytes).ok()).unwrap_or_default()
}

/// Only mints the platform knows about can be traded: minted game assets, or land parcels from the world file.
fn resolve_asset(state: &AppState, mint: &str) -> Option<Asset> {
    if let Some(asset) = state
        .market
        .db()
        .query_row("SELECT kind, name, reference FROM assets WHERE mint = ?1", [mint], |row| {
            Ok(Asset { kind: row.get(0)?, name: row.get(1)?, reference: row.get(2)? })
        })
        .optional()
        .ok()
        .flatten()
    {
        return Some(asset);
    }
    parcels(state).into_iter().find(|p| p.get("land_nft_id").and_then(Value::as_str) == Some(mint)).map(|p| {
        let text = |field: &str| p.get(field).and_then(Value::as_str).unwrap_or_default().to_owned();
        Asset { kind: "land".into(), name: format!("{} Â· {}", title(&text("land_type")), title(&text("region"))), reference: text("id") }
    })
}

struct TokenAccount {
    owner: String,
    amount: String,
    delegate: Option<String>,
    delegated: String,
}

async fn token_account(state: &AppState, address: &Key) -> Result<Option<TokenAccount>, ApiError> {
    let result = rpc(state, "getAccountInfo", json!([b58(address), { "encoding": "jsonParsed", "commitment": "confirmed" }])).await?;
    let Some(info) = result.pointer("/value/data/parsed/info") else { return Ok(None) };
    let text = |pointer: &str| info.pointer(pointer).and_then(Value::as_str).map(str::to_owned);
    Ok(Some(TokenAccount {
        owner: text("/owner").unwrap_or_default(),
        amount: text("/tokenAmount/amount").unwrap_or_default(),
        delegate: text("/delegate"),
        delegated: text("/delegatedAmount/amount").unwrap_or_default(),
    }))
}

/// The seller must still hold the NFT and must have approved the platform key for it.
async fn ensure_sellable(state: &AppState, seller: &str, mint: &str) -> Result<(), ApiError> {
    let account = token_account(state, &ata(&key(seller)?, &key(mint)?)).await?;
    let delegate = b58(&state.market.delegate());
    match account {
        Some(a) if a.owner == seller && a.amount == "1" => {
            if a.delegate.as_deref() == Some(delegate.as_str()) && a.delegated == "1" {
                Ok(())
            } else {
                Err(bad("Approve the marketplace for this asset in your wallet first."))
            }
        },
        _ => Err(bad("The seller no longer holds this asset.")),
    }
}

async fn vgld(state: &AppState) -> Result<(Key, u8), ApiError> {
    let mint = state.cfg.vgld_mint.as_deref().ok_or_else(|| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "VGLD is not configured yet."))?;
    let supply = rpc(state, "getTokenSupply", json!([mint])).await?;
    let decimals = supply.pointer("/value/decimals").and_then(Value::as_u64).ok_or_else(|| ApiError::bad_gateway("Could not read the VGLD token."))?;
    Ok((key(mint)?, decimals as u8))
}

fn listing_json(row: &rusqlite::Row) -> rusqlite::Result<Value> {
    Ok(json!({
        "id": row.get::<_, i64>(0)?, "mint": row.get::<_, String>(1)?, "kind": row.get::<_, String>(2)?,
        "name": row.get::<_, String>(3)?, "reference": row.get::<_, String>(4)?, "seller": row.get::<_, String>(5)?,
        "price": row.get::<_, i64>(6)?.to_string(), "created_at": row.get::<_, i64>(7)?,
    }))
}

const LISTING_COLUMNS: &str = "id, mint, kind, name, reference, seller, price, created_at";

pub async fn listings(State(state): State<AppState>, headers: HeaderMap, Query(query): Query<std::collections::HashMap<String, String>>) -> ApiResult {
    alpha_session(&headers, &state)?;
    let kind = query.get("kind").filter(|kind| matches!(kind.as_str(), "land" | "item" | "character")).cloned();
    let rows = {
        let db = state.market.db();
        let mut stmt = db
            .prepare(&format!("SELECT {LISTING_COLUMNS} FROM listings WHERE status = 'active' AND (?1 IS NULL OR kind = ?1) ORDER BY id DESC LIMIT 200"))
            .map_err(db_err)?;
        stmt.query_map([kind], listing_json).map_err(db_err)?.collect::<rusqlite::Result<Vec<_>>>().map_err(db_err)?
    };
    let token = match vgld(&state).await {
        Ok((mint, decimals)) => json!({ "mint": b58(&mint), "decimals": decimals }),
        Err(_) => Value::Null,
    };
    Ok(Json(json!({ "listings": rows, "vgld": token, "fee_bps": state.cfg.market_fee_bps })))
}

/// Single-supply tokens the wallet holds, with whether each is approved for the marketplace.
async fn held_nfts(state: &AppState, wallet: &str) -> Result<Vec<(String, bool)>, ApiError> {
    let result = rpc(state, "getTokenAccountsByOwner", json!([wallet, { "programId": SPL_TOKEN_PROGRAM }, { "encoding": "jsonParsed" }])).await?;
    let delegate = b58(&state.market.delegate());
    Ok(result
        .get("value")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            let info = entry.pointer("/account/data/parsed/info")?;
            if info.pointer("/tokenAmount/amount")?.as_str()? != "1" || info.pointer("/tokenAmount/decimals")?.as_u64()? != 0 {
                return None;
            }
            let approved = info.get("delegate").and_then(Value::as_str) == Some(delegate.as_str())
                && info.pointer("/delegatedAmount/amount").and_then(Value::as_str) == Some("1");
            Some((info.get("mint")?.as_str()?.to_owned(), approved))
        })
        .collect())
}

const SPECIES: [&str; 5] = ["Danari", "Dwarf", "Elf", "Orc", "Draugr"];
const BUILDING_TYPES: [&str; 11] = [
    "house", "shop", "inn", "blacksmith", "guild_hall", "farmhouse", "barn", "stable", "castle", "fortress", "town_hall",
];

/// Humanoid species the wallet may play, from the character NFTs it holds. Human is free and not listed.
pub async fn entitlements(State(state): State<AppState>, headers: HeaderMap, Path(wallet): Path<String>) -> ApiResult {
    game_authorized(&state, &headers)?;
    if !valid_wallet(&wallet) {
        return Err(bad("Invalid wallet."));
    }
    let held = held_nfts(&state, &wallet).await?;
    let mut species: Vec<String> = Vec::new();
    for (mint, _) in held {
        let reference: Option<String> = state
            .market
            .db()
            .query_row("SELECT reference FROM assets WHERE mint = ?1 AND kind = 'character'", [&mint], |row| row.get(0))
            .optional()
            .map_err(db_err)?;
        if let Some(name) = reference.as_deref().and_then(|r| r.strip_prefix("species:"))
            && SPECIES.contains(&name)
            && !species.iter().any(|s| s == name)
        {
            species.push(name.to_owned());
        }
    }
    Ok(Json(json!({ "species": species })))
}

/// Assets the signed-in wallet holds that can be traded, and whether each is approved or already listed.
pub async fn owned(State(state): State<AppState>, headers: HeaderMap) -> ApiResult {
    let session = alpha_session(&headers, &state)?;
    let held = held_nfts(&state, &session.wallet).await?;
    let listed: HashSet<String> = {
        let db = state.market.db();
        let mut stmt = db.prepare("SELECT mint FROM listings WHERE status = 'active' AND seller = ?1").map_err(db_err)?;
        stmt.query_map([&session.wallet], |row| row.get(0)).map_err(db_err)?.collect::<rusqlite::Result<_>>().map_err(db_err)?
    };
    let assets: Vec<Value> = held
        .into_iter()
        .filter_map(|(mint, approved)| {
            let asset = resolve_asset(&state, &mint)?;
            Some(json!({ "mint": mint, "kind": asset.kind, "name": asset.name, "reference": asset.reference, "approved": approved, "listed": listed.contains(&mint) }))
        })
        .collect();
    Ok(Json(json!({ "assets": assets })))
}

#[derive(Deserialize)]
pub struct MintBody {
    mint: String,
}

/// Unsigned transaction the seller signs in Phantom to approve the marketplace for one NFT.
pub async fn prepare_approval(State(state): State<AppState>, headers: HeaderMap, Json(body): Json<MintBody>) -> ApiResult {
    let session = alpha_session(&headers, &state)?;
    resolve_asset(&state, &body.mint).ok_or_else(|| bad("This asset cannot be traded on the marketplace."))?;
    let (seller, mint) = (key(&session.wallet)?, key(&body.mint)?);
    let source = ata(&seller, &mint);
    let account = token_account(&state, &source).await?;
    if !account.is_some_and(|a| a.owner == session.wallet && a.amount == "1") {
        return Err(bad("You do not hold this asset."));
    }
    let ixs = [approve_checked_ix(&source, &mint, &state.market.delegate(), &seller)];
    Ok(Json(json!({ "transaction": serialize(&state.market, &seller, &ixs, &blockhash(&state).await?) })))
}

#[derive(Deserialize)]
pub struct CreateBody {
    mint: String,
    price: String,
}

pub async fn create(State(state): State<AppState>, headers: HeaderMap, Json(body): Json<CreateBody>) -> ApiResult {
    let session = alpha_session(&headers, &state)?;
    let price: u64 = body.price.trim().parse().ok().filter(|p| (1..=MAX_PRICE).contains(p)).ok_or_else(|| bad("Enter a valid price."))?;
    let asset = resolve_asset(&state, &body.mint).ok_or_else(|| bad("This asset cannot be traded on the marketplace."))?;
    ensure_sellable(&state, &session.wallet, &body.mint).await?;
    let id = {
        let db = state.market.db();
        db.execute(
            "INSERT INTO listings(mint, kind, name, reference, seller, price, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![body.mint, asset.kind, asset.name, asset.reference, session.wallet, price as i64, now_ms() as i64],
        )
        .map_err(|_| bad("This asset is already listed."))?;
        db.last_insert_rowid()
    };
    Ok(Json(json!({ "id": id })))
}

fn seller_listing(state: &AppState, id: i64, wallet: &str) -> Result<(String, String), ApiError> {
    state
        .market
        .db()
        .query_row("SELECT mint, status FROM listings WHERE id = ?1 AND seller = ?2", params![id, wallet], |row| Ok((row.get(0)?, row.get(1)?)))
        .optional()
        .map_err(db_err)?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Listing not found."))
}

pub async fn cancel(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<i64>) -> ApiResult {
    let session = alpha_session(&headers, &state)?;
    seller_listing(&state, id, &session.wallet)?;
    let changed = state
        .market
        .db()
        .execute("UPDATE listings SET status = 'cancelled', closed_at = ?2 WHERE id = ?1 AND status = 'active'", params![id, now_ms() as i64])
        .map_err(db_err)?;
    Ok(Json(json!({ "cancelled": changed == 1 })))
}

/// Unsigned transaction that removes the marketplace approval, so a cancelled listing leaves nothing open.
pub async fn revoke(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<i64>) -> ApiResult {
    let session = alpha_session(&headers, &state)?;
    let (mint, status) = seller_listing(&state, id, &session.wallet)?;
    if status == "sold" {
        return Err(bad("This listing was already sold."));
    }
    let seller = key(&session.wallet)?;
    let ixs = [revoke_ix(&ata(&seller, &key(&mint)?), &seller)];
    Ok(Json(json!({ "transaction": serialize(&state.market, &seller, &ixs, &blockhash(&state).await?) })))
}

struct Listing {
    mint: String,
    kind: String,
    name: String,
    reference: String,
    seller: String,
    price: u64,
}

fn active_listing(state: &AppState, id: i64) -> Result<Listing, ApiError> {
    state
        .market
        .db()
        .query_row("SELECT mint, kind, name, reference, seller, price FROM listings WHERE id = ?1 AND status = 'active'", [id], |row| {
            Ok(Listing { mint: row.get(0)?, kind: row.get(1)?, name: row.get(2)?, reference: row.get(3)?, seller: row.get(4)?, price: row.get::<_, i64>(5)? as u64 })
        })
        .optional()
        .map_err(db_err)?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "This listing is no longer available."))
}

pub async fn purchase(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<i64>) -> ApiResult {
    let session = alpha_session(&headers, &state)?;
    let listing = active_listing(&state, id)?;
    if listing.seller == session.wallet {
        return Err(bad("You cannot buy your own listing."));
    }
    let (vgld_mint, decimals) = vgld(&state).await?;
    ensure_sellable(&state, &listing.seller, &listing.mint).await?;
    let (buyer, seller, mint) = (key(&session.wallet)?, key(&listing.seller)?, key(&listing.mint)?);
    let treasury = match &state.cfg.market_treasury {
        Some(wallet) => key(wallet)?,
        None => state.market.delegate(),
    };
    let (proceeds, fee) = split_price(listing.price, state.cfg.market_fee_bps);
    let buyer_vgld = ata(&buyer, &vgld_mint);

    let mut ixs = vec![create_ata_ix(&buyer, &buyer, &mint), create_ata_ix(&buyer, &seller, &vgld_mint)];
    ixs.push(transfer_checked_ix(&buyer_vgld, &vgld_mint, &ata(&seller, &vgld_mint), &buyer, proceeds, decimals));
    if fee > 0 {
        ixs.push(create_ata_ix(&buyer, &treasury, &vgld_mint));
        ixs.push(transfer_checked_ix(&buyer_vgld, &vgld_mint, &ata(&treasury, &vgld_mint), &buyer, fee, decimals));
    }
    ixs.push(transfer_checked_ix(&ata(&seller, &mint), &mint, &ata(&buyer, &mint), &state.market.delegate(), 1, 0));
    Ok(Json(json!({
        "transaction": serialize(&state.market, &buyer, &ixs, &blockhash(&state).await?),
        "price": listing.price.to_string(), "fee": fee.to_string(), "name": listing.name, "kind": listing.kind,
    })))
}

#[derive(Deserialize)]
pub struct ConfirmBody {
    signature: String,
}

pub async fn confirm(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<i64>, Json(body): Json<ConfirmBody>) -> ApiResult {
    let session = alpha_session(&headers, &state)?;
    if body.signature.len() > 100 || bs58::decode(&body.signature).into_vec().map_or(true, |bytes| bytes.len() != 64) {
        return Err(bad("Invalid transaction signature."));
    }
    let sold_to_caller = state
        .market
        .db()
        .query_row("SELECT 1 FROM listings WHERE id = ?1 AND status = 'sold' AND buyer = ?2", params![id, session.wallet], |_| Ok(()))
        .optional()
        .map_err(db_err)?
        .is_some();
    if sold_to_caller {
        return Ok(Json(json!({ "verified": true, "message": "Purchase complete." })));
    }
    let listing = active_listing(&state, id)?;
    let delegate = b58(&state.market.delegate());

    let mut transaction = Value::Null;
    for _ in 0..30 {
        let result = rpc(&state, "getTransaction", json!([body.signature, { "encoding": "jsonParsed", "commitment": "confirmed", "maxSupportedTransactionVersion": 0 }])).await?;
        if !result.is_null() {
            transaction = result;
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    if transaction.is_null() {
        return Ok(Json(json!({ "verified": false, "message": "Solana has not confirmed the transaction yet. Try again in a moment." })));
    }
    if !transaction.pointer("/meta/err").is_some_and(Value::is_null) {
        return Err(bad("The transaction failed on Solana."));
    }
    let involves = |address: &str| {
        transaction
            .pointer("/transaction/message/accountKeys")
            .and_then(Value::as_array)
            .is_some_and(|keys| keys.iter().any(|k| k.get("pubkey").and_then(Value::as_str) == Some(address)))
    };
    if !involves(&delegate) || !involves(&listing.mint) || !involves(&session.wallet) {
        return Err(bad("That transaction is not a purchase of this listing."));
    }
    let balance = rpc(&state, "getTokenAccountBalance", json!([b58(&ata(&key(&session.wallet)?, &key(&listing.mint)?)), { "commitment": "confirmed" }])).await;
    if !balance.ok().and_then(|b| b.pointer("/value/amount").and_then(Value::as_str).map(|a| a == "1")).unwrap_or(false) {
        return Ok(Json(json!({ "verified": false, "message": "The asset has not reached your wallet." })));
    }

    let mut db = state.market.db();
    let tx = db.transaction().map_err(db_err)?;
    let closed = tx
        .execute(
            "UPDATE listings SET status = 'sold', buyer = ?2, signature = ?3, closed_at = ?4 WHERE id = ?1 AND status = 'active'",
            params![id, session.wallet, body.signature, now_ms() as i64],
        )
        .map_err(|_| bad("This purchase was already recorded."))?;
    if closed == 1 {
        tx.execute(
            "INSERT INTO deliveries(listing_id, kind, reference, mint, name, wallet, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![id, listing.kind, listing.reference, listing.mint, listing.name, session.wallet, now_ms() as i64],
        )
        .map_err(db_err)?;
    }
    tx.commit().map_err(db_err)?;
    Ok(Json(json!({ "verified": true, "message": "Purchase complete. It will appear in game on your next login." })))
}

fn game_authorized(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let expected = state.cfg.game_key.as_deref().ok_or_else(|| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "Game delivery is not enabled."))?;
    let given = headers.get("x-game-key").and_then(|v| v.to_str().ok()).unwrap_or_default();
    let same = given.len() == expected.len() && given.bytes().zip(expected.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0;
    if same { Ok(()) } else { Err(ApiError::unauthorized("Invalid game key.")) }
}

pub async fn pending_deliveries(State(state): State<AppState>, headers: HeaderMap) -> ApiResult {
    game_authorized(&state, &headers)?;
    let db = state.market.db();
    let mut stmt = db
        .prepare("SELECT id, kind, reference, mint, name, wallet FROM deliveries WHERE status = 'pending' ORDER BY id LIMIT 200")
        .map_err(db_err)?;
    let rows = stmt
        .query_map([], |row| {
            Ok(json!({
                "id": row.get::<_, i64>(0)?, "kind": row.get::<_, String>(1)?, "reference": row.get::<_, String>(2)?,
                "mint": row.get::<_, String>(3)?, "name": row.get::<_, String>(4)?, "wallet": row.get::<_, String>(5)?,
            }))
        })
        .map_err(db_err)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(db_err)?;
    Ok(Json(json!({ "deliveries": rows })))
}

pub async fn ack_delivery(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<i64>) -> ApiResult {
    game_authorized(&state, &headers)?;
    let changed = state
        .market
        .db()
        .execute("UPDATE deliveries SET status = 'delivered', delivered_at = ?2 WHERE id = ?1 AND status = 'pending'", params![id, now_ms() as i64])
        .map_err(db_err)?;
    Ok(Json(json!({ "acknowledged": changed == 1 })))
}

#[derive(Deserialize)]
pub struct AssetBody {
    mint: String,
    kind: String,
    name: String,
    reference: String,
}

/// Registers a minted game NFT so it may be traded. Minting itself happens outside this service.
pub async fn register_asset(State(state): State<AppState>, headers: HeaderMap, Json(body): Json<AssetBody>) -> ApiResult {
    let admin = admin_session(&headers, &state)?;
    let name: String = body.name.chars().filter(|c| !c.is_control()).take(80).collect();
    let reference: String = body.reference.chars().filter(|c| !c.is_control()).take(200).collect();
    if !valid_wallet(&body.mint) || !matches!(body.kind.as_str(), "item" | "character") || name.trim().is_empty() || reference.trim().is_empty() {
        return Err(bad("Provide a valid mint, a kind of item or character, a name and a game reference."));
    }
    if body.kind == "character" && !reference.strip_prefix("species:").is_some_and(|name| SPECIES.contains(&name)) {
        return Err(bad("A character reference must be species:Danari, Dwarf, Elf, Orc or Draugr."));
    }
    state
        .market
        .db()
        .execute(
            "INSERT INTO assets(mint, kind, name, reference, created_at) VALUES (?1,?2,?3,?4,?5)
             ON CONFLICT(mint) DO UPDATE SET kind = ?2, name = ?3, reference = ?4",
            params![body.mint, body.kind, name.trim(), reference.trim(), now_ms() as i64],
        )
        .map_err(db_err)?;
    audit(&state, &admin.wallet, "market_register_asset", json!({ "mint": body.mint, "kind": body.kind }));
    Ok(Json(json!({ "registered": true })))
}

pub async fn market_info(State(state): State<AppState>, headers: HeaderMap) -> ApiResult {
    admin_session(&headers, &state)?;
    let sol_lamports = rpc(&state, "getBalance", json!([b58(&state.market.delegate())])).await.ok().and_then(|v| v.get("value").and_then(Value::as_u64));
    let db = state.market.db();
    let count = |sql: &str| db.query_row(sql, [], |row| row.get::<_, i64>(0)).unwrap_or(0);
    let characters: Vec<Value> = db
        .prepare("SELECT mint, name, reference FROM assets WHERE kind = 'character' ORDER BY created_at DESC LIMIT 50")
        .and_then(|mut stmt| {
            stmt.query_map([], |row| Ok(json!({ "mint": row.get::<_, String>(0)?, "name": row.get::<_, String>(1)?, "reference": row.get::<_, String>(2)? })))?
                .collect::<rusqlite::Result<Vec<_>>>()
        })
        .unwrap_or_default();
    let land_parcels: Vec<Value> = parcels(&state)
        .into_iter()
        .map(|parcel| {
            let mint = parcel.get("land_nft_id").and_then(Value::as_str).unwrap_or_default();
            json!({
                "id": parcel.get("id").and_then(Value::as_str).unwrap_or_default(),
                "region": parcel.get("region").and_then(Value::as_str).unwrap_or_default(),
                "land_type": parcel.get("land_type").and_then(Value::as_str).unwrap_or_default(),
                "world_id": parcel.get("world_id").and_then(Value::as_str).unwrap_or_default(),
                "mint": mint,
                "minted": valid_wallet(mint),
            })
        })
        .collect();
    let buildings: Vec<Value> = fs::read(&state.cfg.buildings_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default();
    Ok(Json(json!({
        "delegate": b58(&state.market.delegate()),
        "sol_lamports": sol_lamports,
        "vgld_mint": state.cfg.vgld_mint,
        "fee_bps": state.cfg.market_fee_bps,
        "assets": count("SELECT COUNT(*) FROM assets"),
        "active_listings": count("SELECT COUNT(*) FROM listings WHERE status = 'active'"),
        "sales": count("SELECT COUNT(*) FROM listings WHERE status = 'sold'"),
        "pending_deliveries": count("SELECT COUNT(*) FROM deliveries WHERE status = 'pending'"),
        "game_delivery_enabled": state.cfg.game_key.is_some(),
        "characters": characters,
        "parcels": land_parcels,
        "buildings": buildings,
    })))
}

fn system_create_account_ix(from: &Key, to: &Key, lamports: u64, space: u64, owner: &Key) -> Ix {
    let mut data = vec![0, 0, 0, 0];
    data.extend_from_slice(&lamports.to_le_bytes());
    data.extend_from_slice(&space.to_le_bytes());
    data.extend_from_slice(owner);
    Ix { program: konst(SYSTEM_PROGRAM), accounts: vec![(*from, true, true), (*to, true, true)], data }
}

fn initialize_mint2_ix(mint: &Key, authority: &Key) -> Ix {
    let mut data = vec![20, 0];
    data.extend_from_slice(authority);
    data.push(0);
    Ix { program: konst(SPL_TOKEN_PROGRAM), accounts: vec![(*mint, false, true)], data }
}

fn mint_to_ix(mint: &Key, dest: &Key, authority: &Key) -> Ix {
    let mut data = vec![7];
    data.extend_from_slice(&1u64.to_le_bytes());
    Ix { program: konst(SPL_TOKEN_PROGRAM), accounts: vec![(*mint, false, true), (*dest, false, true), (*authority, true, false)], data }
}

/// Removing the mint authority guarantees the supply stays at exactly one.
fn lock_supply_ix(mint: &Key, authority: &Key) -> Ix {
    Ix { program: konst(SPL_TOKEN_PROGRAM), accounts: vec![(*mint, false, true), (*authority, true, false)], data: vec![6, 0, 0] }
}

fn sign_with(keys: &[&SigningKey], payer: &Key, instructions: &[Ix], blockhash: &Key) -> Vec<u8> {
    let (message, signers) = compile(payer, instructions, blockhash);
    let mut tx = Vec::new();
    compact(&mut tx, signers.len());
    for signer in &signers {
        match keys.iter().find(|key| key.verifying_key().to_bytes() == *signer) {
            Some(key) => tx.extend_from_slice(&key.sign(&message).to_bytes()),
            None => tx.extend_from_slice(&[0u8; 64]),
        }
    }
    tx.extend_from_slice(&message);
    tx
}

async fn mint_one_of_one(state: &AppState, recipient: &Key) -> Result<(String, String), ApiError> {
    let payer = state.market.delegate();
    let mint_key = SigningKey::from_bytes(&rand::random());
    let mint = mint_key.verifying_key().to_bytes();
    let rent = rpc(state, "getMinimumBalanceForRentExemption", json!([82]))
        .await?
        .as_u64()
        .ok_or_else(|| ApiError::bad_gateway("Could not read the rent amount."))?;
    let ixs = [
        system_create_account_ix(&payer, &mint, rent, 82, &konst(SPL_TOKEN_PROGRAM)),
        initialize_mint2_ix(&mint, &payer),
        create_ata_ix(&payer, recipient, &mint),
        mint_to_ix(&mint, &ata(recipient, &mint), &payer),
        lock_supply_ix(&mint, &payer),
    ];
    let raw = sign_with(&[&state.market.key, &mint_key], &payer, &ixs, &blockhash(state).await?);
    let encoded = base64::engine::general_purpose::STANDARD.encode(raw);
    let signature = rpc(state, "sendTransaction", json!([encoded, { "encoding": "base64", "preflightCommitment": "confirmed" }]))
        .await?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| bad("Solana rejected the mint. The marketplace wallet may need devnet SOL."))?;
    for _ in 0..30 {
        let status = rpc(state, "getSignatureStatuses", json!([[signature]])).await?;
        if let Some(entry) = status.pointer("/value/0").filter(|e| !e.is_null()) {
            if !entry.get("err").is_some_and(Value::is_null) {
                return Err(bad("The mint transaction failed on Solana."));
            }
            if matches!(entry.get("confirmationStatus").and_then(Value::as_str), Some("confirmed" | "finalized")) {
                return Ok((b58(&mint), signature));
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Err(bad(format!("Mint sent but not confirmed yet. Signature {signature}")))
}

fn save_parcels(state: &AppState, parcels: &[Value]) -> Result<(), ApiError> {
    let path = &state.cfg.parcels_path;
    let temp = path.with_extension("tmp");
    let bytes = serde_json::to_vec_pretty(parcels)
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Could not serialize parcel registry."))?;
    fs::write(&temp, bytes).map_err(|_| bad("Could not write the parcel registry."))?;
    for attempt in 0..8 {
        if fs::rename(&temp, path).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(40 * (attempt + 1)));
    }
    let _ = fs::remove_file(&temp);
    Err(bad("Could not update the parcel registry. The land NFT is minted; contact an admin with its mint address."))
}

fn save_buildings(state: &AppState, buildings: &[Value]) -> Result<(), ApiError> {
    let path = &state.cfg.buildings_path;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| bad("Could not create the building registry directory."))?;
    }
    let temp = path.with_extension("tmp");
    let bytes = serde_json::to_vec_pretty(buildings)
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Could not serialize building registry."))?;
    fs::write(&temp, bytes).map_err(|_| bad("Could not write the building registry."))?;
    for attempt in 0..8 {
        if fs::rename(&temp, path).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(40 * (attempt + 1)));
    }
    let _ = fs::remove_file(&temp);
    Err(bad("Could not update the building registry. The NFT is minted; contact an admin with its mint address."))
}

fn load_buildings(path: &FsPath) -> Result<Vec<Value>, ApiError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(bad("Could not read the building registry.")),
    };
    serde_json::from_slice(&bytes)
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "The building registry is invalid; refusing to overwrite it."))
}

#[derive(Deserialize)]
pub struct MintCharacterBody {
    species: String,
    recipient: String,
}

/// Mints a one-of-one character NFT with the platform key, sends it to `recipient`, and registers it for trading.
pub async fn mint_character(State(state): State<AppState>, headers: HeaderMap, Json(body): Json<MintCharacterBody>) -> ApiResult {
    let admin = admin_session(&headers, &state)?;
    if !SPECIES.contains(&body.species.as_str()) {
        return Err(bad("Species must be Danari, Dwarf, Elf, Orc or Draugr."));
    }
    let recipient = key(&body.recipient)?;
    let (mint_text, signature) = mint_one_of_one(&state, &recipient).await?;
    state
        .market
        .db()
        .execute(
            "INSERT INTO assets(mint, kind, name, reference, created_at) VALUES (?1,'character',?2,?3,?4)",
            params![mint_text, format!("{} character", body.species), format!("species:{}", body.species), now_ms() as i64],
        )
        .map_err(db_err)?;
    audit(&state, &admin.wallet, "market_mint_character", json!({ "mint": mint_text, "species": body.species, "recipient": body.recipient }));
    Ok(Json(json!({ "mint": mint_text, "signature": signature })))
}

#[derive(Deserialize)]
pub struct MintLandBody {
    parcel_id: String,
    recipient: String,
}

pub async fn mint_land(State(state): State<AppState>, headers: HeaderMap, Json(body): Json<MintLandBody>) -> ApiResult {
    let admin = admin_session(&headers, &state)?;
    let recipient = key(&body.recipient)?;
    let mut parcels = parcels(&state);
    let parcel = parcels
        .iter_mut()
        .find(|parcel| parcel.get("id").and_then(Value::as_str) == Some(body.parcel_id.as_str()))
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Parcel not found."))?;
    let current_mint = parcel.get("land_nft_id").and_then(Value::as_str).unwrap_or_default();
    if valid_wallet(current_mint) {
        return Err(bad("This parcel already has a land NFT."));
    }
    let (mint, signature) = mint_one_of_one(&state, &recipient).await?;
    parcel["land_nft_id"] = Value::String(mint.clone());
    save_parcels(&state, &parcels)?;
    audit(&state, &admin.wallet, "market_mint_land", json!({ "mint": mint, "parcel_id": body.parcel_id, "recipient": body.recipient }));
    Ok(Json(json!({ "mint": mint, "signature": signature, "parcel_id": body.parcel_id })))
}

#[derive(Deserialize)]
pub struct MintBuildingBody {
    building_type: String,
    recipient: String,
}

pub async fn mint_building(State(state): State<AppState>, headers: HeaderMap, Json(body): Json<MintBuildingBody>) -> ApiResult {
    let admin = admin_session(&headers, &state)?;
    if !BUILDING_TYPES.contains(&body.building_type.as_str()) {
        return Err(bad("Choose a supported building type."));
    }
    let recipient = key(&body.recipient)?;
    let (mint, signature) = mint_one_of_one(&state, &recipient).await?;
    let mut buildings = load_buildings(&state.cfg.buildings_path)?;
    buildings.push(json!({ "mint": mint, "building_type": body.building_type }));
    save_buildings(&state, &buildings)?;
    state
        .market
        .db()
        .execute(
            "INSERT INTO assets(mint, kind, name, reference, created_at) VALUES (?1,'item',?2,?3,?4)",
            params![mint, format!("{} building", body.building_type.replace('_', " ")), format!("building:{}", body.building_type), now_ms() as i64],
        )
        .map_err(db_err)?;
    audit(&state, &admin.wallet, "market_mint_building", json!({ "mint": mint, "building_type": body.building_type, "recipient": body.recipient }));
    Ok(Json(json!({ "mint": mint, "signature": signature, "building_type": body.building_type })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corrupt_building_registry_is_not_silently_reset() {
        let path = std::env::temp_dir().join(format!("rh-buildings-{}.json", rand::random::<u64>()));
        assert!(load_buildings(&path).unwrap().is_empty());
        fs::write(&path, b"not json").unwrap();
        assert!(load_buildings(&path).is_err());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn compact_encoding() {
        let mut out = Vec::new();
        compact(&mut out, 127);
        compact(&mut out, 128);
        assert_eq!(out, [127, 0x80, 0x01]);
    }

    #[test]
    fn fee_split_never_exceeds_price() {
        assert_eq!(split_price(1000, 250), (975, 25));
        assert_eq!(split_price(1, 250), (1, 0));
        assert_eq!(split_price(1000, 99_999), (0, 1000));
        let (proceeds, fee) = split_price(u64::MAX, 250);
        assert_eq!(proceeds as u128 + fee as u128, u64::MAX as u128);
    }

    #[test]
    fn message_orders_accounts_and_header_counts() {
        let (payer, delegate, writable, readonly, program) = ([1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32]);
        let ix = Ix {
            program,
            accounts: vec![(readonly, false, false), (writable, false, true), (delegate, true, false), (payer, true, true)],
            data: vec![9, 9],
        };
        let (message, signers) = compile(&payer, &[ix], &[7u8; 32]);
        assert_eq!(signers, vec![payer, delegate]);
        assert_eq!(&message[..3], &[2, 1, 2]);
        assert_eq!(message[3], 5);
        let keys: Vec<&[u8]> = message[4..4 + 160].chunks(32).collect();
        assert_eq!(keys, vec![&payer[..], &delegate[..], &writable[..], &readonly[..], &program[..]]);
        // instruction: program idx 4, 4 accounts [3,2,1,0] data [9,9]
        assert_eq!(&message[4 + 160 + 32..], &[1, 4, 4, 3, 2, 1, 0, 2, 9, 9]);
    }

    #[test]
    fn derived_addresses_are_off_curve_and_stable() {
        let (owner, mint) = ([8u8; 32], [9u8; 32]);
        let derived = ata(&owner, &mint);
        assert_eq!(derived, ata(&owner, &mint));
        assert!(VerifyingKey::from_bytes(&derived).is_err());
        assert_ne!(derived, ata(&mint, &owner));
    }

    #[test]
    #[ignore = "prints a sample purchase transaction for devnet simulateTransaction"]
    fn print_sample_purchase() {
        let market = Market::open(FsPath::new(":memory:"), &std::env::temp_dir().join("rh-test-key.hex")).unwrap();
        let (buyer, seller, nft, gold) = ([11u8; 32], [12u8; 32], [13u8; 32], [14u8; 32]);
        let mut ixs = vec![create_ata_ix(&buyer, &buyer, &nft), create_ata_ix(&buyer, &seller, &gold)];
        ixs.push(transfer_checked_ix(&ata(&buyer, &gold), &gold, &ata(&seller, &gold), &buyer, 975, 6));
        ixs.push(transfer_checked_ix(&ata(&seller, &nft), &nft, &ata(&buyer, &nft), &market.delegate(), 1, 0));
        println!("TX={}", serialize(&market, &buyer, &ixs, &[3u8; 32]));
    }

    #[test]
    #[ignore = "prints a signed mint transaction for devnet simulateTransaction"]
    fn print_sample_mint() {
        let market = Market::open(FsPath::new(":memory:"), &std::env::temp_dir().join("rh-test-key.hex")).unwrap();
        let payer = market.delegate();
        let mint_key = SigningKey::from_bytes(&[21u8; 32]);
        let mint = mint_key.verifying_key().to_bytes();
        let recipient = [22u8; 32];
        let ixs = [
            system_create_account_ix(&payer, &mint, 1_461_600, 82, &konst(SPL_TOKEN_PROGRAM)),
            initialize_mint2_ix(&mint, &payer),
            create_ata_ix(&payer, &recipient, &mint),
            mint_to_ix(&mint, &ata(&recipient, &mint), &payer),
            lock_supply_ix(&mint, &payer),
        ];
        let raw = sign_with(&[&market.key, &mint_key], &payer, &ixs, &[3u8; 32]);
        println!("PAYER={}", b58(&payer));
        println!("MINTTX={}", base64::engine::general_purpose::STANDARD.encode(raw));
    }
}