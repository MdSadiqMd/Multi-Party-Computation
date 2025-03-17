use crate::{
    error::Result,
    meta::{StorageLocation, TransactionRequest, UserRequest},
    processing,
};
use axum::{
    extract::Path,
    routing::{get, post},
    Json, Router,
};
use worker::Env;

pub fn routes() -> Router {
    Router::new()
        .route("/vault", post(store_vault))
        .route("/vault/:pubkey", get(retrieve_vault))
        .route("/sign", post(sign_transaction))
}

pub async fn store_vault(
    env: Env,
    Json(payload): Json<UserRequest>,
) -> Result<Json<Vec<StorageLocation>>> {
    processing::validate_signature(&payload)?;
    let locations = processing::distribute_shares(&env, payload).await?;
    Ok(Json(locations))
}

pub async fn retrieve_vault(Path(pubkey): Path<String>) -> Result<Json<Vec<String>>> {
    let shares = processing::retrieve_shares(&pubkey).await?;
    Ok(Json(shares))
}

pub async fn sign_transaction(Json(payload): Json<TransactionRequest>) -> Result<Json<String>> {
    let signature = processing::solana_sign(payload).await?;
    Ok(Json(signature))
}
