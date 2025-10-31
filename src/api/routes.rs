use crate::{
    env_wrapper::WorkerEnv,
    error::Result,
    meta::{StorageLocation, TransactionRequest, UserRequest},
    processing,
};
use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};

pub fn routes(env: worker::Env) -> Router {
    let state = WorkerEnv::new(env);
    Router::new()
        .route("/vault", post(store_vault))
        .route("/vault/:pubkey", get(retrieve_vault))
        .route("/sign", post(sign_transaction))
        .with_state(state)
}

pub async fn store_vault(
    State(state): State<WorkerEnv>,
    Json(payload): Json<UserRequest>,
) -> Result<Json<Vec<StorageLocation>>> {
    let env = state.inner();
    let locations = processing::distribute_shares(env, payload).await?;
    Ok(Json(locations))
}

pub async fn retrieve_vault(
    State(state): State<WorkerEnv>,
    Path(pubkey): Path<String>,
) -> Result<Json<Vec<String>>> {
    let env = state.inner();
    let shares = processing::retrieve_shares(env, &pubkey).await?;
    Ok(Json(shares))
}

pub async fn sign_transaction(Json(payload): Json<TransactionRequest>) -> Result<Json<String>> {
    let signature = processing::solana_sign(payload).await?;
    Ok(Json(signature))
}
