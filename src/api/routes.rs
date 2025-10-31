use crate::{
    env_wrapper::WorkerEnv,
    meta::{TransactionRequest, UserRequest},
    processing,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::post,
    Json, Router,
};

pub fn routes(env: worker::Env) -> Router {
    let state = WorkerEnv::new(env);
    Router::new()
        // .route("/vault", post(store_vault))
        // .route("/vault/:pubkey", get(retrieve_vault))
        .route("/sign", post(sign_transaction))
        .with_state(state)
}

pub async fn store_vault(
    State(state): State<WorkerEnv>,
    Json(payload): Json<UserRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let env = state.inner();
    match processing::distribute_shares(env, payload).await {
        Ok(locations) => (
            StatusCode::OK,
            Json(serde_json::to_value(locations).unwrap()),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        ),
    }
}

pub async fn retrieve_vault(
    State(state): State<WorkerEnv>,
    Path(pubkey): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let env = state.inner();
    match processing::retrieve_shares(env, &pubkey).await {
        Ok(shares) => (StatusCode::OK, Json(serde_json::to_value(shares).unwrap())),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        ),
    }
}

pub async fn sign_transaction(
    Json(payload): Json<TransactionRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    match processing::solana_sign(payload).await {
        Ok(signature) => (
            StatusCode::OK,
            Json(serde_json::to_value(signature).unwrap()),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        ),
    }
}
