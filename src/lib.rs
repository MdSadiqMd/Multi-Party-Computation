use axum::{body::Body, Router};
use worker::{event, Env, Request as WorkerRequest, Response as WorkerResponse};

pub mod api;
pub mod env_wrapper;
pub mod error;
pub mod meta;
pub mod processing;
pub mod storage;

#[event(fetch)]
pub async fn main(
    req: WorkerRequest,
    env: Env,
    _ctx: worker::Context,
) -> worker::Result<WorkerResponse> {
    let router = api::routes(env.clone());

    // Convert Cloudflare Workers Request to Axum Request
    let method = req.method().into();
    let uri = req.url()?.to_string().parse().unwrap();
    let headers = req.headers().into();
    let body = Body::from(req.bytes().await?);

    let axum_request = http::Request::builder()
        .method(method)
        .uri(uri)
        .headers(headers)
        .body(body)
        .unwrap();

    // Call the Axum router
    let axum_response = router
        .oneshot(axum_request)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;

    // Convert Axum Response to Cloudflare Workers Response
    let status = axum_response.status().as_u16();
    let headers = axum_response.headers().clone();
    let body = hyper::body::to_bytes(axum_response.into_body())
        .await
        .unwrap_or_default();

    let worker_response = WorkerResponse::from_bytes(body.to_vec())?
        .with_status(status)
        .with_headers(headers);

    Ok(worker_response)
}
