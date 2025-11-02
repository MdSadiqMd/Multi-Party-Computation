use axum::body::Body;
use tower::util::ServiceExt;
use worker::{event, Env, Request as WorkerRequest, Response as WorkerResponse};

pub mod api;
pub mod crypto;
pub mod env_wrapper;
pub mod error;
pub mod meta;
pub mod monitoring;
pub mod processing;
pub mod storage;

#[event(fetch)]
pub async fn main(
    mut req: WorkerRequest,
    env: Env,
    _ctx: worker::Context,
) -> worker::Result<WorkerResponse> {
    let router = api::routes(env.clone());

    // Convert Cloudflare Workers Request to Axum Request
    let method: http::Method = match req.method() {
        worker::Method::Get => http::Method::GET,
        worker::Method::Post => http::Method::POST,
        worker::Method::Put => http::Method::PUT,
        worker::Method::Delete => http::Method::DELETE,
        worker::Method::Patch => http::Method::PATCH,
        worker::Method::Options => http::Method::OPTIONS,
        worker::Method::Head => http::Method::HEAD,
        _ => http::Method::GET,
    };
    let uri_str = req.url()?.to_string();
    let uri: http::Uri = uri_str.parse().unwrap();

    // Get body first to avoid borrow issues
    let body_bytes = req.bytes().await?;
    let body = Body::from(body_bytes);

    let worker_headers = req.headers();

    let mut builder = http::Request::builder().method(method).uri(uri);
    for (key, value) in worker_headers.entries() {
        builder = builder.header(key, value);
    }

    let axum_request = builder.body(body).unwrap();
    let axum_response = router
        .oneshot(axum_request)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;

    let status = axum_response.status().as_u16();
    let axum_headers = axum_response.headers().clone();
    let body = hyper::body::to_bytes(axum_response.into_body())
        .await
        .unwrap_or_default();

    let mut worker_response = WorkerResponse::from_bytes(body.to_vec())?.with_status(status);
    for (key, value) in axum_headers.iter() {
        if let Ok(val_str) = value.to_str() {
            worker_response = worker_response.with_headers({
                let mut headers = worker::Headers::new();
                let _ = headers.set(key.as_str(), val_str);
                headers
            });
        }
    }

    Ok(worker_response)
}
