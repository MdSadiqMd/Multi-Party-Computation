use worker::{event, Context, Env, Request, Response, Result};
mod processing;
pub mod error;
pub mod meta;
pub mod storage;

#[event(fetch)]
pub async fn main(_req: Request, _env: Env, _ctx: Context) -> Result<Response> {
    Response::ok("Hello, world!")
}
