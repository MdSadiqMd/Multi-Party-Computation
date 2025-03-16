use worker::{event, Context, Env, Request, Response, Result};
mod processing;

#[event(fetch)]
pub async fn main(_req: Request, _env: Env, _ctx: Context) -> Result<Response> {
    Response::ok("Hello, world!")
}
