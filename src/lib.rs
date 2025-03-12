use worker::{event, Context, Env, Request, Response, Result, Router};

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let router = Router::new();
    router
        .get_async("/", |_, _| async move { Response::ok("200") })
        .run(req, env)
        .await
}
