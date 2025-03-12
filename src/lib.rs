use worker::*;

#[event(fetch)]
pub async fn main(_req: Request, _env: Env, _ctx: Context) -> Result<Response> {
    console_log!("Hello from Rust!");
    Response::ok("Hello World!")
}
