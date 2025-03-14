use worker::{console_log, event, Context, Env, Request, Response, Result, Router};
mod crypto;

#[event(fetch)]
pub async fn main(_req: Request, _env: Env, _ctx: Context) -> Result<Response> {
    example_usage();

    Response::ok("Hello, world!")
}

pub fn example_usage() {
    let secret = b"This is a secret message";
    let threshold = 3;
    let num_shares = 5;

    match crypto::split_secret(secret, threshold, num_shares) {
        Ok(shamir_secret) => {
            console_log!(
                "Secret split into {} shares, threshold: {}",
                num_shares,
                threshold
            );
            let subset_shares = shamir_secret.shares[0..threshold as usize].to_vec();
            match crypto::reconstruct_secret(&subset_shares, secret.len()) {
                Ok(reconstructed) => {
                    console_log!(
                        "Reconstructed secret: {}",
                        String::from_utf8_lossy(&reconstructed)
                    );
                }
                Err(e) => {
                    console_log!("Failed to reconstruct: {:?}", e);
                }
            }
        }
        Err(e) => {
            console_log!("Failed to split secret: {:?}", e);
        }
    }
}
