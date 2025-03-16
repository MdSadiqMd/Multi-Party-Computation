use crate::error::Result;
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_instruction,
    transaction::Transaction,
};

pub fn sign_transaction(
    private_key: &str,
    receiver: &str,
    amount: u64,
    blockhash: &str,
) -> Result<String> {
    let keypair = Keypair::from_bytes(
        &bs58::decode(private_key)
            .into_vec()
            .map_err(|_| MpcError::CryptoError("Invalid private key".into()))?,
    )?;

    let to_pubkey = Pubkey::from_str(receiver)
        .map_err(|_| MpcError::CryptoError("Invalid receiver address".into()))?;

    let mut tx = Transaction::new_with_payer(
        &[system_instruction::transfer(
            &keypair.pubkey(),
            &to_pubkey,
            amount,
        )],
        Some(&keypair.pubkey()),
    );

    tx.recent_blockhash =
        Hash::from_str(blockhash).map_err(|_| MpcError::CryptoError("Invalid blockhash".into()))?;

    tx.sign(&[&keypair], tx.recent_blockhash);
    Ok(bs58::encode(tx.signatures[0]).into_string())
}
