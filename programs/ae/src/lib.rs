use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

use xsalsa20poly1305::{
    aead::{Aead, NewAead},
    Nonce, XSalsa20Poly1305,
};

#[program]
pub mod ae {
    use super::*;

    pub fn commit_value(
        ctx: Context<CommitValue>,
        public_key: Vec<u8>,
        nonce: Vec<u8>,
        cipher_text: Vec<u8>,
    ) -> Result<()> {
        let acc = &mut ctx.accounts.encrypted_account;
        acc.public_key = public_key;
        acc.nonce = nonce;
        acc.cipher_text = cipher_text;
        Ok(())
    }

    pub fn reveal_value(ctx: Context<RevealValue>, secret_key: Vec<u8>) -> Result<()> {
        let acc = &mut ctx.accounts.encrypted_account;

        let nonce = Nonce::from_slice(acc.nonce.as_slice());
        let key = xsalsa20poly1305::Key::from_slice(secret_key.as_slice());
        let cypher = XSalsa20Poly1305::new(key);
        acc.plain_text = cypher.decrypt(nonce, acc.cipher_text.as_slice()).unwrap();

        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(
    public_key: Vec<u8>,
    nonce: Vec<u8>,
    cipher_text: Vec<u8>)]

pub struct CommitValue<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(init,
        seeds = [&public_key],
        bump,
        payer = payer,
        space = 4096)]
    pub encrypted_account: Account<'info, EncryptedAccount>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction()]

pub struct RevealValue<'info> {
    #[account(mut)]
    pub encrypted_account: Account<'info, EncryptedAccount>,
}

#[account]
#[derive(Default)]
pub struct EncryptedAccount {
    pub public_key: Vec<u8>,  // 4+32 bytes
    pub nonce: Vec<u8>,       // 4+24 bytes
    pub cipher_text: Vec<u8>, // 4+24 bytes (for 8 byte plain_text)
    pub plain_text: Vec<u8>,  // 4+8 bytes
}
