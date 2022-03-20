import * as anchor from "@project-serum/anchor";
import { Program } from "@project-serum/anchor";
import { Ae } from "../target/types/ae";
import nacl from "tweetnacl";

import chai, { expect } from "chai";
import chai_as_promised from "chai-as-promised";
chai.use(chai_as_promised);
import chai_bytes from "chai-bytes";
chai.use(chai_bytes);

describe("ae", () => {
  const provider = anchor.Provider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.Ae as Program<Ae>;

  it("commits and reveals the value", async () => {
    const aliceKeypair = nacl.box.keyPair();
    const bobKeypair = nacl.box.keyPair();

    const nonce = nacl.randomBytes(nacl.box.nonceLength);
    const plainText = Buffer.from("12345678", "utf-8");

    // generate cyphertext with alice' secret and bob's public key
    const cipherText = nacl.box(
      plainText,
      nonce,
      bobKeypair.publicKey,
      aliceKeypair.secretKey
    );

    // publish alice' public key, nonce & cipher text publicly
    const [pda] = await anchor.web3.PublicKey.findProgramAddress(
      [aliceKeypair.publicKey],
      program.programId
    );
    await program.rpc.commitValue(
      Buffer.from(aliceKeypair.publicKey),
      Buffer.from(nonce),
      Buffer.from(cipherText),
      {
        accounts: {
          payer: provider.wallet.publicKey,
          encryptedAccount: pda,
          systemProgram: anchor.web3.SystemProgram.programId,
        },
      }
    );

    // generate decryption key with bob's secret and alice' public key
    const sharedKey = nacl.box.before(
      aliceKeypair.publicKey,
      bobKeypair.secretKey
    );

    // decrypt on-chain
    await program.rpc.revealValue(Buffer.from(sharedKey), {
      accounts: { encryptedAccount: pda },
    });

    // verify results
    const acc = await program.account.encryptedAccount.fetch(pda);
    expect(acc.nonce).to.equalBytes(nonce);
    expect(acc.publicKey).to.equalBytes(aliceKeypair.publicKey);
    expect(acc.cipherText).to.equalBytes(cipherText);
    expect(acc.plainText).to.equalBytes(plainText);
    console.log(acc);
  });

  it("detects forged secret keys", async () => {
    const aliceKeypair = nacl.box.keyPair();
    const bobKeypair = nacl.box.keyPair();

    const nonce = nacl.randomBytes(nacl.box.nonceLength);
    const plainText = Buffer.from("12345678", "utf-8");

    // generate cyphertext with alice' secret and bob's public key
    const cipherText = nacl.box(
      plainText,
      nonce,
      bobKeypair.publicKey,
      aliceKeypair.secretKey
    );

    // publish alice' public key, nonce & cipher text publicly
    const [pda] = await anchor.web3.PublicKey.findProgramAddress(
      [aliceKeypair.publicKey],
      program.programId
    );
    await program.rpc.commitValue(
      Buffer.from(aliceKeypair.publicKey),
      Buffer.from(nonce),
      Buffer.from(cipherText),
      {
        accounts: {
          payer: provider.wallet.publicKey,
          encryptedAccount: pda,
          systemProgram: anchor.web3.SystemProgram.programId,
        },
      }
    );

    // generate false decryption key with bob's secret and alice' public key
    const sharedKey = nacl.box.before(
      bobKeypair.secretKey,
      aliceKeypair.publicKey
    );

    // try to decrypt with wrong key on-chain
    expect(
      program.rpc.revealValue(Buffer.from(sharedKey), {
        accounts: { encryptedAccount: pda },
      })
    ).to.be.rejectedWith(anchor.web3.SendTransactionError);
  });
});
