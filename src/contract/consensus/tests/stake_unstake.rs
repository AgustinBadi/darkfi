/* This file is part of DarkFi (https://dark.fi)
 *
 * Copyright (C) 2020-2023 Dyne.org foundation
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//! Integration test of consensus staking and unstaking for Alice.
//!
//! We first airdrop Alica native tokes, and then she can stake and unstake
//! them a couple of times.
//!
//! With this test, we want to confirm the consensus contract state
//! transitions work for a single party and are able to be verified.
//!
//! TODO: Malicious cases

use darkfi::{tx::Transaction, Result};
use darkfi_sdk::{
    crypto::{
        merkle_prelude::*, pallas, pasta_prelude::*, poseidon_hash, MerkleNode, Nullifier,
        DARK_TOKEN_ID,
    },
    ContractCall,
};
use darkfi_serial::Encodable;
use log::info;
use rand::rngs::OsRng;

use darkfi_money_contract::{
    client::{build_transfer_tx, Coin, EncryptedNote, OwnCoin},
    MoneyFunction,
};

use darkfi_consensus_contract::{client::build_stake_tx, ConsensusFunction};

mod harness;
use harness::{init_logger, ConsensusTestHarness};

#[async_std::test]
async fn consensus_contract_stake_unstake() -> Result<()> {
    init_logger()?;

    // Some numbers we want to assert
    const ALICE_INITIAL: u64 = 100;

    // The faucet will now mint some tokens for Alice
    let mut th = ConsensusTestHarness::new().await?;
    // We're just going to be using a zero spend-hook and user-data
    let spend_hook = pallas::Base::zero();
    let user_data = pallas::Base::zero();
    let user_data_blind = pallas::Base::random(&mut OsRng);

    let mut alice_owncoins = vec![];
    info!(target: "consensus", "[Faucet] ===================================================");
    info!(target: "consensus", "[Faucet] Building Money::Transfer params for Alice's airdrop");
    info!(target: "consensus", "[Faucet] ===================================================");
    let (alice_params, alice_proofs, alicedrop_secret_keys, _spent_coins) = build_transfer_tx(
        &th.faucet_kp,
        &th.alice_kp.public,
        ALICE_INITIAL,
        *DARK_TOKEN_ID,
        spend_hook,
        user_data,
        user_data_blind,
        &[],
        &th.faucet_merkle_tree,
        &th.mint_zkbin,
        &th.mint_pk,
        &th.burn_zkbin,
        &th.burn_pk,
        true,
    )?;

    info!(target: "consensus", "[Faucet] =====================================");
    info!(target: "consensus", "[Faucet] Building airdrop tx with Alice params");
    info!(target: "consensus", "[Faucet] =====================================");
    let mut data = vec![MoneyFunction::Transfer as u8];
    alice_params.encode(&mut data)?;
    let calls = vec![ContractCall { contract_id: th.money_contract_id, data }];
    let proofs = vec![alice_proofs];
    let mut alicedrop_tx = Transaction { calls, proofs, signatures: vec![] };
    let sigs = alicedrop_tx.create_sigs(&mut OsRng, &alicedrop_secret_keys)?;
    alicedrop_tx.signatures = vec![sigs];

    info!(target: "consensus", "[Faucet] ==========================");
    info!(target: "consensus", "[Faucet] Executing Alice airdrop tx");
    info!(target: "consensus", "[Faucet] ==========================");
    th.faucet_state.read().await.verify_transactions(&[alicedrop_tx.clone()], true).await?;
    th.faucet_merkle_tree.append(&MerkleNode::from(alice_params.outputs[0].coin));

    info!(target: "consensus", "[Alice] ==========================");
    info!(target: "consensus", "[Alice] Executing Alice airdrop tx");
    info!(target: "consensus", "[Alice] ==========================");
    th.alice_state.read().await.verify_transactions(&[alicedrop_tx.clone()], true).await?;
    th.alice_merkle_tree.append(&MerkleNode::from(alice_params.outputs[0].coin));
    // Alice has to witness this coin because it's hers.
    let alice_leaf_pos = th.alice_merkle_tree.witness().unwrap();

    assert!(th.faucet_merkle_tree.root(0).unwrap() == th.alice_merkle_tree.root(0).unwrap());

    // Alice builds an `OwnCoin` from her airdrop
    let ciphertext = alice_params.outputs[0].ciphertext.clone();
    let ephem_public = alice_params.outputs[0].ephem_public;
    let e_note = EncryptedNote { ciphertext, ephem_public };
    let note = e_note.decrypt(&th.alice_kp.secret)?;
    let alice_oc = OwnCoin {
        coin: Coin::from(alice_params.outputs[0].coin),
        note: note.clone(),
        secret: th.alice_kp.secret, // <-- What should this be?
        nullifier: Nullifier::from(poseidon_hash([th.alice_kp.secret.inner(), note.serial])),
        leaf_position: alice_leaf_pos,
    };
    alice_owncoins.push(alice_oc);

    // Simulate a stake transaction on slot 1
    let slot = 1;

    info!(target: "consensus", "[Alice] ====================================================");
    info!(target: "consensus", "[Alice] Building Consensus::Stake params for Alice's owncoin");
    info!(target: "consensus", "[Alice] ====================================================");
    let (alice_params, alice_proofs, alicedrop_secret_keys, _alice_consensus_coins) =
        build_stake_tx(
            &alice_owncoins,
            &mut th.alice_merkle_tree,
            &mut th.alice_staked_coins_merkle_tree,
            &mut th.alice_staked_coins_secrets_merkle_tree,
            &th.consensus_mint_zkbin,
            &th.consensus_mint_pk,
            &th.burn_zkbin,
            &th.burn_pk,
            slot,
        )?;

    info!(target: "consensus", "[Alice] ===================================");
    info!(target: "consensus", "[Alice] Building stake tx with Alice params");
    info!(target: "consensus", "[Alice] ===================================");
    let mut data = vec![ConsensusFunction::Stake as u8];
    alice_params.encode(&mut data)?;
    let calls = vec![ContractCall { contract_id: th.consensus_contract_id, data }];
    let proofs = vec![alice_proofs];
    let mut alice_stake_tx = Transaction { calls, proofs, signatures: vec![] };
    let sigs = alice_stake_tx.create_sigs(&mut OsRng, &alicedrop_secret_keys)?;
    alice_stake_tx.signatures = vec![sigs];

    info!(target: "consensus", "[Faucet] ========================");
    info!(target: "consensus", "[Faucet] Executing Alice stake tx");
    info!(target: "consensus", "[Faucet] ========================");
    th.faucet_state.read().await.verify_transactions(&[alice_stake_tx.clone()], true).await?;
    th.faucet_merkle_tree.append(&MerkleNode::from(alice_params.outputs[0].coin_commit_hash));
    th.faucet_staked_coins_merkle_tree
        .append(&MerkleNode::from(alice_params.outputs[0].coin_commit_hash));

    info!(target: "consensus", "[Alice] ========================");
    info!(target: "consensus", "[Alice] Executing Alice stake tx");
    info!(target: "consensus", "[Alice] ========================");
    th.alice_state.read().await.verify_transactions(&[alice_stake_tx.clone()], true).await?;
    th.alice_merkle_tree.append(&MerkleNode::from(alice_params.outputs[0].coin_commit_hash));
    th.alice_merkle_tree.witness().unwrap();

    assert!(th.faucet_merkle_tree.root(0).unwrap() == th.alice_merkle_tree.root(0).unwrap());
    assert!(
        th.faucet_staked_coins_merkle_tree.root(0).unwrap() ==
            th.alice_staked_coins_merkle_tree.root(0).unwrap()
    );

    // TODO: Execute unstake transaction

    // Thanks for reading
    Ok(())
}
