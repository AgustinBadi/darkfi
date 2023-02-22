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

#[cfg(not(feature = "no-entrypoint"))]
use darkfi_sdk::{
    crypto::{
        pallas, pasta_prelude::*, pedersen_commitment_base, Coin, ContractId, MerkleNode,
        PublicKey, DARK_TOKEN_ID,
    },
    db::{db_contains_key, db_init, db_lookup, db_set, SMART_CONTRACT_ZKAS_DB_NAME},
    error::ContractResult,
    merkle::merkle_add,
    msg, set_return_data, ContractCall,
};

use darkfi_sdk::error::ContractError;

#[cfg(not(feature = "no-entrypoint"))]
use darkfi_serial::{deserialize, serialize, Encodable, WriteExt};

#[cfg(not(feature = "no-entrypoint"))]
use darkfi_money_contract::{MONEY_CONTRACT_ZKAS_BURN_NS_V1, MONEY_CONTRACT_ZKAS_MINT_NS_V1};

/// Functions we allow in this contract
#[repr(u8)]
pub enum ConsensusFunction {
    Stake = 0x00,
    Unstake = 0x01,
}

impl TryFrom<u8> for ConsensusFunction {
    type Error = ContractError;

    fn try_from(b: u8) -> core::result::Result<ConsensusFunction, Self::Error> {
        match b {
            0x00 => Ok(Self::Stake),
            0x01 => Ok(Self::Unstake),
            _ => Err(ContractError::InvalidFunction),
        }
    }
}

/// Structures and object definitions
pub mod model;

#[cfg(not(feature = "no-entrypoint"))]
use model::{ConsensusStakeParams, ConsensusStakeUpdate, ConsensusUnstakeParams};

#[cfg(feature = "client")]
/// Transaction building API for clients interacting with this contract.
pub mod client;

#[cfg(not(feature = "no-entrypoint"))]
darkfi_sdk::define_contract!(
    init: init_contract,
    exec: process_instruction,
    apply: process_update,
    metadata: get_metadata
);

// These are the different sled trees that will be created
pub const CONSENSUS_CONTRACT_MERKLE_TREE: &str = "consensus_coin_tree";
pub const CONSENSUS_CONTRACT_ROOTS_TREE: &str = "consensus_coin_roots";
pub const CONSENSUS_CONTRACT_SK_ROOTS_TREE: &str = "consensus_coin_sk_roots";
pub const CONSENSUS_CONTRACT_NULLIFIERS_TREE: &str = "consensus_nullifiers";
pub const CONSENSUS_CONTRACT_INFO_TREE: &str = "consensus_info";

/// zkas contract namespaces
pub const CONSENSUS_CONTRACT_ZKAS_MINT_NS_V1: &str = "Consensus_Mint_V1";
pub const CONSENSUS_CONTRACT_ZKAS_BURN_NS_V1: &str = "Consensus_Burn_V1";

/// This function runs when the contract is (re)deployed and initialized.
#[cfg(not(feature = "no-entrypoint"))]
fn init_contract(cid: ContractId, _ix: &[u8]) -> ContractResult {
    // The zkas circuits can simply be embedded in the wasm and set up by
    // the initialization. Note that the tree should then be called "zkas".
    // The lookups can then be done by `contract_id+_zkas+namespace`.
    let zkas_db = match db_lookup(cid, SMART_CONTRACT_ZKAS_DB_NAME) {
        Ok(v) => v,
        Err(_) => db_init(cid, SMART_CONTRACT_ZKAS_DB_NAME)?,
    };

    let consensus_mint_v1_bincode = include_bytes!("../proof/consensus_mint_v1.zk.bin");
    let consensus_burn_v1_bincode = include_bytes!("../proof/consensus_burn_v1.zk.bin");

    db_set(
        zkas_db,
        &serialize(&CONSENSUS_CONTRACT_ZKAS_MINT_NS_V1),
        &consensus_mint_v1_bincode[..],
    )?;
    db_set(
        zkas_db,
        &serialize(&CONSENSUS_CONTRACT_ZKAS_BURN_NS_V1),
        &consensus_burn_v1_bincode[..],
    )?;

    // Set up a database tree to hold lead Merkle roots
    if db_lookup(cid, CONSENSUS_CONTRACT_ROOTS_TREE).is_err() {
        db_init(cid, CONSENSUS_CONTRACT_ROOTS_TREE)?;
    }

    // Set up a database tree to hold lead Merkle roots
    if db_lookup(cid, CONSENSUS_CONTRACT_SK_ROOTS_TREE).is_err() {
        db_init(cid, CONSENSUS_CONTRACT_SK_ROOTS_TREE)?;
    }

    // Set up a database tree to hold nullifiers
    if db_lookup(cid, CONSENSUS_CONTRACT_NULLIFIERS_TREE).is_err() {
        db_init(cid, CONSENSUS_CONTRACT_NULLIFIERS_TREE)?;
    }

    // Set up a database tree to hold info
    if db_lookup(cid, CONSENSUS_CONTRACT_INFO_TREE).is_err() {
        db_init(cid, CONSENSUS_CONTRACT_INFO_TREE)?;
    }

    Ok(())
}

/// This function is used by the VM's host to fetch the necessary metadata for
/// verifying signatures and zk proofs.
#[cfg(not(feature = "no-entrypoint"))]
fn get_metadata(_cid: ContractId, ix: &[u8]) -> ContractResult {
    let (call_idx, call): (u32, Vec<ContractCall>) = deserialize(ix)?;
    assert!(call_idx < call.len() as u32);

    let self_ = &call[call_idx as usize];

    match ConsensusFunction::try_from(self_.data[0])? {
        ConsensusFunction::Stake => {
            let params: ConsensusStakeParams = deserialize(&self_.data[1..])?;

            let mut zk_public_values: Vec<(String, Vec<pallas::Base>)> = vec![];
            let mut signature_pubkeys: Vec<PublicKey> = vec![];

            for input in &params.inputs {
                let value_coords = input.value_commit.to_affine().coordinates().unwrap();
                let token_coords = input.token_commit.to_affine().coordinates().unwrap();
                let (sig_x, sig_y) = input.signature_public.xy();

                zk_public_values.push((
                    MONEY_CONTRACT_ZKAS_BURN_NS_V1.to_string(),
                    vec![
                        input.nullifier.inner(),
                        *value_coords.x(),
                        *value_coords.y(),
                        *token_coords.x(),
                        *token_coords.y(),
                        input.merkle_root.inner(),
                        input.user_data_enc,
                        sig_x,
                        sig_y,
                    ],
                ));

                signature_pubkeys.push(input.signature_public);
            }

            for output in &params.outputs {
                let value_coords = output.value_commit.to_affine().coordinates().unwrap();

                zk_public_values.push((
                    CONSENSUS_CONTRACT_ZKAS_MINT_NS_V1.to_string(),
                    vec![
                        *value_coords.x(),
                        *value_coords.y(),
                        output.coin_pk_hash,
                        output.coin_commit_hash,
                    ],
                ));
            }

            let mut metadata = vec![];
            zk_public_values.encode(&mut metadata)?;
            signature_pubkeys.encode(&mut metadata)?;

            // Using this, we pass the above data to the host.
            set_return_data(&metadata)?;
            Ok(())
        }

        ConsensusFunction::Unstake => {
            let params: ConsensusUnstakeParams = deserialize(&self_.data[1..])?;

            let mut zk_public_values: Vec<(String, Vec<pallas::Base>)> = vec![];

            for input in &params.inputs {
                let value_coords = input.value_commit.to_affine().coordinates().unwrap();
                zk_public_values.push((
                    CONSENSUS_CONTRACT_ZKAS_BURN_NS_V1.to_string(),
                    vec![
                        *value_coords.x(),
                        *value_coords.y(),
                        input.coin_pk_hash,
                        input.coin_commit_hash,
                        input.coin_commit_root.inner(),
                        input.sk_root.inner(),
                        input.nullifier.inner(),
                    ],
                ));
            }

            for output in &params.outputs {
                let value_coords = output.value_commit.to_affine().coordinates().unwrap();
                let token_coords = output.token_commit.to_affine().coordinates().unwrap();

                zk_public_values.push((
                    MONEY_CONTRACT_ZKAS_MINT_NS_V1.to_string(),
                    vec![
                        output.coin,
                        *value_coords.x(),
                        *value_coords.y(),
                        *token_coords.x(),
                        *token_coords.y(),
                    ],
                ));
            }
            let mut metadata = vec![];
            zk_public_values.encode(&mut metadata)?;

            // Using this, we pass the above data to the host.
            set_return_data(&metadata)?;
            Ok(())
        }
    }
}

/// This function verifies a state transition and produces an
/// update if everything is successful.
#[cfg(not(feature = "no-entrypoint"))]
fn process_instruction(cid: ContractId, ix: &[u8]) -> ContractResult {
    let (call_idx, call): (u32, Vec<ContractCall>) = deserialize(ix)?;
    assert!(call_idx < call.len() as u32);

    let self_ = &call[call_idx as usize];

    match ConsensusFunction::try_from(self_.data[0])? {
        ConsensusFunction::Stake => {
            msg!("[Stake] Entered match arm");
            let params: ConsensusStakeParams = deserialize(&self_.data[1..])?;

            assert!(params.inputs.len() == params.outputs.len());

            // Verify token commitment
            let tokcom = pedersen_commitment_base(DARK_TOKEN_ID.inner(), params.token_blind);
            if params.inputs.iter().any(|input| input.token_commit != tokcom) {
                msg!("[Stake] Error: Tried to stake non-native token. Unable to proceed");
                return Err(ContractError::Custom(26))
            }

            let nullifiers_db = db_lookup(cid, CONSENSUS_CONTRACT_NULLIFIERS_TREE)?;
            let coin_roots_db = db_lookup(cid, CONSENSUS_CONTRACT_ROOTS_TREE)?;

            // Accumulator for the value commitments
            let mut valcom_total = pallas::Point::identity();

            // State transition for payments
            let mut new_nullifiers = Vec::with_capacity(params.inputs.len());

            msg!("[Stake] Iterating over anonymous inputs");
            for (i, input) in params.inputs.iter().enumerate() {
                // The Merkle root is used to know whether this is a coin that existed
                // in a previous state.
                if !db_contains_key(coin_roots_db, &serialize(&input.merkle_root))? {
                    msg!("[Stake] Error: Merkle root not found in previous state (input {})", i);
                    return Err(ContractError::Custom(21))
                }

                // The nullifiers should not already exist. It is the double-spend protection.
                if new_nullifiers.contains(&input.nullifier) ||
                    db_contains_key(nullifiers_db, &serialize(&input.nullifier))?
                {
                    msg!("[Stake] Error: Duplicate nullifier found in input {}", i);
                    return Err(ContractError::Custom(22))
                }

                new_nullifiers.push(input.nullifier);
                valcom_total += input.value_commit;
            }

            // Newly created coins for this transaction are in the outputs.
            let mut new_coins = Vec::with_capacity(params.outputs.len());
            for (i, output) in params.outputs.iter().enumerate() {
                // TODO: Should we have coins in a sled tree too to check dupes?
                if new_coins.contains(&Coin::from(output.coin_commit_hash)) {
                    msg!("[Stake] Error: Duplicate coin found in output {}", i);
                    return Err(ContractError::Custom(23))
                }
                new_coins.push(Coin::from(output.coin_commit_hash));
                valcom_total -= output.value_commit;
            }

            // If the accumulator is not back in its initial state, there's a value mismatch.
            if valcom_total != pallas::Point::identity() {
                msg!("[Stake] Error: Value commitments do not result in identity");
                return Err(ContractError::Custom(24))
            }

            // Create a state update
            let update = ConsensusStakeUpdate { nullifiers: new_nullifiers, coins: new_coins };
            let mut update_data = vec![];
            update_data.write_u8(ConsensusFunction::Stake as u8)?;
            update.encode(&mut update_data)?;
            set_return_data(&update_data)?;
            msg!("[Stake] State update set!");

            Ok(())
        }

        ConsensusFunction::Unstake => {
            msg!("[Unstake] Entered match arm");
            let params: ConsensusUnstakeParams = deserialize(&self_.data[1..])?;

            assert!(params.inputs.len() == params.outputs.len());

            // Verify token commitment
            let tokcom = pedersen_commitment_base(DARK_TOKEN_ID.inner(), params.token_blind);
            if params.outputs.iter().any(|output| output.token_commit != tokcom) {
                msg!("[Stake] Error: Tried to unstake non-native token. Unable to proceed");
                return Err(ContractError::Custom(26))
            }

            let nullifiers_db = db_lookup(cid, CONSENSUS_CONTRACT_NULLIFIERS_TREE)?;
            let coin_roots_db = db_lookup(cid, CONSENSUS_CONTRACT_ROOTS_TREE)?;
            let sk_roots_db = db_lookup(cid, CONSENSUS_CONTRACT_SK_ROOTS_TREE)?;

            // Accumulator for the value commitments
            let mut valcom_total = pallas::Point::identity();

            // State transition for payments
            let mut new_nullifiers = Vec::with_capacity(params.inputs.len());

            msg!("[Stake] Iterating over anonymous inputs");
            for (i, input) in params.inputs.iter().enumerate() {
                // The Merkle root is used to know whether this is a coin that existed
                // in a previous state.
                if !db_contains_key(coin_roots_db, &serialize(&input.coin_commit_root))? {
                    msg!("[Unstake] Error: Merkle root not found in previous state (input {})", i);
                    return Err(ContractError::Custom(21))
                }

                // Add secret key root to db.
                if !db_contains_key(sk_roots_db, &serialize(&input.sk_root))? {
                    msg!(
                        "[Unstake] Error: sk merkle root not found in previous state (input {})",
                        i
                    );
                    return Err(ContractError::Custom(21))
                }

                // The nullifiers should not already exist. It is the double-spend protection.
                if new_nullifiers.contains(&input.nullifier) ||
                    db_contains_key(nullifiers_db, &serialize(&input.nullifier))?
                {
                    msg!("[Unstake] Error: Duplicate nullifier found in input {}", i);
                    return Err(ContractError::Custom(22))
                }

                new_nullifiers.push(input.nullifier);
                valcom_total += input.value_commit;
            }

            // Newly created coins for this transaction are in the outputs.
            let mut new_coins = Vec::with_capacity(params.outputs.len());
            for (i, output) in params.outputs.iter().enumerate() {
                // TODO: Should we have coins in a sled tree too to check dupes?
                if new_coins.contains(&Coin::from(output.coin)) {
                    msg!("[Unstake] Error: Duplicate coin found in output {}", i);
                    return Err(ContractError::Custom(23))
                }
                new_coins.push(Coin::from(output.coin));
                valcom_total -= output.value_commit;
            }

            // If the accumulator is not back in its initial state, there's a value mismatch.
            if valcom_total != pallas::Point::identity() {
                msg!("[UnStake] Error: Value commitments do not result in identity");
                return Err(ContractError::Custom(24))
            }

            // Create a state update
            let update = ConsensusStakeUpdate { nullifiers: new_nullifiers, coins: new_coins };
            let mut update_data = vec![];
            update_data.write_u8(ConsensusFunction::Unstake as u8)?;
            update.encode(&mut update_data)?;
            set_return_data(&update_data)?;
            msg!("[Unstake] State update set!");

            Ok(())
        }
    }
}

#[cfg(not(feature = "no-entrypoint"))]
fn process_update(cid: ContractId, update_data: &[u8]) -> ContractResult {
    match ConsensusFunction::try_from(update_data[0])? {
        ConsensusFunction::Stake | ConsensusFunction::Unstake => {
            let update: ConsensusStakeUpdate = deserialize(&update_data[1..])?;

            let info_db = db_lookup(cid, CONSENSUS_CONTRACT_INFO_TREE)?;
            let nullifiers_db = db_lookup(cid, CONSENSUS_CONTRACT_NULLIFIERS_TREE)?;
            let coin_roots_db = db_lookup(cid, CONSENSUS_CONTRACT_ROOTS_TREE)?;

            for nullifier in update.nullifiers {
                db_set(nullifiers_db, &serialize(&nullifier), &[])?;
            }

            msg!("Adding coins {:?} to Merkle tree", update.coins);
            let coins: Vec<_> = update.coins.iter().map(|x| MerkleNode::from(x.inner())).collect();
            merkle_add(
                info_db,
                coin_roots_db,
                &serialize(&CONSENSUS_CONTRACT_MERKLE_TREE),
                &coins,
            )?;

            Ok(())
        }
    }
}
