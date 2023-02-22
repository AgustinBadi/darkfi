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

use std::collections::HashMap;

use darkfi::{
    consensus::{
        ValidatorState, ValidatorStatePtr, TESTNET_BOOTSTRAP_TIMESTAMP, TESTNET_GENESIS_HASH_BYTES,
        TESTNET_GENESIS_TIMESTAMP, TESTNET_INITIAL_DISTRIBUTION,
    },
    wallet::WalletDb,
    zk::{empty_witnesses, ProvingKey, ZkCircuit},
    zkas::ZkBinary,
    Result,
};
use darkfi_money_contract::{MONEY_CONTRACT_ZKAS_BURN_NS_V1, MONEY_CONTRACT_ZKAS_MINT_NS_V1};
use darkfi_sdk::{
    crypto::{
        pasta_prelude::*, ContractId, Keypair, MerkleTree, PublicKey, CONSENSUS_CONTRACT_ID,
        MONEY_CONTRACT_ID,
    },
    db::SMART_CONTRACT_ZKAS_DB_NAME,
};
use darkfi_serial::serialize;
use log::{info, warn};
use rand::rngs::OsRng;

use darkfi_consensus_contract::{
    CONSENSUS_CONTRACT_ZKAS_BURN_NS_V1, CONSENSUS_CONTRACT_ZKAS_MINT_NS_V1,
};

pub fn init_logger() -> Result<()> {
    let mut cfg = simplelog::ConfigBuilder::new();
    cfg.add_filter_ignore("sled".to_string());
    if let Err(_) = simplelog::TermLogger::init(
        //simplelog::LevelFilter::Info,
        simplelog::LevelFilter::Debug,
        //simplelog::LevelFilter::Trace,
        cfg.build(),
        simplelog::TerminalMode::Mixed,
        simplelog::ColorChoice::Auto,
    ) {
        warn!(target: "consensus_harness", "Logger already initialized");
    }

    Ok(())
}

pub struct ConsensusTestHarness {
    pub faucet_kp: Keypair,
    pub alice_kp: Keypair,
    pub faucet_pubkeys: Vec<PublicKey>,
    pub faucet_state: ValidatorStatePtr,
    pub alice_state: ValidatorStatePtr,
    pub money_contract_id: ContractId,
    pub consensus_contract_id: ContractId,
    pub proving_keys: HashMap<[u8; 32], Vec<(&'static str, ProvingKey)>>,
    pub mint_zkbin: ZkBinary,
    pub burn_zkbin: ZkBinary,
    pub mint_pk: ProvingKey,
    pub burn_pk: ProvingKey,
    pub consensus_mint_zkbin: ZkBinary,
    pub consensus_burn_zkbin: ZkBinary,
    pub consensus_mint_pk: ProvingKey,
    pub consensus_burn_pk: ProvingKey,
    pub faucet_merkle_tree: MerkleTree,
    pub faucet_staked_coins_merkle_tree: MerkleTree,
    pub faucet_staked_coins_secrets_merkle_tree: MerkleTree,
    pub alice_merkle_tree: MerkleTree,
    pub alice_staked_coins_merkle_tree: MerkleTree,
    pub alice_staked_coins_secrets_merkle_tree: MerkleTree,
}

impl ConsensusTestHarness {
    pub async fn new() -> Result<Self> {
        let faucet_kp = Keypair::random(&mut OsRng);
        let alice_kp = Keypair::random(&mut OsRng);
        let faucet_pubkeys = vec![faucet_kp.public];

        let faucet_wallet = WalletDb::new("sqlite::memory:", "foo").await?;
        let alice_wallet = WalletDb::new("sqlite::memory:", "foo").await?;

        let faucet_sled_db = sled::Config::new().temporary(true).open()?;
        let alice_sled_db = sled::Config::new().temporary(true).open()?;

        let faucet_state = ValidatorState::new(
            &faucet_sled_db,
            *TESTNET_BOOTSTRAP_TIMESTAMP,
            *TESTNET_GENESIS_TIMESTAMP,
            *TESTNET_GENESIS_HASH_BYTES,
            *TESTNET_INITIAL_DISTRIBUTION,
            faucet_wallet,
            faucet_pubkeys.clone(),
            false,
            false,
        )
        .await?;

        let alice_state = ValidatorState::new(
            &alice_sled_db,
            *TESTNET_BOOTSTRAP_TIMESTAMP,
            *TESTNET_GENESIS_TIMESTAMP,
            *TESTNET_GENESIS_HASH_BYTES,
            *TESTNET_INITIAL_DISTRIBUTION,
            alice_wallet,
            faucet_pubkeys.clone(),
            false,
            false,
        )
        .await?;

        let faucet_sled = faucet_state.read().await.blockchain.sled_db.clone();

        info!(target: "consensus_harness", "Decoding money contract bincode");
        let money_contract_id = *MONEY_CONTRACT_ID;
        let db_handle = faucet_state.read().await.blockchain.contracts.lookup(
            &faucet_sled,
            &money_contract_id,
            SMART_CONTRACT_ZKAS_DB_NAME,
        )?;
        let mint_zkbin = db_handle.get(&serialize(&MONEY_CONTRACT_ZKAS_MINT_NS_V1))?.unwrap();
        let burn_zkbin = db_handle.get(&serialize(&MONEY_CONTRACT_ZKAS_BURN_NS_V1))?.unwrap();
        let mint_zkbin = ZkBinary::decode(&mint_zkbin)?;
        let burn_zkbin = ZkBinary::decode(&burn_zkbin)?;
        let mint_witnesses = empty_witnesses(&mint_zkbin);
        let burn_witnesses = empty_witnesses(&burn_zkbin);
        let mint_circuit = ZkCircuit::new(mint_witnesses, mint_zkbin.clone());
        let burn_circuit = ZkCircuit::new(burn_witnesses, burn_zkbin.clone());

        info!(target: "consensus_harness", "Decoding consensus contract bincode");
        let consensus_contract_id = *CONSENSUS_CONTRACT_ID;
        let db_handle = faucet_state.read().await.blockchain.contracts.lookup(
            &faucet_sled,
            &consensus_contract_id,
            SMART_CONTRACT_ZKAS_DB_NAME,
        )?;
        let consensus_mint_zkbin =
            db_handle.get(&serialize(&CONSENSUS_CONTRACT_ZKAS_MINT_NS_V1))?.unwrap();
        let consensus_burn_zkbin =
            db_handle.get(&serialize(&CONSENSUS_CONTRACT_ZKAS_BURN_NS_V1))?.unwrap();
        let consensus_mint_zkbin = ZkBinary::decode(&consensus_mint_zkbin)?;
        let consensus_burn_zkbin = ZkBinary::decode(&consensus_burn_zkbin)?;
        let consensus_mint_witnesses = empty_witnesses(&consensus_mint_zkbin);
        let consensus_burn_witnesses = empty_witnesses(&consensus_burn_zkbin);
        let consensus_mint_circuit =
            ZkCircuit::new(consensus_mint_witnesses, consensus_mint_zkbin.clone());
        let consensus_burn_circuit =
            ZkCircuit::new(consensus_burn_witnesses, consensus_burn_zkbin.clone());

        info!(target: "consensus_harness", "Creating zk proving keys");
        let k = 13;
        let mut proving_keys = HashMap::<[u8; 32], Vec<(&str, ProvingKey)>>::new();
        let mint_pk = ProvingKey::build(k, &mint_circuit);
        let burn_pk = ProvingKey::build(k, &burn_circuit);
        let pks = vec![
            (MONEY_CONTRACT_ZKAS_MINT_NS_V1, mint_pk.clone()),
            (MONEY_CONTRACT_ZKAS_BURN_NS_V1, burn_pk.clone()),
        ];
        proving_keys.insert(money_contract_id.inner().to_repr(), pks);
        let consensus_mint_pk = ProvingKey::build(k, &consensus_mint_circuit);
        let consensus_burn_pk = ProvingKey::build(k, &consensus_burn_circuit);
        let pks = vec![
            (CONSENSUS_CONTRACT_ZKAS_MINT_NS_V1, consensus_mint_pk.clone()),
            (CONSENSUS_CONTRACT_ZKAS_BURN_NS_V1, consensus_burn_pk.clone()),
        ];
        proving_keys.insert(consensus_contract_id.inner().to_repr(), pks);

        let faucet_merkle_tree = MerkleTree::new(100);
        let faucet_staked_coins_merkle_tree = MerkleTree::new(100);
        let faucet_staked_coins_secrets_merkle_tree = MerkleTree::new(100);
        let alice_merkle_tree = MerkleTree::new(100);
        let alice_staked_coins_merkle_tree = MerkleTree::new(100);
        let alice_staked_coins_secrets_merkle_tree = MerkleTree::new(100);

        Ok(Self {
            faucet_kp,
            alice_kp,
            faucet_pubkeys,
            faucet_state,
            alice_state,
            money_contract_id,
            consensus_contract_id,
            proving_keys,
            mint_pk,
            burn_pk,
            mint_zkbin,
            burn_zkbin,
            consensus_mint_pk,
            consensus_burn_pk,
            consensus_mint_zkbin,
            consensus_burn_zkbin,
            faucet_merkle_tree,
            faucet_staked_coins_merkle_tree,
            faucet_staked_coins_secrets_merkle_tree,
            alice_merkle_tree,
            alice_staked_coins_merkle_tree,
            alice_staked_coins_secrets_merkle_tree,
        })
    }
}
