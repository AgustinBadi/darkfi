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

use darkfi_money_contract::model::{Input, Output};
use darkfi_sdk::crypto::{pallas, Coin, MerkleNode, Nullifier, PublicKey, ValueBlind, ValueCommit};
use darkfi_serial::{SerialDecodable, SerialEncodable};

/// Inputs and outputs for staking coins
#[derive(Clone, Debug, SerialEncodable, SerialDecodable)]
pub struct ConsensusStakeParams {
    /// Anonymous inputs
    pub inputs: Vec<Input>,
    /// Anonymous outputs for staking
    pub outputs: Vec<StakedOutput>,
    /// Token blind to reveal token ID
    pub token_blind: ValueBlind,
}

/// Inputs and outputs for unstaking coins
#[derive(Clone, Debug, SerialEncodable, SerialDecodable)]
pub struct ConsensusUnstakeParams {
    /// Anonymous staked inputs
    pub inputs: Vec<StakedInput>,
    /// Anonymous outputs
    pub outputs: Vec<Output>,
    /// Token blind to reveal token ID
    pub token_blind: ValueBlind,
}

/// Staking anonymous input
#[derive(Clone, Debug, SerialEncodable, SerialDecodable)]
pub struct StakedInput {
    /// Revealed nullifier
    pub nullifier: Nullifier,
    /// Pedersen commitment for the output's value
    pub value_commit: ValueCommit,
    /// Minted coin
    pub coin_commit_hash: pallas::Base,
    /// Coin public key hash
    pub coin_pk_hash: pallas::Base,
    /// Coin commitment root
    pub coin_commit_root: MerkleNode,
    /// Secret key merkle tree root
    pub sk_root: MerkleNode,
}

/// Staking anonymous output
#[derive(Clone, Debug, SerialEncodable, SerialDecodable)]
pub struct StakedOutput {
    /// Pedersen commitment for the output's value
    pub value_commit: ValueCommit,
    /// Minted coin
    pub coin_commit_hash: pallas::Base,
    /// Coin public key hash
    pub coin_pk_hash: pallas::Base,
    /// The encrypted note ciphertext
    pub ciphertext: Vec<u8>,
    /// The ephemeral public key
    pub ephem_public: PublicKey,
}

/// State update produced by staking
#[derive(Clone, Debug, SerialEncodable, SerialDecodable)]
pub struct ConsensusStakeUpdate {
    /// Revealed nullifiers
    pub nullifiers: Vec<Nullifier>,
    /// Minted coins
    pub coins: Vec<Coin>,
}
