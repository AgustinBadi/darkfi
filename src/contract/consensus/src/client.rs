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

//! This module implements the client-side of this contract's interaction.
//! What we basically do here is implement an API that creates the necessary
//! structures and is able to export them to create a DarkFi Transaction
//! object that can be broadcasted to the network when we want to stake some
//! coins in our wallet.
//! Note that this API doesn't involve any wallet interaction, but only
//! takes the necessary objects provided by the caller. This is so we can
//! abstract away the wallet interface to client implementations.

use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit};
use darkfi::{
    consensus::LeadCoin as ConsensusCoin,
    zk::{Proof, ProvingKey, Witness, ZkCircuit},
    zkas::ZkBinary,
    ClientFailed, Error, Result,
};
use darkfi_money_contract::{
    client::{create_transfer_burn_proof, create_transfer_mint_proof, Note, OwnCoin},
    model::{Input, Output},
};
use darkfi_sdk::crypto::{
    diffie_hellman::{kdf_sapling, sapling_ka_agree},
    merkle_prelude::*,
    pallas,
    pasta_prelude::*,
    pedersen_commitment_base, pedersen_commitment_u64, poseidon_hash, Keypair, MerkleNode,
    MerklePosition, MerkleTree, PublicKey, SecretKey, TokenId, ValueBlind, ValueCommit,
    DARK_TOKEN_ID,
};
use darkfi_serial::{Decodable, Encodable, SerialDecodable, SerialEncodable};
use halo2_proofs::circuit::Value;
use log::error;
use rand::rngs::OsRng;

use crate::model::{ConsensusStakeParams, ConsensusUnstakeParams, StakedInput, StakedOutput};

/// Byte length of the AEAD tag of the chacha20 cipher used for note encryption
pub const AEAD_TAG_SIZE: usize = 16;

/// The `ConsensusNote` holds the inner attributes of a staked `OwnCoin`
#[derive(Debug, Clone, Eq, PartialEq, SerialEncodable, SerialDecodable)]
pub struct ConsensusNote {
    /// Serial number of the coin
    pub serial: pallas::Base,
    /// Value of the coin
    pub value: u64,
    /// Token ID of the coin
    pub token_id: TokenId,
    /// Coin's secret key
    pub secret: SecretKey,
    /// Coin's creation slot
    pub slot: u64,
}

impl ConsensusNote {
    /// Encrypt the note to some given `PublicKey` using an AEAD cipher.
    pub fn encrypt(&self, public_key: &PublicKey) -> Result<EncryptedConsensusNote> {
        let ephem_keypair = Keypair::random(&mut OsRng);
        let shared_secret = sapling_ka_agree(&ephem_keypair.secret, public_key);
        let key = kdf_sapling(&shared_secret, &ephem_keypair.public);

        let mut input = vec![];
        self.encode(&mut input)?;
        let input_len = input.len();

        let mut ciphertext = vec![0_u8; input_len + AEAD_TAG_SIZE];
        ciphertext[..input_len].copy_from_slice(&input);

        ChaCha20Poly1305::new(key.as_ref().into())
            .encrypt_in_place([0u8; 12][..].into(), &[], &mut ciphertext)
            .unwrap();

        Ok(EncryptedConsensusNote { ciphertext, ephem_public: ephem_keypair.public })
    }
}

/// The `EncryptedConsensusNote` represents a structure holding the ciphertext (which is
/// an encryption of the `ConsensusNote` object, and the ephemeral `PublicKey` created at
/// the time when the encryption was done
#[derive(Debug, Clone, Eq, PartialEq, SerialEncodable, SerialDecodable)]
pub struct EncryptedConsensusNote {
    /// Ciphertext of the encrypted `ConsensusNote`
    pub ciphertext: Vec<u8>,
    /// Ephemeral public key created at the time of encrypting the note
    pub ephem_public: PublicKey,
}

impl EncryptedConsensusNote {
    /// Attempt to decrypt an `EncryptedConsensusNote` given a secret key.
    pub fn decrypt(&self, secret: &SecretKey) -> Result<ConsensusNote> {
        let shared_secret = sapling_ka_agree(secret, &self.ephem_public);
        let key = kdf_sapling(&shared_secret, &self.ephem_public);

        let ciphertext_len = self.ciphertext.len();
        let mut plaintext = vec![0_u8; ciphertext_len];
        plaintext.copy_from_slice(&self.ciphertext);

        match ChaCha20Poly1305::new(key.as_ref().into()).decrypt_in_place(
            [0u8; 12][..].into(),
            &[],
            &mut plaintext,
        ) {
            Ok(()) => Ok(ConsensusNote::decode(&plaintext[..ciphertext_len - AEAD_TAG_SIZE])?),
            Err(e) => Err(Error::NoteDecryptionFailed(e.to_string())),
        }
    }
}

/// Struct representing the public inputs of consensus mint proof
struct ConsensusMintRevealed {
    /// Value commitment
    pub value_commit: ValueCommit,
    /// Public key
    pub pk: pallas::Base,
    /// Commitment x coordinate
    pub commitment_x: pallas::Base,
    /// Commitment y coordinate
    pub commitment_y: pallas::Base,
}

impl ConsensusMintRevealed {
    /// Generate the public inputs of consensus mint proof
    pub fn compute(
        value: u64,
        pk: pallas::Base,
        value_blind: pallas::Scalar,
        commitment: pallas::Point,
    ) -> Self {
        let value_commit = pedersen_commitment_u64(value, value_blind);
        let coord = commitment.to_affine().coordinates().unwrap();
        Self { value_commit, pk, commitment_x: *coord.x(), commitment_y: *coord.y() }
    }

    /// Convert struct to halo2 API compatible vector
    pub fn to_vec(&self) -> Vec<pallas::Base> {
        let value_coord = self.value_commit.to_affine().coordinates().unwrap();
        let value_cm_x = *value_coord.x();
        let value_cm_y = *value_coord.y();
        let coin_commit_coords = [self.commitment_x, self.commitment_y];
        let coin_commit_hash = poseidon_hash(coin_commit_coords);
        vec![value_cm_x, value_cm_y, self.pk, coin_commit_hash]
    }
}

/// Generate a consensus mint proof
fn create_consensus_mint_proof(
    zkbin: &ZkBinary,
    pk: &ProvingKey,
    public_key: pallas::Base,
    coin_commitment: pallas::Point,
    value: u64,
    value_blind: ValueBlind,
    coin_blind: ValueBlind,
    sk: pallas::Base,
    sk_root: pallas::Base,
    slot: pallas::Base,
    nonce: pallas::Base,
) -> Result<(Proof, ConsensusMintRevealed)> {
    let revealed = ConsensusMintRevealed::compute(value, public_key, value_blind, coin_commitment);

    let prover_witnesses = vec![
        Witness::Base(Value::known(sk)),
        Witness::Base(Value::known(sk_root)),
        Witness::Base(Value::known(slot)),
        Witness::Base(Value::known(nonce)),
        Witness::Scalar(Value::known(coin_blind)),
        Witness::Base(Value::known(pallas::Base::from(value))),
        Witness::Scalar(Value::known(value_blind)),
    ];
    let circuit = ZkCircuit::new(prover_witnesses, zkbin.clone());
    let proof = Proof::create(pk, &[circuit], &revealed.to_vec(), &mut OsRng)?;

    Ok((proof, revealed))
}

/// Struct representing the public inputs of consensus burn proof
struct ConsensusBurnRevealed {
    /// Value commitment
    pub value_commit: ValueCommit,
    /// Public key
    pub pk: pallas::Base,
    /// Commitment x coordinate
    pub commitment_x: pallas::Base,
    /// Commitment y coordinate
    pub commitment_y: pallas::Base,
    /// Commitment merkle root
    pub commitment_root: pallas::Base,
    /// Secret key merkle root
    pub sk_root: pallas::Base,
    /// Burnt coin nullifier
    pub nullifier: pallas::Base,
}

impl ConsensusBurnRevealed {
    /// Generate the public inputs of consensus burn proof
    pub fn compute(
        value: pallas::Base,
        value_blind: ValueBlind,
        pk: pallas::Base,
        commitment: pallas::Point,
        commitment_root: pallas::Base,
        sk_root: pallas::Base,
        nullifier: pallas::Base,
    ) -> Self {
        let value_commit = pedersen_commitment_base(value, value_blind);
        let coord = commitment.to_affine().coordinates().unwrap();
        let commitment_x = *coord.x();
        let commitment_y = *coord.y();
        Self { value_commit, pk, commitment_x, commitment_y, commitment_root, sk_root, nullifier }
    }

    /// Convert struct to halo2 API compatible vector
    pub fn to_vec(&self) -> Vec<pallas::Base> {
        let coord = self.value_commit.to_affine().coordinates().unwrap();
        let value_cm_x = *coord.x();
        let value_cm_y = *coord.y();
        vec![
            value_cm_x,
            value_cm_y,
            self.pk,
            self.commitment_x,
            self.commitment_y,
            self.commitment_root,
            self.sk_root,
            self.nullifier,
        ]
    }
}

/// Generate a consensus burn proof
fn create_consensus_burn_proof(
    zkbin: &ZkBinary,
    pk: &ProvingKey,
    value: pallas::Base,
    value_blind: ValueBlind,
    coin_blind: ValueBlind,
    public_key: pallas::Base,
    sk: pallas::Base,
    sk_root: pallas::Base,
    sk_pos: MerklePosition,
    sk_path: Vec<MerkleNode>,
    commitment_merkle_path: Vec<MerkleNode>,
    commitment: pallas::Point,
    commitment_root: pallas::Base,
    commitment_pos: MerklePosition,
    slot: u64,
    nonce: pallas::Base,
    nullifier: pallas::Base,
) -> Result<(Proof, ConsensusBurnRevealed)> {
    let revealed = ConsensusBurnRevealed::compute(
        value,
        value_blind,
        public_key,
        commitment,
        commitment_root,
        sk_root,
        nullifier,
    );

    let prover_witnesses = vec![
        Witness::MerklePath(Value::known(commitment_merkle_path.try_into().unwrap())),
        Witness::Uint32(Value::known(u64::from(commitment_pos).try_into().unwrap())), // u32
        Witness::Uint32(Value::known(u64::from(sk_pos).try_into().unwrap())),         // u32
        Witness::Base(Value::known(sk)),
        Witness::Base(Value::known(sk_root)),
        Witness::MerklePath(Value::known(sk_path.try_into().unwrap())),
        Witness::Base(Value::known(pallas::Base::from(slot))),
        Witness::Base(Value::known(nonce)),
        Witness::Scalar(Value::known(coin_blind)),
        Witness::Base(Value::known(value)),
        Witness::Scalar(Value::known(value_blind)),
    ];
    let circuit = ZkCircuit::new(prover_witnesses, zkbin.clone());
    let proof = Proof::create(pk, &[circuit], &revealed.to_vec(), &mut OsRng)?;

    Ok((proof, revealed))
}

/// Build consensus contract stake transaction parameters with the given data:
/// * `coins` - Set of coins we're able to stake
/// * `tx_tree` - Current Merkle tree of coins
/// * `cm_tree` - Current Merkle tree of staked coins
/// * `sk_tree` - Current Merkle tree of staked coins secret keys
/// * `consenus_mint_zkbin` - ZkBinary of the consensus mint circuit
/// * `consenus_mint_pk` - Proving key for the ZK consensus mint proof
/// * `burn_zkbin` - ZkBinary of the burn circuit
/// * `burn_pk` - Proving key for the ZK burn proof
/// * `slot` - Coin creation slot
pub fn build_stake_tx(
    coins: &[OwnCoin],
    tx_tree: &mut MerkleTree,
    cm_tree: &mut MerkleTree,
    sk_tree: &mut MerkleTree,
    consenus_mint_zkbin: &ZkBinary,
    consenus_mint_pk: &ProvingKey,
    burn_zkbin: &ZkBinary,
    burn_pk: &ProvingKey,
    slot: u64,
    user_public_key: &PublicKey,
) -> Result<(ConsensusStakeParams, Vec<Proof>, Vec<SecretKey>)> {
    let token_blind = ValueBlind::random(&mut OsRng);
    let mut params = ConsensusStakeParams { inputs: vec![], outputs: vec![], token_blind };
    let mut proofs = vec![];
    // I assumed this vec will contain a secret key for each clear input and anonymous input.
    let mut signature_secrets = vec![];
    for coin in coins.iter() {
        // Skip OwnCoins that are not DARK_TOKEN_ID
        if coin.note.token_id != *DARK_TOKEN_ID {
            let error = "Tried to stake non-native token. Unable to proceed";
            error!(target: "consensus", "Consensus::build_stake_tx(): {}", error);
            return Err(ClientFailed::VerifyError(error.to_string()).into())
        }

        // Burning own coin
        let spend_hook = pallas::Base::zero();
        let user_data = pallas::Base::zero();
        let user_data_blind = pallas::Base::random(&mut OsRng);
        let tx_leaf_position = coin.leaf_position;
        let tx_root = tx_tree.root(0).unwrap();
        let tx_merkle_path = tx_tree.authentication_path(tx_leaf_position, &tx_root).unwrap();
        let signature_secret = SecretKey::random(&mut OsRng);
        signature_secrets.push(signature_secret);
        let (own_proof, own_revealed) = create_transfer_burn_proof(
            burn_zkbin,
            burn_pk,
            coin.note.value,
            coin.note.token_id,
            coin.note.value_blind,
            token_blind,
            coin.note.serial,
            spend_hook,
            user_data,
            user_data_blind,
            coin.note.coin_blind,
            coin.secret,
            coin.leaf_position,
            tx_merkle_path.clone(),
            signature_secret,
        )?;
        params.inputs.push(Input {
            value_commit: own_revealed.value_commit,
            token_commit: own_revealed.token_commit,
            nullifier: own_revealed.nullifier,
            merkle_root: own_revealed.merkle_root,
            spend_hook: own_revealed.spend_hook,
            user_data_enc: own_revealed.user_data_enc,
            signature_public: own_revealed.signature_public,
        });
        proofs.push(own_proof);

        // Generating consensus coin
        sk_tree.append(&MerkleNode::from(coin.secret.inner()));
        let sk_pos = sk_tree.witness().unwrap();
        let sk_root = sk_tree.root(0).unwrap();
        let sk_merkle_path = sk_tree.authentication_path(sk_pos, &sk_root).unwrap();
        let consensus_coin = ConsensusCoin::new(
            coin.note.value,
            slot,                // tau
            coin.secret.inner(), // coin secret key
            sk_root,
            sk_pos.try_into().unwrap(),
            sk_merkle_path,
            coin.note.serial,
            cm_tree,
        );

        let public_key = consensus_coin.pk();
        let (consensus_proof, consensus_revealed) = create_consensus_mint_proof(
            consenus_mint_zkbin,
            consenus_mint_pk,
            public_key,
            consensus_coin.coin1_commitment,
            coin.note.value,
            coin.note.value_blind,
            consensus_coin.coin1_blind,
            coin.secret.inner(),
            sk_root.inner(),
            pallas::Base::from(slot), // tau
            coin.note.serial,         // nonce
        )?;

        // Encrypted note
        let note = ConsensusNote {
            serial: coin.note.serial,
            value: coin.note.value,
            token_id: coin.note.token_id,
            secret: coin.secret,
            slot,
        };

        let encrypted_note = note.encrypt(&user_public_key)?;

        let coin_commit_coords = [consensus_revealed.commitment_x, consensus_revealed.commitment_y];
        let coin_commit_hash = poseidon_hash(coin_commit_coords);
        params.outputs.push(StakedOutput {
            value_commit: consensus_revealed.value_commit,
            coin_commit_hash,
            coin_pk_hash: public_key,
            ciphertext: encrypted_note.ciphertext,
            ephem_public: encrypted_note.ephem_public,
        });
        proofs.push(consensus_proof);
    }
    Ok((params, proofs, signature_secrets))
}

/// Build consensus contract unstake transaction parameters with the given data:
/// * `pubkey` - Public key of the recipient
/// * `coins` - Set of coins we're able to unstake
/// * `mint_zkbin` - ZkBinary of the mint circuit
/// * `mint_pk` - Proving key for the ZK mint proof
/// * `consenus_burn_zkbin` - ZkBinary of the consensus burn circuit
/// * `consenus_burn_pk` - Proving key for the ZK consensus burn proof
pub fn build_unstake_tx(
    pubkey: &PublicKey,
    coins: &[ConsensusCoin],
    mint_zkbin: &ZkBinary,
    mint_pk: &ProvingKey,
    consenus_burn_zkbin: &ZkBinary,
    consenus_burn_pk: &ProvingKey,
) -> Result<(ConsensusUnstakeParams, Vec<Proof>, Vec<SecretKey>, Vec<ValueBlind>, Vec<ValueBlind>)>
{
    // TODO: verify this token blind usage
    let token_blind = ValueBlind::random(&mut OsRng);
    let mut params = ConsensusUnstakeParams { inputs: vec![], outputs: vec![], token_blind };
    let mut proofs = vec![];
    let mut own_blinds = vec![];
    let mut consenus_blinds = vec![];
    for coin in coins.iter() {
        // Burn consensus coin
        let value_blind = ValueBlind::random(&mut OsRng);
        consenus_blinds.push(value_blind);
        let pk = coin.pk();
        let nullifier = coin.sn();
        let (unstake_proof, unstake_revealed) = create_consensus_burn_proof(
            consenus_burn_zkbin,
            consenus_burn_pk,
            pallas::Base::from(coin.value),
            value_blind,
            coin.coin1_blind,
            pk,
            coin.coin1_sk,
            coin.coin1_sk_root.inner(),
            MerklePosition::from(coin.coin1_sk_pos as usize),
            coin.coin1_sk_merkle_path.to_vec(),
            coin.coin1_commitment_merkle_path.to_vec(),
            coin.coin1_commitment,
            coin.coin1_commitment_root.inner(),
            MerklePosition::from(coin.coin1_commitment_pos as usize),
            coin.slot,
            coin.nonce,
            nullifier,
        )?;
        let commitment_coord = [unstake_revealed.commitment_x, unstake_revealed.commitment_y];
        let coin_commitment_hash = poseidon_hash(commitment_coord);
        params.inputs.push(StakedInput {
            nullifier: nullifier.into(),
            value_commit: unstake_revealed.value_commit,
            coin_commit_hash: coin_commitment_hash,
            coin_pk_hash: unstake_revealed.pk,
            coin_commit_root: unstake_revealed.commitment_root.into(),
            sk_root: unstake_revealed.sk_root.into(),
        });
        proofs.push(unstake_proof);
        let own_value_blind = ValueBlind::random(&mut OsRng);
        own_blinds.push(own_value_blind);

        // Mint own coin
        let serial = pallas::Base::random(&mut OsRng);
        let coin_blind = pallas::Base::random(&mut OsRng);
        let token_recv_blind = ValueBlind::random(&mut OsRng);
        // Disable composability for this old obsolete API
        let spend_hook = pallas::Base::zero();
        let user_data = pallas::Base::zero();
        let (proof, revealed) = create_transfer_mint_proof(
            mint_zkbin,
            mint_pk,
            coin.value,
            *DARK_TOKEN_ID,
            own_value_blind,
            token_recv_blind,
            serial,
            spend_hook,
            user_data,
            coin_blind,
            *pubkey, //receipient public_key
        )?;
        proofs.push(proof);
        // Encrypted note
        let note = Note {
            serial,
            value: coin.value,
            token_id: *DARK_TOKEN_ID,
            spend_hook: pallas::Base::zero(),
            user_data: pallas::Base::zero(),
            coin_blind,
            value_blind,
            token_blind: token_recv_blind,
            // Here we store our secret key we use for signing
            memo: vec![],
        };

        let encrypted_note = note.encrypt(&pubkey)?;

        params.outputs.push(Output {
            value_commit: revealed.value_commit,
            token_commit: revealed.token_commit,
            coin: revealed.coin.inner(),
            ciphertext: encrypted_note.ciphertext,
            ephem_public: encrypted_note.ephem_public,
        });
    }

    Ok((params, proofs, vec![], consenus_blinds, own_blinds))
}
