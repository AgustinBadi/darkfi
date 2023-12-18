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

use darkfi_money_contract::model::CoinParams;
use darkfi_sdk::{
    crypto::{pasta_prelude::*, pedersen_commitment_u64, poseidon_hash, SecretKey},
    pasta::pallas,
};

use log::debug;
use rand::rngs::OsRng;

use darkfi::{
    zk::{halo2::Value, Proof, ProvingKey, Witness, ZkCircuit},
    zkas::ZkBinary,
    Result,
};

use crate::model::{Dao, DaoBlindAggregateVote, DaoExecParams, DaoProposal};

pub struct DaoExecCall {
    pub proposal: DaoProposal,
    pub dao: Dao,
    pub yes_vote_value: u64,
    pub all_vote_value: u64,
    pub yes_vote_blind: pallas::Scalar,
    pub all_vote_blind: pallas::Scalar,
    pub user_serial: pallas::Base,
    pub dao_serial: pallas::Base,
    pub input_value: u64,
    pub input_value_blind: pallas::Scalar,
    pub input_user_data_blind: pallas::Base,
    pub hook_dao_exec: pallas::Base,
    pub signature_secret: SecretKey,
}

impl DaoExecCall {
    pub fn make(
        self,
        exec_zkbin: &ZkBinary,
        exec_pk: &ProvingKey,
    ) -> Result<(DaoExecParams, Vec<Proof>)> {
        debug!(target: "dao", "build()");
        let mut proofs = vec![];

        let (proposal_dest_x, proposal_dest_y) = self.proposal.dest.xy();

        let proposal_amount = pallas::Base::from(self.proposal.amount);

        let dao_proposer_limit = pallas::Base::from(self.dao.proposer_limit);
        let dao_quorum = pallas::Base::from(self.dao.quorum);
        let dao_approval_ratio_quot = pallas::Base::from(self.dao.approval_ratio_quot);
        let dao_approval_ratio_base = pallas::Base::from(self.dao.approval_ratio_base);

        let (dao_pub_x, dao_pub_y) = self.dao.public_key.xy();

        let user_spend_hook = pallas::Base::from(0);
        let user_data = pallas::Base::from(0);
        let input_value = pallas::Base::from(self.input_value);
        let change = self.input_value - self.proposal.amount;

        let dao_bulla = self.dao.to_bulla();
        assert_eq!(dao_bulla, self.proposal.dao_bulla);
        let proposal_bulla = self.proposal.to_bulla();

        let coin_0 = CoinParams {
            public_key: self.proposal.dest,
            value: self.proposal.amount,
            token_id: self.proposal.token_id,
            serial: self.user_serial,
            spend_hook: user_spend_hook,
            user_data,
        }
        .to_coin();
        debug!("created coin_0 {:?}", coin_0);

        let coin_1 = CoinParams {
            public_key: self.dao.public_key,
            value: change,
            token_id: self.proposal.token_id,
            serial: self.dao_serial,
            spend_hook: self.hook_dao_exec,
            user_data: dao_bulla.inner(),
        }
        .to_coin();
        debug!("created coin_1 {:?}", coin_1);

        let yes_vote_commit = pedersen_commitment_u64(self.yes_vote_value, self.yes_vote_blind);
        let yes_vote_commit_coords = yes_vote_commit.to_affine().coordinates().unwrap();

        let all_vote_commit = pedersen_commitment_u64(self.all_vote_value, self.all_vote_blind);
        let all_vote_commit_coords = all_vote_commit.to_affine().coordinates().unwrap();

        let input_value_commit = pedersen_commitment_u64(self.input_value, self.input_value_blind);
        let input_value_commit_coords = input_value_commit.to_affine().coordinates().unwrap();

        let prover_witnesses = vec![
            // proposal params
            Witness::Base(Value::known(proposal_dest_x)),
            Witness::Base(Value::known(proposal_dest_y)),
            Witness::Base(Value::known(proposal_amount)),
            Witness::Base(Value::known(self.proposal.token_id.inner())),
            Witness::Base(Value::known(self.proposal.content_commit)),
            Witness::Base(Value::known(self.proposal.auth_contract_id)),
            Witness::Base(Value::known(self.proposal.auth_function_id)),
            Witness::Base(Value::known(self.proposal.blind)),
            // DAO params
            Witness::Base(Value::known(dao_proposer_limit)),
            Witness::Base(Value::known(dao_quorum)),
            Witness::Base(Value::known(dao_approval_ratio_quot)),
            Witness::Base(Value::known(dao_approval_ratio_base)),
            Witness::Base(Value::known(self.dao.gov_token_id.inner())),
            Witness::Base(Value::known(dao_pub_x)),
            Witness::Base(Value::known(dao_pub_y)),
            Witness::Base(Value::known(self.dao.bulla_blind)),
            // votes
            Witness::Base(Value::known(pallas::Base::from(self.yes_vote_value))),
            Witness::Base(Value::known(pallas::Base::from(self.all_vote_value))),
            Witness::Scalar(Value::known(self.yes_vote_blind)),
            Witness::Scalar(Value::known(self.all_vote_blind)),
            // outputs + inputs
            Witness::Base(Value::known(self.user_serial)),
            Witness::Base(Value::known(self.dao_serial)),
            Witness::Base(Value::known(input_value)),
            Witness::Scalar(Value::known(self.input_value_blind)),
            // misc
            Witness::Base(Value::known(self.hook_dao_exec)),
            Witness::Base(Value::known(user_spend_hook)),
            Witness::Base(Value::known(user_data)),
            // DAO bulla spend check
            Witness::Base(Value::known(self.input_user_data_blind)),
        ];

        let input_user_data_enc = poseidon_hash([dao_bulla.inner(), self.input_user_data_blind]);
        debug!(target: "dao", "input_user_data_enc: {:?}", input_user_data_enc);

        debug!(target: "dao", "proposal_bulla: {:?}", proposal_bulla);
        let public_inputs = vec![
            proposal_bulla.inner(),
            coin_0.inner(),
            coin_1.inner(),
            *yes_vote_commit_coords.x(),
            *yes_vote_commit_coords.y(),
            *all_vote_commit_coords.x(),
            *all_vote_commit_coords.y(),
            *input_value_commit_coords.x(),
            *input_value_commit_coords.y(),
            self.hook_dao_exec,
            user_spend_hook,
            user_data,
            input_user_data_enc,
        ];
        //export_witness_json("witness.json", &prover_witnesses, &public_inputs);

        let circuit = ZkCircuit::new(prover_witnesses, exec_zkbin);
        let input_proof = Proof::create(exec_pk, &[circuit], &public_inputs, &mut OsRng)
            .expect("DAO::exec() proving error!)");
        proofs.push(input_proof);

        let params = DaoExecParams {
            proposal: proposal_bulla,
            blind_total_vote: DaoBlindAggregateVote { yes_vote_commit, all_vote_commit },
        };

        Ok((params, proofs))
    }
}
