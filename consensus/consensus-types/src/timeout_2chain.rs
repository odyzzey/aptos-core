// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

use crate::{common::Author, quorum_cert::QuorumCert};
use anyhow::ensure;
use aptos_crypto::bls12381;
use aptos_crypto_derive::{BCSCryptoHash, CryptoHasher};
use aptos_types::multi_signature::{AggregatedSignatureWithRounds, PartialSignaturesWithRound};
use aptos_types::validator_verifier::VerifyError;
use aptos_types::{
    block_info::Round, validator_signer::ValidatorSigner, validator_verifier::ValidatorVerifier,
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

/// This structure contains all the information necessary to construct a signature
/// on the equivalent of a AptosBFT v4 timeout message.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TwoChainTimeout {
    /// Epoch number corresponds to the set of validators that are active for this round.
    epoch: u64,
    /// The consensus protocol executes proposals (blocks) in rounds, which monotonically increase per epoch.
    round: Round,
    /// The highest quorum cert the signer has seen.
    quorum_cert: QuorumCert,
}

impl TwoChainTimeout {
    pub fn new(epoch: u64, round: Round, quorum_cert: QuorumCert) -> Self {
        Self {
            epoch,
            round,
            quorum_cert,
        }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn round(&self) -> Round {
        self.round
    }

    pub fn hqc_round(&self) -> Round {
        self.quorum_cert.certified_block().round()
    }

    pub fn quorum_cert(&self) -> &QuorumCert {
        &self.quorum_cert
    }

    pub fn sign(&self, signer: &ValidatorSigner) -> bls12381::Signature {
        signer.sign(&self.signing_format())
    }

    pub fn signing_format(&self) -> TimeoutSigningRepr {
        TimeoutSigningRepr {
            epoch: self.epoch(),
            round: self.round(),
            hqc_round: self.hqc_round(),
        }
    }

    pub fn verify(&self, validators: &ValidatorVerifier) -> anyhow::Result<()> {
        ensure!(
            self.hqc_round() < self.round(),
            "Timeout round should be larger than the QC round"
        );
        self.quorum_cert.verify(validators)?;
        Ok(())
    }
}

impl Display for TwoChainTimeout {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "Timeout: [epoch: {}, round: {}, hqc_round: {}]",
            self.epoch,
            self.round,
            self.hqc_round(),
        )
    }
}

/// Validators sign this structure that allows the TwoChainTimeoutCertificate to store a round number
/// instead of a quorum cert per validator in the signatures field.
#[derive(Serialize, Deserialize, Debug, CryptoHasher, BCSCryptoHash)]
pub struct TimeoutSigningRepr {
    pub epoch: u64,
    pub round: Round,
    pub hqc_round: Round,
}

/// TimeoutCertificate is a proof that 2f+1 participants in epoch i
/// have voted in round r and we can now move to round r+1. AptosBFT v4 requires signature to sign on
/// the TimeoutSigningRepr and carry the TimeoutWithHighestQC with highest quorum cert among 2f+1.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct TwoChainTimeoutWithSignatures {
    timeout: TwoChainTimeout,
    signatures_with_rounds: AggregatedSignatureWithRounds,
}

impl Display for TwoChainTimeoutWithSignatures {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "TimeoutCertificate[epoch: {}, round: {}, hqc_round: {}]",
            self.timeout.epoch(),
            self.timeout.round(),
            self.timeout.hqc_round(),
        )
    }
}

impl TwoChainTimeoutWithSignatures {
    /// Creates new TimeoutCertificate
    pub fn new(timeout: TwoChainTimeout) -> Self {
        Self {
            timeout,
            signatures_with_rounds: AggregatedSignatureWithRounds::empty(),
        }
    }
    /// Verifies the signatures for each validator, the signature is on the TimeoutSigningRepr where the
    /// hqc_round is in the signature map.
    /// We verify the following:
    /// 1. the highest quorum cert is valid
    /// 2. all signatures are properly formed (timeout.epoch, timeout.round, round)
    /// 3. timeout.hqc_round == max(signed round)
    pub fn verify(&self, validators: &ValidatorVerifier) -> anyhow::Result<()> {
        // Verify the highest timeout validity.
        self.timeout.verify(validators)?;
        let hqc_round = self.timeout.hqc_round();
        let timeout_messages: Vec<_> = self
            .signatures_with_rounds
            .get_voters_and_rounds(
                &validators
                    .get_ordered_account_addresses_iter()
                    .collect_vec(),
            )
            .into_iter()
            .map(|(_, round)| TimeoutSigningRepr {
                epoch: self.timeout.epoch(),
                round: self.timeout.round(),
                hqc_round: round,
            })
            .collect();
        let timeout_messages_ref: Vec<_> = timeout_messages.iter().collect();
        validators.verify_aggregated_signatures(
            &timeout_messages_ref,
            self.signatures_with_rounds.aggregated_sig(),
        )?;
        let signed_hqc = self
            .signatures_with_rounds
            .rounds()
            .iter()
            .max()
            .expect("Empty rounds");
        ensure!(
            hqc_round == *signed_hqc,
            "Inconsistent hqc round, qc has round {}, highest signed round {}",
            hqc_round,
            *signed_hqc
        );
        Ok(())
    }

    /// The epoch of the timeout.
    pub fn epoch(&self) -> u64 {
        self.timeout.epoch()
    }

    /// The round of the timeout.
    pub fn round(&self) -> Round {
        self.timeout.round()
    }

    /// The highest hqc round of the 2f+1 participants
    pub fn highest_hqc_round(&self) -> Round {
        self.timeout.hqc_round()
    }

    pub fn signatures_with_rounds(&self) -> &AggregatedSignatureWithRounds {
        &self.signatures_with_rounds
    }
}

/// TimeoutCertificate is a proof that 2f+1 participants in epoch i
/// have voted in round r and we can now move to round r+1. AptosBFT v4 requires signature to sign on
/// the TimeoutSigningRepr and carry the TimeoutWithHighestQC with highest quorum cert among 2f+1.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TwoChainTimeoutWithPartialSignatures {
    timeout: TwoChainTimeout,
    signatures: PartialSignaturesWithRound,
}

impl TwoChainTimeoutWithPartialSignatures {
    /// Creates new TimeoutCertificate
    pub fn new(timeout: TwoChainTimeout) -> Self {
        Self {
            timeout,
            signatures: PartialSignaturesWithRound::empty(),
        }
    }

    /// The epoch of the timeout.
    pub fn epoch(&self) -> u64 {
        self.timeout.epoch()
    }

    /// The round of the timeout.
    pub fn round(&self) -> Round {
        self.timeout.round()
    }

    /// The highest hqc round of the 2f+1 participants
    pub fn highest_hqc_round(&self) -> Round {
        self.timeout.hqc_round()
    }

    /// Returns the signatures certifying the round
    pub fn signers(&self) -> impl Iterator<Item = &Author> {
        self.signatures.signatures().iter().map(|(k, _)| k)
    }

    /// Add a new timeout message from author, the timeout should already be verified in upper layer.
    pub fn add(
        &mut self,
        author: Author,
        timeout: TwoChainTimeout,
        signature: bls12381::Signature,
    ) {
        debug_assert_eq!(
            self.timeout.epoch(),
            timeout.epoch(),
            "Timeout should have the same epoch as TimeoutCert"
        );
        debug_assert_eq!(
            self.timeout.round(),
            timeout.round(),
            "Timeout should have the same round as TimeoutCert"
        );
        let hqc_round = timeout.hqc_round();
        if timeout.hqc_round() > self.timeout.hqc_round() {
            self.timeout = timeout;
        }
        self.signatures.add_signature(author, hqc_round, signature);
    }

    pub fn aggregate_signatures(
        &self,
        verifier: &ValidatorVerifier,
        verify: bool,
    ) -> Result<TwoChainTimeoutWithSignatures, VerifyError> {
        let (partial_sign, ordered_rounds) = self
            .signatures
            .get_partial_sig_with_rounds(verifier.address_to_validator_index());
        let timeout_messages: Vec<_> = ordered_rounds
            .iter()
            .map(|round| TimeoutSigningRepr {
                epoch: self.timeout.epoch(),
                round: self.timeout.round(),
                hqc_round: *round,
            })
            .collect();
        let timeout_messages_ref: Vec<_> = timeout_messages.iter().collect();
        let aggregated_sig =
            verifier.generate_aggregated_signature(&partial_sign, &timeout_messages_ref, verify)?;
        Ok(TwoChainTimeoutWithSignatures {
            timeout: self.timeout.clone(),
            signatures_with_rounds: AggregatedSignatureWithRounds::new(
                aggregated_sig,
                ordered_rounds,
            ),
        })
    }
}

#[test]
fn test_2chain_timeout_certificate() {
    use crate::vote_data::VoteData;
    use aptos_crypto::hash::CryptoHash;
    use aptos_types::{
        block_info::BlockInfo,
        ledger_info::{LedgerInfo, LedgerInfoWithPartialSignatures},
        multi_signature::PartialSignatures,
        validator_verifier::random_validator_verifier,
    };

    let num_nodes = 4;
    let (signers, validators) = random_validator_verifier(num_nodes, None, false);
    let quorum_size = validators.quorum_voting_power() as usize;
    let generate_quorum = |round, num_of_signature| {
        let vote_data = VoteData::new(BlockInfo::random(round), BlockInfo::random(0));
        let mut ledger_info = LedgerInfoWithPartialSignatures::new(
            LedgerInfo::new(BlockInfo::empty(), vote_data.hash()),
            PartialSignatures::empty(),
        );
        for signer in &signers[0..num_of_signature] {
            let signature = signer.sign(ledger_info.ledger_info());
            ledger_info.add_signature(signer.author(), signature);
        }
        QuorumCert::new(
            vote_data,
            ledger_info.aggregate_signatures(&validators).unwrap(),
        )
    };
    let generate_timeout =
        |round, qc_round| TwoChainTimeout::new(1, round, generate_quorum(qc_round, quorum_size));

    let timeouts: Vec<_> = (1..=3)
        .map(|qc_round| generate_timeout(4, qc_round))
        .collect();
    // timeout cert with (round, hqc round) = (4, 1), (4, 2), (4, 3)
    let mut tc_with_partial_sig = TwoChainTimeoutWithPartialSignatures::new(timeouts[0].clone());
    for (timeout, signer) in timeouts.iter().zip(&signers) {
        tc_with_partial_sig.add(signer.author(), timeout.clone(), timeout.sign(signer));
    }

    let tc_with_sig = tc_with_partial_sig
        .aggregate_signatures(&validators, false)
        .unwrap();
    tc_with_sig.verify(&validators).unwrap();

    // timeout round < hqc round
    let mut invalid_tc_with_partial_sig = tc_with_partial_sig.clone();
    invalid_tc_with_partial_sig.timeout.round = 1;

    let invalid_tc_with_sig = invalid_tc_with_partial_sig
        .aggregate_signatures(&validators, false)
        .unwrap();
    invalid_tc_with_sig.verify(&validators).unwrap_err();

    // invalid signature
    let mut invalid_timeout_cert = invalid_tc_with_partial_sig.clone();
    invalid_timeout_cert.signatures.replace_signature(
        signers[0].author(),
        0,
        bls12381::Signature::dummy_signature(),
    );

    let invalid_tc_with_sig = invalid_timeout_cert
        .aggregate_signatures(&validators, false)
        .unwrap();
    invalid_tc_with_sig.verify(&validators).unwrap_err();

    // not enough signatures
    let mut invalid_timeout_cert = invalid_tc_with_partial_sig.clone();
    invalid_timeout_cert
        .signatures
        .remove_signature(&signers[0].author());
    let invalid_tc_with_sig = invalid_timeout_cert
        .aggregate_signatures(&validators, false)
        .unwrap();

    invalid_tc_with_sig.verify(&validators).unwrap_err();

    // hqc round does not match signed round
    let mut invalid_timeout_cert = invalid_tc_with_partial_sig.clone();
    invalid_timeout_cert.timeout.quorum_cert = generate_quorum(2, quorum_size);

    let invalid_tc_with_sig = invalid_timeout_cert
        .aggregate_signatures(&validators, false)
        .unwrap();
    invalid_tc_with_sig.verify(&validators).unwrap_err();

    // invalid quorum cert
    let mut invalid_timeout_cert = invalid_tc_with_partial_sig;
    invalid_timeout_cert.timeout.quorum_cert = generate_quorum(3, quorum_size - 1);
    let invalid_tc_with_sig = invalid_timeout_cert
        .aggregate_signatures(&validators, false)
        .unwrap();

    invalid_tc_with_sig.verify(&validators).unwrap_err();
}
