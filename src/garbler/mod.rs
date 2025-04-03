use std::collections::BTreeMap;

use bristol_fashion::Circuit;
use rand::{CryptoRng, Rng};
use scuttlebutt::ring::FiniteRing;
use swanky_field_binary::{F2, F128b};

use crate::{
    MsgRound1, MsgRound2, MsgRound3, error::GcError, prep::Preprocessor, sharing::AuthShare,
};

pub mod copz;
pub mod wrk17;

pub trait Garbler {
    type Gc: Garbling;
    type MR1: MsgRound1;
    type MR2: MsgRound2 + Clone;
    type MR3: MsgRound3;

    fn garble<R: Rng + CryptoRng>(&mut self, rng: &mut R, circuit: &Circuit) -> Self::Gc;
    fn party_id(&self) -> u16;
    fn num_parties(&self) -> u16;

    fn input_round_1(&self) -> Self::MR1;
    fn input_round_2(
        &self,
        true_inputs: Vec<F2>,
        msgs: Vec<Self::MR1>,
    ) -> Result<Vec<Self::MR2>, GcError>;
    fn input_round_3(&self, msg: Self::MR2) -> Self::MR3;

    fn is_garbler(&self) -> bool {
        self.party_id() != self.num_parties() - 1
    }

    fn gen_labels<R>(&mut self, rng: &mut R, circuit: &Circuit) -> BTreeMap<u64, F128b>
    where
        R: Rng + CryptoRng,
    {
        let mut output = BTreeMap::new();
        let input_length: u64 = circuit.input_sizes().iter().sum();
        for i in 0..input_length {
            output.insert(i, F128b::random(rng));
        }
        if self.is_garbler() {
            for gate in circuit.gates() {
                match gate {
                    bristol_fashion::Gate::AND { a: _, b: _, out } => {
                        output.insert(*out, F128b::random(rng));
                    }
                    _ => { /* do nothing */ }
                }
            }
        }
        output
    }
}

pub trait Garbling {}

pub(crate) fn auth_bits_from_prep<P: Preprocessor>(
    prep: &mut P,
    circuit: &Circuit,
) -> BTreeMap<u64, AuthShare<F2, F128b>> {
    let input_wire_count: u64 = circuit.input_sizes().iter().sum();
    let and_gate_count = circuit.nand();

    // Sample wire masks and labels for input wires
    let mut unindexed_auth_bits = prep.auth_bits(input_wire_count + and_gate_count).unwrap();
    let mut auth_bits = BTreeMap::new();
    for i in 0..input_wire_count {
        auth_bits.insert(i, unindexed_auth_bits.pop().unwrap());
    }
    for gate in circuit.gates() {
        match gate {
            bristol_fashion::Gate::AND { a: _, b: _, out } => {
                auth_bits.insert(*out, unindexed_auth_bits.pop().unwrap());
            }
            _ => { /* do nothing */ }
        }
    }
    assert!(unindexed_auth_bits.is_empty());
    auth_bits
}
