use bristol_fashion::Circuit;
use rand::{CryptoRng, Rng};
use swanky_field_binary::F2;

use crate::{error::GcError, MsgRound1, MsgRound2, MsgRound3};

pub mod wrk17;

pub trait Garbler<Gc: Garbling> {
    type MR1: MsgRound1;
    type MR2: MsgRound2;
    type MR3: MsgRound3;

    fn garble<R: Rng + CryptoRng>(&mut self, rng: &mut R, circuit: &Circuit) -> Gc;
    fn party_id(&self) -> u16;

    fn input_round_1(&self) -> Self::MR1;
    fn input_round_2(&self, true_inputs: Vec<F2>, msgs: Vec<Self::MR1>) -> Result<Vec<Self::MR2>, GcError>;
    fn input_round_3(&self, msg: Self::MR2) -> Self::MR3;
}

pub trait Garbling {}
