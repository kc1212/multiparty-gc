use bristol_fashion::Circuit;
use scuttlebutt::field::FiniteField;

use crate::{MsgRound1, MsgRound2, error::GcError, garbler::Garbling};

pub mod wrk17;

pub trait Evaluator {
    type Gc: Garbling;
    type Input: FiniteField;
    type Label: FiniteField;
    type GarbledOutput;
    type Decoder;

    fn eval(
        &self,
        circuit: &Circuit,
        garblings: Vec<Self::Gc>,
        masked_inputs: Vec<Self::Input>,
        input_labels: Vec<Vec<Self::Label>>,
    ) -> Result<Self::GarbledOutput, GcError>;

    fn decode(
        &self,
        encoded: Self::GarbledOutput,
        decoder: Self::Decoder,
    ) -> Result<Vec<u8>, GcError>;

    // fn input_round_2(&self, msg: Self::MR1) -> Self::MR2;
}
