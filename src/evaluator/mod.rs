use bristol_fashion::Circuit;
use scuttlebutt::field::FiniteField;
use swanky_field_binary::F2;

use crate::{error::GcError, garbler::Garbling};

pub mod wrk17;

pub trait Evaluator {
    type Gc: Garbling;
    type Label: FiniteField;
    type GarbledOutput;
    type Decoder;

    fn from_garbling(garbling: Self::Gc) -> Self;

    fn eval(
        &self,
        circuit: &Circuit,
        garblings: Vec<Self::Gc>,
        masked_inputs: Vec<F2>,
        input_labels: Vec<Vec<Self::Label>>,
    ) -> Result<Self::GarbledOutput, GcError>;

    fn decode(
        &self,
        encoded: Self::GarbledOutput,
        decoder: Vec<Self::Decoder>,
    ) -> Result<Vec<F2>, GcError>;

    // fn input_round_2(&self, msg: Self::MR1) -> Self::MR2;
}
