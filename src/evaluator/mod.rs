use bristol_fashion::Circuit;
use scuttlebutt::field::FiniteField;

use crate::{error::GcError, garbler::Garbling};

mod wrk17;

trait Evaluator {
    type G: Garbling;
    type Input: FiniteField;
    type Label: FiniteField;
    type GarbledOutput;
    type Decoder;

    fn eval(
        &self,
        circuit: &Circuit,
        garblings: Vec<Self::G>,
        masked_inputs: Vec<Self::Input>,
        input_labels: Vec<Vec<Self::Label>>,
    ) -> Result<Self::GarbledOutput, GcError>;

    fn decode(
        &self,
        encoded: Self::GarbledOutput,
        decoder: Self::Decoder,
    ) -> Result<Vec<u8>, GcError>;
}
