use bristol_fashion::Circuit;
use scuttlebutt::field::FiniteField;
use swanky_field_binary::F2;

use crate::{ExtractOutputMsg1, OutputMsg1, OutputMsg2, error::GcError, garbler::Garbling};

pub mod copz;
pub mod wrk17;

pub trait Evaluator {
    type Gc: Garbling;
    type OM1: OutputMsg1;
    type OM2: OutputMsg2;
    type Label: FiniteField;
    type GarbledOutput: ExtractOutputMsg1;
    type Decoder;

    fn from_garbling(garbling: Self::Gc) -> Self;

    fn eval(
        &self,
        circuit: &Circuit,
        garblings: Vec<Self::Gc>,
        masked_inputs: Vec<F2>,
        input_labels: Vec<Vec<Self::Label>>,
    ) -> Result<Self::GarbledOutput, GcError>;

    fn check_and_decode(
        &self,
        output_msg2: Vec<Self::OM2>,
        chi: &[u8; 32],
        encoded: Self::GarbledOutput,
        decoder: Vec<Self::Decoder>,
        circuit: &Circuit,
    ) -> Result<Vec<F2>, GcError>;
}
