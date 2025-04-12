use bristol_fashion::{Circuit, Gate};
use rand::{CryptoRng, Rng};
use scuttlebutt::ring::FiniteRing;
use swanky_field_binary::{F2, F128b};

use crate::{
    InputMsg1, InputMsg2, InputMsg3, OutputMsg1, OutputMsg2, error::GcError, prep::Preprocessor,
    sharing::AuthShare,
};

pub mod copz;
pub mod wrk17;

pub trait Garbler {
    type Gc: Garbling;
    type IM1: InputMsg1;
    type IM2: InputMsg2 + Clone;
    type IM3: InputMsg3;
    type OM1: OutputMsg1;
    type OM2: OutputMsg2;

    fn garble<R: Rng + CryptoRng>(&mut self, rng: &mut R, circuit: &Circuit) -> Self::Gc;
    fn party_id(&self) -> u16;
    fn num_parties(&self) -> u16;

    /// Called by the garblers, messages are sent to the single evaluator.
    fn input_round_1(&self) -> Self::IM1;

    /// Called by the evaluator, messages are sent to the garblers.
    fn input_round_2(
        &self,
        true_inputs: &[F2],
        msgs: Vec<Self::IM1>,
    ) -> Result<Vec<Self::IM2>, GcError>;

    /// Called by the garblers, messages are sent to the evaluator.
    fn input_round_3(&self, msg: Self::IM2) -> Self::IM3;

    fn is_garbler(&self) -> bool {
        self.party_id() != self.num_parties() - 1
    }

    /// - `msg1`: from the evaluator, that the garbler needs to verify
    fn check_output_msg1(
        &self,
        msg1: Self::OM1,
        masked_inputs: &[F2],
        circuit: &Circuit,
    ) -> Result<Self::OM2, GcError>;

    fn gen_labels<R>(&mut self, rng: &mut R, circuit: &Circuit) -> Vec<F128b>
    where
        R: Rng + CryptoRng,
    {
        let mut output = vec![F128b::ZERO; circuit.nwires() as usize];
        let input_length: u64 = circuit.input_sizes().iter().sum();
        output.iter_mut().take(input_length as usize).for_each(|x| {
            *x = F128b::random(rng);
        });
        if self.is_garbler() {
            for gate in circuit.gates() {
                match gate {
                    bristol_fashion::Gate::AND { a: _, b: _, out } => {
                        output[*out as usize] = F128b::random(rng);
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
) -> Vec<AuthShare<F2, F128b>> {
    let input_wire_count: u64 = circuit.input_sizes().iter().sum();
    let and_gate_count = circuit.nand();

    // Sample wire masks and labels for input wires
    let mut unindexed_auth_bits = prep.auth_bits(input_wire_count + and_gate_count).unwrap();
    let mut auth_bits = vec![AuthShare::<F2, F128b>::make_empty(); circuit.nwires() as usize];
    auth_bits
        .iter_mut()
        .take(input_wire_count as usize)
        .for_each(|x| {
            *x = unindexed_auth_bits.pop().unwrap();
        });
    for gate in circuit.gates() {
        match gate {
            bristol_fashion::Gate::AND { a: _, b: _, out } => {
                auth_bits[*out as usize] = unindexed_auth_bits.pop().unwrap();
            }
            _ => { /* do nothing */ }
        }
    }
    assert!(unindexed_auth_bits.is_empty());
    auth_bits
}

pub(crate) fn process_linear_gates(
    auth_bits: &mut [AuthShare<F2, F128b>],
    wire_labels: &mut [F128b],
    circuit: &Circuit,
    delta: F128b,
    is_garbler: bool,
) {
    for gate in circuit.gates() {
        match gate {
            Gate::XOR { a, b, out } => {
                let output_share = &auth_bits[*a as usize] + &auth_bits[*b as usize];
                assert!(auth_bits[*out as usize].is_empty());
                auth_bits[*out as usize] = output_share;
                if is_garbler {
                    wire_labels[*out as usize] =
                        wire_labels[*a as usize] + wire_labels[*b as usize];
                }
            }
            Gate::INV { a, out } => {
                if is_garbler {
                    wire_labels[*out as usize] = wire_labels[*a as usize] + delta;
                }
                auth_bits[*out as usize] = auth_bits[*a as usize].clone();
            }
            Gate::AND { .. } => { /* ignore */ }
            unsupported_gate => unimplemented!("unsupported gate {unsupported_gate:?}"),
        }
    }
}
