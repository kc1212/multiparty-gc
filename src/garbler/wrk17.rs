use bristol_fashion::Circuit;
use scuttlebutt::ring::FiniteRing;
use swanky_field_binary::F128b;

use crate::{prep::Preprocessor, sharing::AuthShare};

use super::Garbler;

pub struct Wrk17Garbler<P: Preprocessor> {
    party_id: u32,
    preprocessor: P,
}

impl<P: Preprocessor> Wrk17Garbler<P> {
    fn gen_input_labels(&mut self, inputs: u64, delta: F128b) -> (Vec<F128b>, Vec<F128b>) {
        todo!()
    }
}

impl<P: Preprocessor> Garbler for Wrk17Garbler<P> {
    fn party_id(&self) -> u32 {
        self.party_id
    }

    fn garble(&mut self, circuit: &Circuit) {
        let delta = self.preprocessor.init();
        // Circuit input wire masks and keys.
        let input_bit_count: u64 = circuit.input_sizes().iter().sum();
        let input_masks = self.preprocessor.random_bit(input_bit_count);
        let (input_keys_0, input_keys_1) = self.gen_input_labels(input_bit_count, delta);

        // Intermediate wire masks and keys.
        // we need to prepare some data structures that will store
        // the output wire keys/labels and masks so that they can be
        // used in the loop below
        let mut gate_output_keys = vec![None; circuit.gates().len() + input_bit_count as usize];
        let mut gate_output_masks = vec![None; circuit.gates().len() + input_bit_count as usize];

        for gate in circuit.gates() {
            match gate {
                bristol_fashion::Gate::XOR { a, b, out } => {
                    let lambda_u = gate_output_masks[*a as usize].as_ref().unwrap();
                    let lambda_v = gate_output_masks[*b as usize].as_ref().unwrap();
                    let lambda_w = self.preprocessor.add(lambda_u, lambda_v);
                    gate_output_masks[*out as usize] = Some(lambda_w);

                    // TODO do we need to store the intermediate 1-keys?
                    let (k_u_0, k_u_1) = gate_output_keys[*a as usize].as_ref().unwrap();
                    let (k_v_0, k_v_1) = gate_output_keys[*b as usize].as_ref().unwrap();
                    let k_w_0 = k_u_0 + k_v_0;
                    let k_w_1 = k_w_0 + delta;
                    gate_output_keys[*out as usize] = Some((k_w_0, k_w_1));
                }
                bristol_fashion::Gate::AND { a: _, b: _, out } => {
                    let lambda_w = {
                        let m = self.preprocessor.random_bit(1);
                        m[0].clone()
                    };
                    let and_keys = {
                        let (k0, k1) = self.gen_input_labels(1, delta);
                        (k0[0], k1[0])
                    };
                    gate_output_masks[*out as usize] = Some(lambda_w);
                    gate_output_keys[*out as usize] = Some(and_keys);
                }
                bristol_fashion::Gate::INV { a: _, out: _ } => todo!(),
                bristol_fashion::Gate::EQ { lit: _, out: _ } => todo!(),
                bristol_fashion::Gate::EQW { a: _, out: _ } => todo!(),
            }
        }
        
        // Generate garbled gates.
        todo!()
    }
}
