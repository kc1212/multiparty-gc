use bristol_fashion::{Circuit, Gate};
use itertools::Itertools;
use scuttlebutt::ring::FiniteRing;
use swanky_field_binary::{F2, F128b};

use crate::{
    error::GcError,
    garbler::wrk17::{Wrk17Garbling, decrypt_garbled_gate},
    sharing::AuthShare,
};

use super::Evaluator;

pub struct Wrk17Evaluator {
    /// Ordererd by topological order of AND gate
    /// r^1_{\gamma, \ell}, {M_j[r^1_{\gamma, \ell}]}, {K_1[r^j_{\gamma, \ell}]}
    garbling_shares: Vec<[AuthShare<F2, F128b>; 4]>,
    /// Shares of the final output wire masks \lambda_w,
    /// w are the circuit output wires
    wire_mask_shares: Vec<AuthShare<F2, F128b>>,
    delta: F128b,
}

pub struct Wrk17EncodedOutput {
    masked_output_values: Vec<F2>,
}

pub struct Wrk17Decoder {
    // To decode, each party needs to send
    // { (r^i_w, M_1[r^i_w]) } to the evaluator
    // inner[i][j] is the ith wire and jth party
    inner: Vec<Vec<(F2, F128b)>>,
}

impl Evaluator for Wrk17Evaluator {
    type Gc = Wrk17Garbling;
    type Input = F2;
    type Label = F128b;
    type GarbledOutput = Wrk17EncodedOutput;
    type Decoder = Wrk17Decoder;

    /// `input_labels` - input_labels[i][j] means party i wire j
    fn eval(
        &self,
        circuit: &Circuit,
        garblings: Vec<Wrk17Garbling>, // one per party
        masked_inputs: Vec<F2>,
        input_labels: Vec<Vec<F128b>>, // indexed by party and then by wire
    ) -> Result<Wrk17EncodedOutput, GcError> {
        // party with index n - 1 is the evaluator
        let party_count = garblings.len() + 1;
        let input_len: u64 = circuit.input_sizes().iter().sum();
        let gate_count = circuit.gates().len();
        assert_eq!(input_len as usize, masked_inputs.len());
        assert_eq!(party_count - 1, input_labels.len());
        let mut masked_wire_values = [masked_inputs, vec![F2::ZERO; gate_count]].concat();

        // TODO avoid these transposes
        // labels[i][j] means the label on wire i and party j,
        // this is different from the input_labels because we've transposed it
        let mut labels: Vec<Vec<F128b>> = transpose(
            input_labels
                .into_iter()
                .map(|labels| vec![labels, vec![F128b::ZERO; gate_count]].concat())
                .collect(),
        );

        // We iterate over the gates, so we need to transpose `garblings`
        // since we need the garbled gates from all parties to evaluate one gate.
        let garblings = transpose(
            garblings
                .into_iter()
                .map(|garbling| garbling.get_garbler_gates())
                .collect_vec(),
        );

        let mut and_gate_ctr = 0usize;
        for gate in circuit.gates() {
            match gate {
                Gate::XOR { a, b, out } => {
                    // z_\gamma + \lambda_\gamma = (z_a + \lambda_a) + (z_b + \lambda_b)
                    masked_wire_values[*out as usize] =
                        masked_wire_values[*a as usize] + masked_wire_values[*b as usize];
                    // L^i_\gamma = L^i_a + L^i_b, for i != evaluator_id
                    let label = (0..(party_count - 1))
                        .map(|i| labels[*a as usize][i] + labels[*b as usize][i])
                        .collect_vec();
                    labels[*out as usize] = label;
                }
                Gate::AND { a, b, out } => {
                    let alpha = masked_wire_values[*a as usize];
                    let beta = masked_wire_values[*b as usize];
                    let (new_share, new_labels) = decrypt_garbled_gate(
                        &garblings[and_gate_ctr],
                        alpha,
                        beta,
                        &labels[*a as usize],
                        &labels[*b as usize],
                        *out,
                        &self.garbling_shares[*out as usize],
                        self.delta,
                    )?;
                    masked_wire_values[*out as usize] = new_share;
                    #[cfg(test)]
                    {
                        assert_eq!(labels[*out as usize].len(), new_labels.len());
                        assert!(labels[*out as usize].iter().all(|x| *x == F128b::ZERO));
                    }
                    labels[*out as usize] = new_labels;
                    and_gate_ctr += 1;
                }
                Gate::INV { a: _, out: _ } => unimplemented!(),
                Gate::EQ { lit: _, out: _ } => unimplemented!(),
                Gate::EQW { a: _, out: _ } => unimplemented!(),
            }
        }

        // Output what we have at the end of the evaluation.
        // In bristol fashion, the output wires have numbers from
        // wire_length - output_count ... wire_length
        let output_count: u64 = circuit.output_sizes().iter().sum();
        let wire_length: u64 = circuit.nwires();
        let mut masked_output_values = Vec::with_capacity(output_count as usize);
        for out in (wire_length - output_count)..wire_length {
            masked_output_values.push(masked_wire_values[out as usize]);
        }

        Ok(Wrk17EncodedOutput {
            masked_output_values,
        })
    }

    fn decode(
        &self,
        encoded: Wrk17EncodedOutput,
        decoder: Wrk17Decoder,
    ) -> Result<Vec<u8>, GcError> {
        for (all_shares_macs, key) in decoder.inner.into_iter().zip(&self.wire_mask_shares) {
            for (i, (share, mac)) in all_shares_macs.into_iter().enumerate() {
                let key = key.mac_keys[&(i as u16)];
                if share * self.delta + key != mac {
                    return Err(GcError::DecoderCheckFailure);
                }
            }
        }

        // reconstruct the shares
        todo!()
    }
}

fn transpose<T>(v: Vec<Vec<T>>) -> Vec<Vec<T>> {
    assert!(!v.is_empty());
    let len = v[0].len();
    let mut iters: Vec<_> = v.into_iter().map(|n| n.into_iter()).collect();
    (0..len)
        .map(|_| {
            iters
                .iter_mut()
                .map(|n| n.next().unwrap())
                .collect::<Vec<T>>()
        })
        .collect()
}
