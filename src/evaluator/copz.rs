use bristol_fashion::{Circuit, Gate};
use itertools::{Itertools, izip};
use rand::{CryptoRng, Rng};
use scuttlebutt::ring::FiniteRing;
use scuttlebutt::serialization::CanonicalSerialize;
use swanky_field_binary::{F2, F128b};

use crate::{
    ExtractOutputMsg1,
    error::GcError,
    garbler::copz::{
        CopzEvaluatorOutput, CopzGarbling, CopzOutputMsg1, CopzOutputMsg2, decrypt_garbled_gate,
    },
    sharing::AuthShare,
    transpose, universal_hash,
};

use super::Evaluator;

pub struct CopzEvaluator {
    num_parties: u16,
    /// Ordererd by topological order of AND gate
    /// [\lambda_u], [\lambda_v], [\lambda_uv], [\lambda_w]
    garbling_shares: Vec<[AuthShare<F2, F128b>; 4]>,
    /// Shares of the final output wire masks \lambda_w,
    /// w are the circuit output wires
    /// (some of this is redundant, covered by [garbling_shares])
    wire_mask_shares: Vec<AuthShare<F2, F128b>>,
    delta: F128b,
}

pub struct CopzEncodedOutput {
    // TODO the masked output and the and gate values are redundant
    masked_output_values: Vec<F2>,
    masked_and_gates: Vec<F2>,
    masked_wire_values: Vec<F2>,
    digests: Vec<[u8; 32]>,
}

impl ExtractOutputMsg1 for CopzEncodedOutput {
    type OM1 = CopzOutputMsg1;

    fn extract_outupt_msg1<R: Rng + CryptoRng>(&self, rng: &mut R) -> Vec<CopzOutputMsg1> {
        let mut chi = [0u8; 32];
        rng.fill_bytes(&mut chi);
        self.digests
            .iter()
            .map(|h| CopzOutputMsg1 {
                w_hats: self.masked_and_gates.clone(),
                h: *h,
                chi,
            })
            .collect()
    }
}

impl Evaluator for CopzEvaluator {
    type Gc = CopzGarbling;
    type Label = F128b;
    type GarbledOutput = CopzEncodedOutput;
    type OM1 = CopzOutputMsg1;
    type OM2 = CopzOutputMsg2;

    // To decode, each party needs to send the output wire masks.
    type Decoder = Vec<F2>;

    fn from_garbling(garbling: CopzGarbling) -> Self {
        let CopzEvaluatorOutput {
            num_parties: total_num_parties,
            garbling_shares,
            wire_mask_shares,
            delta,
        } = garbling.into_evaluator_gates();
        Self {
            num_parties: total_num_parties,
            garbling_shares,
            wire_mask_shares,
            delta,
        }
    }

    fn eval(
        &self,
        circuit: &Circuit,
        garblings: Vec<CopzGarbling>,
        masked_inputs: Vec<F2>,
        input_labels: Vec<Vec<F128b>>,
    ) -> Result<CopzEncodedOutput, GcError> {
        // party with index n - 1 is the evaluator
        let party_count = garblings.len() + 1;
        let input_len: u64 = circuit.input_sizes().iter().sum();
        let gate_count = circuit.gates().len();
        assert_eq!(input_len as usize, masked_inputs.len());
        assert_eq!(party_count - 1, input_labels.len());

        // Note that input length + gate_count is the wire count
        let mut masked_wire_values = [masked_inputs, vec![F2::ZERO; gate_count]].concat();
        debug_assert_eq!(masked_wire_values.len() as u64, circuit.nwires());

        // TODO avoid these transposes
        // labels[i][j] means the label on wire i and party j,
        // this is different from the input_labels because we've transposed it
        let mut labels: Vec<Vec<F128b>> = transpose(
            input_labels
                .into_iter()
                .map(|labels| [labels, vec![F128b::ZERO; gate_count]].concat())
                .collect(),
        );

        // Received from the first garbler,
        // which are values b_w = lsb(k^2_{w,0}).
        let b_ws = garblings[0].get_b_w();

        // We iterate over the gates, so we need to transpose `garblings`
        // since we need the garbled gates from all parties to evaluate one gate.
        let garblings = transpose(
            garblings
                .into_iter()
                .map(|garbling| garbling.into_garbler_gates())
                .collect_vec(),
        );

        let mut masked_and_gates = vec![];

        // Evaluate the gates, at the same time compute h^i = H({k^i_{w, \hat{w}}})
        let mut hashers = (0..self.num_parties - 1)
            .map(|_| {
                // TODO add domain separator
                blake3::Hasher::new()
            })
            .collect_vec();
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
                Gate::INV { a, out } => {
                    masked_wire_values[*out as usize] = masked_wire_values[*a as usize] + F2::ONE;
                    let label = (0..(party_count - 1))
                        .map(|i| labels[*a as usize][i])
                        .collect_vec();
                    labels[*out as usize] = label;
                }
                Gate::AND { a, b, out } => {
                    let alpha = masked_wire_values[*a as usize];
                    let beta = masked_wire_values[*b as usize];
                    let [lambda_u, lambda_v, lambda_uv, lambda_w] =
                        &self.garbling_shares[and_gate_ctr];

                    let lambda_w_delta_i = lambda_w.to_x_delta_shares(&self.delta);
                    let lambda_u_delta_i = lambda_u.to_x_delta_shares(&self.delta);
                    let lambda_v_delta_i = lambda_v.to_x_delta_shares(&self.delta);
                    let lambda_uv_delta_i = lambda_uv.to_x_delta_shares(&self.delta);

                    let (w_hat, new_labels) = decrypt_garbled_gate(
                        &garblings[and_gate_ctr],
                        &labels[*a as usize],
                        &labels[*b as usize],
                        &lambda_w_delta_i,
                        &lambda_u_delta_i,
                        &lambda_v_delta_i,
                        &lambda_uv_delta_i,
                        alpha,
                        beta,
                        b_ws[and_gate_ctr],
                        *out,
                        self.num_parties,
                    );
                    masked_wire_values[*out as usize] = w_hat;
                    #[cfg(test)]
                    {
                        println!(
                            "\tobtained masked_gamma={:?} with label={:?}",
                            w_hat, &new_labels
                        );
                    }

                    masked_and_gates.push(w_hat);

                    debug_assert_eq!(labels[*out as usize].len(), new_labels.len());
                    debug_assert!(labels[*out as usize].iter().all(|x| *x == F128b::ZERO));

                    for (l, hasher) in new_labels.iter().zip(&mut hashers) {
                        hasher.update(&l.to_bytes());
                    }
                    labels[*out as usize] = new_labels;
                    and_gate_ctr += 1;
                }
                Gate::EQ { lit: _, out: _ } => unimplemented!(),
                Gate::EQW { a: _, out: _ } => unimplemented!(),
            }
        }

        // Output what we have at the end of the evaluation.
        // In bristol fashion, the output wires have numbers from
        // wire_length - output_count ... wire_length
        let output_count: u64 = circuit.output_sizes().iter().sum();
        let wire_count: u64 = circuit.nwires();
        let mut masked_output_values = Vec::with_capacity(output_count as usize);
        for out in (wire_count - output_count)..wire_count {
            masked_output_values.push(masked_wire_values[out as usize]);
        }

        Ok(CopzEncodedOutput {
            masked_output_values,
            masked_and_gates,
            masked_wire_values,
            digests: hashers
                .into_iter()
                .map(|hasher| {
                    let h = hasher.finalize();
                    *h.as_bytes()
                })
                .collect_vec(),
        })
    }

    fn check_and_decode(
        &self,
        output_msg2: Vec<CopzOutputMsg2>,
        chi: &[u8; 32],
        encoded: CopzEncodedOutput,
        decoder: Vec<Vec<F2>>,
        circuit: &Circuit,
    ) -> Result<Vec<F2>, GcError> {
        if decoder.len() != self.num_parties as usize - 1 {
            eprintln!("decoder.len != num_parties - 1");
            return Err(GcError::DecoderLengthError);
        }
        if encoded.masked_output_values.len() != decoder[0].len() {
            eprintln!("masked_output_values.len != decoder[0].len()");
            return Err(GcError::DecoderLengthError);
        }
        if encoded.masked_output_values.len() != self.wire_mask_shares.len() {
            eprintln!("masked_output_values.len != wire_mask_shares.len()");
            return Err(GcError::DecoderLengthError);
        }

        self.check_universal_hash(&output_msg2, &encoded.masked_wire_values, chi, circuit)?;

        let decoder = transpose(decoder);

        let res = izip!(
            encoded.masked_output_values,
            decoder,
            &self.wire_mask_shares
        )
        .map(|(masked_output, mask_shares, evaluator_share)| {
            let mask =
                mask_shares.into_iter().fold(F2::ZERO, |acc, x| acc + x) + evaluator_share.share;
            #[cfg(test)]
            {
                println!("reconstructed output mask: {mask:?}");
            }
            masked_output + mask
        })
        .collect_vec();
        Ok(res)
    }
}

impl CopzEvaluator {
    fn check_universal_hash(
        &self,
        msgs: &[CopzOutputMsg2],
        masked_wire_values: &[F2],
        chi: &[u8; 32],
        circuit: &Circuit,
    ) -> Result<(), GcError> {
        let mut and_gate_counter = 0usize;
        let mut t_g_delta_1 = vec![];
        for gate in circuit.gates() {
            match gate {
                Gate::INV { a: _, out: _ } => {}
                Gate::XOR { a: _, b: _, out: _ } => {}
                Gate::AND { a, b, out } => {
                    let [lambda_u, lambda_v, lambda_uv, lambda_w] =
                        &self.garbling_shares[and_gate_counter];

                    let r1_delta = lambda_v.to_x_delta_i_share(self.num_parties - 1, &self.delta);
                    let r2_0_delta = lambda_w.to_x_delta_i_share(self.num_parties - 1, &self.delta)
                        + lambda_uv.to_x_delta_i_share(self.num_parties - 1, &self.delta);
                    let r2_1_delta =
                        r2_0_delta + lambda_u.to_x_delta_i_share(self.num_parties - 1, &self.delta);

                    let u_hat = masked_wire_values[*a as usize];
                    let v_hat = masked_wire_values[*b as usize];
                    let w_hat = masked_wire_values[*out as usize];

                    t_g_delta_1.push(
                        u_hat * r1_delta
                            + (F2::ONE - v_hat) * r2_0_delta
                            + v_hat * r2_1_delta
                            + (u_hat * v_hat + w_hat) * self.delta,
                    );

                    and_gate_counter += 1;
                }
                bad_gate => {
                    panic!("unimplemented for gate {bad_gate:?}")
                }
            }
        }

        let z_1 = universal_hash(chi, &t_g_delta_1);

        let actual = msgs
            .iter()
            .map(|m| m.z_i)
            .fold(F128b::ZERO, |acc, x| acc + x)
            + z_1;
        if actual == F128b::ZERO {
            Ok(())
        } else {
            Err(GcError::OutputCheckFailure(format!(
                "ferrot checked failed in evaluator, got {actual:?}, expected zero"
            )))
        }
    }
}
