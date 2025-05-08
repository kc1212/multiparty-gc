use std::io::{BufRead, Cursor, Read, Write};

use bristol_fashion::{Circuit, Gate};
use generic_array::GenericArray;
use itertools::{Itertools, izip};
use rand::{CryptoRng, Rng};
use scuttlebutt::{ring::FiniteRing, serialization::CanonicalSerialize};
use swanky_field_binary::{F2, F128b};

use crate::{
    InputMsg1, InputMsg2, InputMsg3, OutputMsg1, OutputMsg2, error::GcError,
    garbler::auth_bits_from_prep, prep::Preprocessor, sharing::AuthShare, universal_hash,
};

use super::{Garbler, Garbling, process_linear_gates};

/// P_1 broadcasts X, {\hat{w}} to all garblers
/// Additionally it sends h_i = H({k^i_{w,\hat{w}}}) to P_i
pub struct CopzOutputMsg1 {
    pub(crate) w_hats: Vec<F2>,
    pub(crate) h: [u8; 32],
    pub(crate) chi: [u8; 32],
}

impl OutputMsg1 for CopzOutputMsg1 {
    fn chi(&self) -> [u8; 32] {
        self.chi
    }
}

/// P_i sends z^i = H_X({<t_g \Delta^1>}_g) to P_1.
pub struct CopzOutputMsg2 {
    pub(crate) z_i: F128b,
}

impl OutputMsg2 for CopzOutputMsg2 {}

pub struct CopzGarbler<P: Preprocessor> {
    party_id: u16,
    num_parties: u16,
    preprocessor: P,

    delta: F128b,

    input_shares: Vec<F2>,

    // Input labels created by the garbler.
    input_labels: Vec<F128b>,

    // This is for the output decoder, basically the shares of output wire masks.
    output_decoder: Vec<F2>,

    // This is all the wire labels of AND gates that we need
    // for the check step.
    and_wire_labels: Vec<F128b>,

    r1_delta_1: Vec<F128b>,
    r2_0_delta_1: Vec<F128b>,
    r2_1_delta_1: Vec<F128b>,
}

impl<P: Preprocessor> CopzGarbler<P> {
    pub fn new(party_id: u16, num_parties: u16, preprocessor: P) -> Self {
        Self {
            party_id,
            num_parties,
            preprocessor,
            delta: F128b::ZERO,
            input_shares: vec![],
            input_labels: vec![],
            output_decoder: vec![],
            and_wire_labels: vec![],
            r1_delta_1: vec![],
            r2_0_delta_1: vec![],
            r2_1_delta_1: vec![],
        }
    }
}

pub struct CopzEvaluatorOutput {
    pub(crate) num_parties: u16,
    pub(crate) garbling_shares: Vec<[AuthShare<F2, F128b>; 4]>,
    /// The authenticated bits of the wire masks \lambda_w of the output wires.
    pub(crate) wire_mask_shares: Vec<AuthShare<F2, F128b>>,
    pub(crate) delta: F128b,
}

pub enum CopzGarbling {
    Garbler((Vec<CopzGarbledGate>, Option<Vec<F2>>)),
    Evaluator(CopzEvaluatorOutput),
}

impl Garbling for CopzGarbling {}

impl CopzGarbling {
    pub fn into_garbler_gates(self) -> Vec<CopzGarbledGate> {
        match self {
            CopzGarbling::Garbler(inner) => inner.0,
            CopzGarbling::Evaluator(_) => panic!("not a garbler"),
        }
    }

    pub fn into_evaluator_gates(self) -> CopzEvaluatorOutput {
        match self {
            CopzGarbling::Garbler(_) => panic!("not an evaluator"),
            CopzGarbling::Evaluator(inner) => inner,
        }
    }

    pub fn get_b_w(&self) -> Vec<F2> {
        match self {
            CopzGarbling::Garbler(inner) => inner.1.clone().expect("b_w is None"),
            CopzGarbling::Evaluator(_) => panic!("not a garbler"),
        }
    }
}

pub struct CopzInputMsg1 {
    shares: Vec<F2>,
}

impl InputMsg1 for CopzInputMsg1 {}

#[derive(Clone)]
pub struct CopzInputMsg2 {
    masked_inputs: Vec<F2>,
}

impl InputMsg2 for CopzInputMsg2 {
    fn into_masked_inputs(self) -> Vec<F2> {
        self.masked_inputs
    }
}

pub struct CopzInputMsg3 {
    labels: Vec<F128b>,
    output_decoder: Vec<F2>,
}

impl InputMsg3 for CopzInputMsg3 {
    type Decoder = Vec<F2>;

    fn into_labels_and_decoder(self) -> (Vec<F128b>, Self::Decoder) {
        (self.labels, self.output_decoder)
    }
}

#[derive(Clone)]
pub struct CopzGarbledGate {
    inner: [Vec<u8>; 3],
}

fn lsb_f128b(x: &F128b) -> F2 {
    if (x.to_bytes()[0] & 1) == 0 {
        F2::ZERO
    } else {
        F2::ONE
    }
}

/// Produce the three garbled tables and encrypt them.
/// - `r1`: [\lambda_v]
/// - `r2_0`: [\lambda_w + \lambda_u \lambda_v]
/// - `r2_1`: [\lambda_w + \lambda_u \lambda_v + \lambda_u]
/// - `k_u_0`:
/// - `k_v_0`:
/// - `k_w_0`:
/// - `delta`:
/// - `gate_id`:
/// - `party_id`:
/// - `num_parties`: the number of parties,
///   should be consistent with the MACs/Keys in the authenticated shares
#[allow(clippy::too_many_arguments)]
fn encrypt_garbled_table(
    r1: &AuthShare<F2, F128b>,
    r2_0: &AuthShare<F2, F128b>,
    r2_1: &AuthShare<F2, F128b>,
    k_u_0: &F128b,
    k_v_0: &F128b,
    k_w_0: &F128b,
    delta: &F128b,
    gate_id: u64,
    party_id: u16,
    num_parties: u16,
) -> CopzGarbledGate {
    let out_len = (128 + (num_parties as usize - 2) * 128) / 8;
    #[cfg(test)]
    {
        println!(
            "[enc] labels=({k_u_0:?}, {k_v_0:?}, {k_w_0:?}), gate={gate_id}, party_id={party_id}"
        );
    }

    let h = |k_left: &F128b, k_right: &F128b| {
        let mut hasher_left = blake3::Hasher::new();
        hasher_left.update(&k_left.to_bytes());
        hasher_left.update(&gate_id.to_le_bytes());
        hasher_left.update(&party_id.to_le_bytes());
        let mut xof_reader_left = hasher_left.finalize_xof();

        let mut hasher_right = blake3::Hasher::new();
        hasher_right.update(&k_right.to_bytes());
        hasher_right.update(&gate_id.to_le_bytes());
        hasher_right.update(&party_id.to_le_bytes());
        let mut xof_reader_right = hasher_left.finalize_xof();

        let mut h_left = vec![0u8; out_len];
        xof_reader_left.fill(&mut h_left);

        let mut h_right = vec![0u8; out_len];
        xof_reader_right.fill(&mut h_right);

        h_left
            .into_iter()
            .zip(h_right)
            .map(|(left, right)| left ^ right)
            .collect_vec()
    };

    // mask_1 = H(k_u_0, gate_id, party_id) + H(k_u_1, gate_id, party_id)
    let mut mask_1 = h(k_u_0, &(k_u_0 + delta));
    // mask_2 = H(k_v_0, gate_id', party_id) + H(k_u_0, gate_id, party_id)
    let mut mask_2 = h(k_v_0, k_u_0);
    // mask_3 = H(k_v_1, gate_id', party_id) + H(k_u_0, gate_id, party_id)
    let mut mask_3 = h(&(k_v_0 + delta), k_u_0);

    let write_body = |r: &AuthShare<F2, F128b>, k: &F128b| {
        let mut body = Cursor::new(Vec::<u8>::with_capacity(out_len));
        body.write_all(&(r.to_x_delta_i_share(party_id, delta) + k).to_bytes())
            .unwrap();
        for j in 0..num_parties - 1 {
            if j != party_id {
                let buf = r.to_x_delta_i_share(j, &F128b::ZERO).to_bytes();
                body.write_all(&buf).unwrap();
            }
        }
        body
    };

    let body_1 = write_body(r1, k_v_0);
    let body_2 = write_body(r2_0, k_w_0);
    let body_3 = write_body(r2_1, k_w_0);
    debug_assert_eq!(body_1.get_ref().len(), mask_1.len());
    debug_assert_eq!(body_2.get_ref().len(), mask_2.len());
    debug_assert_eq!(body_3.get_ref().len(), mask_3.len());

    for (m, b) in mask_1.iter_mut().zip(body_1.get_ref()) {
        *m ^= *b;
    }
    for (m, b) in mask_2.iter_mut().zip(body_2.get_ref()) {
        *m ^= *b;
    }
    for (m, b) in mask_3.iter_mut().zip(body_3.get_ref()) {
        *m ^= *b;
    }

    CopzGarbledGate {
        inner: [mask_1, mask_2, mask_3],
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn decrypt_garbled_gate(
    garbled_tables: &[CopzGarbledGate],
    k_u_hats: &[F128b],
    k_v_hats: &[F128b],
    lambda_w_delta_i: &[F128b],
    lambda_u_delta_i: &[F128b],
    lambda_v_delta_i: &[F128b],
    lambda_uv_delta_i: &[F128b],
    u_hat: F2,
    v_hat: F2,
    b_w: F2,
    gate_id: u64,
    num_parties: u16,
) -> (F2, Vec<F128b>) {
    debug_assert_eq!(garbled_tables.len(), num_parties as usize - 1);
    let out_len = (128 + (num_parties as usize - 2) * 128) / 8;

    let h = |k_left: &F128b, k_right: &F128b, party_id: u16| {
        let mut hasher_left = blake3::Hasher::new();
        hasher_left.update(&k_left.to_bytes());
        hasher_left.update(&gate_id.to_le_bytes());
        hasher_left.update(&party_id.to_le_bytes());
        let mut xof_reader_left = hasher_left.finalize_xof();

        let mut hasher_right = blake3::Hasher::new();
        hasher_right.update(&k_right.to_bytes());
        hasher_right.update(&gate_id.to_le_bytes());
        hasher_right.update(&party_id.to_le_bytes());
        let mut xof_reader_right = hasher_left.finalize_xof();

        let mut h_left = vec![0u8; out_len];
        xof_reader_left.fill(&mut h_left);

        let mut h_right = vec![0u8; out_len];
        xof_reader_right.fill(&mut h_right);

        h_left
            .into_iter()
            .zip(h_right)
            .map(|(left, right)| left ^ right)
            .collect_vec()
    };

    // this is to compute
    // sum_{j != i} r^i_j
    let mut r_i_j_sum = vec![F128b::ZERO; num_parties as usize];
    let mut k_is = Vec::with_capacity(num_parties as usize);

    // iterate over i
    let mut output_labels = vec![];
    for (
        party_id,
        (
            garbled_table,
            k_u_hat,
            k_v_hat,
            lambda_w_delta,
            lambda_u_delta,
            lambda_v_delta,
            lambda_uv_delta,
        ),
    ) in izip!(
        garbled_tables,
        k_u_hats,
        k_v_hats,
        lambda_w_delta_i,
        lambda_u_delta_i,
        lambda_v_delta_i,
        lambda_uv_delta_i
    )
    .enumerate()
    {
        // (k^i || {r^j_i}_{j != i, 1}) :=
        // F_{k_u_hat}(g, i) + F_{k_v_hat}(g, i) + u_hat c1 + c2_v_hat
        let [c1, c2_0, c2_1] = &garbled_table.inner;
        let mask = h(k_u_hat, k_v_hat, party_id as u16);

        assert_eq!(mask.len(), c1.len());
        assert_eq!(mask.len(), c2_0.len());
        assert_eq!(mask.len(), c2_1.len());

        let c2 = if v_hat == F2::ZERO { c2_0 } else { c2_1 };

        let body = if u_hat == F2::ZERO {
            izip!(mask, c2).map(|(a, c)| a ^ c).collect_vec()
        } else {
            izip!(mask, c1, c2).map(|(a, b, c)| a ^ b ^ c).collect_vec()
        };
        let mut body_cursor = Cursor::new(body);

        let mut buf = GenericArray::<u8, <F128b as CanonicalSerialize>::ByteReprLen>::default();

        // read k^i
        body_cursor.read_exact(&mut buf).unwrap();
        let k_i = F128b::from_bytes(&buf).unwrap();
        k_is.push(k_i);

        #[allow(clippy::needless_range_loop)]
        for j in 0..num_parties as usize - 1 {
            if j != party_id {
                body_cursor.read_exact(&mut buf).unwrap();
                r_i_j_sum[j] += F128b::from_bytes(&buf).unwrap();
            }
        }

        // the reader should be empty
        debug_assert_eq!(0, body_cursor.fill_buf().unwrap().len());

        // extract r^i_1
        let r_i_1 =
            u_hat * *lambda_v_delta + lambda_uv_delta + lambda_w_delta + v_hat * *lambda_u_delta;
        r_i_j_sum[party_id] += r_i_1;
    }

    // iterate over i = party_id and
    for (k_v_hat, k_i, r_sum) in izip!(k_v_hats, k_is, r_i_j_sum) {
        let k_w_hat = k_i + u_hat * *k_v_hat + r_sum;
        #[cfg(test)]
        {
            println!(
                "[dec] output_label={:?}, u_hat={u_hat:?}, v_hat={v_hat:?}",
                k_w_hat
            );
        }
        output_labels.push(k_w_hat);
    }

    // \hat{w} = b_w + lsb(k^2_\hat{w})
    // NOTE: party at index 0 is the first garbler
    // (in contrast to party with index 2 in the paper)
    let hat_w = b_w + lsb_f128b(&output_labels[0]);
    (hat_w, output_labels)
}

impl<P: Preprocessor> Garbler for CopzGarbler<P> {
    type Gc = CopzGarbling;
    type IM1 = CopzInputMsg1;
    type IM2 = CopzInputMsg2;
    type IM3 = CopzInputMsg3;
    type OM1 = CopzOutputMsg1;
    type OM2 = CopzOutputMsg2;

    fn num_parties(&self) -> u16 {
        self.num_parties
    }

    fn garble<R: Rng + CryptoRng>(&mut self, rng: &mut R, circuit: &Circuit) -> CopzGarbling {
        // Get the deltas, make sure lsb(\Delta_2) = 1
        // This translates to delta of party_id = 0 since evaluator is party n-1
        self.delta = self.preprocessor.init_delta().unwrap();

        #[cfg(test)]
        {
            if self.party_id == 0 {
                assert_eq!(self.delta.to_bytes()[0] & 1, 1);
            }
        }

        let mut auth_bits = auth_bits_from_prep(&mut self.preprocessor, circuit);
        let mut wire_labels = self.gen_labels(rng, circuit);

        let and_gate_count = circuit.nand();

        let mut garbler_output = Vec::with_capacity(if self.is_garbler() {
            and_gate_count as usize
        } else {
            0
        });

        let mut eval_output = Vec::with_capacity(if self.is_garbler() {
            0
        } else {
            and_gate_count as usize
        });

        // This is the b_w that only party 0 stores (party 2 in the paper)
        let mut b_w_output = Vec::with_capacity(if self.party_id == 0 {
            and_gate_count as usize
        } else {
            0
        });

        // first process XOR and INV gates
        // note that the authenticated bits and labels are updated
        process_linear_gates(
            &mut auth_bits,
            &mut wire_labels,
            circuit,
            self.delta,
            self.is_garbler(),
        );

        // ask the preprocessor to do authenticated multiplication
        // for a batch of authenticated bits
        let indicies_for_mul = circuit
            .gates()
            .iter()
            .filter_map(|gate| match gate {
                Gate::AND { a, b, out: _ } => Some((*a as usize, *b as usize)),
                _ => None,
            })
            .collect_vec();
        let auth_prods = self
            .preprocessor
            .beaver_mul(&auth_bits, &indicies_for_mul)
            .unwrap();

        let mut and_gate_counter = 0usize;
        for gate in circuit.gates() {
            match gate {
                Gate::XOR { .. } | Gate::INV { .. } => { /* already processed */ }
                Gate::AND { a, b, out } => {
                    let lambda_u = &auth_bits[*a as usize];
                    let lambda_v = &auth_bits[*b as usize];
                    let lambda_uv = &auth_prods[and_gate_counter];
                    let lambda_w = &auth_bits[*out as usize];

                    let r1 = lambda_v;
                    let r2_0 = lambda_uv + lambda_w;
                    let r2_1 = &r2_0 + lambda_u;

                    self.r1_delta_1
                        .push(r1.to_x_delta_i_share(self.num_parties - 1, &F128b::ZERO));
                    self.r2_0_delta_1
                        .push(r2_0.to_x_delta_i_share(self.num_parties - 1, &F128b::ZERO));
                    self.r2_1_delta_1
                        .push(r2_1.to_x_delta_i_share(self.num_parties - 1, &F128b::ZERO));

                    if self.is_garbler() {
                        let k_u_0 = wire_labels[*a as usize];
                        let k_v_0 = wire_labels[*b as usize];
                        let k_w_0 = wire_labels[*out as usize];
                        let garbled_table = encrypt_garbled_table(
                            r1,
                            &r2_0,
                            &r2_1,
                            &k_u_0,
                            &k_v_0,
                            &k_w_0,
                            &self.delta,
                            *out,
                            self.party_id,
                            self.num_parties,
                        );
                        garbler_output.push(garbled_table);

                        self.and_wire_labels.push(k_w_0);

                        if self.party_id == 0 {
                            b_w_output.push(lsb_f128b(&k_w_0));
                        }
                    } else {
                        eval_output.push([
                            lambda_u.clone(),
                            lambda_v.clone(),
                            lambda_uv.clone(),
                            lambda_w.clone(),
                        ]);
                    }
                    and_gate_counter += 1;
                }
                Gate::EQ { lit: _, out: _ } => unimplemented!("EQ gate not supported"),
                Gate::EQW { a: _, out: _ } => unimplemented!("EQW gate not supported"),
            }
        }

        self.preprocessor.done();

        // Keep some information that we need for inputs
        let input_wire_count: u64 = circuit.input_sizes().iter().sum();
        for input_idx in 0..input_wire_count as usize {
            let r = auth_bits[input_idx].share;
            self.input_shares.push(r);

            if !self.is_garbler() {
            } else {
                let label = wire_labels[input_idx];
                self.input_labels.push(label);
            }
        }

        // Keep some information we need for outputs
        let output_wire_count: u64 = circuit.output_sizes().iter().sum();
        let nwires = circuit.nwires();
        if self.is_garbler() {
            self.output_decoder = (nwires - output_wire_count..nwires)
                .map(|i| auth_bits[i as usize].share)
                .collect();
        }

        if self.is_garbler() {
            if self.party_id == 0 {
                CopzGarbling::Garbler((garbler_output, Some(b_w_output)))
            } else {
                CopzGarbling::Garbler((garbler_output, None))
            }
        } else {
            debug_assert_eq!(nwires as usize, auth_bits.len());
            CopzGarbling::Evaluator(CopzEvaluatorOutput {
                num_parties: self.num_parties,
                garbling_shares: eval_output,
                wire_mask_shares: (nwires - output_wire_count..nwires)
                    .map(|i| auth_bits[i as usize].clone())
                    .collect(),
                delta: self.delta,
            })
        }
    }

    fn party_id(&self) -> u16 {
        self.party_id
    }

    fn input_round_1(&self) -> CopzInputMsg1 {
        // Only the garbler can all this function
        assert!(self.party_id != self.num_parties - 1);

        CopzInputMsg1 {
            shares: self.input_shares.clone(),
        }
    }

    fn input_round_2(
        &self,
        true_inputs: &[F2],
        msgs: Vec<CopzInputMsg1>,
    ) -> Result<Vec<CopzInputMsg2>, GcError> {
        debug_assert_eq!(self.party_id, self.num_parties - 1);

        #[cfg(test)]
        println!("True inputs: {true_inputs:?}");

        // Reconstruct the \lambda_w shares
        let mut output = true_inputs.to_vec();
        for CopzInputMsg1 { shares } in msgs.into_iter() {
            debug_assert_eq!(output.len(), shares.len());
            for (w, share) in shares.into_iter().enumerate() {
                output[w] += share;
            }
        }

        // We also need to add the shares from the evaluator
        debug_assert_eq!(output.len(), self.input_shares.len());
        for (o, i) in output.iter_mut().zip(&self.input_shares) {
            *o += *i;
        }

        #[cfg(test)]
        println!("Masked inputs: {output:?}");

        Ok((0..self.num_parties)
            .map(|_| CopzInputMsg2 {
                masked_inputs: output.clone(),
            })
            .collect())
    }

    /// We receive the masked input x^1_w + \lambda_w,
    /// then output the correct mask according to the masked input.
    fn input_round_3(&self, msg: CopzInputMsg2) -> CopzInputMsg3 {
        // Only the garbler can all this function
        assert!(self.party_id != self.num_parties - 1);

        let mut output = Vec::with_capacity(msg.masked_inputs.len());
        assert_eq!(msg.masked_inputs.len(), self.input_labels.len());
        for (label, masked_value) in self.input_labels.iter().zip(msg.masked_inputs) {
            if masked_value == F2::ZERO {
                output.push(*label);
            } else {
                output.push(*label + self.delta);
            }
        }
        CopzInputMsg3 {
            labels: output,
            output_decoder: self.output_decoder.clone(),
        }
    }

    fn check_output_msg1(
        &self,
        msg1: CopzOutputMsg1,
        masked_inputs: &[F2],
        circuit: &Circuit,
    ) -> Result<CopzOutputMsg2, GcError> {
        // we assume the opened \hat{w} is correct, i.e., opened with MAC check
        let CopzOutputMsg1 { w_hats, h, chi } = msg1;
        let mut hasher = blake3::Hasher::new();

        for (w_hat, label) in w_hats.iter().zip(&self.and_wire_labels) {
            hasher.update(&(*w_hat * self.delta + label).to_bytes());
        }

        let h_actual = hasher.finalize().as_bytes().to_vec();
        if h_actual != h.to_vec() {
            return Err(GcError::OutputCheckFailure(
                "hash mismatch on garbler".to_string(),
            ));
        }

        let gate_count = circuit.gates().len();
        let mut masked_wire_values = [masked_inputs.to_vec(), vec![F2::ZERO; gate_count]].concat();

        let mut and_gate_counter = 0usize;
        let mut t_g_delta_1 = vec![];
        for gate in circuit.gates() {
            match gate {
                Gate::INV { a, out } => {
                    masked_wire_values[*out as usize] = masked_wire_values[*a as usize] + F2::ONE;
                }
                Gate::XOR { a, b, out } => {
                    let u_hat = masked_wire_values[*a as usize];
                    let v_hat = masked_wire_values[*b as usize];
                    masked_wire_values[*out as usize] = u_hat + v_hat;
                }
                Gate::AND { a, b, out } => {
                    masked_wire_values[*out as usize] = w_hats[and_gate_counter];

                    // <t_g \Delta^1>_i := \hat{u} <r_1 \Delta^1>_i + <r_{2, \hat{v}} \Delta^1>_i
                    let u_hat = masked_wire_values[*a as usize];
                    let v_hat = masked_wire_values[*b as usize];
                    t_g_delta_1.push(
                        u_hat * self.r1_delta_1[and_gate_counter]
                            + (F2::ONE - v_hat) * self.r2_0_delta_1[and_gate_counter]
                            + v_hat * self.r2_1_delta_1[and_gate_counter],
                    );
                    and_gate_counter += 1;
                }
                bad_gate => {
                    panic!("unimplemented for gate {bad_gate:?}")
                }
            }
        }

        let z_i = universal_hash(&chi, &t_g_delta_1);

        Ok(CopzOutputMsg2 { z_i })
    }
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use rand::SeedableRng;
    use scuttlebutt::{AesRng, ring::FiniteRing, serialization::CanonicalSerialize};
    use swanky_field_binary::{F2, F128b};

    use crate::{
        garbler::copz::{decrypt_garbled_gate, lsb_f128b},
        sharing::secret_share_with_delta,
    };

    use super::encrypt_garbled_table;

    #[test]
    fn test_encrypt_garbled_table() {
        let mut rng = AesRng::from_entropy();
        let n = 2;
        let lambda_v = F2::random(&mut rng);
        let lambda_u = F2::random(&mut rng);
        let lambda_uv = lambda_u * lambda_v;
        let lambda_w = F2::random(&mut rng);

        // we need to make the deltas such that lsb(delta[0]) == 1
        let deltas = {
            let mut tmp = (0..n).map(|_| F128b::random(&mut rng)).collect_vec();
            let mut tmp0_buf = tmp[0].to_bytes();
            tmp0_buf[0] |= 1;
            tmp[0] = F128b::from_bytes(&tmp0_buf).unwrap();
            tmp
        };
        assert_eq!(lsb_f128b(&deltas[0]), F2::ONE);

        let lambda_v_shares = secret_share_with_delta::<_, F128b, _>(lambda_v, &deltas, &mut rng);
        let lambda_u_shares = secret_share_with_delta::<_, F128b, _>(lambda_u, &deltas, &mut rng);
        let lambda_uv_shares = secret_share_with_delta::<_, F128b, _>(lambda_uv, &deltas, &mut rng);
        let lambda_w_shares = secret_share_with_delta::<_, F128b, _>(lambda_w, &deltas, &mut rng);

        let k_u_0 = F128b::random(&mut rng);
        let k_v_0 = F128b::random(&mut rng);
        let k_w_0 = F128b::random(&mut rng);
        let b_w = lsb_f128b(&k_w_0);

        assert_eq!(
            (&lambda_w_shares[0] + &lambda_uv_shares[0]).to_x_delta_i_share(0, &deltas[0])
                + (&lambda_w_shares[1] + &lambda_uv_shares[1]).to_x_delta_i_share(0, &deltas[0]),
            (lambda_w + lambda_uv) * deltas[0]
        );

        let garbled_table = encrypt_garbled_table(
            &lambda_v_shares[0],
            &(&lambda_w_shares[0] + &lambda_uv_shares[0]),
            &(&lambda_w_shares[0] + &lambda_uv_shares[0] + &lambda_u_shares[0]),
            &k_u_0,
            &k_v_0,
            &k_w_0,
            &deltas[0],
            0,
            0,
            n,
        );

        for (u_hat, v_hat) in [
            (F2::ZERO, F2::ZERO),
            (F2::ZERO, F2::ONE),
            (F2::ONE, F2::ONE),
            (F2::ONE, F2::ZERO),
        ] {
            println!("testing u_hat={u_hat:?}, v_hat={v_hat:?}");

            let k_u_hat = u_hat * deltas[0] + k_u_0;
            let k_v_hat = v_hat * deltas[0] + k_v_0;

            // NOTE: party with index 1 is the evaluator
            let lambda_w_delta_i = lambda_w_shares[1].to_x_delta_shares(&deltas[1]);
            let lambda_u_delta_i = lambda_u_shares[1].to_x_delta_shares(&deltas[1]);
            let lambda_v_delta_i = lambda_v_shares[1].to_x_delta_shares(&deltas[1]);
            let lambda_uv_delta_i = lambda_uv_shares[1].to_x_delta_shares(&deltas[1]);

            let (w_hat, k_w_hat) = decrypt_garbled_gate(
                &[garbled_table.clone()],
                &[k_u_hat],
                &[k_v_hat],
                &lambda_w_delta_i,
                &lambda_u_delta_i,
                &lambda_v_delta_i,
                &lambda_uv_delta_i,
                u_hat,
                v_hat,
                b_w,
                0,
                n,
            );
            assert_eq!(k_w_hat.len(), 1);

            let k_w_hat = k_w_hat[0];
            if k_w_hat == k_w_0 {
                assert_eq!(w_hat, F2::ZERO);
            } else {
                assert_eq!(w_hat, F2::ONE);
            }
            assert_eq!(
                k_w_hat,
                (u_hat * v_hat + u_hat * lambda_v + lambda_w + lambda_uv + v_hat * lambda_u)
                    * deltas[0]
                    + k_w_0
            );
        }
    }
}
