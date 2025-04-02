use std::io::{BufRead, Cursor, Read, Write};

use bristol_fashion::{Circuit, Gate};
use generic_array::GenericArray;
use itertools::{Itertools, izip};
use rand::{CryptoRng, Rng};
use scuttlebutt::{ring::FiniteRing, serialization::CanonicalSerialize};
use swanky_field_binary::{F2, F128b};

use crate::{
    MsgRound1, MsgRound2, MsgRound3, error::GcError, garbler::auth_bits_from_prep,
    prep::Preprocessor, sharing::AuthShare,
};

use super::{Garbler, Garbling};

pub struct CopzGarbler<P: Preprocessor> {
    party_id: u16,
    num_parties: u16,
    preprocessor: P,

    delta: F128b,
}

pub struct CopzEvaluatorOutput {
    pub(crate) total_num_parties: u16,
    pub(crate) garbling_shares: Vec<[AuthShare<F2, F128b>; 4]>,
    /// The authenticated bits of the wire masks \lambda_w of the output wires.
    pub(crate) wire_mask_shares: Vec<AuthShare<F2, F128b>>,
    pub(crate) delta: F128b,
}

pub enum CopzGarbling {
    Garbler(Vec<CopzGarbledGate>),
    Evaluator(CopzEvaluatorOutput),
}

impl Garbling for CopzGarbling {}

impl CopzGarbling {
    pub fn get_garbler_gates(self) -> Vec<CopzGarbledGate> {
        match self {
            CopzGarbling::Garbler(inner) => inner,
            CopzGarbling::Evaluator(_) => panic!("not a garbler"),
        }
    }

    pub fn get_evaluator_gates(self) -> CopzEvaluatorOutput {
        match self {
            CopzGarbling::Garbler(_) => panic!("not an evaluator"),
            CopzGarbling::Evaluator(inner) => inner,
        }
    }
}

pub struct CopzMsgRound1 {}
impl MsgRound1 for CopzMsgRound1 {}

#[derive(Clone)]
pub struct CopzMsgRound2 {}
impl MsgRound2 for CopzMsgRound2 {
    fn into_masked_inputs(self) -> Vec<F2> {
        todo!()
    }
}

pub struct CopzMsgRound3 {}
impl MsgRound3 for CopzMsgRound3 {
    type Decoder = Vec<(F2, F128b)>;

    fn into_labels_and_decoder(self) -> (Vec<F128b>, Self::Decoder) {
        todo!()
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
        for j in 0..num_parties {
            if j != party_id && j != num_parties - 1 {
                let buf = r.to_x_delta_i_share(j, delta).to_bytes();
                body.write_all(&buf).unwrap();
            }
        }
        body
    };

    let body_1 = write_body(r1, k_v_0);
    let body_2 = write_body(r2_0, k_w_0);
    let body_3 = write_body(r2_1, k_w_0);
    assert_eq!(body_1.get_ref().len(), mask_1.len());
    assert_eq!(body_2.get_ref().len(), mask_2.len());
    assert_eq!(body_3.get_ref().len(), mask_3.len());

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
    assert_eq!(garbled_tables.len(), num_parties as usize - 1);
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
        let mask = h(&k_u_hat, &k_v_hat, party_id as u16);

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

        // read {r^j_i}_{j != i, 1} and then sum everything
        let r_i_sum = (0..num_parties - 2)
            .map(|_| {
                body_cursor.read_exact(&mut buf).unwrap();
                F128b::from_bytes(&buf).unwrap()
            })
            .fold(F128b::ZERO, |acc, x| acc + x);

        // the reader should be empty
        debug_assert_eq!(0, body_cursor.fill_buf().unwrap().len());

        let r_i_1 =
            u_hat * *lambda_v_delta + lambda_uv_delta + lambda_w_delta + v_hat * *lambda_u_delta;
        let k_w_hat = k_i + u_hat * *k_v_hat + r_i_sum + r_i_1;
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
    type MR1 = CopzMsgRound1;
    type MR2 = CopzMsgRound2;
    type MR3 = CopzMsgRound3;

    fn num_parties(&self) -> u16 {
        self.num_parties
    }

    fn garble<R: Rng + CryptoRng>(&mut self, rng: &mut R, circuit: &Circuit) -> CopzGarbling {
        // Get the deltas, make sure lsb(\Delta_2) = 1
        // This translates to delta of party_id = 1 since evaluator is party 0
        let delta = self.preprocessor.init_delta().unwrap();
        if self.party_id == 1 {
            assert_eq!(delta.to_bytes()[0] & 1, 1);
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

        for gate in circuit.gates() {
            match gate {
                Gate::XOR { a, b, out } => {
                    let output_share = &auth_bits[a] + &auth_bits[b];
                    assert!(!auth_bits.contains_key(out));
                    auth_bits.insert(*out, output_share);
                    if self.is_garbler() {
                        assert!(!wire_labels.contains_key(out));
                        wire_labels.insert(*out, wire_labels[a] + wire_labels[b]);
                    }
                }
                Gate::INV { a, out } => {
                    if self.is_garbler() {
                        wire_labels.insert(*out, wire_labels[a] + delta);
                    }
                    auth_bits.insert(*out, auth_bits[a].clone());
                }
                Gate::AND { a, b, out } => {
                    let lambda_u = &auth_bits[a];
                    let lambda_v = &auth_bits[b];
                    let lambda_uv = &auth_bits[out];
                    let lambda_w = self.preprocessor.auth_mul(lambda_u, lambda_v).unwrap();

                    /*
                    // <\lambda_u \Delta_j>, j \in [n]
                    let u_delta_js = bit_a.to_x_delta_shares(&delta);
                    // <\lambda_v \Delta_j>, j \in [n]
                    let v_delta_js = bit_b.to_x_delta_shares(&delta);
                    // <\lambda_w \Delta_j>, j \in [n]
                    let w_delta_js = bit_out.to_x_delta_shares(&delta);
                    // <\lambda_v \lambda_v \Delta_j>, j \in [n]
                    let uv_delta_js = bit_prod.to_x_delta_shares(&delta);
                    */

                    let r1 = lambda_v;
                    let r2_0 = lambda_uv + &lambda_w;
                    let r2_1 = &r2_0 + lambda_u;

                    if self.is_garbler() {
                        let k_u_0 = wire_labels[a];
                        let k_v_0 = wire_labels[b];
                        let k_w_0 = wire_labels[out];
                        let garbled_table = encrypt_garbled_table(
                            r1,
                            &r2_0,
                            &r2_1,
                            &k_u_0,
                            &k_v_0,
                            &k_w_0,
                            &delta,
                            *out,
                            self.party_id,
                            self.num_parties,
                        );
                        garbler_output.push(garbled_table);
                    } else {
                        eval_output.push([
                            lambda_u.clone(),
                            lambda_v.clone(),
                            lambda_uv.clone(),
                            lambda_w.clone(),
                        ]);
                    }
                }
                Gate::EQ { lit: _, out: _ } => unimplemented!("EQ gate not supported"),
                Gate::EQW { a: _, out: _ } => unimplemented!("EQW gate not supported"),
            }
        }

        self.preprocessor.done();

        if self.is_garbler() {
            CopzGarbling::Garbler(garbler_output)
        } else {
            let output_wire_count: u64 = circuit.output_sizes().iter().sum();
            let nwires = circuit.nwires();
            debug_assert_eq!(nwires as usize, auth_bits.len());
            CopzGarbling::Evaluator(CopzEvaluatorOutput {
                total_num_parties: self.num_parties,
                garbling_shares: eval_output,
                wire_mask_shares: (nwires - output_wire_count..nwires)
                    .map(|i| auth_bits[&i].clone())
                    .collect(),
                delta,
            })
        }
    }

    fn party_id(&self) -> u16 {
        self.party_id
    }

    fn input_round_1(&self) -> Self::MR1 {
        todo!()
    }

    fn input_round_2(
        &self,
        true_inputs: Vec<F2>,
        msgs: Vec<Self::MR1>,
    ) -> Result<Vec<Self::MR2>, GcError> {
        todo!()
    }

    fn input_round_3(&self, msg: Self::MR2) -> Self::MR3 {
        todo!()
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
                &vec![garbled_table.clone()],
                &vec![k_u_hat],
                &vec![k_v_hat],
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
