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

pub enum CopzGarbling {}
impl Garbling for CopzGarbling {}

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

struct CopzGarbledTable {
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
) -> CopzGarbledTable {
    let out_len = 128 + (num_parties as usize - 2) * 128;
    let h = |k_left: &F128b, k_right: &F128b| {
        // NOTE, we use a single hasher instead of two,
        // ideally we should use two CCR
        let mut hasher = blake3::Hasher::new();

        // first part
        hasher.update(&k_left.to_bytes());
        hasher.update(&gate_id.to_le_bytes());
        hasher.update(&party_id.to_le_bytes());

        // second part
        hasher.update(&k_right.to_bytes());
        hasher.update(&gate_id.to_le_bytes());
        hasher.update(&party_id.to_le_bytes());

        let mut xof_reader = hasher.finalize_xof();
        let mut output = vec![0u8; out_len];
        xof_reader.fill(&mut output);
        output
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
                body.write_all(&r.to_x_delta_i_share(j, delta).to_bytes())
                    .unwrap();
            }
        }
        body
    };

    let body_1 = write_body(r1, k_v_0);
    let body_2 = write_body(r2_0, k_w_0);
    let body_3 = write_body(r2_1, k_w_0);

    for (m, b) in mask_1.iter_mut().zip(body_1.get_ref()) {
        *m ^= *b;
    }
    for (m, b) in mask_2.iter_mut().zip(body_2.get_ref()) {
        *m ^= *b;
    }
    for (m, b) in mask_3.iter_mut().zip(body_3.get_ref()) {
        *m ^= *b;
    }

    CopzGarbledTable {
        inner: [mask_1, mask_2, mask_3],
    }
}

fn decrypt_garbled_table(
    garbled_tables: Vec<CopzGarbledTable>,
    k_u_hats: Vec<F128b>,
    k_v_hats: Vec<F128b>,
    lambda_w_delta_i: Vec<F128b>,
    lambda_v_delta_i: Vec<F128b>,
    lambda_uv_delta_i: Vec<F128b>,
    u_hat: F2,
    v_hat: F2,
    b_w: F2,
    gate_id: u64,
    party_id: u16,
    num_parties: u16,
) -> (Vec<F128b>, F2) {
    assert_eq!(garbled_tables.len() - 1, num_parties as usize);
    let out_len = 128 + (num_parties as usize - 2) * 128;
    let h = |k_left: &F128b, k_right: &F128b| {
        // NOTE, we use a single hasher instead of two,
        // ideally we should use two CCR
        let mut hasher = blake3::Hasher::new();

        // first part
        hasher.update(&k_left.to_bytes());
        hasher.update(&gate_id.to_le_bytes());
        hasher.update(&party_id.to_le_bytes());

        // second part
        hasher.update(&k_right.to_bytes());
        hasher.update(&gate_id.to_le_bytes());
        hasher.update(&party_id.to_le_bytes());

        let mut xof_reader = hasher.finalize_xof();
        let mut output = vec![0u8; out_len];
        xof_reader.fill(&mut output);
        output
    };

    // iterate over i
    let mut output_labels = vec![];
    for (garbled_table, k_u_hat, k_v_hat, lambda_w_delta, lambda_v_delta, lambda_uv_delta) in izip!(
        garbled_tables,
        k_u_hats,
        k_v_hats,
        lambda_w_delta_i,
        lambda_v_delta_i,
        lambda_uv_delta_i
    ) {
        // (k^i || {r^j_i}_{j != i, 1}) :=
        // F_{k_u_hat}(g, i) + F_{k_v_hat}(g, i) + u_hat c1 + c2_v_hat
        let [c1, c2_0, c2_1] = garbled_table.inner;
        let mask = h(&k_u_hat, &k_v_hat);

        assert_eq!(mask.len(), c1.len());
        assert_eq!(mask.len(), c2_0.len());
        assert_eq!(mask.len(), c2_1.len());

        let c2 = if v_hat == F2::ZERO { c2_0 } else { c2_1 };

        let body = izip!(mask, c1, c2).map(|(a, b, c)| a ^ b ^ c).collect_vec();
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

        let r_i_1 = u_hat * lambda_v_delta + lambda_uv_delta + lambda_w_delta;
        let k_w_hat = k_i + u_hat * k_v_hat + r_i_sum + r_i_1;
        output_labels.push(k_w_hat);
    }

    // \hat{w} = b_w + lsb(k^2_\hat{w})
    let hat_w = b_w + lsb_f128b(&output_labels[0]);
    (output_labels, hat_w)
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
        let auth_bits = auth_bits_from_prep(&mut self.preprocessor, circuit);
        let wire_labels = self.gen_labels(rng, circuit);

        for gate in circuit.gates() {
            match gate {
                Gate::XOR { a, b, out } => todo!(),
                Gate::INV { a, out } => todo!(),
                Gate::AND { a, b, out } => {
                    let bit_a = &auth_bits[a];
                    let bit_b = &auth_bits[b];
                    let bit_out = &auth_bits[out];
                    let bit_prod = self.preprocessor.auth_mul(bit_a, bit_b).unwrap();

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

                    let r1 = bit_b;
                    let r2_0 = bit_out + &bit_prod;
                    let r2_1 = &r2_0 + bit_a;

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
                }
                Gate::EQ { lit: _, out: _ } => unimplemented!("EQ gate not supported"),
                Gate::EQW { a: _, out: _ } => unimplemented!("EQW gate not supported"),
            }
        }

        todo!()
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
    use rand::SeedableRng;
    use scuttlebutt::{AesRng, ring::FiniteRing};
    use swanky_field_binary::{F2, F128b};

    use crate::sharing::{secret_share, secret_share_with_delta};

    use super::encrypt_garbled_table;

    #[test]
    fn test_encrypt_garbled_table() {
        let mut rng = AesRng::from_entropy();
        let n = 3;
        let lambda_v = F2::random(&mut rng);
        let lambda_u = F2::random(&mut rng);
        let lambda_uv = lambda_u * lambda_v;
        let lambda_w = F2::random(&mut rng);
        let (lambda_v_shares, deltas) = secret_share::<_, F128b, _>(lambda_v, n, &mut rng);
        // let lambda_u_shares = secret_share_with_delta::<_, F128b, _>(lambda_u, &deltas, &mut rng);
        let lambda_uv_shares = secret_share_with_delta::<_, F128b, _>(lambda_uv, &deltas, &mut rng);
        let lambda_w_shares = secret_share_with_delta::<_, F128b, _>(lambda_w, &deltas, &mut rng);

        let k_u_0 = F128b::random(&mut rng);
        let k_v_0 = F128b::random(&mut rng);
        let k_w_0 = F128b::random(&mut rng);

        let _garbled_table = encrypt_garbled_table(
            &lambda_v_shares[0],
            &(&lambda_w_shares[0] + &lambda_uv_shares[0]),
            &(&lambda_w_shares[0] + &lambda_uv_shares[0] + &lambda_w_shares[0]),
            &k_u_0,
            &k_v_0,
            &k_w_0,
            &deltas[0],
            0,
            0,
            n,
        );
    }
}
