use std::io::{Cursor, Write};

use bristol_fashion::{Circuit, Gate};
use itertools::Itertools;
use rand::{CryptoRng, Rng};
use scuttlebutt::serialization::CanonicalSerialize;
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
