use std::{
    collections::BTreeMap,
    io::{Cursor, Read, Write},
};

use bristol_fashion::{Circuit, Gate};
use rand::{CryptoRng, Rng};
use scuttlebutt::ring::FiniteRing;
use scuttlebutt::serialization::CanonicalSerialize;
use swanky_field_binary::{F2, F128b};

use crate::{prep::Preprocessor, sharing::AuthShare};

use super::{GarbledTable, Garbler};

pub struct Wrk17Garbler<P: Preprocessor> {
    party_id: u16,
    preprocessor: P,
}

impl<P: Preprocessor> Wrk17Garbler<P> {
    fn gen_labels<R>(&mut self, rng: &mut R, circuit: &Circuit) -> BTreeMap<u64, F128b>
    where
        R: Rng + CryptoRng,
    {
        let mut output = BTreeMap::new();
        if self.party_id != 0 {
            // TODO not the most efficient way to make labels
            // a better way would to find all the wire IDs first
            for gate in circuit.gates() {
                match gate {
                    Gate::XOR { a, b, out } => {
                        output.entry(*a).or_insert_with(|| F128b::random(rng));
                        output.entry(*b).or_insert_with(|| F128b::random(rng));
                        output.entry(*out).or_insert_with(|| F128b::random(rng));
                    }
                    Gate::AND { a, b, out } => {
                        output.entry(*a).or_insert_with(|| F128b::random(rng));
                        output.entry(*b).or_insert_with(|| F128b::random(rng));
                        output.entry(*out).or_insert_with(|| F128b::random(rng));
                    }
                    Gate::INV { a, out } => {
                        output.entry(*a).or_insert_with(|| F128b::random(rng));
                        output.entry(*out).or_insert_with(|| F128b::random(rng));
                    }
                    Gate::EQ { lit: _, out: _ } => unimplemented!("EQ gate is not implemented"),
                    Gate::EQW { a: _, out: _ } => unimplemented!("EQW gate is not implemented"),
                }
            }
        }
        output
    }
}

struct Wrk17GarbledRow {
    inner: Vec<u8>,
}

impl Wrk17GarbledRow {
    // we need to encrypt the row with
    // H(L_a, L_b, gate_id, row_id)
    // and we need to encrypt the MAC keys with L_gamma
    fn encrypt_row(
        share: AuthShare<F2, F128b>,
        delta: F128b,
        label_a_0: F128b,
        label_b_0: F128b,
        label_gamma: F128b,
        gate_id: u64,
        row_id: u8,
    ) -> Self {
        // Create XOF of H(L_a, L_b, gate_id, row_id)
        let mut hasher = blake3::Hasher::new();
        assert!(row_id <= 3);
        let label_a = label_a_0
            + if (row_id ^ 1) == 0 {
                F128b::ZERO
            } else {
                delta
            };
        let label_b = label_b_0
            + if ((row_id >> 1) ^ 1) == 0 {
                F128b::ZERO
            } else {
                delta
            };
        hasher.update(&label_a.to_bytes());
        hasher.update(&label_b.to_bytes());
        hasher.update(&gate_id.to_le_bytes());
        hasher.update(&row_id.to_le_bytes());
        let mut xof_reader = hasher.finalize_xof();

        // Use the XOF to encrypt the following byte buffer
        // r^i (1 bit) || {M_j[r^1]} (128 * (n-1) bits) || L_gamma xor (sum K_i[r^j]) xor r^i \Delta_i
        let output_len = 1 + 128 / 8 * share.mac_keys.len() + 128 / 8;
        let mut to_encrypt = Cursor::new(Vec::<u8>::with_capacity(output_len));
        let r = share.share;
        to_encrypt.write(&r.to_bytes()).unwrap();
        share.serialize_mac_values(&mut to_encrypt);

        // L_gamma xor (sum K_i[r^j]) xor r^i \Delta_i
        let label_gamma_xor_sum_key =
            label_gamma + share.sum_mac_keys() + if r == F2::ZERO { F128b::ZERO } else { delta };
        to_encrypt
            .write(&label_gamma_xor_sum_key.to_bytes())
            .unwrap();
        // to_encrypt.flush().unwrap();

        // Expand the xof and use it as the key to encrypt the buffer `to_encrypt`
        let mut xof_buf = vec![0u8; output_len];
        xof_reader.fill(&mut xof_buf);
        let to_encrypt = to_encrypt.into_inner();
        assert_eq!(xof_buf.len(), to_encrypt.len());
        Self {
            inner: to_encrypt
                .into_iter()
                .zip(xof_buf)
                .map(|(a, b)| a ^ b)
                .collect(),
        }
    }
}

struct Wrk17GarbledAndGate {
    row0: AuthShare<F2, F128b>,
    row1: AuthShare<F2, F128b>,
    row2: AuthShare<F2, F128b>,
    row3: AuthShare<F2, F128b>,
}

struct Wrk17GarbledTable {
    gates: Vec<Wrk17GarbledAndGate>,
}

impl GarbledTable for Wrk17GarbledTable {
    type GarbledGate = Wrk17GarbledAndGate;

    fn push_gate(&mut self, garbled_gate: Self::GarbledGate) {
        self.gates.push(garbled_gate);
    }

    fn read_gate(&self, i: usize) -> &Self::GarbledGate {
        &self.gates[i]
    }
}

impl<P: Preprocessor> Garbler<Wrk17GarbledTable> for Wrk17Garbler<P> {
    fn party_id(&self) -> u16 {
        self.party_id
    }

    fn garble<R>(&mut self, rng: &mut R, circuit: &Circuit, output: &mut Wrk17GarbledTable)
    where
        R: Rng + CryptoRng,
    {
        let delta = self.preprocessor.init_delta();

        let (mut auth_bits, mut auth_prods) =
            self.preprocessor.auth_materials_from_circuit(circuit);
        // Reverse the authenticated products since we're going to pop them later
        auth_prods.reverse();
        assert_eq!(
            auth_prods.len(),
            circuit
                .gates()
                .iter()
                .filter(|g| matches!(g, Gate::AND { a: _, b: _, out: _ }))
                .count()
        );

        let mut wire_labels = self.gen_labels(rng, circuit);

        for gate in circuit.gates() {
            match gate {
                Gate::XOR { a, b, out } => {
                    let output_share = &auth_bits[a] + &auth_bits[b];
                    assert!(auth_bits.get(out).is_none());
                    auth_bits.insert(*out, output_share);
                    if self.party_id != 0 {
                        assert!(wire_labels.get(out).is_none());
                        wire_labels.insert(*out, wire_labels[a] + wire_labels[b]);
                    }
                }
                Gate::AND { a, b, out } => {
                    // we assume the and triples come in topological order
                    let auth_prod = auth_prods.pop().unwrap();
                    let row0 = &auth_prod + &auth_bits[out];
                    let row1 = &row0 + &auth_bits[a];
                    let row2 = &row0 + &auth_bits[b];
                    let row3 = if self.party_id != 0 {
                        let mut tmp = &row1 + &auth_bits[b];
                        tmp.mac_keys.get_mut(&0).map(|x| *x += delta);
                        tmp
                    } else {
                        let mut tmp = &row1 + &auth_bits[b];
                        tmp.share += F2::ONE;
                        tmp
                    };
                    let garbled_gate = Wrk17GarbledAndGate {
                        row0,
                        row1,
                        row2,
                        row3,
                    };
                    output.push_gate(garbled_gate);
                }
                bristol_fashion::Gate::INV { a: _, out: _ } => todo!(),
                bristol_fashion::Gate::EQ { lit: _, out: _ } => todo!(),
                bristol_fashion::Gate::EQW { a: _, out: _ } => todo!(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use scuttlebutt::AesRng;

    use crate::sharing::secret_share;

    use super::*;

    #[test]
    fn test_encrypt_row() {
        let mut rng = AesRng::new();
        let n = 10u16;
        let secret = F2::random(&mut rng);
        let (shares, deltas) = secret_share::<_, F128b, _>(secret, n, &mut rng);
        let share = shares[0].clone();
        let delta = deltas[0];
        let label_a_0 = F128b::random(&mut rng);
        let label_b_0 = F128b::random(&mut rng);
        let label_gamma = F128b::random(&mut rng);
        let _row =
            Wrk17GarbledRow::encrypt_row(share, delta, label_a_0, label_b_0, label_gamma, 12, 0);
    }
}
