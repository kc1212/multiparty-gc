use std::{
    collections::BTreeMap,
    io::{Cursor, Read, Write},
    ops::Index,
};

use bristol_fashion::{Circuit, Gate};
use generic_array::GenericArray;
use rand::{CryptoRng, Rng};
use scuttlebutt::ring::FiniteRing;
use scuttlebutt::serialization::CanonicalSerialize;
use swanky_field_binary::{F2, F128b};

use crate::{error::GcError, prep::Preprocessor, sharing::AuthShare};

use super::{Garbler, Garbling};

/// Garbler for WRK17. Due to the way parties are indexed,
/// we set the last party (n-1) as the evaluator instead of the first.
pub struct Wrk17Garbler<P: Preprocessor> {
    party_id: u16,
    total_num_parties: u16,
    preprocessor: P,
}

impl<P: Preprocessor> Wrk17Garbler<P> {
    fn is_garbler(&self) -> bool {
        self.party_id != self.total_num_parties - 1
    }

    fn gen_labels<R>(&mut self, rng: &mut R, circuit: &Circuit) -> BTreeMap<u64, F128b>
    where
        R: Rng + CryptoRng,
    {
        let mut output = BTreeMap::new();
        if self.is_garbler() {
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

pub struct Wrk17GarbledRow {
    inner: Vec<u8>,
}

impl Wrk17GarbledRow {
    // we need to encrypt the row with
    // H(L_a, L_b, gate_id, row_id)
    // and we need to encrypt the MAC keys with L_gamma_0
    fn encrypt_row(
        share: &AuthShare<F2, F128b>,
        delta: F128b,
        label_a_0: F128b,
        label_b_0: F128b,
        label_gamma_0: F128b,
        gate_id: u64,
        row_id: u8,
    ) -> Self {
        // Create XOF of H(L_a, L_b, gate_id, row_id)
        let mut hasher = blake3::Hasher::new();
        assert!(row_id <= 3);
        let label_a = label_a_0
            + if (row_id & 1) == 0 {
                F128b::ZERO
            } else {
                delta
            };
        let label_b = label_b_0
            + if ((row_id >> 1) & 1) == 0 {
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
        // r^i (1 bit) || {M_j[r^1]} (128 * (n-1) bits) || L_gamma_0 xor (sum K_i[r^j]) xor r^i \Delta_i
        let output_len = 1 + 128 / 8 * share.mac_keys.len() + 128 / 8;
        let mut to_encrypt = Cursor::new(Vec::<u8>::with_capacity(output_len));
        let r = share.share;
        to_encrypt.write_all(&r.to_bytes()).unwrap();
        #[cfg(test)]
        {
            println!("encrypt writing MAC: {:?}", share.mac_values);
        }
        share.serialize_mac_values(&mut to_encrypt);

        // L_gamma_0 xor (sum K_i[r^j]) xor r^i \Delta_i
        let label_gamma_xor_sum_key =
            label_gamma_0 + share.sum_mac_keys() + if r == F2::ZERO { F128b::ZERO } else { delta };
        to_encrypt
            .write_all(&label_gamma_xor_sum_key.to_bytes())
            .unwrap();

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

    fn extract_macs_and_label_gamma(
        &self,
        label_a: F128b,
        label_b: F128b,
        gate_id: u64,
        row_id: u8,
        party_id: u16,
        party_count: u16,
    ) -> (
        GenericArray<u8, <F128b as CanonicalSerialize>::ByteReprLen>,
        AuthShare<F2, F128b>,
    ) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&label_a.to_bytes());
        hasher.update(&label_b.to_bytes());
        hasher.update(&gate_id.to_le_bytes());
        hasher.update(&row_id.to_le_bytes());
        let mut xof_reader = hasher.finalize_xof();

        let mut xof_buf = vec![0u8; self.inner.len()];
        xof_reader.fill(&mut xof_buf);
        #[cfg(test)]
        {
            println!(
                "decryption len {}, xof: {}",
                xof_buf.len(),
                hex::encode(&xof_buf)
            );
        }

        // G_{\gamma,\ell}^i xor H(L_a, L_b, \gamma, \ell)
        for (b, g) in xof_buf.iter_mut().zip(&self.inner) {
            *b ^= *g;
        }

        // In the cursor, first byte is r, then we have the MACs, finally the label
        let mut cursor = Cursor::new(xof_buf);

        // First read the byte and convert it to F2
        let mut r_buf = [0u8; 1];
        cursor.read_exact(&mut r_buf).unwrap();
        let r = F2::from_bytes((&r_buf).into()).unwrap();

        // Second read the MACs
        // M_j[r^i_{\gamma, \ell}], i is fixed in every iteration, j \in [n] \ i
        let mut r_share: AuthShare<_, F128b> = AuthShare {
            party_id,
            share: r,
            mac_values: BTreeMap::new(),
            mac_keys: BTreeMap::new(),
        };
        // TODO do we need to deserialize everything?
        r_share.deserialize_mac_values(party_count, &mut cursor);
        assert_eq!(r_share.mac_values.len(), party_count as usize - 1);
        #[cfg(test)]
        {
            println!("decrypt read MAC: {:?}", r_share.mac_values);
        }

        // Next we read the encrypted label:
        // L_\gamma^i + (sum K_i[r^j_{\gamma, \ell}]) + r^i_{\gamma, \ell} \Delta_i
        let mut enc_label_gamma_buf =
            GenericArray::<u8, <F128b as CanonicalSerialize>::ByteReprLen>::default();
        cursor.read_exact(&mut enc_label_gamma_buf).unwrap();
        (enc_label_gamma_buf, r_share)
    }

    fn decrypt_label_gamma(
        enc_label_gamma: &mut GenericArray<u8, <F128b as CanonicalSerialize>::ByteReprLen>,
        macs: F128b,
    ) -> F128b {
        // Remove the mask using the MACs
        // Decrypt it using sum_j, M_i[r^j_{\gamma, \ell}] for row \ell, j != i.
        for (a, b) in enc_label_gamma.iter_mut().zip(macs.to_bytes()) {
            *a ^= b;
        }

        let label_gamma = F128b::from_bytes(enc_label_gamma).unwrap();
        label_gamma
    }
}

pub struct Wrk17GarbledGate {
    party_id: u16,
    rows: [Wrk17GarbledRow; 4],
}

impl Index<u8> for Wrk17GarbledGate {
    type Output = Wrk17GarbledRow;

    fn index(&self, index: u8) -> &Self::Output {
        &self.rows[index as usize]
    }
}

/// Called by party_id = n-1, the evaluator
///
/// - `garbled_gates`: one garbled gate for each garbler (there are n-1 garblers)
/// - `a`: a masked wire value, z_a + \lambda_a
/// - `b`: a masked wire value, z_b + \lambda_b
/// - `label_as`: wire labels for the wire `a`, one for every party
/// - `label_bs`: wire labels for the wire `b`, one for every party
/// - `gate_id`: the gate ID (value of the output wire)
/// - `evaluator_shares`: shares produced by the evaluator during garbling, i.e.,
///   r^1_{\gamma, \ell}, { M_j[r^1_{\gamma, \ell}], K_1[r^i_{\gamma, \ell}] }
/// - `evaluator_delta`: the delta of the evaluator
pub(crate) fn decrypt_garbled_gate(
    garbled_gates: &[Wrk17GarbledGate],
    a: F2,
    b: F2,
    label_as: &[F128b],
    label_bs: &[F128b],
    gate_id: u64,
    evaluator_shares: &[AuthShare<F2, F128b>], // indexed over the 4 rows
    evaluator_delta: F128b,
) -> Result<(F2, Vec<F128b>), GcError> {
    // first get the row that we want to decrypt
    // row_id is \ell
    // TODO check order
    let row_id = match (<bool as From<F2>>::from(b), <bool as From<F2>>::from(a)) {
        (true, true) => 3,
        (true, false) => 2,
        (false, true) => 1,
        (false, false) => 0u8,
    };
    let party_count = garbled_gates.len() + 1;
    assert_eq!(party_count - 1, label_as.len());
    assert_eq!(party_count - 1, label_bs.len());
    let evaluator_index = party_count as u16 - 1;

    let mut r_shares = Vec::with_capacity(party_count - 1);
    let mut enc_label_gammas = Vec::with_capacity(party_count - 1);
    for party_id in 0..party_count - 1 {
        assert_eq!(garbled_gates[party_id].party_id as usize, party_id);

        // G_{\gamma,\ell}^i
        let garbled_row = Wrk17GarbledRow {
            // TODO don't need to clone
            inner: garbled_gates[party_id][row_id].inner.clone(),
        };

        let (enc_label_gamma, r_share) = garbled_row.extract_macs_and_label_gamma(
            label_as[party_id],
            label_bs[party_id],
            gate_id,
            row_id,
            party_id as u16,
            party_count as u16,
        );

        // perform mac check:
        // r^i_{\gamma, \ell} * \Delta_1 + K_1[r^i_{\gamma, \ell}] = M_1[r^i_{\gamma, \ell}]
        // where i is party_id
        if r_share.share * evaluator_delta
            + evaluator_shares[row_id as usize].mac_keys[&(party_id as u16)]
            != r_share.mac_values[&evaluator_index]
        {
            return Err(GcError::MacCheckFailure);
        }

        enc_label_gammas.push(enc_label_gamma);
        r_shares.push(r_share);
    }

    let mut output_share = F2::ZERO;
    let mut output_label = vec![F128b::ZERO; party_count - 1];
    for (party_id, enc_label_gamma) in enc_label_gammas.iter_mut().enumerate() {
        // We need to decrypt the labels, for this we need MACs of the form
        // M_i[r^j_{\gamma, \ell}]

        let macs = (0..party_count - 1)
            .map(|i| r_shares[i].mac_values[&(party_id as u16)])
            .fold(F128b::ZERO, |acc, x| acc + x);
        let recovered_label = Wrk17GarbledRow::decrypt_label_gamma(enc_label_gamma, macs);

        // \sum r^i_{\gamma, \ell} = z_\gamma + \lambda_\gamma
        output_share += r_shares[party_id].share;

        // If the labels start as zero, first set the labels to be
        // [L^0, L^1, ..., L^{n-1}]
        // Then we need to xor each label L^i with \sum_j M_i[r^j_{\gamma, \ell}]
        // But we're given M_j[r^i_{\gamma, \ell}] (note i and j are reversed)
        // So we iterate over j and add the MACs to each L^i.
        output_label[party_id] += recovered_label;
        for (k, v) in &r_shares[party_id].mac_values {
            output_label[*k as usize] += v;
        }
    }

    Ok((output_share, output_label))
}

pub struct Wrk17EvaluatorOutput {
    garbling_shares: Vec<[AuthShare<F2, F128b>; 4]>,
    // TODO we can just use a Vec here, only need the final shares for the output wires
    wire_mask_shares: BTreeMap<u64, AuthShare<F2, F128b>>,
    delta: F128b,
}

pub enum Wrk17Garbling {
    // the index (starting from 0) should correspond to the party_id
    // the length should be exactly n-1
    // party_id = n-1 is the evaluator
    Garbler(Vec<Wrk17GarbledGate>),
    Evaluator(Wrk17EvaluatorOutput),
}

impl Garbling for Wrk17Garbling {
    // type GarbledGate = Wrk17GarbledGate;

    // fn push_gate(&mut self, garbled_gate: Self::GarbledGate) {
    //     self.gates.push(garbled_gate);
    // }

    // fn read_gate(&self, i: usize) -> &Self::GarbledGate {
    //     &self.gates[i]
    // }
}

impl Wrk17Garbling {
    pub fn get_garbler_gates(self) -> Vec<Wrk17GarbledGate> {
        match self {
            Wrk17Garbling::Garbler(inner) => inner,
            Wrk17Garbling::Evaluator(_) => panic!("not a garbler"),
        }
    }

    pub fn get_evaluator_gates(self) -> Wrk17EvaluatorOutput {
        match self {
            Wrk17Garbling::Garbler(_) => panic!("not an evaluator"),
            Wrk17Garbling::Evaluator(inner) => inner,
        }
    }
}

impl<P: Preprocessor> Garbler<Wrk17Garbling> for Wrk17Garbler<P> {
    fn party_id(&self) -> u16 {
        self.party_id
    }

    fn garble<R>(&mut self, rng: &mut R, circuit: &Circuit) -> Wrk17Garbling
    where
        R: Rng + CryptoRng,
    {
        let delta = self.preprocessor.init_delta();
        let gate_count = circuit.gates().len();

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

        let mut garbler_output = Vec::with_capacity(if self.is_garbler() { gate_count } else { 0 });
        let mut eval_output = Vec::with_capacity(if self.is_garbler() { 0 } else { gate_count });
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
                Gate::AND { a, b, out } => {
                    // we assume the and triples come in topological order
                    let auth_prod = auth_prods.pop().unwrap();
                    let share0 = &auth_prod + &auth_bits[out];
                    let share1 = &share0 + &auth_bits[a];
                    let share2 = &share0 + &auth_bits[b];
                    let share3 = if self.is_garbler() {
                        let mut tmp = &share1 + &auth_bits[b];
                        tmp.mac_keys.get_mut(&0).map(|x| *x += delta);
                        tmp
                    } else {
                        let mut tmp = &share1 + &auth_bits[b];
                        tmp.share += F2::ONE;
                        tmp
                    };
                    if self.is_garbler() {
                        let label_a_0 = wire_labels[a];
                        let label_b_0 = wire_labels[b];
                        let label_gamma_0 = wire_labels[out];
                        let garbled_gate = Wrk17GarbledGate {
                            party_id: self.party_id,
                            rows: [
                                Wrk17GarbledRow::encrypt_row(
                                    &share0,
                                    delta,
                                    label_a_0,
                                    label_b_0,
                                    label_gamma_0,
                                    *out,
                                    0,
                                ),
                                Wrk17GarbledRow::encrypt_row(
                                    &share1,
                                    delta,
                                    label_a_0,
                                    label_b_0,
                                    label_gamma_0,
                                    *out,
                                    1,
                                ),
                                Wrk17GarbledRow::encrypt_row(
                                    &share2,
                                    delta,
                                    label_a_0,
                                    label_b_0,
                                    label_gamma_0,
                                    *out,
                                    2,
                                ),
                                Wrk17GarbledRow::encrypt_row(
                                    &share3,
                                    delta,
                                    label_a_0,
                                    label_b_0,
                                    label_gamma_0,
                                    *out,
                                    3,
                                ),
                            ],
                        };
                        garbler_output.push(garbled_gate);
                    } else {
                        eval_output.push([share0, share1, share2, share3]);
                    }
                }
                bristol_fashion::Gate::INV { a: _, out: _ } => todo!(),
                bristol_fashion::Gate::EQ { lit: _, out: _ } => todo!(),
                bristol_fashion::Gate::EQW { a: _, out: _ } => todo!(),
            }
        }
        if self.is_garbler() {
            Wrk17Garbling::Garbler(garbler_output)
        } else {
            Wrk17Garbling::Evaluator(Wrk17EvaluatorOutput {
                garbling_shares: eval_output,
                wire_mask_shares: auth_bits,
                delta,
            })
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
        let party_id = 0;
        // share: (r^i, {M_j[r^i], K_i[r^j]})
        let share = shares[party_id].clone();
        let delta = deltas[party_id];
        let label_a_0 = F128b::random(&mut rng);
        let label_b_0 = F128b::random(&mut rng);
        let label_gamma_0 = F128b::random(&mut rng);
        let gate_id = 12;
        let row = Wrk17GarbledRow::encrypt_row(
            &share,
            delta,
            label_a_0,
            label_b_0,
            label_gamma_0,
            gate_id,
            0,
        );

        let (mut enc_label, recovered_share) =
            row.extract_macs_and_label_gamma(label_a_0, label_b_0, gate_id, 0, party_id as u16, n);

        let macs_on_share_0 = shares
            .iter()
            .skip(1)
            .map(|share| {
                // mac held by party j on share i
                share.mac_values[&0]
            })
            .sum();

        let recovered_label = Wrk17GarbledRow::decrypt_label_gamma(&mut enc_label, macs_on_share_0);

        // the label we get back should be label_gamma_0
        assert_eq!(recovered_share.mac_values, share.mac_values);
        assert_eq!(recovered_label, label_gamma_0 + (secret * delta));
    }
}
