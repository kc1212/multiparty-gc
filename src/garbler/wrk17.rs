use std::{
    io::{Cursor, Read, Write},
    ops::Index,
};

use bristol_fashion::{Circuit, Gate};
use generic_array::GenericArray;
use itertools::{Itertools, izip};
use rand::{CryptoRng, Rng};
use scuttlebutt::ring::FiniteRing;
use scuttlebutt::serialization::CanonicalSerialize;
use smallvec::smallvec;
use swanky_field_binary::{F2, F128b};

use crate::{
    DummyOutput, InputMsg1, InputMsg2, InputMsg3, error::GcError, garbler::auth_bits_from_prep,
    prep::Preprocessor, sharing::AuthShare,
};

use super::{Garbler, Garbling, process_linear_gates};

/// Garbler for WRK17. Due to the way parties are indexed,
/// we set the last party (n-1) as the evaluator instead of the first.
pub struct Wrk17Garbler<P: Preprocessor> {
    party_id: u16,
    num_parties: u16,
    preprocessor: P,

    // These are only inputs for party 1
    delta: F128b,
    input_shares: Vec<F2>,
    input_macs: Vec<F128b>,
    input_labels: Vec<F128b>,
    // Only filled for the evaluator
    input_keys: Vec<Vec<F128b>>,

    // This is for the output decoder
    output_decoder: Vec<(F2, F128b)>,
}

impl<P: Preprocessor> Wrk17Garbler<P> {
    pub fn new(party_id: u16, num_parties: u16, preprocessor: P) -> Self {
        Self {
            party_id,
            num_parties,
            preprocessor,
            delta: F128b::ZERO,
            input_shares: vec![],
            input_macs: vec![],
            input_labels: vec![],
            input_keys: vec![],
            output_decoder: vec![],
        }
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
            + if ((row_id >> 1) & 1) == 0 {
                F128b::ZERO
            } else {
                delta
            };
        let label_b = label_b_0
            + if (row_id & 1) == 0 {
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
        let n = share.mac_keys.len(); // not a perfect proxy, depends on implementation
        let output_len = 1 + 128 / 8 * (n - 1) + 128 / 8;
        let mut to_encrypt = Cursor::new(Vec::<u8>::with_capacity(output_len));
        let r = share.share;
        to_encrypt.write_all(&r.to_bytes()).unwrap();
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
            mac_values: smallvec![F128b::ZERO; party_count as usize],
            mac_keys: smallvec![F128b::ZERO; party_count as usize],
        };
        // TODO do we need to deserialize everything?
        r_share.deserialize_mac_values(party_count, &mut cursor);

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

        // we're returning label_gamma
        F128b::from_bytes(enc_label_gamma).unwrap()
    }
}

pub struct Wrk17GarbledGate {
    party_id: u16,
    rows: [Wrk17GarbledRow; 4],
    #[cfg(test)]
    pub(crate) unencrypted_rows: [AuthShare<F2, F128b>; 4],
}

impl Wrk17GarbledGate {
    pub fn len(&self) -> usize {
        self.rows.iter().map(|z| z.inner.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
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
#[allow(clippy::too_many_arguments)]
pub(crate) fn decrypt_garbled_gate(
    garbled_gates: &[Wrk17GarbledGate],
    a: F2,
    b: F2,
    label_as: &[F128b],
    label_bs: &[F128b],
    gate_id: u64,
    evaluator_shares: &[AuthShare<F2, F128b>; 4],
    evaluator_delta: F128b,
) -> Result<(F2, Vec<F128b>), GcError> {
    // first get the row that we want to decrypt
    // row_id is \ell
    let row_id = match (<bool as From<F2>>::from(b), <bool as From<F2>>::from(a)) {
        (true, true) => 3,
        (false, true) => 2,
        (true, false) => 1,
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
        if r_share.share * evaluator_delta + evaluator_shares[row_id as usize].mac_keys[party_id]
            != r_share.mac_values[evaluator_index as usize]
        {
            return Err(GcError::MacCheckFailure);
        }

        enc_label_gammas.push(enc_label_gamma);
        r_shares.push(r_share);
    }

    let mut output_mask = F2::ZERO;
    let mut output_label = vec![F128b::ZERO; party_count - 1];
    for (party_id, enc_label_gamma) in enc_label_gammas.iter_mut().enumerate() {
        // We need to decrypt the labels, for this we need MACs of the form
        // sum_j M_i[r^j_{\gamma, \ell}] for j != i, this needs to include M_1[...]
        let macs = (0..party_count - 1)
            .filter(|i| *i != party_id)
            .map(|i| r_shares[i].mac_values[party_id])
            .fold(F128b::ZERO, |acc, x| acc + x)
            + evaluator_shares[row_id as usize].mac_values[party_id];

        // Decrypt using the sum of MACs
        let recovered_label = Wrk17GarbledRow::decrypt_label_gamma(enc_label_gamma, macs);

        // \sum r^i_{\gamma, \ell} = z_\gamma + \lambda_\gamma
        output_mask += r_shares[party_id].share;

        // L^i_{\gamma, z_\gamma + \lambda_\gamma}
        output_label[party_id] = recovered_label;
    }

    // The output_mask is a sum of shares of all parties
    // we're still missing one from the evaluator from the above loop, so add it here
    output_mask += evaluator_shares[row_id as usize].share;

    Ok((output_mask, output_label))
}

pub struct Wrk17EvaluatorOutput {
    pub(crate) total_num_parties: u16,
    pub(crate) garbling_shares: Vec<[AuthShare<F2, F128b>; 4]>,
    /// The authenticated bits of the wire masks \lambda_w of the output wires.
    pub(crate) wire_mask_shares: Vec<AuthShare<F2, F128b>>,
    pub(crate) delta: F128b,
}

pub enum Wrk17Garbling {
    // the index (starting from 0) should correspond to the party_id
    // the length should be exactly n-1
    // party_id = n-1 is the evaluator
    Garbler(Vec<Wrk17GarbledGate>),
    Evaluator(Wrk17EvaluatorOutput),
}

impl Garbling for Wrk17Garbling {
    fn estimate_size(&self) -> usize {
        match self {
            Wrk17Garbling::Garbler(gates) => gates.iter().map(|g| g.len()).sum::<usize>(),
            Wrk17Garbling::Evaluator(_) => 0,
        }
    }
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

pub struct Wrk17InputMsg1 {
    shares: Vec<F2>,
    macs: Vec<F128b>,
}

impl InputMsg1 for Wrk17InputMsg1 {}

#[derive(Clone)]
pub struct Wrk17InputMsg2 {
    masked_inputs: Vec<F2>,
}

impl InputMsg2 for Wrk17InputMsg2 {
    fn into_masked_inputs(self) -> Vec<F2> {
        self.masked_inputs
    }
}

pub struct Wrk17InputMsg3 {
    labels: Vec<F128b>,
    output_decoder: Vec<(F2, F128b)>,
}

impl InputMsg3 for Wrk17InputMsg3 {
    type Decoder = Vec<(F2, F128b)>;

    fn into_labels_and_decoder(self) -> (Vec<F128b>, Vec<(F2, F128b)>) {
        (self.labels, self.output_decoder)
    }
}

impl<P: Preprocessor> Garbler for Wrk17Garbler<P> {
    type Gc = Wrk17Garbling;
    type IM1 = Wrk17InputMsg1;
    type IM2 = Wrk17InputMsg2;
    type IM3 = Wrk17InputMsg3;
    type OM1 = DummyOutput;
    type OM2 = DummyOutput;

    fn party_id(&self) -> u16 {
        self.party_id
    }

    fn num_parties(&self) -> u16 {
        self.num_parties
    }

    fn garble<R>(&mut self, rng: &mut R, circuit: &Circuit) -> Wrk17Garbling
    where
        R: Rng + CryptoRng,
    {
        self.delta = self.preprocessor.init_delta().unwrap();

        // these are the authenticated shares of the wire masks, indexed by the wire ID
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

        // garble the AND gates
        let mut and_gate_counter = 0usize;
        for gate in circuit.gates() {
            match gate {
                Gate::XOR { .. } | Gate::INV { .. } => { /* already processed */ }
                Gate::AND { a, b, out } => {
                    let bit_a = &auth_bits[*a as usize];
                    let bit_b = &auth_bits[*b as usize];
                    let bit_out = &auth_bits[*out as usize];
                    let auth_prod = &auth_prods[and_gate_counter];

                    // a = 0, b = 0: \lambda_a \lambda_b + \lambda_\gamma
                    let share0 = auth_prod + bit_out;
                    // a = 0, b = 1: \lambda_a + \lambda_a \lambda_b + \lambda_\gamma
                    let share1 = &share0 + bit_a;
                    // a = 1, b = 0: \lambda_b + \lambda_a \lambda_b + \lambda_\gamma
                    let share2 = &share0 + bit_b;
                    // a = 1, b = 1: 1 + \lambda_a + \lambda_b + \lambda_a \lambda_b + \lambda_\gamma
                    let share3 = if self.is_garbler() {
                        let mut tmp = &share1 + bit_b;
                        *tmp.mac_keys
                            .get_mut((&self.num_parties - 1) as usize)
                            .unwrap() += self.delta;
                        tmp
                    } else {
                        let mut tmp = &share1 + bit_b;
                        tmp.share += F2::ONE;
                        tmp
                    };
                    if self.is_garbler() {
                        let label_a_0 = wire_labels[*a as usize];
                        let label_b_0 = wire_labels[*b as usize];
                        let label_gamma_0 = wire_labels[*out as usize];
                        let garbled_gate = Wrk17GarbledGate {
                            party_id: self.party_id,
                            rows: [
                                Wrk17GarbledRow::encrypt_row(
                                    &share0,
                                    self.delta,
                                    label_a_0,
                                    label_b_0,
                                    label_gamma_0,
                                    *out,
                                    0,
                                ),
                                Wrk17GarbledRow::encrypt_row(
                                    &share1,
                                    self.delta,
                                    label_a_0,
                                    label_b_0,
                                    label_gamma_0,
                                    *out,
                                    1,
                                ),
                                Wrk17GarbledRow::encrypt_row(
                                    &share2,
                                    self.delta,
                                    label_a_0,
                                    label_b_0,
                                    label_gamma_0,
                                    *out,
                                    2,
                                ),
                                Wrk17GarbledRow::encrypt_row(
                                    &share3,
                                    self.delta,
                                    label_a_0,
                                    label_b_0,
                                    label_gamma_0,
                                    *out,
                                    3,
                                ),
                            ],
                            #[cfg(test)]
                            unencrypted_rows: [share0, share1, share2, share3],
                        };
                        garbler_output.push(garbled_gate);
                    } else {
                        // NOTE: this is topological order
                        eval_output.push([share0, share1, share2, share3]);
                    }
                    and_gate_counter += 1;
                }
                Gate::EQ { lit: _, out: _ } => unimplemented!("EQ gate not supported"),
                Gate::EQW { a: _, out: _ } => unimplemented!("EQW gate not supported"),
            }
        }

        // Keep some information that we need for inputs
        let input_wire_count: u64 = circuit.input_sizes().iter().sum();
        for input_idx in 0..input_wire_count as usize {
            // Shared by garblers and evaluator
            let r = auth_bits[input_idx].share;
            self.input_shares.push(r);

            if !self.is_garbler() {
                self.input_keys
                    .push(auth_bits[input_idx].mac_keys.iter().cloned().collect_vec());
            } else {
                let mac = auth_bits[input_idx].mac_values[self.num_parties as usize - 1];
                self.input_macs.push(mac);

                let label = wire_labels[input_idx];
                self.input_labels.push(label);
            }
        }

        // Keep some information for the output decoder
        let output_wire_count: u64 = circuit.output_sizes().iter().sum();
        let nwires = circuit.nwires();
        if self.is_garbler() {
            // (r^i_w, M_1[r^i_w])
            self.output_decoder = (nwires - output_wire_count..nwires)
                .map(|i| {
                    (
                        auth_bits[i as usize].share,
                        auth_bits[i as usize].mac_values[self.num_parties as usize - 1],
                    )
                })
                .collect();
        }
        self.preprocessor.done();

        // prepare the actual garbled circuit
        #[cfg(test)]
        {
            println!("Party {} finished garbling", self.party_id);
        }

        if self.is_garbler() {
            // Keep some information for the output decoder
            Wrk17Garbling::Garbler(garbler_output)
        } else {
            debug_assert_eq!(nwires as usize, auth_bits.len());
            Wrk17Garbling::Evaluator(Wrk17EvaluatorOutput {
                total_num_parties: self.num_parties,
                garbling_shares: eval_output,
                wire_mask_shares: (nwires - output_wire_count..nwires)
                    .map(|i| auth_bits[i as usize].clone())
                    .collect(),
                delta: self.delta,
            })
        }
    }

    fn input_round_1(&self) -> Wrk17InputMsg1 {
        // Only the garbler can all this function
        assert!(self.party_id != self.num_parties - 1);

        Wrk17InputMsg1 {
            shares: self.input_shares.clone(),
            macs: self.input_macs.clone(),
        }
    }

    fn input_round_2(
        &self,
        true_inputs: &[F2],
        msgs: Vec<Wrk17InputMsg1>,
    ) -> Result<Vec<Wrk17InputMsg2>, GcError> {
        debug_assert_eq!(self.party_id, self.num_parties - 1);

        #[cfg(test)]
        println!("True inputs: {true_inputs:?}");

        // The evaluator receives r^i_w, M_1[r^i_w]
        // so we find the corresponding MAC key and do a MAC check.
        // Also reconstruct at the same time.
        let mut output = true_inputs.to_vec();
        for (party_id, Wrk17InputMsg1 { macs, shares }) in msgs.into_iter().enumerate() {
            debug_assert_eq!(macs.len(), shares.len());
            debug_assert_eq!(macs.len(), output.len());
            // get the mac keys that I have
            for (w, (share, mac)) in izip!(shares, macs).enumerate() {
                // note that self.input_keys[i][j] is the ith gate and jth party
                let key = &self.input_keys[w][party_id];
                if share * self.delta + *key != mac {
                    return Err(GcError::InputRound2CheckFailure);
                }
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
            .map(|_| Wrk17InputMsg2 {
                masked_inputs: output.clone(),
            })
            .collect())
    }

    /// We receive the masked input x^1_w + \lambda_w,
    /// then output the correct mask according to the masked input.
    fn input_round_3(&self, msg: Wrk17InputMsg2) -> Wrk17InputMsg3 {
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
        Wrk17InputMsg3 {
            labels: output,
            output_decoder: self.output_decoder.clone(),
        }
    }

    fn check_output_msg1(
        &self,
        _msg1: Self::OM1,
        _masked_inputs: &[F2],
        _circuit: &Circuit,
    ) -> Result<Self::OM2, GcError> {
        Ok(DummyOutput)
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
                share.mac_values[0]
            })
            .sum();

        let recovered_label = Wrk17GarbledRow::decrypt_label_gamma(&mut enc_label, macs_on_share_0);

        // the label we get back should be label_gamma_0
        assert_eq!(recovered_share.mac_values, share.mac_values);
        assert_eq!(recovered_label, label_gamma_0 + (secret * delta));
    }
}
