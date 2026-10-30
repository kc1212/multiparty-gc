use std::io::{BufRead, Cursor, Read};

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

use super::{GarbleOutput, Garbler, process_linear_gates};

mod wire;

/// P_1 broadcasts X, {\hat{w}} to all garblers
/// Additionally it sends h_i = H({k^i_{w,\hat{w}}}) to P_i
pub struct CopzOutputMsg1 {
    pub(crate) w_hats: Vec<F2>,
    pub(crate) h: [u8; 32],
    pub(crate) chi: [u8; 32],
}

impl OutputMsg1 for CopzOutputMsg1 {
    type Public = CopzOutputMsg1Public;
    type Private = CopzOutputMsg1Private;

    fn chi(&self) -> [u8; 32] {
        self.chi
    }

    fn split(self) -> (CopzOutputMsg1Public, CopzOutputMsg1Private) {
        let Self { w_hats, h, chi } = self;
        (
            CopzOutputMsg1Public { w_hats, chi },
            CopzOutputMsg1Private { h },
        )
    }

    fn join(public: CopzOutputMsg1Public, private: CopzOutputMsg1Private) -> Self {
        Self {
            w_hats: public.w_hats,
            h: private.h,
            chi: public.chi,
        }
    }
}

/// The part of [CopzOutputMsg1] that the evaluator broadcasts: `chi` and the
/// external values of the AND gates.
pub struct CopzOutputMsg1Public {
    w_hats: Vec<F2>,
    chi: [u8; 32],
}

/// The part of [CopzOutputMsg1] that is sent to one garbler: the hash of its labels.
pub struct CopzOutputMsg1Private {
    h: [u8; 32],
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

/// Private evaluator state has no network encoding.
/// ```compile_fail
/// use multiparty_gc::{garbler::copz::CopzEvaluatorOutput, net::Wire};
/// fn requires_wire<T: Wire>() {}
/// requires_wire::<CopzEvaluatorOutput>();
/// ```
pub struct CopzEvaluatorOutput {
    pub(crate) num_parties: u16,
    pub(crate) garbling_shares: Vec<[AuthShare<F2, F128b>; 4]>,
    /// The authenticated bits of the wire masks \lambda_w of the output wires.
    pub(crate) wire_mask_shares: Vec<AuthShare<F2, F128b>>,
    pub(crate) delta: F128b,
}

/// The garbling transmitted to the evaluator; it contains no evaluator secrets.
pub struct CopzGarbling {
    pub(crate) gates: Vec<CopzGarbledGate>,
    pub(crate) b_w: Option<Vec<F2>>,
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

impl CopzGarbledGate {
    pub fn len(&self) -> usize {
        self.inner.iter().map(|z| z.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn lsb_f128b(x: &F128b) -> F2 {
    if (x.to_bytes()[0] & 1) == 0 {
        F2::ZERO
    } else {
        F2::ONE
    }
}

/// Which input wire of an AND gate a key belongs to. These are the two gate
/// indices `g` (left input `u`) and `g'` (right input `v`) of COPZ Figure 9,
/// they keep the PRF outputs of the two inputs independent even if both inputs
/// are the same wire.
#[derive(Clone, Copy)]
#[repr(u8)]
enum InputWire {
    Left = 0,
    Right = 1,
}

/// The concatenated PRF `F̂_k(g, i)` of COPZ Definition 6, instantiated with BLAKE3
/// as an extendable output function: one label `k` of garbler `party_id` is expanded
/// into `out_len` bytes for the AND gate `gate_id`.
fn garbling_prf(
    key: &F128b,
    wire: InputWire,
    gate_id: u64,
    party_id: u16,
    out_len: usize,
) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new_derive_key("multiparty-gc copz garbling prf v1");
    hasher.update(&key.to_bytes());
    hasher.update(&[wire as u8]);
    hasher.update(&gate_id.to_le_bytes());
    hasher.update(&party_id.to_le_bytes());
    let mut out = vec![0u8; out_len];
    hasher.finalize_xof().fill(&mut out);
    out
}

fn xor_into(acc: &mut [u8], other: &[u8]) {
    debug_assert_eq!(acc.len(), other.len());
    for (a, b) in acc.iter_mut().zip(other) {
        *a ^= *b;
    }
}

/// Length of one garbled table of a garbler: its output label share and one share for
/// every other garbler.
fn table_len(num_parties: u16) -> usize {
    16 * (num_parties as usize - 1)
}

/// The plaintext of a garbled table of garbler `party_id`:
/// `k ⊕ ⟨r Δ_i⟩_i ∥ {⟨r Δ_j⟩_i}_{j ≠ i, evaluator}`.
fn table_body(
    r: &AuthShare<F2, F128b>,
    k: &F128b,
    delta: &F128b,
    party_id: u16,
    num_parties: u16,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(table_len(num_parties));
    body.extend_from_slice(&(r.to_x_delta_i_share(party_id, delta) + k).to_bytes());
    for j in 0..num_parties - 1 {
        if j != party_id {
            body.extend_from_slice(&r.to_x_delta_i_share(j, &F128b::ZERO).to_bytes());
        }
    }
    body
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
    let out_len = table_len(num_parties);
    #[cfg(test)]
    {
        println!(
            "[enc] labels=({k_u_0:?}, {k_v_0:?}, {k_w_0:?}), gate={gate_id}, party_id={party_id}"
        );
    }
    let prf = |key: &F128b, wire| garbling_prf(key, wire, gate_id, party_id, out_len);
    let f_u_0 = prf(k_u_0, InputWire::Left);

    // C1 = F̂_{k_u_0}(g) ⊕ F̂_{k_u_1}(g) ⊕ body(r1, k_v_0)
    let mut mask_1 = f_u_0.clone();
    xor_into(&mut mask_1, &prf(&(k_u_0 + delta), InputWire::Left));
    xor_into(
        &mut mask_1,
        &table_body(r1, k_v_0, delta, party_id, num_parties),
    );

    // C2,a = F̂_{k_v_a}(g') ⊕ F̂_{k_u_0}(g) ⊕ body(r2_a, k_w_0)
    let mut mask_2 = prf(k_v_0, InputWire::Right);
    xor_into(&mut mask_2, &f_u_0);
    xor_into(
        &mut mask_2,
        &table_body(r2_0, k_w_0, delta, party_id, num_parties),
    );
    let mut mask_3 = prf(&(k_v_0 + delta), InputWire::Right);
    xor_into(&mut mask_3, &f_u_0);
    xor_into(
        &mut mask_3,
        &table_body(r2_1, k_w_0, delta, party_id, num_parties),
    );

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
    let out_len = table_len(num_parties);

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
        // F̂_{k_u_hat}(g, i) + F̂_{k_v_hat}(g', i) + u_hat c1 + c2_v_hat
        let [c1, c2_0, c2_1] = &garbled_table.inner;
        let mut mask = garbling_prf(k_u_hat, InputWire::Left, gate_id, party_id as u16, out_len);
        xor_into(
            &mut mask,
            &garbling_prf(k_v_hat, InputWire::Right, gate_id, party_id as u16, out_len),
        );

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
    type EvaluatorState = CopzEvaluatorOutput;
    type IM1 = CopzInputMsg1;
    type IM2 = CopzInputMsg2;
    type IM3 = CopzInputMsg3;
    type OM1 = CopzOutputMsg1;
    type OM2 = CopzOutputMsg2;

    fn num_parties(&self) -> u16 {
        self.num_parties
    }

    const OUTPUT_CHECK: bool = true;

    fn garble<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
        circuit: &Circuit,
    ) -> Result<GarbleOutput<CopzGarbling, CopzEvaluatorOutput>, GcError> {
        // Get the deltas, make sure lsb(\Delta_2) = 1
        // This translates to delta of party_id = 0 since evaluator is party n-1
        self.delta = self.preprocessor.init_delta()?;

        #[cfg(test)]
        {
            if self.party_id == 0 {
                assert_eq!(self.delta.to_bytes()[0] & 1, 1);
            }
        }

        let mut auth_bits = auth_bits_from_prep(&mut self.preprocessor, circuit)?;
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
            .beaver_mul(&auth_bits, &indicies_for_mul)?;

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
                Ok(GarbleOutput::Garbler(CopzGarbling {
                    gates: garbler_output,
                    b_w: Some(b_w_output),
                }))
            } else {
                Ok(GarbleOutput::Garbler(CopzGarbling {
                    gates: garbler_output,
                    b_w: None,
                }))
            }
        } else {
            debug_assert_eq!(nwires as usize, auth_bits.len());
            Ok(GarbleOutput::Evaluator(CopzEvaluatorOutput {
                num_parties: self.num_parties,
                garbling_shares: eval_output,
                wire_mask_shares: (nwires - output_wire_count..nwires)
                    .map(|i| auth_bits[i as usize].clone())
                    .collect(),
                delta: self.delta,
            }))
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
    ) -> Result<CopzInputMsg2, GcError> {
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

        Ok(CopzInputMsg2 {
            masked_inputs: output,
        })
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

    use super::{encrypt_garbled_table, table_body};

    #[test]
    fn test_encrypt_garbled_table() {
        garble_and_decrypt(false);
    }

    /// An AND gate whose inputs are the same wire, the PRF tweaks of the two inputs
    /// must differ or the masks of the second and third table cancel out.
    #[test]
    fn test_encrypt_garbled_table_same_input_wire() {
        garble_and_decrypt(true);
    }

    fn garble_and_decrypt(same_input_wire: bool) {
        let mut rng = AesRng::from_entropy();
        let n = 2;
        let lambda_u = F2::random(&mut rng);
        let lambda_v = if same_input_wire {
            lambda_u
        } else {
            F2::random(&mut rng)
        };
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

        let lambda_u_shares = secret_share_with_delta::<_, F128b, _>(lambda_u, &deltas, &mut rng);
        let lambda_v_shares = if same_input_wire {
            lambda_u_shares.clone()
        } else {
            secret_share_with_delta::<_, F128b, _>(lambda_v, &deltas, &mut rng)
        };
        let lambda_uv_shares = secret_share_with_delta::<_, F128b, _>(lambda_uv, &deltas, &mut rng);
        let lambda_w_shares = secret_share_with_delta::<_, F128b, _>(lambda_w, &deltas, &mut rng);

        let k_u_0 = F128b::random(&mut rng);
        let k_v_0 = if same_input_wire {
            k_u_0
        } else {
            F128b::random(&mut rng)
        };
        let k_w_0 = F128b::random(&mut rng);
        let b_w = lsb_f128b(&k_w_0);

        assert_eq!(
            (&lambda_w_shares[0] + &lambda_uv_shares[0]).to_x_delta_i_share(0, &deltas[0])
                + (&lambda_w_shares[1] + &lambda_uv_shares[1]).to_x_delta_i_share(0, &deltas[0]),
            (lambda_w + lambda_uv) * deltas[0]
        );

        let r1 = &lambda_v_shares[0];
        let r2_0 = &lambda_w_shares[0] + &lambda_uv_shares[0];
        let r2_1 = &r2_0 + &lambda_u_shares[0];
        let garbled_table = encrypt_garbled_table(
            r1, &r2_0, &r2_1, &k_u_0, &k_v_0, &k_w_0, &deltas[0], 0, 0, n,
        );

        // every table is encrypted, i.e., differs from its plaintext
        let bodies = [
            table_body(r1, &k_v_0, &deltas[0], 0, n),
            table_body(&r2_0, &k_w_0, &deltas[0], 0, n),
            table_body(&r2_1, &k_w_0, &deltas[0], 0, n),
        ];
        for (table, body) in garbled_table.inner.iter().zip(&bodies) {
            assert_eq!(table.len(), body.len());
            assert_ne!(table, body);
        }

        for (u_hat, v_hat) in [
            (F2::ZERO, F2::ZERO),
            (F2::ZERO, F2::ONE),
            (F2::ONE, F2::ONE),
            (F2::ONE, F2::ZERO),
        ] {
            // the same wire has the same external value
            if same_input_wire && u_hat != v_hat {
                continue;
            }
            println!("testing u_hat={u_hat:?}, v_hat={v_hat:?}");

            let k_u_hat = u_hat * deltas[0] + k_u_0;
            let k_v_hat = v_hat * deltas[0] + k_v_0;

            // NOTE: party with index 1 is the evaluator
            let lambda_w_delta_i = lambda_w_shares[1].to_x_delta_shares(&deltas[1]);
            let lambda_u_delta_i = lambda_u_shares[1].to_x_delta_shares(&deltas[1]);
            let lambda_v_delta_i = lambda_v_shares[1].to_x_delta_shares(&deltas[1]);
            let lambda_uv_delta_i = lambda_uv_shares[1].to_x_delta_shares(&deltas[1]);

            let (w_hat, k_w_hat) = decrypt_garbled_gate(
                std::slice::from_ref(&garbled_table),
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
