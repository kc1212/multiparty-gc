use std::collections::BTreeMap;

use bristol_fashion::{Circuit, Gate};
use rand::{CryptoRng, Rng};
use scuttlebutt::ring::FiniteRing;
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
    fn encrypt_row(
        share: AuthShare<F2, F128b>,
        label_a: F128b,
        label_b: F128b,
        label_gamma: F128b,
        gate_id: u64,
    ) -> Self {
        todo!()
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
