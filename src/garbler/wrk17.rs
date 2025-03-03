use std::collections::BTreeMap;

use bristol_fashion::{Circuit, Gate};
use scuttlebutt::ring::FiniteRing;
use swanky_field_binary::{F2, F128b};

use crate::{prep::Preprocessor, sharing::AuthShare};

use super::{GarbledTable, Garbler};

pub struct Wrk17Garbler<P: Preprocessor> {
    party_id: u16,
    preprocessor: P,
}

impl<P: Preprocessor> Wrk17Garbler<P> {
    fn gen_input_labels(&mut self, inputs: u64) -> BTreeMap<u64, F128b> {
        if self.party_id != 0 {
            // We only output the 0 wire label since the 1 wire label can be computed from the zero label
            todo!()
        }
        BTreeMap::new()
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

    fn garble(&mut self, circuit: &Circuit, output: &mut Wrk17GarbledTable) {
        let input_bit_count: u64 = circuit.input_sizes().iter().sum();
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

        let mut wire_labels = self.gen_input_labels(input_bit_count);

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
