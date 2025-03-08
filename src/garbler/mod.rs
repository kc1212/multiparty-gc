use bristol_fashion::Circuit;
use rand::{CryptoRng, Rng};

mod wrk17;

pub trait Garbler<GT: Garbling> {
    fn garble<R: Rng + CryptoRng>(&mut self, rng: &mut R, circuit: &Circuit, output: &mut GT);
    fn party_id(&self) -> u16;
}

pub trait Garbling {
    type GarbledGate;

    fn push_gate(&mut self, garbled_gate: Self::GarbledGate);

    fn read_gate(&self, i: usize) -> &Self::GarbledGate;
}
