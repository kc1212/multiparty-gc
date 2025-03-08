use bristol_fashion::Circuit;
use rand::{CryptoRng, Rng};

mod wrk17;

pub trait Garbler<GT: Garbling> {
    fn garble<R: Rng + CryptoRng>(&mut self, rng: &mut R, circuit: &Circuit) -> GT;
    fn party_id(&self) -> u16;
}

pub trait Garbling {
    type GarbledGate;
}
