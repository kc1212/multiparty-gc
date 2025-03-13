use bristol_fashion::Circuit;
use rand::{CryptoRng, Rng};

pub mod wrk17;

pub trait Garbler<G: Garbling> {
    fn garble<R: Rng + CryptoRng>(&mut self, rng: &mut R, circuit: &Circuit) -> G;
    fn party_id(&self) -> u16;
}

pub trait Garbling {}
