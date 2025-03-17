use std::collections::BTreeMap;

use bristol_fashion::Circuit;
use itertools::izip;
use rand::CryptoRng;
use rand::Rng;
use scuttlebutt::ring::FiniteRing;
use swanky_field_binary::F2;
use swanky_field_binary::F128b;

use crate::sharing::AuthShare;
use crate::sharing::secret_share_with_delta;

/// Static preprocessor is one that has no networking.
///
/// Authenticated shares are only consistent
/// if this function is called in the same order
/// by all parties.
pub trait StaticPreprocessor {
    fn party_count(&self) -> u16;
    fn init_delta(&mut self) -> F128b;
    fn auth_random(&mut self, m: u64) -> Vec<AuthShare<F2, F128b>>;
    fn auth_mul(
        &mut self,
        x: &AuthShare<F2, F128b>,
        y: &AuthShare<F2, F128b>,
    ) -> AuthShare<F2, F128b>;

    /// Produce authenticated materials from a circuit description.
    /// Returns a map of authenticated random bits along with the
    /// authenticated product of some of the bits.
    /// The key is the wire ID.
    fn auth_materials_from_circuit(
        &mut self,
        circ: &Circuit,
    ) -> (
        BTreeMap<u64, AuthShare<F2, F128b>>,
        Vec<AuthShare<F2, F128b>>,
    );

    /// Compute z = x*y and then output unauthenticated shares <x * \Delta^i>
    fn and_output_mask(&mut self, x: &AuthShare<F2, F128b>, y: &AuthShare<F2, F128b>)
    -> Vec<F128b>;

    fn open_value(&mut self, x: &AuthShare<F2, F128b>);
    fn open_values(&mut self, x: &[AuthShare<F2, F128b>]);
}

pub trait Preprocessor: StaticPreprocessor {
    /// Perform setup, depending on the preprocessing implementation,
    /// this step might do nothing.
    fn prep(&mut self);
}

/// This is a preprocessor constructed for a specific circuit using [Self::new].
/// Thus, non-circuit specific preprocessing are not supported
/// such as [Self::auth_random] and [Self::auth_mul].
pub struct InsecureCircuitPreprocessor {
    party_count: u16,
    auth_bits: BTreeMap<u64, AuthShare<F2, F128b>>,
    auth_prods: Vec<AuthShare<F2, F128b>>,
    delta: F128b,
}

impl InsecureCircuitPreprocessor {
    pub fn new<R: Rng + CryptoRng>(party_count: u16, circuit: &Circuit, rng: &mut R) -> Vec<Self> {
        let mut all_auth_bits = vec![BTreeMap::new(); party_count as usize];

        // generate deltas
        let deltas: Vec<_> = (0..party_count).map(|_| F128b::random(rng)).collect();

        // first generate input auth bits
        let input_wire_count: u64 = circuit.input_sizes().iter().sum();
        for w in 0..input_wire_count {
            let secret = F2::random(rng);
            // let secret = F2::ZERO;
            for (party_id, auth_share) in secret_share_with_delta(secret, &deltas, rng)
                .into_iter()
                .enumerate()
            {
                all_auth_bits[party_id].insert(w, auth_share);
            }
        }

        // then for every AND gate, we generate another auth bit, and the product
        let mut all_auth_prods = vec![vec![]; party_count as usize];
        for gate in circuit.gates() {
            match gate {
                bristol_fashion::Gate::AND { a, b, out } => {
                    // generate the auth bit
                    let secret = F2::random(rng);
                    // let secret = F2::ZERO;
                    #[cfg(test)]
                    {
                        println!("secret for auth bit: {secret:?}");
                    }
                    for (party_id, auth_share) in secret_share_with_delta(secret, &deltas, rng)
                        .into_iter()
                        .enumerate()
                    {
                        all_auth_bits[party_id].insert(*out, auth_share);
                    }

                    // take the prior two auth bits, reconstruct, do a product, and then secret share
                    let (a, b) = (0..party_count as usize)
                        .map(|party_id| {
                            let a_share = all_auth_bits[party_id][a].share;
                            let b_share = all_auth_bits[party_id][b].share;
                            (a_share, b_share)
                        })
                        .fold((F2::ZERO, F2::ZERO), |acc, (a, b)| (acc.0 + a, acc.1 + b));
                    let prod = a * b;

                    for (party_id, auth_share) in secret_share_with_delta(prod, &deltas, rng)
                        .into_iter()
                        .enumerate()
                    {
                        all_auth_prods[party_id].push(auth_share);
                    }
                }
                _ => { /* ignored */ }
            }
        }

        assert_eq!(all_auth_bits.len(), party_count as usize);
        assert_eq!(all_auth_prods.len(), party_count as usize);

        izip!(deltas, all_auth_bits, all_auth_prods)
            .map(|(delta, auth_bits, auth_prods)| Self {
                party_count,
                auth_bits,
                auth_prods,
                delta,
            })
            .collect()
    }
}

impl StaticPreprocessor for InsecureCircuitPreprocessor {
    fn party_count(&self) -> u16 {
        self.party_count
    }

    fn init_delta(&mut self) -> F128b {
        self.delta
    }

    fn auth_random(&mut self, _m: u64) -> Vec<AuthShare<F2, F128b>> {
        unimplemented!("unsupported")
    }

    fn auth_mul(
        &mut self,
        _x: &AuthShare<F2, F128b>,
        _y: &AuthShare<F2, F128b>,
    ) -> AuthShare<F2, F128b> {
        unimplemented!("unsupported")
    }

    fn auth_materials_from_circuit(
        &mut self,
        circ: &Circuit,
    ) -> (
        BTreeMap<u64, AuthShare<F2, F128b>>,
        Vec<AuthShare<F2, F128b>>,
    ) {
        let auth_bits = std::mem::take(&mut self.auth_bits);
        let auth_prods = std::mem::take(&mut self.auth_prods);

        // sanity check that the circuit matches these output
        let input_wire_count: u64 = circ.input_sizes().iter().sum();
        assert_eq!(circ.nand() + input_wire_count, auth_bits.len() as u64);
        assert_eq!(circ.nand(), auth_prods.len() as u64);
        (auth_bits, auth_prods)
    }

    fn and_output_mask(
        &mut self,
        _x: &AuthShare<F2, F128b>,
        _y: &AuthShare<F2, F128b>,
    ) -> Vec<F128b> {
        unimplemented!("unsupported")
    }

    fn open_value(&mut self, _x: &AuthShare<F2, F128b>) {
        unimplemented!("unsupported")
    }

    fn open_values(&mut self, _x: &[AuthShare<F2, F128b>]) {
        unimplemented!("unsupported")
    }
}

impl Preprocessor for InsecureCircuitPreprocessor {
    fn prep(&mut self) {
        unimplemented!("unsupported")
    }
}
