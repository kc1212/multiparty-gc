use std::collections::VecDeque;

use itertools::izip;
use rand::CryptoRng;
use rand::Rng;
use rand::SeedableRng;
use scuttlebutt::AesRng;
use scuttlebutt::Block;
use scuttlebutt::ring::FiniteRing;
use scuttlebutt::serialization::CanonicalSerialize;
use swanky_field_binary::F2;
use swanky_field_binary::F128b;

use crate::error::GcError;
use crate::net::NetworkConfig;
use crate::net::Session;
use crate::net::memory::LinkModel;
use crate::net::memory::mesh;
use crate::sharing::AuthShare;
use crate::sharing::secret_share_with_delta;

use super::Preprocessor;
use super::ReceiverParty;
use super::StaticPreprocessor;
use super::Triple;
use super::open_with_mac_check;

/// Insecure preprocessing that simulates a trusted dealer.
///
/// All parties derive the dealer's output from a shared seed and keep their own shares,
/// so every party could compute the secrets of all other parties. Openings are sent over
/// the network and MAC-checked like in [super::SecurePreprocessor], so the online phase
/// has realistic cost. Only meant for benchmarking the garbling.
pub struct InsecurePreprocessor {
    session: Session,
    seed: [u8; 32],
    tweak_delta_lsb: bool,
    bits_needed: usize,
    triples_needed: usize,
    delta: Option<F128b>,
    auth_bits: VecDeque<AuthShare<F2, F128b>>,
    triples: VecDeque<Triple>,
}

impl InsecurePreprocessor {
    /// All parties must use the same `seed` and parameters.
    /// If `tweak_delta_lsb` is set, party 0 has a global key with `lsb(Δ_0) = 1`.
    pub fn new(
        session: Session,
        seed: [u8; 32],
        tweak_delta_lsb: bool,
        bits: usize,
        triples: usize,
    ) -> Self {
        Self {
            session,
            seed,
            tweak_delta_lsb,
            bits_needed: bits,
            triples_needed: triples,
            delta: None,
            auth_bits: VecDeque::new(),
            triples: VecDeque::new(),
        }
    }

    /// Create preprocessors for `party_count` parties in this process that are connected
    /// with the in-memory transport.
    pub fn new_in_memory<R: Rng + CryptoRng>(
        rng: &mut R,
        party_count: u16,
        tweak_delta_lsb: bool,
        bits: usize,
        triples: usize,
    ) -> Result<Vec<Self>, GcError> {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        mesh(party_count, LinkModel::default(), NetworkConfig::default())?
            .into_iter()
            .map(|net| {
                let session = net.session("insecure prep")?;
                Ok(Self::new(session, seed, tweak_delta_lsb, bits, triples))
            })
            .collect()
    }
}

impl StaticPreprocessor for InsecurePreprocessor {
    fn my_party_id(&self) -> u16 {
        self.session.party_id()
    }

    fn party_count(&self) -> u16 {
        self.session.party_count()
    }

    fn init_delta(&mut self) -> Result<F128b, GcError> {
        self.delta
            .ok_or_else(|| GcError::NotEnoughMaterial("preprocessing has not run".into()))
    }

    fn auth_bits(&mut self, m: u64) -> Result<Vec<AuthShare<F2, F128b>>, GcError> {
        if m > self.auth_bits.len() as u64 {
            return Err(GcError::NotEnoughMaterial(format!(
                "requested {m} authenticated bits but only {} are available",
                self.auth_bits.len()
            )));
        }
        Ok(self.auth_bits.drain(..m as usize).collect())
    }

    fn beaver_triples(&mut self, m: u64) -> Result<Vec<Triple>, GcError> {
        if m > self.triples.len() as u64 {
            return Err(GcError::NotEnoughMaterial(format!(
                "requested {m} triples but only {} are available",
                self.triples.len()
            )));
        }
        Ok(self.triples.drain(..m as usize).collect())
    }

    fn open_values_to(
        &mut self,
        receiver_party: ReceiverParty,
        xs: &[AuthShare<F2, F128b>],
    ) -> Result<Option<Vec<F2>>, GcError> {
        let delta = self.init_delta()?;
        let result = open_with_mac_check(&mut self.session, delta, receiver_party, xs, false);
        if let Err(err) = &result {
            self.session.abort(&format!("opening failed: {err}"));
        }
        result
    }

    fn done(&mut self) {
        // nothing to clean up, the material is consumed by the garbler
    }
}

impl Preprocessor for InsecurePreprocessor {
    /// Run the dealer for all parties and keep our shares.
    fn prep(&mut self) -> Result<(), GcError> {
        let me = self.session.party_id() as usize;
        let n = self.session.party_count();
        let mut rng = AesRng::from_seed(Block::from(u128::from_le_bytes(
            self.seed[..16].try_into().unwrap(),
        )));

        let mut deltas: Vec<F128b> = (0..n).map(|_| F128b::random(&mut rng)).collect();
        if self.tweak_delta_lsb {
            let mut buf = deltas[0].to_bytes();
            buf[0] |= 1;
            deltas[0] = F128b::from_bytes(&buf).unwrap();
        }
        self.delta = Some(deltas[me]);

        self.auth_bits = (0..self.bits_needed)
            .map(|_| {
                let secret = F2::random(&mut rng);
                secret_share_with_delta(secret, &deltas, &mut rng).swap_remove(me)
            })
            .collect();
        self.triples = (0..self.triples_needed)
            .map(|_| {
                let a = F2::random(&mut rng);
                let b = F2::random(&mut rng);
                let c = a * b;
                let a = secret_share_with_delta(a, &deltas, &mut rng).swap_remove(me);
                let b = secret_share_with_delta(b, &deltas, &mut rng).swap_remove(me);
                let c = secret_share_with_delta(c, &deltas, &mut rng).swap_remove(me);
                (a, b, c)
            })
            .collect();
        Ok(())
    }
}

// The this preprocessor produces wrong values,
// it should only be used for benchmarking the garbler.
#[derive(Clone)]
pub struct InsecureBenchPreprocessor {
    party_count: u16,
    delta: F128b,
    dummy_auth_bits: Vec<AuthShare<F2, F128b>>,
}

impl InsecureBenchPreprocessor {
    pub fn new<R: Rng + CryptoRng>(party_count: u16, max_auth_bits: usize, rng: &mut R) -> Self {
        let deltas: Vec<_> = (0..party_count).map(|_| F128b::random(rng)).collect();
        let dummy_auth_bits = (0..max_auth_bits)
            .map(|_| secret_share_with_delta(F2::ZERO, &deltas, rng)[0].clone())
            .collect();
        Self {
            party_count,
            delta: deltas[0],
            dummy_auth_bits,
        }
    }
}

impl StaticPreprocessor for InsecureBenchPreprocessor {
    fn my_party_id(&self) -> u16 {
        // the party ID here doesn't matter
        // since only one party is garbling
        1
    }

    fn beaver_triples(&mut self, m: u64) -> Result<Vec<Triple>, GcError> {
        let m_auth_bits = self.dummy_auth_bits[0..m as usize].to_vec();
        Ok(izip!(m_auth_bits.clone(), m_auth_bits.clone(), m_auth_bits)
            .map(|(a, b, c)| (a, b, c))
            .collect())
    }

    fn party_count(&self) -> u16 {
        self.party_count
    }

    fn init_delta(&mut self) -> Result<F128b, GcError> {
        Ok(self.delta)
    }

    fn auth_bits(&mut self, m: u64) -> Result<Vec<AuthShare<F2, F128b>>, GcError> {
        Ok(self.dummy_auth_bits[..m as usize].to_vec())
    }

    fn open_values_to(
        &mut self,
        receiver_party: ReceiverParty,
        xs: &[AuthShare<F2, F128b>],
    ) -> Result<Option<Vec<F2>>, GcError> {
        match receiver_party {
            ReceiverParty::All => Ok(Some(vec![F2::ZERO; xs.len()])),
            ReceiverParty::Party(party_id) => {
                if party_id == self.my_party_id() {
                    Ok(Some(vec![F2::ZERO; xs.len()]))
                } else {
                    Ok(None)
                }
            }
        }
    }

    fn done(&mut self) {
        // do nothing
    }
}

impl Preprocessor for InsecureBenchPreprocessor {
    fn prep(&mut self) -> Result<(), GcError> {
        // the dummy material is generated in the constructor
        Ok(())
    }
}
