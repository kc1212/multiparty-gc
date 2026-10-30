//! Maliciously secure preprocessing following [WRK17](https://eprint.iacr.org/2017/189)
//! (Section 5 and Appendix B) and its implementation in
//! [emp-agmpc](https://github.com/emp-toolkit/emp-agmpc) (`abitmp.h`, `fpremp.h`).
//!
//! The function-independent phase ([Preprocessor::prep]) consists of
//! 1. pairwise correlated OT (KOS, from `ocelot`) where every party uses its global key `Δ_i`
//!    as the correlation, giving two-party authenticated bits,
//! 2. Π_aBit^n (Figure 14): random linear combinations ensure that every party used the same
//!    bits with all other parties,
//! 3. Π_aShare (Figure 15): partially opening some authenticated bits ensures that every party
//!    used a consistent `Δ_i` with all other parties,
//! 4. Π_HaAND (Figure 16) and Π_LaAND (Figure 8): leaky authenticated AND triples,
//! 5. Π_aAND (Figure 18): random bucketing removes the leakage.
//!
//! In the function-dependent phase, the garblers multiply wire masks with
//! [StaticPreprocessor::beaver_mul], all openings are MAC-checked.
//!
//! Differences to emp-agmpc:
//! - Values that the paper broadcasts are sent with echo broadcast, emp-agmpc sends them
//!   point-to-point which lets a malicious party send different values to different parties.
//! - Values opened during bucketing and Beaver multiplication are MAC-checked.
//! - The final check of Π_LaAND is compressed with a random linear combination over
//!   `F_{2^128}` (instead of ρ binary combinations) before it is committed and opened.

use std::{collections::VecDeque, time::Duration};

mod auth;
mod params;
mod triples;

pub use params::SecurePrepParams;

use itertools::Itertools;
use rand::{CryptoRng, Rng, SeedableRng};
use scuttlebutt::{AesHash, AesRng, Block, ring::FiniteRing, serialization::CanonicalSerialize};
use swanky_field_binary::{F2, F128b};

use crate::{
    error::GcError,
    net::{
        NetworkConfig, Session,
        memory::{LinkModel, mesh},
    },
    sharing::AuthShare,
};

use super::{Preprocessor, ReceiverParty, StaticPreprocessor, Triple};

const F128B_LEN: usize = 16;

/// Deviations from the protocol that a corrupt party can make.
/// This is only used in tests to check that the honest parties abort.
/// Unless stated otherwise, the deviation targets the next party, see [SecurePreprocessor::victim].
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Cheat {
    /// Use a different choice bit in the correlated OT with the victim.
    AbitInconsistentBits,
    /// Use a different global key in the correlated OT with the victim.
    InconsistentDelta,
    /// Use a different `y` in Π_HaAND with the victim.
    HalfAndFlipY,
    /// Broadcast a wrong `e` for one triple in Π_LaAND.
    LeakyAndFlipE,
    /// Send a wrong `U` to the victim in the Π_LaAND check.
    LeakyAndWrongU,
    /// Commit to a wrong `H` in the Π_LaAND check.
    LeakyAndWrongH,
    /// Send a different `e` to the victim than to the other parties in Π_LaAND.
    EquivocateBroadcast,
    /// Open a coin tossing commitment to a different value.
    CoinTossBadOpening,
    /// Open a wrong share during bucketing.
    BucketWrongOpening,
    /// Open a wrong share during Beaver multiplication.
    BeaverWrongOpening,
}

/// Domain separation for [hash].
#[derive(Clone, Copy)]
#[repr(u8)]
enum HashDomain {
    HalfAnd = 1,
    LeakyAnd = 2,
}

/// Maliciously secure preprocessor, see the module documentation.
///
/// Every party creates its preprocessor with [SecurePreprocessor::new] from a [Session]
/// that is used for all its communication, all parties must use the same parameters.
/// They must run [Preprocessor::prep] concurrently, e.g., with [super::run_prep],
/// before the material can be used.
pub struct SecurePreprocessor {
    party_id: u16,
    party_count: u16,
    delta: F128b,
    session: Session,
    /// Key of the TCCR hash, derived from the session ID.
    tccr_key: Block,
    rng: AesRng,
    rho: usize,
    bucket_size: usize,
    /// Number of random authenticated bits to generate.
    bits_needed: usize,
    /// Number of AND triples to generate.
    triples_needed: usize,
    /// Simulated latency for every opening in the function-dependent phase.
    open_delay: Option<Duration>,
    prepped: bool,
    auth_bits: VecDeque<AuthShare<F2, F128b>>,
    triples: VecDeque<Triple>,
    #[cfg(test)]
    cheat: Option<Cheat>,
}

impl SecurePreprocessor {
    /// Create the preprocessor of the party that owns `session`, it will generate
    /// `bits` random authenticated bits and `triples` AND triples.
    ///
    /// If `tweak_delta_lsb` is set, party 0 chooses a global key with `lsb(Δ_0) = 1`.
    pub fn new<R: Rng + CryptoRng>(
        session: Session,
        rng: &mut R,
        tweak_delta_lsb: bool,
        bits: usize,
        triples: usize,
        params: SecurePrepParams,
        open_delay: Option<Duration>,
    ) -> Result<Self, GcError> {
        let bucket_size = params.bucket_size_for(triples)?;
        // Validate all material and field-message sizes before starting any party.
        triples
            .checked_mul(bucket_size)
            .and_then(|count| count.checked_mul(3))
            .and_then(|count| count.checked_add(bits))
            .and_then(|count| count.checked_add(3 * params.rho))
            .and_then(|count| count.checked_mul(F128B_LEN))
            .ok_or_else(|| GcError::InvalidPrepParams("material size overflows usize".into()))?;

        let party_id = session.party_id();
        let mut rng = AesRng::from_rng(&mut *rng).unwrap();
        let mut delta = F128b::random(&mut rng);
        if tweak_delta_lsb && party_id == 0 {
            let mut buf = delta.to_bytes();
            buf[0] |= 1;
            delta = F128b::from_bytes(&buf).unwrap();
        }
        let tccr_key = blake3::derive_key("multiparty-gc secure prep tccr key v1", session.sid());
        Ok(Self {
            party_id,
            party_count: session.party_count(),
            delta,
            tccr_key: Block::from(u128::from_le_bytes(tccr_key[..16].try_into().unwrap())),
            session,
            rng,
            rho: params.rho,
            bucket_size,
            bits_needed: bits,
            triples_needed: triples,
            open_delay,
            prepped: false,
            auth_bits: VecDeque::new(),
            triples: VecDeque::new(),
            #[cfg(test)]
            cheat: None,
        })
    }

    /// Create preprocessors for `party_count` parties in this process that are connected
    /// with the in-memory transport, see [SecurePreprocessor::new] for the parameters.
    pub fn new_in_memory<R: Rng + CryptoRng>(
        rng: &mut R,
        party_count: u16,
        tweak_delta_lsb: bool,
        bits: usize,
        triples: usize,
        params: SecurePrepParams,
        open_delay: Option<Duration>,
    ) -> Result<Vec<Self>, GcError> {
        mesh(party_count, LinkModel::default(), NetworkConfig::default())?
            .into_iter()
            .map(|net| {
                let session = net.session("secure prep")?;
                Self::new(
                    session,
                    rng,
                    tweak_delta_lsb,
                    bits,
                    triples,
                    params,
                    open_delay,
                )
            })
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn set_cheat(&mut self, cheat: Cheat) {
        self.cheat = Some(cheat);
    }

    fn cheating(&self, _cheat: Cheat) -> bool {
        #[cfg(test)]
        {
            self.cheat == Some(_cheat)
        }
        #[cfg(not(test))]
        {
            false
        }
    }

    /// Abort with `err` because a check failed.
    /// A cheating party in tests ignores failed checks, like a real adversary would.
    fn detected(&self, err: GcError) -> Result<(), GcError> {
        #[cfg(test)]
        if self.cheat.is_some() {
            return Ok(());
        }
        Err(err)
    }

    /// The party targeted by a deviation, see [Cheat].
    fn victim(&self) -> u16 {
        (self.party_id + 1) % self.party_count
    }

    fn coin_toss(&mut self) -> Result<[u8; 32], GcError> {
        let bad_opening = self.cheating(Cheat::CoinTossBadOpening);
        Ok(self.session.coin_with(&mut self.rng, bad_opening)?)
    }

    fn tccr(&self) -> AesHash {
        AesHash::new(self.tccr_key)
    }
}

impl StaticPreprocessor for SecurePreprocessor {
    fn party_count(&self) -> u16 {
        self.party_count
    }

    fn my_party_id(&self) -> u16 {
        self.party_id
    }

    fn init_delta(&mut self) -> Result<F128b, GcError> {
        Ok(self.delta)
    }

    fn auth_bits(&mut self, m: u64) -> Result<Vec<AuthShare<F2, F128b>>, GcError> {
        if !self.prepped || m > self.auth_bits.len() as u64 {
            return Err(GcError::NotEnoughMaterial(format!(
                "requested {m} authenticated bits but only {} are available",
                self.auth_bits.len()
            )));
        }
        Ok(self.auth_bits.drain(..m as usize).collect())
    }

    fn beaver_triples(&mut self, m: u64) -> Result<Vec<Triple>, GcError> {
        if !self.prepped || m > self.triples.len() as u64 {
            return Err(GcError::NotEnoughMaterial(format!(
                "requested {m} triples but only {} are available",
                self.triples.len()
            )));
        }
        Ok(self.triples.drain(..m as usize).collect())
    }

    /// Every party sends its shares to the receivers together with a digest of the MACs
    /// under the receiver's key, the receivers check the digest.
    fn open_values_to(
        &mut self,
        receiver_party: ReceiverParty,
        xs: &[AuthShare<F2, F128b>],
    ) -> Result<Option<Vec<F2>>, GcError> {
        let result = self.open_values_to_inner(receiver_party, xs);
        if let Err(err) = &result {
            self.abort(&format!("opening failed: {err}"));
        }
        result
    }

    fn done(&mut self) {
        // nothing to clean up, the material is consumed by the garbler
    }
}

impl SecurePreprocessor {
    fn abort(&mut self, reason: &str) {
        self.session.abort(reason);
        self.prepped = false;
        self.auth_bits.clear();
        self.triples.clear();
    }

    fn open_values_to_inner(
        &mut self,
        receiver_party: ReceiverParty,
        xs: &[AuthShare<F2, F128b>],
    ) -> Result<Option<Vec<F2>>, GcError> {
        if let ReceiverParty::Party(receiver) = receiver_party
            && receiver >= self.party_count
        {
            return Err(GcError::WrongOpening(format!(
                "invalid receiver {receiver}"
            )));
        }
        if xs.iter().any(|x| {
            x.party_id != self.party_id
                || x.mac_keys.len() != self.party_count as usize
                || x.mac_values.len() != self.party_count as usize
        }) {
            return Err(GcError::WrongOpening(
                "invalid authenticated share shape or owner".into(),
            ));
        }
        let me = self.party_id;
        let is_receiver = |j: u16| match receiver_party {
            ReceiverParty::All => true,
            ReceiverParty::Party(r) => r == j,
        };
        // only simulate latency in the function-dependent phase, like the insecure preprocessor
        if self.prepped
            && let Some(dur) = self.open_delay
        {
            std::thread::sleep(dur);
        }

        let mut my_shares = pack_bits(xs.iter().map(|x| bool::from(x.share)));
        let wrong_opening = if self.prepped {
            Cheat::BeaverWrongOpening
        } else {
            Cheat::BucketWrongOpening
        };
        if self.cheating(wrong_opening) && !xs.is_empty() {
            my_shares[0] ^= 1;
        }
        for peer in self.session.peers() {
            if is_receiver(peer) {
                let digest = mac_digest(
                    self.session.sid(),
                    xs.iter().map(|x| x.mac_values[peer as usize]),
                );
                self.session
                    .send(peer, &[my_shares.as_slice(), &digest].concat())?;
            }
        }
        if !is_receiver(me) {
            return Ok(None);
        }

        let shares_len = xs.len().div_ceil(8);
        let mut output = xs.iter().map(|x| bool::from(x.share)).collect_vec();
        for peer in self.session.peers() {
            let msg = self.session.recv(peer, shares_len + blake3::OUT_LEN)?;
            let (shares, digest) = msg.split_at(shares_len);
            let shares = unpack_bits(shares, xs.len());
            let expected = mac_digest(
                self.session.sid(),
                xs.iter()
                    .zip(&shares)
                    .map(|(x, s)| x.mac_keys[peer as usize] + mul_bit(*s, self.delta)),
            );
            if expected != digest {
                self.detected(GcError::MacCheckFailure)?;
            }
            for (o, s) in output.iter_mut().zip(shares) {
                *o ^= s;
            }
        }
        Ok(Some(output.into_iter().map(F2::from).collect()))
    }

    fn prep_inner(&mut self) -> Result<(), GcError> {
        if self.prepped {
            return Err(GcError::UnexpectedMessageType(
                "preprocessing already done".to_string(),
            ));
        }
        let bucket_size = self.bucket_size;
        let leaky_count = self.triples_needed * bucket_size;

        // every leaky triple needs three authenticated shares (x, y, r)
        let mut shares = self.random_auth_shares(3 * leaky_count + self.bits_needed)?;
        let auth_bits = shares.split_off(3 * leaky_count);
        if leaky_count > 0 {
            let leaky = self.leaky_and(shares)?;
            self.triples = self.combine_buckets(leaky, bucket_size)?.into();
        }
        self.auth_bits = auth_bits.into();
        self.prepped = true;
        Ok(())
    }
}

impl Preprocessor for SecurePreprocessor {
    fn prep(&mut self) -> Result<(), GcError> {
        let result = self.prep_inner();
        if let Err(err) = &result {
            // close all links so that the other parties abort instead of blocking
            self.abort(&format!("preprocessing failed: {err}"));
        }
        result
    }
}

/// Tweakable circular correlation robust hash, the tweak is unique for every
/// `(domain, index, from, to, bit)` and the key is unique per session.
fn hash(
    tccr: &AesHash,
    x: F128b,
    domain: HashDomain,
    index: usize,
    from: u16,
    to: u16,
    bit: bool,
) -> F128b {
    let tweak = ((index as u128) << 64)
        | ((from as u128) << 48)
        | ((to as u128) << 32)
        | ((domain as u128) << 8)
        | bit as u128;
    block_to_f128b(tccr.tccr_hash(Block::from(tweak), f128b_to_block(x)))
}

/// Digest of the MACs of opened shares, bound to the session.
fn mac_digest(sid: &[u8; 32], macs: impl Iterator<Item = F128b>) -> [u8; blake3::OUT_LEN] {
    let mut hasher = blake3::Hasher::new_derive_key("multiparty-gc opening macs v1");
    hasher.update(sid);
    for mac in macs {
        hasher.update(&mac.to_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn f128b_to_block(x: F128b) -> Block {
    Block::from(u128::from_le_bytes(x.to_bytes().into()))
}

fn block_to_f128b(x: Block) -> F128b {
    F128b::from_uniform_bytes(&u128::from(x).to_le_bytes())
}

fn seed_to_block(seed: &[u8; 32]) -> Block {
    Block::from(u128::from_le_bytes(seed[..16].try_into().unwrap()))
}

fn lsb(x: F128b) -> bool {
    x.to_bytes()[0] & 1 == 1
}

fn mul_bit(b: bool, x: F128b) -> F128b {
    if b { x } else { F128b::ZERO }
}

fn f128b_to_bytes(xs: &[F128b]) -> Vec<u8> {
    xs.iter().flat_map(|x| x.to_bytes()).collect()
}

fn bytes_to_f128b(bytes: &[u8]) -> Vec<F128b> {
    bytes
        .chunks_exact(F128B_LEN)
        .map(|b| F128b::from_uniform_bytes(b.try_into().unwrap()))
        .collect()
}

fn pack_bits(bits: impl IntoIterator<Item = bool>) -> Vec<u8> {
    bits.into_iter()
        .chunks(8)
        .into_iter()
        .map(|chunk| {
            chunk
                .enumerate()
                .fold(0u8, |acc, (i, b)| acc | ((b as u8) << i))
        })
        .collect()
}

fn unpack_bits(bytes: &[u8], len: usize) -> Vec<bool> {
    (0..len)
        .map(|i| (bytes[i / 8] >> (i % 8)) & 1 == 1)
        .collect()
}

#[cfg(test)]
mod tests;
