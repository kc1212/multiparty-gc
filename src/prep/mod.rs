use itertools::Itertools;
use itertools::izip;
use scuttlebutt::ring::FiniteRing;
use scuttlebutt::serialization::CanonicalSerialize;
use swanky_field_binary::F2;
use swanky_field_binary::F128b;

use crate::error::GcError;
use crate::net::Bits;
use crate::net::Session;
use crate::sharing::AuthShare;

pub mod insecure;
pub mod secure;

pub use insecure::InsecureBenchPreprocessor;
pub use insecure::InsecurePreprocessor;
pub use secure::SecurePrepParams;
pub use secure::SecurePreprocessor;

pub type Triple = (
    AuthShare<F2, F128b>,
    AuthShare<F2, F128b>,
    AuthShare<F2, F128b>,
);

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum ReceiverParty {
    All,
    Party(u16),
}

/// Interface to authenticated preprocessing material and interactive openings.
///
/// Authenticated shares are only consistent
/// if this function is called in the same order
/// by all parties.
pub trait StaticPreprocessor {
    fn party_count(&self) -> u16;
    fn my_party_id(&self) -> u16;
    fn init_delta(&mut self) -> Result<F128b, GcError>;
    fn auth_bits(&mut self, m: u64) -> Result<Vec<AuthShare<F2, F128b>>, GcError>;

    fn beaver_triples(&mut self, m: u64) -> Result<Vec<Triple>, GcError>;

    /// Perform a Beaver multiplication using triples from [Self::beaver_triples].
    fn beaver_mul(
        &mut self,
        shares: &[AuthShare<F2, F128b>],
        indices: &[(usize, usize)],
    ) -> Result<Vec<AuthShare<F2, F128b>>, GcError> {
        // [x], [y] is the input
        // take two random bits [a], [b]
        let beaver_triples = self.beaver_triples(indices.len() as u64)?;
        // d = Open([x + a]), e = Open([y + b])
        let (shares_d, shares_e): (Vec<_>, Vec<_>) = izip!(indices, &beaver_triples)
            .map(|((i, j), (a, b, _c))| {
                let unopened_d = &shares[*i] + a;
                let unopened_e = &shares[*j] + b;
                (unopened_d, unopened_e)
            })
            .unzip();

        // open d and e together, this takes one round instead of two
        let mut ds = self
            .open_values_to(ReceiverParty::All, &[shares_d, shares_e].concat())?
            .ok_or_else(|| GcError::WrongOpening("opening to all returned nothing".into()))?;
        let es = ds.split_off(indices.len());

        // z = d * [y] + [a] * e + [c]
        Ok(izip!(indices, ds, es, beaver_triples)
            .map(|((_idx_x, idx_y), d, e, beaver_triple)| {
                let share_y = &shares[*idx_y];
                let (share_a, _, share_c) = beaver_triple;
                share_y * d + &(share_a * e) + &share_c
            })
            .collect_vec())
    }

    /// Open values `xs` to a party with ID `party_id`.
    /// Returns None if the caller does not have ID `party_id`, otherwise return the opened values.
    fn open_values_to(
        &mut self,
        receiver_party: ReceiverParty,
        xs: &[AuthShare<F2, F128b>],
    ) -> Result<Option<Vec<F2>>, GcError>;

    fn done(&mut self);
}

pub trait Preprocessor: StaticPreprocessor {
    /// Run the function-independent preprocessing phase.
    /// Depending on the preprocessing implementation, this step might do nothing.
    ///
    /// For interactive implementations, all parties must call this concurrently,
    /// see [run_prep].
    fn prep(&mut self) -> Result<(), GcError>;
}

/// Run [Preprocessor::prep] for all parties concurrently (one thread per party)
/// and return the preprocessors in the same order.
///
/// Returns the first error if any party fails.
pub fn run_prep<P: Preprocessor + Send>(mut preps: Vec<P>) -> Result<Vec<P>, GcError> {
    let results = std::thread::scope(|s| {
        let handles = preps
            .iter_mut()
            .map(|prep| s.spawn(move || prep.prep()))
            .collect_vec();
        handles
            .into_iter()
            .map(|h| h.join().expect("preprocessing thread panicked"))
            .collect_vec()
    });
    results.into_iter().collect::<Result<Vec<_>, _>>()?;
    Ok(preps)
}

/// Open authenticated shares to `receiver_party` with a MAC check.
///
/// Every party sends its shares together with a digest of its MACs under the receiver's
/// global key, and each receiver checks the digest against its keys. Returns `None`
/// if we are not a receiver. If `tamper` is set, we flip our first share, this is only
/// useful to simulate cheating in tests.
pub(crate) fn open_with_mac_check(
    session: &mut Session,
    delta: F128b,
    receiver_party: ReceiverParty,
    xs: &[AuthShare<F2, F128b>],
    tamper: bool,
) -> Result<Option<Vec<F2>>, GcError> {
    let me = session.party_id();
    let n = session.party_count();
    if let ReceiverParty::Party(receiver) = receiver_party
        && receiver >= n
    {
        return Err(GcError::WrongOpening(format!(
            "invalid receiver {receiver}"
        )));
    }
    if xs.iter().any(|x| {
        x.party_id != me || x.mac_keys.len() != n as usize || x.mac_values.len() != n as usize
    }) {
        return Err(GcError::WrongOpening(
            "invalid authenticated share shape or owner".into(),
        ));
    }
    let is_receiver = |j: u16| match receiver_party {
        ReceiverParty::All => true,
        ReceiverParty::Party(r) => r == j,
    };

    let mut my_shares = Bits(xs.iter().map(|x| bool::from(x.share)).collect());
    if tamper && !xs.is_empty() {
        my_shares.0[0] ^= true;
    }
    for peer in session.peers() {
        if is_receiver(peer) {
            let digest = mac_digest(
                session.sid(),
                xs.iter().map(|x| x.mac_values[peer as usize]),
            );
            session.send_msg(peer, &(my_shares.clone(), digest))?;
        }
    }
    if !is_receiver(me) {
        return Ok(None);
    }

    let mut output = xs.iter().map(|x| bool::from(x.share)).collect_vec();
    for peer in session.peers() {
        let (Bits(shares), digest): (Bits, [u8; blake3::OUT_LEN]) =
            session.recv_msg(peer, &(xs.len(), ()))?;
        let expected = mac_digest(
            session.sid(),
            xs.iter()
                .zip(&shares)
                .map(|(x, s)| x.mac_keys[peer as usize] + if *s { delta } else { F128b::ZERO }),
        );
        if expected != digest {
            return Err(GcError::MacCheckFailure);
        }
        for (o, s) in output.iter_mut().zip(shares) {
            *o ^= s;
        }
    }
    Ok(Some(output.into_iter().map(F2::from).collect()))
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
