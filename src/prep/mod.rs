use itertools::Itertools;
use itertools::izip;
use swanky_field_binary::F2;
use swanky_field_binary::F128b;

use crate::error::GcError;
use crate::sharing::AuthShare;

pub mod insecure;
pub mod secure;

pub use insecure::InsecureBenchPreprocessor;
pub use insecure::InsecurePreprocessor;
pub use insecure::InsecurePreprocessorRunner;
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

        let ds = self.open_values_to(ReceiverParty::All, &shares_d)?.unwrap();
        let es = self.open_values_to(ReceiverParty::All, &shares_e)?.unwrap();

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
