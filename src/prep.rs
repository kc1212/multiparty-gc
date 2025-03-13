use std::collections::BTreeMap;

use bristol_fashion::Circuit;
use swanky_field_binary::F2;
use swanky_field_binary::F128b;

use crate::sharing::AuthShare;

/// Static preprocessor is one that has no networking.
///
/// Authenticated shares are only consistent
/// if this function is called in the same order
/// by all parties.
pub trait StaticPreprocessor {
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
