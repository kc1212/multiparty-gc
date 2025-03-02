use swanky_field_binary::F128b;
use swanky_field_binary::F2;

use crate::sharing::AuthShare;

pub trait StaticPreprocessor {
    fn init(&mut self) -> F128b;
    /// Authenticated shares are only consistent
    /// if this function is called in the same order
    /// by all parties.
    fn random_bit(&mut self, m: u64) -> Vec<AuthShare<F2, F128b>>;
    fn add(&mut self, x: &AuthShare<F2, F128b>, y: &AuthShare<F2, F128b>) -> AuthShare<F2, F128b>;
    /// Compute z = x*y and then output unauthenticated shares <x * \Delta^i>
    fn and_output_mask(&mut self, x: &AuthShare<F2, F128b>, y: &AuthShare<F2, F128b>) -> Vec<F128b>;
    fn open_value(&mut self);
}

pub trait Preprocessor: StaticPreprocessor {
    fn prep(&mut self);
}
