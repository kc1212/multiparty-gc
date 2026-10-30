use crate::error::GcError;

/// Parameters of [super::SecurePreprocessor].
#[derive(Clone, Copy, Debug)]
pub struct SecurePrepParams {
    /// Statistical security parameter ρ, at most 128.
    pub rho: usize,
    /// Bucket size `B` used to combine leaky AND triples.
    /// If it is `None`, it is chosen from the actual batch size and `rho`.
    /// Explicit sizes below the calculated minimum are rejected.
    pub bucket_size: Option<usize>,
}

impl Default for SecurePrepParams {
    fn default() -> Self {
        Self {
            rho: 40,
            bucket_size: None,
        }
    }
}

impl SecurePrepParams {
    /// The bucket size for generating `triples` AND triples.
    pub fn bucket_size_for(&self, triples: usize) -> Result<usize, GcError> {
        if !(1..=128).contains(&self.rho) {
            return Err(GcError::InvalidPrepParams("rho must be in [1, 128]".into()));
        }
        if self.bucket_size == Some(0) {
            return Err(GcError::InvalidPrepParams(
                "bucket size must be positive".into(),
            ));
        }
        if triples == 0 {
            return Ok(self.bucket_size.unwrap_or(1));
        }

        let minimum = (1..)
            .find(|&b| {
                if triples == 1 {
                    // The bound is exactly 2^-b here, so b = rho is sufficient, but the
                    // floating-point margin below would wrongly require b = rho + 1.
                    b >= self.rho
                } else {
                    // Leave a margin for floating-point rounding at the boundary.
                    leakage_log2_bound(triples, b) <= -(self.rho as f64) - 1e-9
                }
            })
            .expect("a sufficiently large bucket always bounds the leakage");
        let bucket_size = self.bucket_size.unwrap_or(minimum);
        if bucket_size < minimum {
            return Err(GcError::InvalidPrepParams(format!(
                "bucket size {bucket_size} is below the minimum {minimum} for {triples} triples at rho={}",
                self.rho
            )));
        }
        Ok(bucket_size)
    }
}

/// For g guessed leaky bits, passing costs 2^-g; a union bound for an all-leaky
/// bucket is l * C(g, B) / C(l*B, B). Their product is largest at
/// g = min(l*B, 2*B-1), since successive terms have ratio (g+1)/(2*(g+1-B)).
/// This is the random bucketing analysis used by WRK17's AND combiner.
fn leakage_log2_bound(triples: usize, bucket_size: usize) -> f64 {
    let total = triples as u128 * bucket_size as u128;
    let guesses = total.min(2 * bucket_size as u128 - 1);
    (triples as f64).log2() - guesses as f64
        + (0..bucket_size)
            .map(|i| ((guesses - i as u128) as f64 / (total - i as u128) as f64).log2())
            .sum::<f64>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_size_tracks_actual_batch_and_security() {
        for (rho, triples, expected) in [
            (40, 1, 40),
            (40, 2, 21),
            (40, 30, 8),
            (40, 320, 5),
            (40, 3100, 4),
            (40, 280_000, 3),
            (64, 3100, 6),
            (128, 1, 128),
            (128, 3100, 11),
        ] {
            let params = SecurePrepParams {
                rho,
                bucket_size: None,
            };
            assert_eq!(params.bucket_size_for(triples).unwrap(), expected);
            assert!(
                SecurePrepParams {
                    bucket_size: Some(expected - 1),
                    ..params
                }
                .bucket_size_for(triples)
                .is_err()
            );
            assert_eq!(
                SecurePrepParams {
                    bucket_size: Some(expected + 1),
                    ..params
                }
                .bucket_size_for(triples)
                .unwrap(),
                expected + 1
            );
        }
    }

    #[test]
    fn reject_invalid_parameters_even_without_triples() {
        for rho in [0, 129, usize::MAX] {
            assert!(
                SecurePrepParams {
                    rho,
                    bucket_size: None
                }
                .bucket_size_for(0)
                .is_err()
            );
        }
        assert!(
            SecurePrepParams {
                rho: 40,
                bucket_size: Some(0)
            }
            .bucket_size_for(0)
            .is_err()
        );
        assert!(
            SecurePrepParams {
                rho: 40,
                bucket_size: Some(1)
            }
            .bucket_size_for(50)
            .is_err()
        );
        assert_eq!(SecurePrepParams::default().bucket_size_for(0).unwrap(), 1);
    }

    #[test]
    fn bucket_bound_covers_every_guess_count() {
        // Enumerate all attacks in small batches, using the product form directly
        // rather than assuming where its maximum occurs.
        for triples in 1..=12 {
            for rho in 1..=12 {
                let b = SecurePrepParams {
                    rho,
                    bucket_size: None,
                }
                .bucket_size_for(triples)
                .unwrap();
                let total = triples * b;
                for guesses in b..=total {
                    let mut bound = triples as f64 * 2f64.powi(-(guesses as i32));
                    for i in 0..b {
                        bound *= (guesses - i) as f64 / (total - i) as f64;
                    }
                    assert!(bound <= 2f64.powi(-(rho as i32)) * (1.0 + 1e-12));
                }
            }
        }
    }
}
