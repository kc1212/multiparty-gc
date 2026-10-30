use crate::{prep::run_prep, sharing::verify_and_reconstruct, transpose};

use super::*;

fn new_preps(
    n: u16,
    bits: usize,
    triples: usize,
    params: SecurePrepParams,
) -> Vec<SecurePreprocessor> {
    let mut rng = AesRng::new();
    SecurePreprocessor::new(&mut rng, n, true, bits, triples, params, None).unwrap()
}

/// Run `f` for every party concurrently.
fn run_parties<T: Send>(
    preps: &mut [SecurePreprocessor],
    f: impl Fn(&mut SecurePreprocessor) -> T + Sync,
) -> Vec<T> {
    std::thread::scope(|s| {
        let handles = preps
            .iter_mut()
            .map(|prep| {
                let f = &f;
                s.spawn(move || f(prep))
            })
            .collect_vec();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    })
}

/// Check that the material is correctly authenticated and that the triples are correct.
fn check_material(preps: &mut [SecurePreprocessor], bits: usize, triples: usize) {
    let n = preps.len() as u16;
    let deltas = preps
        .iter_mut()
        .map(|p| p.init_delta().unwrap())
        .collect_vec();
    assert!(lsb(deltas[0]));

    let all_bits = preps
        .iter_mut()
        .map(|p| p.auth_bits(bits as u64).unwrap())
        .collect_vec();
    let values = transpose(all_bits)
        .into_iter()
        .map(|shares| verify_and_reconstruct(n, shares, &deltas).unwrap())
        .collect_vec();
    assert_eq!(values.len(), bits);

    let all_triples = preps
        .iter_mut()
        .map(|p| p.beaver_triples(triples as u64).unwrap())
        .collect_vec();
    for triple in transpose(all_triples) {
        let (a, b, c): (Vec<_>, Vec<_>, Vec<_>) = triple.into_iter().multiunzip();
        let a = verify_and_reconstruct(n, a, &deltas).unwrap();
        let b = verify_and_reconstruct(n, b, &deltas).unwrap();
        let c = verify_and_reconstruct(n, c, &deltas).unwrap();
        assert_eq!(a * b, c);
    }

    // all the material is used
    for p in preps.iter_mut() {
        assert!(p.auth_bits(1).is_err());
        assert!(p.beaver_triples(1).is_err());
    }
}

#[test]
fn test_constructor_rejects_overflow_before_allocating() {
    let mut rng = AesRng::new();
    for (bits, triples) in [(usize::MAX, 0), (0, usize::MAX), (0, usize::MAX / 4)] {
        assert!(matches!(
            SecurePreprocessor::new(&mut rng, 2, true, bits, triples, Default::default(), None),
            Err(GcError::InvalidPrepParams(_))
        ));
    }
    for n in [0, 1] {
        assert!(
            SecurePreprocessor::new(&mut rng, n, true, 0, 0, Default::default(), None).is_err()
        );
    }
}

#[test]
fn test_failed_prep_does_not_release_material() {
    let mut preps = new_preps(3, 20, 10, Default::default());
    preps[0].set_cheat(Cheat::LeakyAndFlipE);
    let results = run_parties(&mut preps, |p| p.prep());
    for (i, (prep, result)) in preps.iter_mut().zip(results).enumerate() {
        // the honest parties must abort, the cheater may or may not
        assert!(i == 0 || result.is_err(), "honest party {i} did not abort");
        if result.is_err() {
            assert!(!prep.prepped);
            assert!(prep.auth_bits.is_empty());
            assert!(prep.triples.is_empty());
            assert!(prep.auth_bits(1).is_err());
            assert!(prep.beaver_triples(1).is_err());
        }
    }
}

#[test]
fn test_empty_prep() {
    let mut preps = run_prep(new_preps(2, 0, 0, Default::default())).unwrap();
    for prep in &mut preps {
        assert_eq!(prep.auth_bits(0).unwrap().len(), 0);
        assert_eq!(prep.beaver_triples(0).unwrap().len(), 0);
        assert!(prep.auth_bits(u64::MAX).is_err());
        assert!(prep.beaver_triples(u64::MAX).is_err());
    }
}

#[test]
fn test_opening_rejects_invalid_receiver_and_shares() {
    for receiver in [ReceiverParty::Party(3), ReceiverParty::All] {
        let mut preps = run_prep(new_preps(3, 1, 0, Default::default())).unwrap();
        let results = run_parties(&mut preps, |p| {
            let mut shares = p.auth_bits(1).unwrap();
            if p.party_id == 0 && receiver == ReceiverParty::All {
                shares[0].mac_keys.clear();
            }
            p.open_values_to(receiver, &shares)
        });
        assert!(results.iter().all(Result::is_err));
    }
}

#[test]
fn test_secure_prep_correctness() {
    for n in [2, 3, 4] {
        let (bits, triples) = (100, 200);
        let mut preps = run_prep(new_preps(n, bits, triples, Default::default())).unwrap();
        check_material(&mut preps, bits, triples);
    }
}

#[test]
fn test_secure_prep_params() {
    let (bits, triples) = (50, 30);
    // explicit bucket sizes above the minimum for 30 triples (8 at rho = 40) are accepted
    for (rho, bucket_size) in [
        (1, None),
        (10, None),
        (40, Some(9)),
        (40, Some(12)),
        (64, None),
        (128, None),
    ] {
        let params = SecurePrepParams { rho, bucket_size };
        let mut preps = run_prep(new_preps(3, bits, triples, params)).unwrap();
        check_material(&mut preps, bits, triples);
    }
}

#[test]
fn test_secure_prep_no_triples() {
    let mut preps = run_prep(new_preps(3, 20, 0, Default::default())).unwrap();
    check_material(&mut preps, 20, 0);
}

#[test]
fn test_secure_open_and_beaver_mul() {
    let n = 3u16;
    let count = 64;
    let mut preps = run_prep(new_preps(n, 2 * count, count, Default::default())).unwrap();
    let deltas = preps
        .iter_mut()
        .map(|p| p.init_delta().unwrap())
        .collect_vec();
    let indices = (0..count).map(|i| (2 * i, 2 * i + 1)).collect_vec();

    let outputs = run_parties(&mut preps, |p| {
        let shares = p.auth_bits(2 * count as u64).unwrap();
        let opened_all = p.open_values_to(ReceiverParty::All, &shares).unwrap();
        let opened_one = p.open_values_to(ReceiverParty::Party(1), &shares).unwrap();
        let products = p.beaver_mul(&shares, &indices).unwrap();
        (shares, opened_all, opened_one, products)
    });
    let (shares, opened_all, opened_one, products): (Vec<_>, Vec<_>, Vec<_>, Vec<_>) =
        outputs.into_iter().multiunzip();

    let values = transpose(shares)
        .into_iter()
        .map(|s| verify_and_reconstruct(n, s, &deltas).unwrap())
        .collect_vec();
    for opened in &opened_all {
        assert_eq!(opened.as_ref().unwrap(), &values);
    }
    assert_eq!(opened_one[0], None);
    assert_eq!(opened_one[1].as_ref().unwrap(), &values);
    assert_eq!(opened_one[2], None);

    for ((i, j), product) in indices.iter().zip(transpose(products)) {
        let product = verify_and_reconstruct(n, product, &deltas).unwrap();
        assert_eq!(product, values[*i] * values[*j]);
    }
}

/// Run the preprocessing where `cheater` deviates with `cheat`
/// and check that every honest party aborts and at least one detects the cheating.
fn assert_detected(n: u16, cheater: usize, cheat: Cheat) {
    let mut preps = new_preps(n, 20, 50, Default::default());
    preps[cheater].set_cheat(cheat);
    let results = run_parties(&mut preps, |p| p.prep());
    assert_honest_abort(&results, cheater, cheat);
}

fn assert_honest_abort(results: &[Result<(), GcError>], cheater: usize, cheat: Cheat) {
    for (i, result) in results.iter().enumerate() {
        if i != cheater {
            assert!(
                result.is_err(),
                "honest party {i} did not abort for {cheat:?}"
            );
        }
    }
    let detected = results.iter().enumerate().any(|(i, r)| {
        i != cheater
            && matches!(
                r,
                Err(GcError::CheatDetected(_)) | Err(GcError::MacCheckFailure)
            )
    });
    assert!(detected, "no honest party detected {cheat:?}: {results:?}");
}

#[test]
fn test_malicious_inconsistent_bits() {
    assert_detected(3, 0, Cheat::AbitInconsistentBits);
    assert_detected(4, 2, Cheat::AbitInconsistentBits);
}

#[test]
fn test_malicious_inconsistent_delta() {
    assert_detected(3, 1, Cheat::InconsistentDelta);
    assert_detected(4, 3, Cheat::InconsistentDelta);
}

#[test]
fn test_malicious_half_and() {
    assert_detected(2, 0, Cheat::HalfAndFlipY);
    assert_detected(3, 1, Cheat::HalfAndFlipY);
}

#[test]
fn test_malicious_leaky_and() {
    for cheat in [
        Cheat::LeakyAndFlipE,
        Cheat::LeakyAndWrongU,
        Cheat::LeakyAndWrongH,
    ] {
        assert_detected(2, 1, cheat);
        assert_detected(3, 2, cheat);
    }
}

#[test]
fn test_malicious_equivocation() {
    assert_detected(3, 0, Cheat::EquivocateBroadcast);
    assert_detected(4, 1, Cheat::EquivocateBroadcast);
}

#[test]
fn test_malicious_coin_toss() {
    assert_detected(2, 0, Cheat::CoinTossBadOpening);
    assert_detected(3, 2, Cheat::CoinTossBadOpening);
}

#[test]
fn test_malicious_bucket_opening() {
    assert_detected(2, 1, Cheat::BucketWrongOpening);
    assert_detected(3, 0, Cheat::BucketWrongOpening);
}

#[test]
fn test_malicious_beaver_opening() {
    let (n, cheater, count) = (3u16, 1, 16);
    let mut preps = run_prep(new_preps(n, 2 * count, count, Default::default())).unwrap();
    preps[cheater].set_cheat(Cheat::BeaverWrongOpening);
    let indices = (0..count).map(|i| (2 * i, 2 * i + 1)).collect_vec();
    let results = run_parties(&mut preps, |p| {
        let shares = p.auth_bits(2 * count as u64).unwrap();
        p.beaver_mul(&shares, &indices).map(|_| ())
    });
    assert_honest_abort(&results, cheater, Cheat::BeaverWrongOpening);
}
