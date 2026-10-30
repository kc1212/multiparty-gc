//! Tests of the QUIC transport on localhost.

use std::{net::SocketAddr, time::Duration};

use itertools::Itertools;
use rustls::pki_types::CertificateDer;
use scuttlebutt::{AesRng, ring::FiniteRing};
use swanky_field_binary::F2;

use super::{
    NetError, Network,
    quic::{Identity, QuicConfig, QuicEndpoint},
};
use crate::{
    NamedCircuit, SimParty,
    error::GcError,
    evaluator::{copz::CopzEvaluator, wrk17::Wrk17Evaluator},
    full_simulation,
    garbler::{copz::CopzGarbler, wrk17::Wrk17Garbler},
    prep::{Preprocessor, SecurePrepParams, SecurePreprocessor, run_prep, secure::Cheat},
};

fn localhost() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

/// Bind all endpoints first so that their ports are known, then connect concurrently.
fn quic_mesh_with(
    n: u16,
    config: QuicConfig,
    certificates_for: impl Fn(u16, &[CertificateDer<'static>]) -> Vec<CertificateDer<'static>>,
) -> Vec<Result<Network, NetError>> {
    let identities = (0..n).map(|_| Identity::generate().unwrap()).collect_vec();
    let certificates = identities
        .iter()
        .map(|id| id.certificate().clone())
        .collect_vec();
    let endpoints = identities
        .into_iter()
        .enumerate()
        .map(|(i, identity)| {
            let certs = certificates_for(i as u16, &certificates);
            QuicEndpoint::bind(localhost(), i as u16, identity, certs, config).unwrap()
        })
        .collect_vec();
    let addresses = endpoints
        .iter()
        .map(|e| e.local_addr().unwrap())
        .collect_vec();
    std::thread::scope(|s| {
        let handles = endpoints
            .into_iter()
            .map(|e| {
                let addresses = &addresses;
                s.spawn(move || e.connect(addresses))
            })
            .collect_vec();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    })
}

fn quic_mesh(n: u16) -> Vec<Network> {
    quic_mesh_with(n, QuicConfig::default(), |_, certs| certs.to_vec())
        .into_iter()
        .map(Result::unwrap)
        .collect()
}

fn run_all<T: Send>(nets: Vec<Network>, f: impl Fn(Network) -> T + Sync) -> Vec<T> {
    std::thread::scope(|s| {
        let handles = nets
            .into_iter()
            .map(|net| {
                let f = &f;
                s.spawn(move || f(net))
            })
            .collect_vec();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    })
}

#[test]
fn test_quic_session_primitives() {
    let outputs = run_all(quic_mesh(3), |net| {
        let me = net.party_id();
        let mut s = net.session("s").unwrap();
        let mut rng = AesRng::new();
        let msgs = (0..3u8).map(|j| vec![me as u8, j]).collect_vec();
        let exchanged = s.exchange(&msgs, 2).unwrap();
        let all = s.broadcast_all(&[me as u8; 3]).unwrap();
        let from = s
            .broadcast_from(1, (me == 1).then_some(b"hello".as_slice()), 5)
            .unwrap();
        let coin = s.coin(&mut rng).unwrap();
        // a large message exercises flow control and framing
        let big = vec![me as u8; 5_000_000];
        let bigs = s.exchange(&vec![big; 3], 5_000_000).unwrap();
        (me, exchanged, all, from, coin, bigs)
    });
    let coin = outputs[0].4;
    for (me, exchanged, all, from, c, bigs) in outputs {
        for j in 0..3usize {
            if j != me as usize {
                assert_eq!(exchanged[j], vec![j as u8, me as u8]);
                assert!(bigs[j].iter().all(|b| *b == j as u8));
            }
            assert_eq!(all[j], vec![j as u8; 3]);
        }
        assert_eq!(from, b"hello");
        assert_eq!(c, coin);
    }
}

#[test]
fn test_quic_abort_propagates_with_reason() {
    let outputs = run_all(quic_mesh(3), |net| {
        let mut s = net.session("s").unwrap();
        if net.party_id() == 0 {
            s.abort("bad things");
            Ok(vec![])
        } else {
            s.recv(0, 1)
        }
    });
    for output in &outputs[1..] {
        match output {
            Err(NetError::PeerAborted { party: 0, reason }) => assert_eq!(reason, "bad things"),
            other => panic!("unexpected {other:?}"),
        }
    }
}

#[test]
fn test_quic_close_delivers_queued_frames() {
    let outputs = run_all(quic_mesh(2), |net| {
        let mut s = net.session("s").unwrap();
        if net.party_id() == 0 {
            // a large last message that is still in flight when we close
            s.send(1, &vec![7u8; 10_000_000]).unwrap();
            drop(s);
            drop(net);
            Ok(vec![])
        } else {
            std::thread::sleep(Duration::from_millis(100));
            let last = s.recv(0, 10_000_000).unwrap();
            assert!(last.iter().all(|b| *b == 7));
            s.recv(0, 1)
        }
    });
    assert!(
        matches!(outputs[1], Err(NetError::Disconnected(0))),
        "{:?}",
        outputs[1]
    );
}

#[test]
fn test_quic_rejects_unpinned_certificate() {
    let config = QuicConfig {
        connect_timeout: Duration::from_secs(3),
        ..Default::default()
    };
    // party 0 expects a different certificate for party 1
    let outputs = quic_mesh_with(2, config, |me, certs| {
        let mut certs = certs.to_vec();
        if me == 0 {
            certs[1] = Identity::generate().unwrap().certificate().clone();
        }
        certs
    });
    assert!(outputs.iter().all(Result::is_err));
}

#[test]
fn test_quic_bind_validates_identity() {
    let identity = Identity::generate().unwrap();
    let other = Identity::generate().unwrap().certificate().clone();
    let config = QuicConfig::default();
    // our certificate must match our identity
    assert!(
        QuicEndpoint::bind(localhost(), 0, identity, vec![other.clone(), other], config).is_err()
    );
    let identity = Identity::generate().unwrap();
    let mine = identity.certificate().clone();
    // certificates must be distinct to identify the parties
    assert!(
        QuicEndpoint::bind(localhost(), 0, identity, vec![mine.clone(), mine], config).is_err()
    );
}

fn secure_quic_parties(
    circuit: &NamedCircuit,
    n: u16,
    cheat: Option<(usize, Cheat)>,
) -> Result<Vec<(SecurePreprocessor, super::Session, Network)>, GcError> {
    let inputs: u64 = circuit.input_sizes().iter().sum();
    let (bits, triples) = ((circuit.nand() + inputs) as usize, circuit.nand() as usize);
    let mut preps = vec![];
    let mut rest = vec![];
    for (i, net) in quic_mesh(n).into_iter().enumerate() {
        let mut prep = SecurePreprocessor::new(
            net.session("prep")?,
            &mut AesRng::new(),
            true,
            bits,
            triples,
            SecurePrepParams::default(),
        )?;
        if let Some((cheater, cheat)) = cheat
            && cheater == i
        {
            prep.set_cheat(cheat);
        }
        preps.push(prep);
        rest.push((net.session("online")?, net));
    }
    if let Some((cheater, cheat)) = cheat {
        let results = std::thread::scope(|scope| {
            let handles = preps
                .iter_mut()
                .map(|prep| scope.spawn(|| prep.prep()))
                .collect_vec();
            handles.into_iter().map(|h| h.join().unwrap()).collect_vec()
        });
        for (i, result) in results.iter().enumerate() {
            if i != cheater {
                assert!(result.is_err(), "honest party {i} accepted {cheat:?}");
            }
        }
        // Abort delivery can race another honest party's local check. Observe every
        // outcome, rather than assuming party 0 is the first to detect the attack.
        let detected = results
            .into_iter()
            .enumerate()
            .find_map(|(i, result)| match result {
                Err(err @ GcError::CheatDetected(_)) | Err(err @ GcError::MacCheckFailure)
                    if i != cheater =>
                {
                    Some(err)
                }
                _ => None,
            })
            .expect("an honest party must detect the attack");
        return Err(detected);
    }
    let preps = run_prep(preps)?;
    Ok(preps
        .into_iter()
        .zip(rest)
        .map(|(p, (o, n))| (p, o, n))
        .collect())
}

#[test]
fn test_quic_full_protocol() {
    let circuit = NamedCircuit::from_path("circuits/aes_128.txt");
    let n = 3;
    let mut rng = AesRng::new();
    let input_length: u64 = circuit.input_sizes().iter().sum();
    let inputs: Vec<F2> = (0..input_length).map(|_| F2::random(&mut rng)).collect();

    let parties = secure_quic_parties(&circuit, n, None)
        .unwrap()
        .into_iter()
        .enumerate()
        .map(|(i, (prep, online, network))| SimParty {
            garbler: CopzGarbler::new(i as u16, n, prep),
            online,
            network,
        })
        .collect_vec();
    let report =
        full_simulation::<_, CopzEvaluator>(parties, &circuit, inputs.clone(), true, None, None)
            .unwrap();
    assert!(report.online_bytes > 0);

    let parties = secure_quic_parties(&circuit, n, None)
        .unwrap()
        .into_iter()
        .enumerate()
        .map(|(i, (prep, online, network))| SimParty {
            garbler: Wrk17Garbler::new(i as u16, n, prep),
            online,
            network,
        })
        .collect_vec();
    full_simulation::<_, Wrk17Evaluator>(parties, &circuit, inputs, true, None, None).unwrap();
}

#[test]
fn test_quic_cheating_is_detected() {
    let circuit = NamedCircuit::from_path("circuits/and2.txt");
    for cheat in [Cheat::EquivocateBroadcast, Cheat::LeakyAndFlipE] {
        let result = secure_quic_parties(&circuit, 3, Some((1, cheat)));
        assert!(
            matches!(result, Err(GcError::CheatDetected(_))),
            "{cheat:?}"
        );
    }
}

#[test]
fn test_quic_many_sessions_and_out_of_order_reads() {
    let config = QuicConfig {
        network: super::NetworkConfig {
            timeout: Duration::from_secs(3),
        },
        close_timeout: Duration::from_secs(1),
        ..Default::default()
    };
    let nets = quic_mesh_with(2, config, |_, certs| certs.to_vec())
        .into_iter()
        .map(Result::unwrap)
        .collect();
    run_all(nets, |net| {
        let peer = 1 - net.party_id();
        for i in 0..300 {
            let mut s = net.session(&format!("session {i}")).unwrap();
            s.send(peer, &[7]).unwrap();
            assert_eq!(s.recv(peer, 1).unwrap(), vec![7]);
        }
        let mut a = net.session("a").unwrap();
        let mut b = net.session("b").unwrap();
        b.send(peer, b"b").unwrap();
        a.send(peer, b"a").unwrap();
        assert_eq!(a.recv(peer, 1).unwrap(), b"a");
        assert_eq!(b.recv(peer, 1).unwrap(), b"b");
    });
}
