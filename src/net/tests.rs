use std::time::{Duration, Instant};

use itertools::Itertools;
use ocelot::ot::{
    FixedKeyInitializer, KosDeltaReceiver, KosDeltaSender, RandomReceiver, RandomSender,
    Receiver as OtReceiver,
};
use scuttlebutt::{AesRng, Block};

use super::{
    NetError, Network, NetworkConfig, PartyId, StreamId,
    inbox::Inbox,
    memory::{LinkModel, mesh},
};

/// (peer, keys as OT sender, MACs as OT receiver)
type OtResult = (PartyId, Vec<(Block, Block)>, Vec<Block>);

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

fn default_mesh(n: u16) -> Vec<Network> {
    mesh(n, LinkModel::default(), NetworkConfig::default()).unwrap()
}

#[test]
fn test_network_new_validates_links() {
    let config = NetworkConfig::default();
    assert!(mesh(1, LinkModel::default(), config).is_err());
    assert!(Network::new(0, vec![None], config).is_err());
    assert!(Network::new(2, vec![None, None], config).is_err());
    // the own link must be missing and all others present
    assert!(Network::new(0, vec![None, None], config).is_err());
}

#[test]
fn test_sessions_are_isolated() {
    let outputs = run_all(default_mesh(2), |net| {
        let mut a = net.session("a").unwrap();
        let mut b = net.session("b").unwrap();
        if net.party_id() == 0 {
            b.send(1, b"from b").unwrap();
            a.send(1, b"from a").unwrap();
            a.send(1, b"second").unwrap();
            vec![]
        } else {
            // receive in the opposite order of sending
            vec![
                a.recv(0, 6).unwrap(),
                b.recv(0, 6).unwrap(),
                a.recv(0, 6).unwrap(),
            ]
        }
    });
    assert_eq!(
        outputs[1],
        vec![b"from a".to_vec(), b"from b".to_vec(), b"second".to_vec()]
    );
}

#[test]
fn test_duplicate_sessions_are_rejected() {
    let net = default_mesh(2).remove(0);
    let root = net.session("root").unwrap();
    assert!(matches!(
        net.session("root"),
        Err(NetError::DuplicateSession(_))
    ));
    let _child = root.child("child").unwrap();
    assert!(matches!(
        root.child("child"),
        Err(NetError::DuplicateSession(_))
    ));
    // the same label under a different parent is a different session
    let other = net.session("other").unwrap();
    assert!(other.child("child").is_ok());
    assert_ne!(root.sid(), other.sid());
}

#[test]
fn test_exchange_and_broadcast() {
    let outputs = run_all(default_mesh(4), |net| {
        let me = net.party_id();
        let mut s = net.session("s").unwrap();
        let msgs = (0..4u8).map(|j| vec![me as u8, j]).collect_vec();
        let exchanged = s.exchange(&msgs, 2).unwrap();
        let all = s.broadcast_all(&[me as u8; 3]).unwrap();
        let from = s
            .broadcast_from(2, (me == 2).then_some(b"hello".as_slice()), 5)
            .unwrap();
        (exchanged, all, from)
    });
    for (me, (exchanged, all, from)) in outputs.into_iter().enumerate() {
        for j in 0..4 {
            if j == me {
                assert!(exchanged[j].is_empty());
            } else {
                assert_eq!(exchanged[j], vec![j as u8, me as u8]);
            }
            assert_eq!(all[j], vec![j as u8; 3]);
        }
        assert_eq!(from, b"hello");
    }
}

#[test]
fn test_broadcast_all_equivocation() {
    let outputs = run_all(default_mesh(3), |net| {
        let mut s = net.session("s").unwrap();
        if net.party_id() == 0 {
            s.broadcast_all_with(&[1], |j| if j == 2 { vec![2] } else { vec![1] })
        } else {
            s.broadcast_all(&[1])
        }
    });
    assert!(matches!(outputs[1], Err(NetError::CheatDetected(_))));
    assert!(matches!(outputs[2], Err(NetError::CheatDetected(_))));
}

#[test]
fn test_broadcast_from_equivocation() {
    let outputs = run_all(default_mesh(3), |net| {
        let mut s = net.session("s").unwrap();
        if net.party_id() == 0 {
            // a malicious sender sends different messages and arbitrary digests
            s.send(1, b"aaa").unwrap();
            s.send(2, b"bbb").unwrap();
            let _ = s.exchange(&vec![vec![0u8; 32]; 3], 32);
            Ok(vec![])
        } else {
            s.broadcast_from(0, None, 3)
        }
    });
    assert!(matches!(outputs[1], Err(NetError::CheatDetected(_))));
    assert!(matches!(outputs[2], Err(NetError::CheatDetected(_))));
}

#[test]
fn test_broadcast_from_misuse() {
    let net = default_mesh(2).remove(0);
    let mut s = net.session("s").unwrap();
    assert!(matches!(
        s.broadcast_from(5, None, 1),
        Err(NetError::Config(_))
    ));
    // errors abort the network, so later operations fail
    assert!(s.send(1, b"x").is_err());
}

#[test]
fn test_wrong_length_aborts() {
    let outputs = run_all(default_mesh(2), |net| {
        let mut s = net.session("s").unwrap();
        if net.party_id() == 0 {
            s.send(1, b"too long").unwrap();
            s.recv(1, 1)
        } else {
            s.recv(0, 3)
        }
    });
    assert!(matches!(
        outputs[1],
        Err(NetError::UnexpectedLength {
            party: 0,
            expected: 3,
            received: 8
        })
    ));
    assert!(matches!(
        outputs[0],
        Err(NetError::PeerAborted { party: 1, .. })
    ));
}

#[test]
fn test_coin() {
    let outputs = run_all(default_mesh(3), |net| {
        let mut s = net.session("s").unwrap();
        let mut rng = AesRng::new();
        (s.coin(&mut rng).unwrap(), s.coin(&mut rng).unwrap())
    });
    assert!(outputs.iter().all_equal());
    assert_ne!(outputs[0].0, outputs[0].1);

    let outputs = run_all(default_mesh(3), |net| {
        let mut s = net.session("s").unwrap();
        let mut rng = AesRng::new();
        s.coin_with(&mut rng, net.party_id() == 1)
    });
    assert!(matches!(outputs[0], Err(NetError::CheatDetected(_))));
    assert!(matches!(outputs[2], Err(NetError::CheatDetected(_))));
}

#[test]
fn test_commitments_are_bound_to_sessions() {
    let net = default_mesh(2).remove(0);
    let a = net.session("a").unwrap();
    let b = net.session("b").unwrap();
    let mut rng = AesRng::new();
    let (com, nonce) = a.commit(&mut rng, b"msg");
    assert!(a.verify_commitment(&com, b"msg", &nonce));
    assert!(!a.verify_commitment(&com, b"other", &nonce));
    assert!(!b.verify_commitment(&com, b"msg", &nonce));
    assert!(!a.verify_commitment(&com[..31], b"msg", &nonce));
}

#[test]
fn test_abort_propagates_with_reason() {
    let outputs = run_all(default_mesh(3), |net| {
        let mut s = net.session("s").unwrap();
        if net.party_id() == 0 {
            s.abort("bad things");
            // our own operations fail after aborting
            assert!(matches!(s.send(1, b"x"), Err(NetError::Closed(_))));
            assert!(matches!(s.recv(1, 1), Err(NetError::Closed(_))));
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
fn test_close_delivers_queued_frames() {
    let outputs = run_all(default_mesh(2), |net| {
        let mut s = net.session("s").unwrap();
        if net.party_id() == 0 {
            s.send(1, b"last").unwrap();
            drop(s);
            drop(net);
            Ok(vec![])
        } else {
            // give the peer time to close
            std::thread::sleep(Duration::from_millis(50));
            let last = s.recv(0, 4).unwrap();
            assert_eq!(last, b"last");
            s.recv(0, 4)
        }
    });
    assert!(matches!(outputs[1], Err(NetError::Disconnected(0))));
}

#[test]
fn test_timeout() {
    let config = NetworkConfig {
        timeout: Duration::from_millis(100),
    };
    let mut nets = mesh(2, LinkModel::default(), config).unwrap();
    let _silent = nets.remove(0);
    let net = nets.remove(0);
    let mut s = net.session("s").unwrap();
    let start = Instant::now();
    assert!(matches!(s.recv(0, 1), Err(NetError::Timeout(0))));
    assert!(start.elapsed() >= Duration::from_millis(100));
}

#[test]
fn test_invalid_peer() {
    let net = default_mesh(2).remove(0);
    let mut s = net.session("s").unwrap();
    assert!(matches!(s.send(0, b"x"), Err(NetError::Config(_))));
}

#[test]
fn test_link_model() {
    let latency = Duration::from_millis(50);
    let nets = mesh(
        2,
        LinkModel {
            latency,
            bandwidth: Some(10_000_000),
        },
        NetworkConfig::default(),
    )
    .unwrap();
    let outputs = run_all(nets, |net| {
        let mut s = net.session("s").unwrap();
        let start = Instant::now();
        // two rounds of exchanging 1 MB, each takes 100 ms + 50 ms
        for _ in 0..2 {
            let msgs = vec![vec![0u8; 1_000_000]; 2];
            s.exchange(&msgs, 1_000_000).unwrap();
        }
        start.elapsed()
    });
    for elapsed in outputs {
        assert!(elapsed >= Duration::from_millis(300), "{elapsed:?}");
        assert!(elapsed < Duration::from_millis(2000), "{elapsed:?}");
    }
}

#[test]
fn test_stats() {
    let outputs = run_all(default_mesh(2), |net| {
        let mut s = net.session("prep").unwrap();
        let mut c = s.child("c").unwrap();
        let _other = net.session("online").unwrap();
        assert!(net.session("online").is_err());
        let peer = 1 - net.party_id();
        s.send(peer, &[0u8; 10]).unwrap();
        c.send(peer, &[0u8; 5]).unwrap();
        s.recv(peer, 10).unwrap();
        c.recv(peer, 5).unwrap();
        net.stats()
    });
    for stats in outputs {
        assert_eq!(stats.len(), 2);
        assert_eq!(stats[0].0, "prep");
        assert_eq!(stats[0].1.bytes_sent, 15);
        assert_eq!(stats[0].1.bytes_received, 15);
        assert_eq!(stats[0].1.frames_sent, 2);
        assert_eq!(stats[1].0, "online");
        assert_eq!(stats[1].1.bytes_sent, 0);
    }
}

#[test]
fn test_pairwise_channels_with_ot() {
    let outputs = run_all(default_mesh(3), |net| {
        let me = net.party_id();
        let mut s = net.session("s").unwrap();
        let channels = s.pairwise_channels().unwrap();
        // messages on the session do not interfere with the channels
        let msgs = vec![vec![me as u8]; 3];
        let exchanged = s.exchange(&msgs, 1).unwrap();
        let delta = [me as u8 + 1; 16];
        let bits = vec![true, false, true, true];
        let results: Vec<OtResult> = std::thread::scope(|sc| {
            let handles = channels
                .into_iter()
                .map(|(peer, mut channel)| {
                    let bits = bits.clone();
                    sc.spawn(move || {
                        let mut rng = AesRng::new();
                        if me < peer {
                            let mut sender =
                                KosDeltaSender::init_fixed_key(&mut channel, delta, &mut rng)
                                    .unwrap();
                            let mut receiver =
                                KosDeltaReceiver::init(&mut channel, &mut rng).unwrap();
                            let keys = sender.send_random(&mut channel, 4, &mut rng).unwrap();
                            let macs = receiver
                                .receive_random(&mut channel, &bits, &mut rng)
                                .unwrap();
                            (peer, keys, macs)
                        } else {
                            let mut receiver =
                                KosDeltaReceiver::init(&mut channel, &mut rng).unwrap();
                            let mut sender =
                                KosDeltaSender::init_fixed_key(&mut channel, delta, &mut rng)
                                    .unwrap();
                            let macs = receiver
                                .receive_random(&mut channel, &bits, &mut rng)
                                .unwrap();
                            let keys = sender.send_random(&mut channel, 4, &mut rng).unwrap();
                            (peer, keys, macs)
                        }
                    })
                })
                .collect_vec();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        (exchanged, results)
    });
    for (me, (exchanged, results)) in outputs.iter().enumerate() {
        for (peer, keys, macs) in results {
            assert_eq!(exchanged[*peer as usize], vec![*peer as u8]);
            // our keys correlate with the peer's MACs
            let (_, _, peer_macs) = outputs[*peer as usize]
                .1
                .iter()
                .find(|(p, _, _)| *p as usize == me)
                .unwrap();
            let delta = Block::from(u128::from_le_bytes([me as u8 + 1; 16]));
            for (i, (k0, k1)) in keys.iter().enumerate() {
                assert_eq!(*k1, *k0 ^ delta);
                let expected = if i == 1 { *k0 } else { *k1 };
                assert_eq!(peer_macs[i], expected);
            }
            assert_eq!(macs.len(), 4);
        }
    }
}

#[test]
fn test_pairwise_channels_only_once() {
    let net = default_mesh(2).remove(0);
    let mut s = net.session("s").unwrap();
    let _channels = s.pairwise_channels().unwrap();
    assert!(matches!(
        s.pairwise_channels(),
        Err(NetError::DuplicateSession(_))
    ));
    // like every other error, this aborts the network
    assert!(matches!(s.send(1, b"x"), Err(NetError::Closed(_))));
}

#[test]
fn test_inbox_buffer_limit() {
    let inbox = Inbox::new(7, 10);
    let stream = StreamId([0; 16]);
    let now = Instant::now();
    inbox.push(stream, now, vec![0; 6]).unwrap();
    assert!(matches!(
        inbox.push(stream, now, vec![0; 6]),
        Err(NetError::BufferLimit(7))
    ));
    // the receiver observes the violation instead of the buffered frames
    assert!(matches!(
        inbox.pop(stream, now + Duration::from_secs(1)),
        Err(NetError::BufferLimit(7))
    ));
}
