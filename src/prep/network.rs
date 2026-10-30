//! In-process point-to-point network used by the secure preprocessor.
//!
//! Every pair of parties is connected by a [Duplex] link that is backed by
//! unbounded channels, so writes never block and a party only blocks when
//! it waits for a message that has not arrived yet. When a party drops its
//! [PartyNet] (e.g., because it aborts), its peers observe a disconnection
//! instead of blocking forever.

use std::io::{Read, Write};
use std::sync::mpsc::{Receiver, Sender, channel};

use itertools::Itertools;
use rand::{CryptoRng, Rng};

use crate::error::GcError;

/// Writes are buffered until this many bytes are pending.
const MAX_WRITE_BUFFER: usize = 1 << 20;

/// Length of a commitment, see [commit].
pub(crate) const COMMITMENT_LEN: usize = 32;
/// Length of the randomness used in a commitment.
pub(crate) const NONCE_LEN: usize = 32;

/// One end of a bidirectional byte stream between two parties.
///
/// It implements [Read] and [Write] so that it can be used as a
/// [scuttlebutt::AbstractChannel] by the OT protocols.
pub(crate) struct Duplex {
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
    write_buf: Vec<u8>,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl Duplex {
    fn pair() -> (Self, Self) {
        let (tx_a, rx_b) = channel();
        let (tx_b, rx_a) = channel();
        let make = |tx, rx| Self {
            tx,
            rx,
            write_buf: vec![],
            read_buf: vec![],
            read_pos: 0,
        };
        (make(tx_a, rx_a), make(tx_b, rx_b))
    }
}

impl Read for Duplex {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.read_pos == self.read_buf.len() {
            // We are about to block, make sure the peer has everything we wrote.
            self.flush()?;
            self.read_buf = self.rx.recv().map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "peer disconnected")
            })?;
            self.read_pos = 0;
        }
        let n = buf.len().min(self.read_buf.len() - self.read_pos);
        buf[..n].copy_from_slice(&self.read_buf[self.read_pos..self.read_pos + n]);
        self.read_pos += n;
        Ok(n)
    }
}

impl Write for Duplex {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.write_buf.extend_from_slice(buf);
        if self.write_buf.len() >= MAX_WRITE_BUFFER {
            self.flush()?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if !self.write_buf.is_empty() {
            self.tx
                .send(std::mem::take(&mut self.write_buf))
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "peer disconnected")
                })?;
        }
        Ok(())
    }
}

/// The network view of a single party: one [Duplex] link to every other party.
pub(crate) struct PartyNet {
    party_id: u16,
    party_count: u16,
    /// `links[j]` connects to party `j`, it is `None` for `j == party_id`.
    links: Vec<Option<Duplex>>,
    /// Number of broadcasts so far, used for domain separation of the echo digests.
    broadcast_counter: u64,
}

impl PartyNet {
    /// Create a fully connected network for `party_count` parties.
    // indexing both links[i][j] and links[j][i] is clearer than iterators
    #[allow(clippy::needless_range_loop)]
    pub(crate) fn new_mesh(party_count: u16) -> Vec<Self> {
        let n = party_count as usize;
        let mut links: Vec<Vec<Option<Duplex>>> =
            (0..n).map(|_| (0..n).map(|_| None).collect()).collect();
        for i in 0..n {
            for j in i + 1..n {
                let (a, b) = Duplex::pair();
                links[i][j] = Some(a);
                links[j][i] = Some(b);
            }
        }
        links
            .into_iter()
            .enumerate()
            .map(|(i, links)| Self {
                party_id: i as u16,
                party_count,
                links,
                broadcast_counter: 0,
            })
            .collect()
    }

    pub(crate) fn peers(&self) -> impl Iterator<Item = u16> + use<> {
        let me = self.party_id;
        (0..self.party_count).filter(move |j| *j != me)
    }

    /// Mutable access to every link, used to run two-party protocols with all peers in parallel.
    pub(crate) fn links_mut(&mut self) -> impl Iterator<Item = (u16, &mut Duplex)> {
        self.links
            .iter_mut()
            .enumerate()
            .filter_map(|(j, link)| link.as_mut().map(|link| (j as u16, link)))
    }

    fn link(&mut self, peer: u16) -> Result<&mut Duplex, GcError> {
        debug_assert_ne!(peer, self.party_id, "no link to self");
        self.links[peer as usize]
            .as_mut()
            .ok_or_else(|| GcError::NetworkError("the network has been closed".to_string()))
    }

    /// Close all links, peers that wait for a message from us observe a disconnection.
    /// This must be called when a party aborts, otherwise the other parties might block.
    pub(crate) fn abort(&mut self) {
        self.links.iter_mut().for_each(|link| *link = None);
    }

    /// Send a length-prefixed message to `peer`.
    pub(crate) fn send(&mut self, peer: u16, msg: &[u8]) -> Result<(), GcError> {
        let link = self.link(peer)?;
        link.write_all(&(msg.len() as u64).to_le_bytes())
            .and_then(|_| link.write_all(msg))
            .and_then(|_| link.flush())
            .map_err(|e| GcError::NetworkError(format!("sending to party {peer}: {e}")))
    }

    /// Receive a frame, rejecting unexpected lengths before allocating its payload.
    pub(crate) fn recv_exact(&mut self, peer: u16, len: usize) -> Result<Vec<u8>, GcError> {
        let link = self.link(peer)?;
        let err = |e: std::io::Error| GcError::NetworkError(format!("receiving from {peer}: {e}"));
        let mut len_buf = [0u8; 8];
        link.read_exact(&mut len_buf).map_err(err)?;
        let claimed_len = u64::from_le_bytes(len_buf);
        if claimed_len != len as u64 {
            return Err(GcError::NetworkError(format!(
                "expected {len} bytes from party {peer} but got frame length {claimed_len}"
            )));
        }
        let mut msg = vec![0u8; len];
        link.read_exact(&mut msg).map_err(err)?;
        Ok(msg)
    }

    /// Send `msgs[j]` to every peer `j`, then receive one message of length `len` from every peer.
    /// The output is indexed by party, the entry of the caller is empty.
    pub(crate) fn exchange(
        &mut self,
        msgs: &[Vec<u8>],
        len: usize,
    ) -> Result<Vec<Vec<u8>>, GcError> {
        for peer in self.peers() {
            self.send(peer, &msgs[peer as usize])?;
        }
        let mut out = vec![vec![]; self.party_count as usize];
        for peer in self.peers() {
            out[peer as usize] = self.recv_exact(peer, len)?;
        }
        Ok(out)
    }

    /// Broadcast with abort (echo broadcast).
    ///
    /// Every party sends `msg` to all other parties and then all parties compare
    /// a digest of everything they received in this round. If a party sent different
    /// messages to different honest parties, the honest parties abort.
    ///
    /// The output is indexed by party, including the caller's own message.
    pub(crate) fn broadcast(&mut self, msg: &[u8], len: usize) -> Result<Vec<Vec<u8>>, GcError> {
        self.broadcast_with(msg, |_| msg.to_vec(), len)
    }

    /// Same as [Self::broadcast] but `msg_for(j)` is sent to party `j`.
    /// This is only useful for simulating an equivocating party in tests.
    pub(crate) fn broadcast_with(
        &mut self,
        msg: &[u8],
        msg_for: impl Fn(u16) -> Vec<u8>,
        len: usize,
    ) -> Result<Vec<Vec<u8>>, GcError> {
        debug_assert_eq!(msg.len(), len);
        let to_send = (0..self.party_count).map(&msg_for).collect_vec();
        let mut received = self.exchange(&to_send, len)?;
        received[self.party_id as usize] = msg.to_vec();

        // Echo round
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ECHO_BROADCAST");
        hasher.update(&self.broadcast_counter.to_le_bytes());
        for m in &received {
            hasher.update(&(m.len() as u64).to_le_bytes());
            hasher.update(m);
        }
        self.broadcast_counter += 1;
        let digest = hasher.finalize();
        let digests = self.exchange(
            &vec![digest.as_bytes().to_vec(); self.party_count as usize],
            blake3::OUT_LEN,
        )?;
        for peer in self.peers() {
            if digests[peer as usize] != digest.as_bytes() {
                return Err(GcError::CheatDetected(format!(
                    "inconsistent broadcast detected with party {peer}"
                )));
            }
        }
        Ok(received)
    }

    /// Jointly sample a public random seed using commit-and-open.
    ///
    /// If `bad_opening` is set, this party opens its commitment to a different value
    /// (only used to simulate a cheating party in tests).
    pub(crate) fn coin_toss<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
        bad_opening: bool,
    ) -> Result<[u8; 32], GcError> {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let (com, nonce) = commit(rng, &seed);
        let coms = self.broadcast(&com, COMMITMENT_LEN)?;

        if bad_opening {
            seed[0] ^= 1;
        }
        let opening = [seed.as_slice(), nonce.as_slice()].concat();
        let openings = self.broadcast(&opening, opening.len())?;

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"COIN_TOSS");
        for (party, (com, opening)) in coms.iter().zip(&openings).enumerate() {
            let (seed, nonce) = opening.split_at(32);
            if !verify_commitment(com, seed, nonce) {
                return Err(GcError::CheatDetected(format!(
                    "party {party} opened coin toss commitment incorrectly"
                )));
            }
            hasher.update(seed);
        }
        Ok(*hasher.finalize().as_bytes())
    }
}

/// Commit to `msg`, returns the commitment and the opening randomness.
pub(crate) fn commit<R: Rng + CryptoRng>(
    rng: &mut R,
    msg: &[u8],
) -> ([u8; COMMITMENT_LEN], [u8; NONCE_LEN]) {
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    (commitment(msg, &nonce), nonce)
}

pub(crate) fn verify_commitment(com: &[u8], msg: &[u8], nonce: &[u8]) -> bool {
    commitment(msg, nonce).as_slice() == com
}

fn commitment(msg: &[u8], nonce: &[u8]) -> [u8; COMMITMENT_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"COMMITMENT");
    hasher.update(nonce);
    hasher.update(msg);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use scuttlebutt::AesRng;

    use super::*;

    #[test]
    fn test_reject_frame_length_before_reading_payload() {
        for claimed_len in [0u64, 2, 1 << 32, u64::MAX] {
            let mut nets = PartyNet::new_mesh(2);
            let mut receiver = nets.pop().unwrap();
            let mut sender = nets.pop().unwrap();
            sender
                .link(1)
                .unwrap()
                .write_all(&claimed_len.to_le_bytes())
                .unwrap();
            sender.link(1).unwrap().flush().unwrap();
            // No payload follows. A wrong length must be rejected without reading it.
            assert!(matches!(
                receiver.recv_exact(0, 1),
                Err(GcError::NetworkError(_))
            ));
        }
    }

    fn run_all<T: Send>(nets: Vec<PartyNet>, f: impl Fn(PartyNet) -> T + Sync) -> Vec<T> {
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
    fn test_broadcast() {
        let outputs = run_all(PartyNet::new_mesh(4), |mut net| {
            let msg = vec![net.party_id as u8; 3];
            net.broadcast(&msg, 3).unwrap()
        });
        for out in outputs {
            assert_eq!(out, (0..4u8).map(|i| vec![i; 3]).collect_vec());
        }
    }

    #[test]
    fn test_broadcast_equivocation() {
        let outputs = run_all(PartyNet::new_mesh(3), |mut net| {
            let msg = vec![1u8; 3];
            if net.party_id == 0 {
                // send a different message to party 2
                net.broadcast_with(
                    &msg,
                    |j| if j == 2 { vec![2u8; 3] } else { vec![1u8; 3] },
                    3,
                )
            } else {
                net.broadcast(&msg, 3)
            }
        });
        // the honest parties must abort
        assert!(matches!(outputs[1], Err(GcError::CheatDetected(_))));
        assert!(matches!(outputs[2], Err(GcError::CheatDetected(_))));
    }

    #[test]
    fn test_coin_toss() {
        let outputs = run_all(PartyNet::new_mesh(3), |mut net| {
            let mut rng = AesRng::new();
            net.coin_toss(&mut rng, false).unwrap()
        });
        assert!(outputs.iter().all_equal());

        let outputs = run_all(PartyNet::new_mesh(3), |mut net| {
            let mut rng = AesRng::new();
            let cheat = net.party_id == 1;
            net.coin_toss(&mut rng, cheat)
        });
        assert!(matches!(outputs[0], Err(GcError::CheatDetected(_))));
        assert!(matches!(outputs[2], Err(GcError::CheatDetected(_))));
    }

    #[test]
    fn test_abort() {
        let outputs = run_all(PartyNet::new_mesh(3), |mut net| {
            if net.party_id == 0 {
                // abort but keep the network object alive
                net.abort();
                let res = net.broadcast(&[0u8], 1);
                assert!(matches!(res, Err(GcError::NetworkError(_))));
                std::mem::forget(net);
                Ok(vec![])
            } else {
                net.broadcast(&[0u8], 1)
            }
        });
        assert!(matches!(outputs[1], Err(GcError::NetworkError(_))));
        assert!(matches!(outputs[2], Err(GcError::NetworkError(_))));
    }

    #[test]
    fn test_disconnect() {
        let outputs = run_all(PartyNet::new_mesh(3), |mut net| {
            if net.party_id == 0 {
                // abort immediately
                drop(net);
                Ok(vec![])
            } else {
                net.broadcast(&[0u8], 1)
            }
        });
        assert!(matches!(outputs[1], Err(GcError::NetworkError(_))));
        assert!(matches!(outputs[2], Err(GcError::NetworkError(_))));
    }
}
