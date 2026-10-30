//! Sessions: isolated streams with the message primitives used by the protocols.

use std::sync::Arc;

use rand::{CryptoRng, Rng};
use scuttlebutt::AbstractChannel;

use super::{
    NetError, NetInner, PartyId, StatsCell, StreamId,
    wire::{PerParty, Wire},
};

/// Length of a commitment, see [Session::commit].
pub const COMMITMENT_LEN: usize = 32;
/// Length of the opening randomness of a commitment.
pub const NONCE_LEN: usize = 32;

pub type Commitment = [u8; COMMITMENT_LEN];
pub type Nonce = [u8; NONCE_LEN];
/// Output of [Session::coin].
pub type Seed = [u8; 32];

/// [ByteChannel] sends a frame once this many bytes are buffered.
const MAX_CHANNEL_BUFFER: usize = 1 << 20;

/// A named stream on all links of a party.
///
/// Messages of different sessions never mix, within a session the messages from
/// a peer are received in the order they were sent. Every party must create the
/// same sessions (by label) for the same purpose.
///
/// Every error aborts the whole network of this party, so a failed operation
/// cannot be retried and the protocol must stop.
pub struct Session {
    net: Arc<NetInner>,
    label: String,
    sid: [u8; 32],
    stream: StreamId,
    stats: Arc<StatsCell>,
    /// Number of broadcasts so far, used for domain separation of the echo digests.
    broadcast_counter: u64,
}

fn derive_sid(parent: Option<&[u8; 32]>, label: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("multiparty-gc session id v1");
    match parent {
        Some(parent) => {
            hasher.update(b"child");
            hasher.update(parent);
        }
        None => {
            hasher.update(b"root");
        }
    }
    hasher.update(&(label.len() as u64).to_le_bytes());
    hasher.update(label.as_bytes());
    *hasher.finalize().as_bytes()
}

fn stream_of(sid: &[u8; 32]) -> StreamId {
    StreamId(sid[..16].try_into().unwrap())
}

impl Session {
    pub(crate) fn root(
        net: Arc<NetInner>,
        label: &str,
        stats: Arc<StatsCell>,
    ) -> Result<Self, NetError> {
        Self::new(net, None, label.to_string(), label, stats)
    }

    fn new(
        net: Arc<NetInner>,
        parent: Option<&[u8; 32]>,
        path: String,
        label: &str,
        stats: Arc<StatsCell>,
    ) -> Result<Self, NetError> {
        let sid = derive_sid(parent, label);
        net.claim(sid, &path)?;
        Ok(Self {
            net,
            label: path,
            stream: stream_of(&sid),
            sid,
            stats,
            broadcast_counter: 0,
        })
    }

    pub fn party_id(&self) -> PartyId {
        self.net.party_id
    }

    pub fn party_count(&self) -> u16 {
        self.net.party_count
    }

    /// All parties except ourselves.
    pub fn peers(&self) -> impl Iterator<Item = PartyId> + use<> {
        let me = self.party_id();
        (0..self.party_count()).filter(move |j| *j != me)
    }

    /// The session ID, it is unique per session and should be used for domain separation.
    pub fn sid(&self) -> &[u8; 32] {
        &self.sid
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    /// Create a sub-session, each label can only be used once per session.
    pub fn child(&self, label: &str) -> Result<Session, NetError> {
        Session::new(
            self.net.clone(),
            Some(&self.sid),
            format!("{}/{label}", self.label),
            label,
            self.stats.clone(),
        )
    }

    /// Abort the network of this party, all peers observe [NetError::PeerAborted].
    pub fn abort(&self, reason: &str) {
        self.net.abort(reason);
    }

    /// Abort the network if `result` is an error.
    fn check<T>(&self, result: Result<T, NetError>) -> Result<T, NetError> {
        if let Err(err) = &result {
            self.net.abort(&format!("{}: {err}", self.label));
        }
        result
    }

    fn check_peer(&self, peer: PartyId) -> Result<(), NetError> {
        if peer == self.party_id() || peer >= self.party_count() {
            return Err(NetError::Config(format!("invalid peer {peer}")));
        }
        Ok(())
    }

    fn send_raw(&self, to: PartyId, msg: Vec<u8>) -> Result<(), NetError> {
        self.check_peer(to)?;
        self.stats.record_send(msg.len());
        self.net.link(to).send(self.stream, msg)
    }

    fn recv_raw(&self, from: PartyId, len: usize) -> Result<Vec<u8>, NetError> {
        self.check_peer(from)?;
        let msg = self.net.link(from).recv(self.stream, self.net.deadline())?;
        self.stats.record_recv(msg.len());
        if msg.len() != len {
            return Err(NetError::UnexpectedLength {
                party: from,
                expected: len,
                received: msg.len(),
            });
        }
        Ok(msg)
    }

    /// Send `msg` to `to`.
    pub fn send(&mut self, to: PartyId, msg: &[u8]) -> Result<(), NetError> {
        let result = self.send_raw(to, msg.to_vec());
        self.check(result)
    }

    /// Receive the next message from `from`, which must have length `len`.
    pub fn recv(&mut self, from: PartyId, len: usize) -> Result<Vec<u8>, NetError> {
        let result = self.recv_raw(from, len);
        self.check(result)
    }

    /// Send `msgs[j]` to every peer `j` and receive a message of length `len` from every peer.
    /// The output is indexed by party, the entry of the caller is empty.
    pub fn exchange(&mut self, msgs: &[Vec<u8>], len: usize) -> Result<Vec<Vec<u8>>, NetError> {
        let result = self.exchange_inner(msgs, len);
        self.check(result)
    }

    fn exchange_inner(&self, msgs: &[Vec<u8>], len: usize) -> Result<Vec<Vec<u8>>, NetError> {
        if msgs.len() != self.party_count() as usize {
            return Err(NetError::Config("one message per party expected".into()));
        }
        for peer in self.peers() {
            self.send_raw(peer, msgs[peer as usize].clone())?;
        }
        let mut out = vec![vec![]; self.party_count() as usize];
        for peer in self.peers() {
            out[peer as usize] = self.recv_raw(peer, len)?;
        }
        Ok(out)
    }

    /// Every party broadcasts a message of the same length (echo broadcast with abort).
    ///
    /// After receiving, all parties compare a digest of everything they received.
    /// If a party sent different messages to different honest parties, the honest
    /// parties abort. The output is indexed by party and includes our own message.
    pub fn broadcast_all(&mut self, msg: &[u8]) -> Result<Vec<Vec<u8>>, NetError> {
        let result = self.broadcast_all_inner(msg, |_| msg.to_vec());
        self.check(result)
    }

    /// Same as [Self::broadcast_all] but `msg_for(j)` is sent to party `j`.
    /// This is only useful to simulate an equivocating party in tests.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn broadcast_all_with(
        &mut self,
        msg: &[u8],
        msg_for: impl Fn(PartyId) -> Vec<u8>,
    ) -> Result<Vec<Vec<u8>>, NetError> {
        let result = self.broadcast_all_inner(msg, msg_for);
        self.check(result)
    }

    fn broadcast_all_inner(
        &mut self,
        msg: &[u8],
        msg_for: impl Fn(PartyId) -> Vec<u8>,
    ) -> Result<Vec<Vec<u8>>, NetError> {
        let to_send = (0..self.party_count()).map(&msg_for).collect::<Vec<_>>();
        let mut received = self.exchange_inner(&to_send, msg.len())?;
        received[self.party_id() as usize] = msg.to_vec();

        let mut hasher = self.echo_hasher(b"all");
        for m in &received {
            hasher.update(m);
        }
        self.echo(hasher)?;
        Ok(received)
    }

    /// `sender` broadcasts a message of length `len` (echo broadcast with abort).
    ///
    /// The sender passes `Some(msg)`, all other parties pass `None`. All parties
    /// output the message, or abort if the sender sent different messages to
    /// different honest parties.
    pub fn broadcast_from(
        &mut self,
        sender: PartyId,
        msg: Option<&[u8]>,
        len: usize,
    ) -> Result<Vec<u8>, NetError> {
        let result = self.broadcast_from_inner(sender, msg, len);
        self.check(result)
    }

    fn broadcast_from_inner(
        &mut self,
        sender: PartyId,
        msg: Option<&[u8]>,
        len: usize,
    ) -> Result<Vec<u8>, NetError> {
        if sender >= self.party_count() {
            return Err(NetError::Config(format!("invalid sender {sender}")));
        }
        let msg = if sender == self.party_id() {
            let msg = msg.ok_or_else(|| NetError::Config("the sender needs a message".into()))?;
            if msg.len() != len {
                return Err(NetError::Config("wrong message length".into()));
            }
            for peer in self.peers() {
                self.send_raw(peer, msg.to_vec())?;
            }
            msg.to_vec()
        } else {
            if msg.is_some() {
                return Err(NetError::Config("only the sender has a message".into()));
            }
            self.recv_raw(sender, len)?
        };

        let mut hasher = self.echo_hasher(b"from");
        hasher.update(&sender.to_le_bytes());
        hasher.update(&msg);
        self.echo(hasher)?;
        Ok(msg)
    }

    fn echo_hasher(&mut self, kind: &[u8]) -> blake3::Hasher {
        let mut hasher = blake3::Hasher::new_derive_key("multiparty-gc echo broadcast v1");
        hasher.update(&self.sid);
        hasher.update(&self.broadcast_counter.to_le_bytes());
        hasher.update(kind);
        self.broadcast_counter += 1;
        hasher
    }

    /// Exchange digests and abort if any differs from ours.
    fn echo(&self, hasher: blake3::Hasher) -> Result<(), NetError> {
        let digest = hasher.finalize();
        let digests = self.exchange_inner(
            &vec![digest.as_bytes().to_vec(); self.party_count() as usize],
            blake3::OUT_LEN,
        )?;
        for peer in self.peers() {
            if digests[peer as usize] != digest.as_bytes() {
                return Err(NetError::CheatDetected(format!(
                    "inconsistent broadcast detected with party {peer}"
                )));
            }
        }
        Ok(())
    }

    /// Commit to `msg`, the commitment is bound to this session.
    pub fn commit<R: Rng + CryptoRng>(&self, rng: &mut R, msg: &[u8]) -> (Commitment, Nonce) {
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        (self.commitment(msg, &nonce), nonce)
    }

    /// Check that `com` is a commitment to `msg` with randomness `nonce` in this session.
    pub fn verify_commitment(&self, com: &[u8], msg: &[u8], nonce: &[u8]) -> bool {
        com.len() == COMMITMENT_LEN
            && nonce.len() == NONCE_LEN
            && self.commitment(msg, nonce).as_slice() == com
    }

    fn commitment(&self, msg: &[u8], nonce: &[u8]) -> Commitment {
        let mut hasher = blake3::Hasher::new_derive_key("multiparty-gc commitment v1");
        hasher.update(&self.sid);
        hasher.update(nonce);
        hasher.update(msg);
        *hasher.finalize().as_bytes()
    }

    /// Jointly sample a public random seed (commit-and-open coin tossing).
    pub fn coin<R: Rng + CryptoRng>(&mut self, rng: &mut R) -> Result<Seed, NetError> {
        self.coin_with(rng, false)
    }

    /// Same as [Self::coin], but if `bad_opening` is set, we open our commitment
    /// to a different value. This is only useful to simulate cheating in tests.
    pub(crate) fn coin_with<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
        bad_opening: bool,
    ) -> Result<Seed, NetError> {
        let result = self.coin_inner(rng, bad_opening);
        self.check(result)
    }

    fn coin_inner<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
        bad_opening: bool,
    ) -> Result<Seed, NetError> {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let (com, nonce) = self.commit(rng, &seed);
        let coms = self.broadcast_all_inner(&com, |_| com.to_vec())?;

        if bad_opening {
            seed[0] ^= 1;
        }
        let opening = [seed.as_slice(), nonce.as_slice()].concat();
        let openings = self.broadcast_all_inner(&opening, |_| opening.clone())?;

        let mut hasher = blake3::Hasher::new_derive_key("multiparty-gc coin toss v1");
        hasher.update(&self.sid);
        hasher.update(&self.broadcast_counter.to_le_bytes());
        for (party, (com, opening)) in coms.iter().zip(&openings).enumerate() {
            let (seed, nonce) = opening.split_at(32);
            if !self.verify_commitment(com, seed, nonce) {
                return Err(NetError::CheatDetected(format!(
                    "party {party} opened a coin tossing commitment incorrectly"
                )));
            }
            hasher.update(seed);
        }
        Ok(*hasher.finalize().as_bytes())
    }

    /// Send a typed message to `to`.
    pub fn send_msg<T: Wire>(&mut self, to: PartyId, msg: &T) -> Result<(), NetError> {
        let result = self.send_raw(to, msg.to_wire_bytes());
        self.check(result)
    }

    /// Receive a typed message of the given shape from `from`.
    pub fn recv_msg<T: Wire>(&mut self, from: PartyId, shape: &T::Shape) -> Result<T, NetError> {
        let result = self
            .recv_raw(from, T::encoded_len(shape))
            .and_then(|bytes| decode_from(from, &bytes, shape));
        self.check(result)
    }

    /// Send `msg_for(j)` to every peer `j` and receive a message of the given shape from
    /// every peer.
    pub fn exchange_msg<T: Wire>(
        &mut self,
        mut msg_for: impl FnMut(PartyId) -> T,
        shape: &T::Shape,
    ) -> Result<PerParty<T>, NetError> {
        let msgs = (0..self.party_count())
            .map(|j| {
                if j == self.party_id() {
                    vec![]
                } else {
                    msg_for(j).to_wire_bytes()
                }
            })
            .collect::<Vec<_>>();
        let result = self
            .exchange_inner(&msgs, T::encoded_len(shape))
            .and_then(|received| self.decode_all(received, shape, false));
        let items = self.check(result)?;
        Ok(PerParty::new(self.party_id(), items))
    }

    /// Typed version of [Self::broadcast_all], the output includes our own message.
    pub fn broadcast_all_msg<T: Wire>(
        &mut self,
        msg: &T,
        shape: &T::Shape,
    ) -> Result<Vec<T>, NetError> {
        let bytes = msg.to_wire_bytes();
        let result = self.broadcast_all_typed(&bytes, |_| bytes.clone(), shape);
        self.check(result)
    }

    /// Typed version of [Self::broadcast_all_with], only useful in tests.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn broadcast_all_msg_with<T: Wire>(
        &mut self,
        msg: &T,
        msg_for: impl Fn(PartyId) -> T,
        shape: &T::Shape,
    ) -> Result<Vec<T>, NetError> {
        let bytes = msg.to_wire_bytes();
        let result = self.broadcast_all_typed(&bytes, |j| msg_for(j).to_wire_bytes(), shape);
        self.check(result)
    }

    fn broadcast_all_typed<T: Wire>(
        &mut self,
        bytes: &[u8],
        msg_for: impl Fn(PartyId) -> Vec<u8>,
        shape: &T::Shape,
    ) -> Result<Vec<T>, NetError> {
        if bytes.len() != T::encoded_len(shape) {
            return Err(NetError::Config("message does not match its shape".into()));
        }
        let received = self.broadcast_all_inner(bytes, msg_for)?;
        Ok(self
            .decode_all(received, shape, true)?
            .into_iter()
            .map(|x| x.expect("all messages are present"))
            .collect())
    }

    /// Typed version of [Self::broadcast_from].
    pub fn broadcast_from_msg<T: Wire>(
        &mut self,
        sender: PartyId,
        msg: Option<&T>,
        shape: &T::Shape,
    ) -> Result<T, NetError> {
        let bytes = msg.map(|msg| msg.to_wire_bytes());
        let result = self
            .broadcast_from_inner(sender, bytes.as_deref(), T::encoded_len(shape))
            .and_then(|bytes| decode_from(sender, &bytes, shape));
        self.check(result)
    }

    /// Decode the messages of all peers, and our own if `include_self` is set.
    fn decode_all<T: Wire>(
        &self,
        received: Vec<Vec<u8>>,
        shape: &T::Shape,
        include_self: bool,
    ) -> Result<Vec<Option<T>>, NetError> {
        received
            .into_iter()
            .enumerate()
            .map(|(j, bytes)| {
                if j == self.party_id() as usize && !include_self {
                    Ok(None)
                } else {
                    decode_from(j as PartyId, &bytes, shape).map(Some)
                }
            })
            .collect()
    }

    /// One byte stream per peer, e.g., to run two-party protocols such as OT.
    ///
    /// The channels use their own stream, so they never interfere with the messages
    /// of this session. They can only be created once per session.
    pub fn pairwise_channels(&mut self) -> Result<Vec<(PartyId, ByteChannel)>, NetError> {
        let child = self.child("pairwise channels");
        let child = self.check(child)?;
        Ok(self
            .peers()
            .map(|peer| {
                (
                    peer,
                    ByteChannel {
                        net: self.net.clone(),
                        peer,
                        stream: child.stream,
                        stats: self.stats.clone(),
                        write_buf: vec![],
                        read_buf: vec![],
                        read_pos: 0,
                    },
                )
            })
            .collect())
    }
}

fn decode_from<T: Wire>(party: PartyId, bytes: &[u8], shape: &T::Shape) -> Result<T, NetError> {
    T::from_wire_bytes(bytes, shape).map_err(|err| NetError::Malformed {
        party,
        reason: err.0,
    })
}

/// A byte stream to one peer that implements [AbstractChannel].
///
/// Written bytes are buffered until [AbstractChannel::flush] is called, or until the
/// channel blocks waiting for data. Errors abort the network.
pub struct ByteChannel {
    net: Arc<NetInner>,
    peer: PartyId,
    stream: StreamId,
    stats: Arc<StatsCell>,
    write_buf: Vec<u8>,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl ByteChannel {
    fn io_error(&self, err: NetError) -> std::io::Error {
        self.net
            .abort(&format!("byte channel to party {}: {err}", self.peer));
        std::io::Error::new(std::io::ErrorKind::BrokenPipe, err)
    }
}

impl AbstractChannel for ByteChannel {
    fn read_bytes(&mut self, bytes: &mut [u8]) -> std::io::Result<()> {
        let mut filled = 0;
        while filled < bytes.len() {
            if self.read_pos == self.read_buf.len() {
                // we are about to block, make sure the peer has everything we wrote
                self.flush()?;
                self.read_buf = self
                    .net
                    .link(self.peer)
                    .recv(self.stream, self.net.deadline())
                    .map_err(|err| self.io_error(err))?;
                self.read_pos = 0;
                self.stats.record_recv(self.read_buf.len());
            }
            let n = (bytes.len() - filled).min(self.read_buf.len() - self.read_pos);
            bytes[filled..filled + n]
                .copy_from_slice(&self.read_buf[self.read_pos..self.read_pos + n]);
            self.read_pos += n;
            filled += n;
        }
        Ok(())
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.write_buf.extend_from_slice(bytes);
        if self.write_buf.len() >= MAX_CHANNEL_BUFFER {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if !self.write_buf.is_empty() {
            let frame = std::mem::take(&mut self.write_buf);
            self.stats.record_send(frame.len());
            self.net
                .link(self.peer)
                .send(self.stream, frame)
                .map_err(|err| self.io_error(err))?;
        }
        Ok(())
    }
}
