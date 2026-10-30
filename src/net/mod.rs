//! Network layer shared by preprocessing, garbling and evaluation.
//!
//! The layer is split into three parts:
//! - [PeerLink]: reliable, ordered and authenticated delivery of frames to one peer,
//!   multiplexed by [StreamId]. Transports implement this trait, see [memory] for an
//!   in-memory transport.
//! - [Network]: the links of one party to all other parties.
//! - [Session]: a named and isolated stream on all links of a party with the
//!   message primitives used by the protocols (point-to-point messages, echo broadcast,
//!   coin tossing and commitments).
//!
//! Every error observed by a [Session] aborts the whole [Network] of that party, which
//! in turn makes all peers abort. Sends never block, a party only blocks when it waits
//! for a frame that has not arrived yet.

use std::{
    collections::HashSet,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use thiserror::Error;

mod inbox;
pub mod memory;
mod session;
#[cfg(test)]
mod tests;

pub use session::{ByteChannel, COMMITMENT_LEN, Commitment, NONCE_LEN, Nonce, Seed, Session};

pub type PartyId = u16;

/// Identifies a logical stream on a link, it is derived from the session ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StreamId(pub [u8; 16]);

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum NetError {
    #[error("party {0} closed the connection")]
    Disconnected(PartyId),
    #[error("party {party} aborted: {reason}")]
    PeerAborted { party: PartyId, reason: String },
    #[error("timed out waiting for party {0}")]
    Timeout(PartyId),
    #[error("the network has been closed: {0}")]
    Closed(String),
    #[error("expected {expected} bytes from party {party} but received {received}")]
    UnexpectedLength {
        party: PartyId,
        expected: usize,
        received: usize,
    },
    #[error("party {0} exceeded the receive buffer limit")]
    BufferLimit(PartyId),
    #[error("cheating detected: {0}")]
    CheatDetected(String),
    #[error("session {0} already exists")]
    DuplicateSession(String),
    #[error("invalid network configuration: {0}")]
    Config(String),
    #[error("transport error: {0}")]
    Transport(String),
}

/// Reliable, ordered and authenticated delivery of frames to a single peer.
///
/// Frames sent on the same [StreamId] are received in order. Implementations must
/// guarantee that frames received on a link were sent by the peer the link belongs to.
pub trait PeerLink: Send + Sync {
    /// Send a frame, this must not block waiting for the peer.
    fn send(&self, stream: StreamId, frame: Vec<u8>) -> Result<(), NetError>;

    /// Receive the next frame on `stream`, blocking until it arrives or `deadline` passes.
    fn recv(&self, stream: StreamId, deadline: Instant) -> Result<Vec<u8>, NetError>;

    /// Abort the link, the peer observes [NetError::PeerAborted] with `reason`
    /// and subsequent local operations fail.
    fn abort(&self, reason: &str);

    /// Close the link gracefully, frames that were already sent are still delivered.
    fn close(&self);
}

/// Configuration of a [Network].
#[derive(Clone, Copy, Debug)]
pub struct NetworkConfig {
    /// How long to wait for a frame before giving up.
    pub timeout: Duration,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(600),
        }
    }
}

/// Communication statistics of a root session and all its children.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub frames_sent: u64,
    pub frames_received: u64,
}

#[derive(Default)]
pub(crate) struct StatsCell {
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    frames_sent: AtomicU64,
    frames_received: AtomicU64,
}

impl StatsCell {
    pub(crate) fn record_send(&self, len: usize) {
        self.bytes_sent.fetch_add(len as u64, Ordering::Relaxed);
        self.frames_sent.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_recv(&self, len: usize) {
        self.bytes_received.fetch_add(len as u64, Ordering::Relaxed);
        self.frames_received.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> Stats {
        Stats {
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            frames_sent: self.frames_sent.load(Ordering::Relaxed),
            frames_received: self.frames_received.load(Ordering::Relaxed),
        }
    }
}

pub(crate) struct NetInner {
    party_id: PartyId,
    party_count: u16,
    /// `links[j]` connects to party `j`, it is `None` for `j == party_id`.
    links: Vec<Option<Box<dyn PeerLink>>>,
    config: NetworkConfig,
    /// Session IDs that are in use, a session ID must only be used once.
    claimed: Mutex<HashSet<[u8; 32]>>,
    aborted: AtomicBool,
    stats: Mutex<Vec<(String, Arc<StatsCell>)>>,
}

impl NetInner {
    pub(crate) fn link(&self, peer: PartyId) -> &dyn PeerLink {
        self.links[peer as usize]
            .as_deref()
            .expect("no link to self")
    }

    pub(crate) fn deadline(&self) -> Instant {
        Instant::now() + self.config.timeout
    }

    pub(crate) fn claim(&self, sid: [u8; 32], label: &str) -> Result<(), NetError> {
        if self.claimed.lock().unwrap().insert(sid) {
            Ok(())
        } else {
            Err(NetError::DuplicateSession(label.to_string()))
        }
    }

    pub(crate) fn abort(&self, reason: &str) {
        if !self.aborted.swap(true, Ordering::SeqCst) {
            for link in self.links.iter().flatten() {
                link.abort(reason);
            }
        }
    }

    pub(crate) fn is_aborted(&self) -> bool {
        self.aborted.load(Ordering::SeqCst)
    }
}

impl Drop for NetInner {
    fn drop(&mut self) {
        if !self.is_aborted() {
            for link in self.links.iter().flatten() {
                link.close();
            }
        }
    }
}

/// The links of one party to all other parties.
///
/// The network stays open as long as the [Network] or any [Session] created from it
/// is alive. It is closed gracefully when all of them are dropped.
pub struct Network {
    inner: Arc<NetInner>,
}

impl Network {
    /// Create a network from the links of party `party_id`, `links[party_id]` must be `None`
    /// and all other links must be present.
    pub fn new(
        party_id: PartyId,
        links: Vec<Option<Box<dyn PeerLink>>>,
        config: NetworkConfig,
    ) -> Result<Self, NetError> {
        let party_count =
            u16::try_from(links.len()).map_err(|_| NetError::Config("too many parties".into()))?;
        if party_count < 2 || party_id >= party_count {
            return Err(NetError::Config(format!(
                "invalid party {party_id} for {party_count} parties"
            )));
        }
        for (j, link) in links.iter().enumerate() {
            if link.is_some() != (j != party_id as usize) {
                return Err(NetError::Config(format!("wrong link for party {j}")));
            }
        }
        Ok(Self {
            inner: Arc::new(NetInner {
                party_id,
                party_count,
                links,
                config,
                claimed: Mutex::new(HashSet::new()),
                aborted: AtomicBool::new(false),
                stats: Mutex::new(vec![]),
            }),
        })
    }

    pub fn party_id(&self) -> PartyId {
        self.inner.party_id
    }

    pub fn party_count(&self) -> u16 {
        self.inner.party_count
    }

    /// Create a root session, all parties must use the same `label` for the same purpose.
    /// The communication of the session and its children is reported under `label`
    /// in [Self::stats].
    pub fn session(&self, label: &str) -> Result<Session, NetError> {
        let stats = Arc::new(StatsCell::default());
        let session = Session::root(self.inner.clone(), label, stats.clone())?;
        // only register the statistics once the session is claimed
        self.inner
            .stats
            .lock()
            .unwrap()
            .push((label.to_string(), stats));
        Ok(session)
    }

    /// Abort the network, all peers observe [NetError::PeerAborted].
    pub fn abort(&self, reason: &str) {
        self.inner.abort(reason);
    }

    /// Communication per root session.
    pub fn stats(&self) -> Vec<(String, Stats)> {
        self.inner
            .stats
            .lock()
            .unwrap()
            .iter()
            .map(|(label, cell)| (label.clone(), cell.snapshot()))
            .collect()
    }
}
