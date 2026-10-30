//! In-memory transport connecting parties of the same process, with an optional
//! latency and bandwidth model.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use super::{NetError, Network, NetworkConfig, PartyId, PeerLink, StreamId, inbox::Inbox};

/// Default limit on the bytes buffered per link, see [Inbox].
const MAX_BUFFERED: usize = 1 << 34;

/// Simulated properties of every link (in each direction).
#[derive(Clone, Copy, Debug, Default)]
pub struct LinkModel {
    /// One-way latency added to every frame.
    pub latency: Duration,
    /// Bandwidth in bytes per second, `None` for unlimited.
    pub bandwidth: Option<u64>,
}

impl LinkModel {
    /// Bandwidth in megabits per second.
    pub fn with_mbps(latency: Duration, mbps: u64) -> Self {
        Self {
            latency,
            bandwidth: Some(mbps * 1_000_000 / 8),
        }
    }
}

/// Create fully connected networks for `party_count` parties in this process,
/// the network of party `i` is at index `i`.
pub fn mesh(
    party_count: u16,
    model: LinkModel,
    config: NetworkConfig,
) -> Result<Vec<Network>, NetError> {
    if party_count < 2 {
        return Err(NetError::Config("need at least two parties".into()));
    }
    let n = party_count as usize;
    // inboxes[i][j] holds the frames sent by party j to party i
    let inboxes: Vec<Vec<Arc<Inbox>>> = (0..n)
        .map(|_| {
            (0..n)
                .map(|j| Arc::new(Inbox::new(j as PartyId, MAX_BUFFERED)))
                .collect()
        })
        .collect();
    (0..n)
        .map(|i| {
            let links = (0..n)
                .map(|j| {
                    (i != j).then(|| {
                        Box::new(MemoryLink {
                            me: i as PartyId,
                            peer: j as PartyId,
                            inbox: inboxes[i][j].clone(),
                            outbox: inboxes[j][i].clone(),
                            model,
                            schedule: Mutex::new(Schedule::default()),
                            local_closed: Mutex::new(None),
                        }) as Box<dyn PeerLink>
                    })
                })
                .collect();
            Network::new(i as PartyId, links, config)
        })
        .collect()
}

#[derive(Default)]
struct Schedule {
    /// When the link finishes transmitting the frames sent so far.
    busy_until: Option<Instant>,
    /// Delivery time of the last frame, frames are delivered in order.
    last_delivery: Option<Instant>,
}

struct MemoryLink {
    me: PartyId,
    peer: PartyId,
    /// Frames from the peer to us.
    inbox: Arc<Inbox>,
    /// Frames from us to the peer.
    outbox: Arc<Inbox>,
    model: LinkModel,
    schedule: Mutex<Schedule>,
    /// Set when we aborted or closed the link ourselves.
    local_closed: Mutex<Option<NetError>>,
}

impl MemoryLink {
    fn delivery_time(&self, len: usize) -> Instant {
        let now = Instant::now();
        let mut schedule = self.schedule.lock().unwrap();
        let sent = match self.model.bandwidth {
            Some(bandwidth) => {
                let start = schedule.busy_until.map_or(now, |t| t.max(now));
                let finish = start + Duration::from_secs_f64(len as f64 / bandwidth.max(1) as f64);
                schedule.busy_until = Some(finish);
                finish
            }
            None => now,
        };
        let delivery = schedule
            .last_delivery
            .map_or(sent + self.model.latency, |t| {
                t.max(sent + self.model.latency)
            });
        schedule.last_delivery = Some(delivery);
        delivery
    }
}

impl PeerLink for MemoryLink {
    fn send(&self, stream: StreamId, frame: Vec<u8>) -> Result<(), NetError> {
        if let Some(err) = self.local_closed.lock().unwrap().clone() {
            return Err(err);
        }
        let deliver_at = self.delivery_time(frame.len());
        self.outbox
            .push(stream, deliver_at, frame)
            .map_err(|err| match err {
                NetError::BufferLimit(_) => err,
                // report why the peer stopped listening if we know it
                _ => self
                    .inbox
                    .sender_error()
                    .unwrap_or(NetError::Disconnected(self.peer)),
            })
    }

    fn recv(&self, stream: StreamId, deadline: Instant) -> Result<Vec<u8>, NetError> {
        self.inbox.pop(stream, deadline)
    }

    fn abort(&self, reason: &str) {
        self.local_closed
            .lock()
            .unwrap()
            .get_or_insert(NetError::Closed(format!("aborted: {reason}")));
        self.outbox.close_sender(NetError::PeerAborted {
            party: self.me,
            reason: reason.to_string(),
        });
        self.inbox
            .close_receiver(NetError::Closed(format!("aborted: {reason}")));
    }

    fn close(&self) {
        self.local_closed
            .lock()
            .unwrap()
            .get_or_insert(NetError::Closed("link closed".into()));
        self.outbox.close_sender(NetError::Disconnected(self.me));
        self.inbox
            .close_receiver(NetError::Closed(format!("link to {} closed", self.peer)));
    }
}
