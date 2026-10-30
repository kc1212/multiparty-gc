//! Receive queues of one link, used by the transports.

use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Condvar, Mutex},
    time::Instant,
};

use super::{
    NetError, PartyId, StreamId,
    buffer::{BufferBudget, BufferPermit},
};

/// Frames received from one peer, queued per stream.
///
/// Frames carry a delivery time so that transports can simulate latency.
pub(crate) struct Inbox {
    /// The party that sends into this inbox.
    peer: PartyId,
    /// Upper bound on the number of buffered bytes, protects against a peer
    /// that floods us with frames that are never read.
    budget: Arc<BufferBudget>,
    state: Mutex<InboxState>,
    cond: Condvar,
}

#[derive(Default)]
struct InboxState {
    queues: HashMap<StreamId, VecDeque<QueuedFrame>>,
    /// Set when the peer will not send anymore, it is returned after the queued frames.
    sender_closed: Option<NetError>,
    /// Set when we will not receive anymore, every receive fails immediately.
    receiver_closed: Option<NetError>,
}

struct QueuedFrame {
    deliver_at: Instant,
    bytes: Vec<u8>,
    _permit: BufferPermit,
}

impl Inbox {
    pub(crate) fn new(peer: PartyId, max_buffered: usize) -> Self {
        Self {
            peer,
            budget: BufferBudget::new(peer, max_buffered),
            state: Mutex::new(InboxState::default()),
            cond: Condvar::new(),
        }
    }

    /// Queue a frame for delivery at `deliver_at`.
    pub(crate) fn push(
        &self,
        stream: StreamId,
        deliver_at: Instant,
        frame: Vec<u8>,
    ) -> Result<(), NetError> {
        let permit = self.reserve(frame.capacity())?;
        self.push_reserved(stream, deliver_at, frame, permit)
    }

    /// Reserve before reading a payload; the same permit follows it into the queue.
    pub(crate) fn reserve(&self, capacity: usize) -> Result<BufferPermit, NetError> {
        self.budget
            .reserve(capacity)
            .inspect_err(|err| self.fail(err.clone()))
    }

    pub(crate) fn push_reserved(
        &self,
        stream: StreamId,
        deliver_at: Instant,
        frame: Vec<u8>,
        mut permit: BufferPermit,
    ) -> Result<(), NetError> {
        permit
            .cover_capacity(frame.capacity())
            .inspect_err(|err| self.fail(err.clone()))?;
        let mut state = self.state.lock().unwrap();
        if let Some(err) = &state.receiver_closed {
            return Err(err.clone());
        }
        if state.sender_closed.is_some() {
            return Err(NetError::Closed("link already closed".into()));
        }
        state
            .queues
            .entry(stream)
            .or_default()
            .push_back(QueuedFrame {
                deliver_at,
                bytes: frame,
                _permit: permit,
            });
        self.cond.notify_all();
        Ok(())
    }

    /// Receive the next frame on `stream`.
    pub(crate) fn pop(&self, stream: StreamId, deadline: Instant) -> Result<Vec<u8>, NetError> {
        let mut state = self.state.lock().unwrap();
        loop {
            if let Some(err) = &state.receiver_closed {
                return Err(err.clone());
            }
            let now = Instant::now();
            let wait_until = match state.queues.get(&stream).and_then(|q| q.front()) {
                Some(frame) if frame.deliver_at <= now => {
                    let queue = state.queues.get_mut(&stream).unwrap();
                    let frame = queue.pop_front().unwrap();
                    if queue.is_empty() {
                        state.queues.remove(&stream);
                    }
                    return Ok(frame.bytes);
                }
                Some(frame) => frame.deliver_at.min(deadline),
                None => {
                    if let Some(err) = &state.sender_closed {
                        return Err(err.clone());
                    }
                    deadline
                }
            };
            if now >= deadline {
                return Err(NetError::Timeout(self.peer));
            }
            state = self
                .cond
                .wait_timeout(state, wait_until.saturating_duration_since(now))
                .unwrap()
                .0;
        }
    }

    /// The peer will not send anymore, receivers get `err` once the queue is empty.
    /// Only the first call has an effect.
    pub(crate) fn close_sender(&self, err: NetError) {
        let mut state = self.state.lock().unwrap();
        if state.sender_closed.is_none() {
            state.sender_closed = Some(err);
        }
        self.cond.notify_all();
    }

    /// We will not receive anymore, pending and future receives fail with `err`.
    pub(crate) fn close_receiver(&self, err: NetError) {
        let mut state = self.state.lock().unwrap();
        if state.receiver_closed.is_none() {
            state.receiver_closed = Some(err);
        }
        state.queues.clear();
        self.cond.notify_all();
    }

    /// A terminal failure discards queued data and wakes all waiters immediately.
    pub(crate) fn fail(&self, err: NetError) {
        let mut state = self.state.lock().unwrap();
        state.sender_closed.get_or_insert(err.clone());
        state.receiver_closed.get_or_insert(err);
        state.queues.clear();
        self.cond.notify_all();
    }

    /// The reason the peer stopped sending, if any.
    pub(crate) fn sender_error(&self) -> Option<NetError> {
        self.state.lock().unwrap().sender_closed.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::buffer::FRAME_OVERHEAD;

    #[test]
    fn empty_frames_consume_budget() {
        let inbox = Inbox::new(7, 2 * FRAME_OVERHEAD);
        let stream = StreamId([0; 16]);
        for _ in 0..2 {
            inbox.push(stream, Instant::now(), vec![]).unwrap();
        }
        assert!(matches!(
            inbox.push(stream, Instant::now(), vec![]),
            Err(NetError::BufferLimit(7))
        ));
        assert!(matches!(
            inbox.pop(stream, Instant::now()),
            Err(NetError::BufferLimit(7))
        ));
        let zero = Inbox::new(7, 0);
        assert!(zero.push(stream, Instant::now(), vec![]).is_err());
    }

    #[test]
    fn queued_and_in_flight_frames_share_budget() {
        let inbox = Inbox::new(7, 2 * FRAME_OVERHEAD + 20);
        let stream = StreamId([0; 16]);
        inbox.push(stream, Instant::now(), vec![0; 10]).unwrap();
        let in_flight = inbox.reserve(10).unwrap();
        assert!(matches!(inbox.reserve(0), Err(NetError::BufferLimit(7))));
        drop(in_flight);
    }

    #[test]
    fn cancellation_and_consumption_release_reservations() {
        let inbox = Inbox::new(7, FRAME_OVERHEAD + 10);
        let stream = StreamId([0; 16]);
        drop(inbox.reserve(10).unwrap());
        let permit = inbox.reserve(10).unwrap();
        inbox
            .push_reserved(stream, Instant::now(), vec![7; 10], permit)
            .unwrap();
        assert_eq!(inbox.pop(stream, Instant::now()).unwrap(), vec![7; 10]);
        assert!(inbox.reserve(10).is_ok());
    }

    #[test]
    fn account_for_allocation_capacity_and_discard_on_failure() {
        let inbox = Inbox::new(7, FRAME_OVERHEAD + 10);
        let stream = StreamId([0; 16]);
        inbox.push(stream, Instant::now(), vec![7; 1]).unwrap();
        let oversized = Vec::with_capacity(100);
        assert!(matches!(
            inbox.push(stream, Instant::now(), oversized),
            Err(NetError::BufferLimit(7))
        ));
        assert!(matches!(
            inbox.pop(stream, Instant::now()),
            Err(NetError::BufferLimit(7))
        ));
    }
}
