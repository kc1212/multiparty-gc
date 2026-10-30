//! Receive queues of one link, used by the transports.

use std::{
    collections::{HashMap, VecDeque},
    sync::{Condvar, Mutex},
    time::Instant,
};

use super::{NetError, PartyId, StreamId};

/// Frames received from one peer, queued per stream.
///
/// Frames carry a delivery time so that transports can simulate latency.
pub(crate) struct Inbox {
    /// The party that sends into this inbox.
    peer: PartyId,
    /// Upper bound on the number of buffered bytes, protects against a peer
    /// that floods us with frames that are never read.
    max_buffered: usize,
    state: Mutex<InboxState>,
    cond: Condvar,
}

#[derive(Default)]
struct InboxState {
    queues: HashMap<StreamId, VecDeque<(Instant, Vec<u8>)>>,
    buffered: usize,
    /// Set when the peer will not send anymore, it is returned after the queued frames.
    sender_closed: Option<NetError>,
    /// Set when we will not receive anymore, every receive fails immediately.
    receiver_closed: Option<NetError>,
}

impl Inbox {
    pub(crate) fn new(peer: PartyId, max_buffered: usize) -> Self {
        Self {
            peer,
            max_buffered,
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
        let mut state = self.state.lock().unwrap();
        if let Some(err) = &state.receiver_closed {
            return Err(err.clone());
        }
        if state.sender_closed.is_some() {
            // the peer is not allowed to send after closing
            return Err(NetError::Closed("link already closed".into()));
        }
        if state.buffered.saturating_add(frame.len()) > self.max_buffered {
            let err = NetError::BufferLimit(self.peer);
            state.sender_closed = Some(err.clone());
            state.queues.clear();
            state.buffered = 0;
            self.cond.notify_all();
            return Err(err);
        }
        state.buffered += frame.len();
        state
            .queues
            .entry(stream)
            .or_default()
            .push_back((deliver_at, frame));
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
                Some((deliver_at, _)) if *deliver_at <= now => {
                    let queue = state.queues.get_mut(&stream).unwrap();
                    let (_, frame) = queue.pop_front().unwrap();
                    if queue.is_empty() {
                        state.queues.remove(&stream);
                    }
                    state.buffered -= frame.len();
                    return Ok(frame);
                }
                Some((deliver_at, _)) => (*deliver_at).min(deadline),
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
        state.buffered = 0;
        self.cond.notify_all();
    }

    /// The reason the peer stopped sending, if any.
    pub(crate) fn sender_error(&self) -> Option<NetError> {
        self.state.lock().unwrap().sender_closed.clone()
    }
}
