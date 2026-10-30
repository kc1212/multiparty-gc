//! Bounded, framed delivery over one physical stream in each direction.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use quinn::{
    Connection, ConnectionError, Endpoint, ReadError, ReadExactError, RecvStream, SendStream,
    VarInt,
};
use tokio::{
    runtime::Runtime,
    sync::{mpsc, watch},
};

use super::{
    CLOSE_ABORT, CLOSE_DONE, CLOSE_VIOLATION, MAX_REASON_LEN, QuicConfig, transport_error,
};
use crate::net::{
    NetError, PartyId, PeerLink, StreamId,
    buffer::{BufferBudget, BufferPermit},
    inbox::Inbox,
};

enum Command {
    Send(StreamId, Vec<u8>, BufferPermit),
    Close(std::sync::mpsc::Sender<()>),
}

struct LinkState {
    connection: Connection,
    inbox: Arc<Inbox>,
    done: watch::Sender<bool>,
    peer: PartyId,
    max_frame_len: usize,
}

impl LinkState {
    fn fail(&self, err: NetError) {
        let reason = err.to_string();
        self.inbox.fail(err);
        self.connection
            .close(VarInt::from_u32(CLOSE_VIOLATION), reason_prefix(&reason));
        self.done.send_replace(true);
    }
}

fn reason_prefix(reason: &str) -> &[u8] {
    let mut end = reason.len().min(MAX_REASON_LEN);
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    &reason.as_bytes()[..end]
}

pub(super) struct QuicLink {
    state: Arc<LinkState>,
    me: PartyId,
    commands: mpsc::UnboundedSender<Command>,
    outbound_budget: Arc<BufferBudget>,
    local_closed: Mutex<Option<NetError>>,
    close_timeout: Duration,
    // The runtime and endpoint must outlive the connection.
    endpoint: Endpoint,
    runtime: Arc<Runtime>,
}

impl Drop for QuicLink {
    fn drop(&mut self) {
        let endpoint = self.endpoint.clone();
        let _ = self.runtime.block_on(async move {
            tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle()).await
        });
    }
}

impl QuicLink {
    pub(super) fn new(
        runtime: Arc<Runtime>,
        endpoint: Endpoint,
        me: PartyId,
        peer: PartyId,
        connection: Connection,
        config: &QuicConfig,
    ) -> Self {
        let (commands, command_rx) = mpsc::unbounded_channel();
        let (done_tx, done_rx) = watch::channel(false);
        let state = Arc::new(LinkState {
            connection,
            inbox: Arc::new(Inbox::new(peer, config.max_buffered)),
            done: done_tx,
            peer,
            max_frame_len: config.max_frame_len,
        });
        runtime.spawn(write_frames(
            state.clone(),
            command_rx,
            done_rx,
            config.close_timeout,
        ));
        runtime.spawn(read_connection(state.clone()));
        let watcher = state.clone();
        runtime.spawn(async move {
            let err = close_error(watcher.connection.closed().await, peer);
            if matches!(err, NetError::Disconnected(_)) {
                watcher.inbox.close_sender(err);
            } else {
                watcher.inbox.fail(err);
            }
            watcher.done.send_replace(true);
        });
        Self {
            state,
            me,
            commands,
            outbound_budget: BufferBudget::new(peer, config.max_buffered),
            local_closed: Mutex::new(None),
            close_timeout: config.close_timeout,
            endpoint,
            runtime,
        }
    }
}

fn close_error(err: ConnectionError, peer: PartyId) -> NetError {
    match err {
        ConnectionError::ApplicationClosed(close) => match close.error_code.into_inner() {
            c if c == CLOSE_DONE as u64 => NetError::Disconnected(peer),
            c if c == CLOSE_ABORT as u64 => NetError::PeerAborted {
                party: peer,
                reason: String::from_utf8_lossy(&close.reason).into_owned(),
            },
            _ => NetError::Transport(format!(
                "party {peer} closed the connection: {}",
                String::from_utf8_lossy(&close.reason)
            )),
        },
        ConnectionError::TimedOut => NetError::Timeout(peer),
        ConnectionError::LocallyClosed => NetError::Closed("connection closed locally".into()),
        err => transport_error(&format!("connection to party {peer}"), err),
    }
}

fn read_error(err: ReadExactError, peer: PartyId) -> NetError {
    match err {
        ReadExactError::ReadError(ReadError::ConnectionLost(err)) => close_error(err, peer),
        err => transport_error(&format!("reading frame from party {peer}"), err),
    }
}

async fn write_frames(
    state: Arc<LinkState>,
    mut commands: mpsc::UnboundedReceiver<Command>,
    mut done: watch::Receiver<bool>,
    close_timeout: Duration,
) {
    let mut send = match state.connection.open_uni().await {
        Ok(send) => send,
        Err(err) => {
            state.fail(close_error(err, state.peer));
            return;
        }
    };
    while let Some(command) = commands.recv().await {
        match command {
            Command::Send(stream, frame, _permit) => {
                if let Err(err) = write_frame(&mut send, stream, &frame).await {
                    state.fail(err);
                    return;
                }
            }
            Command::Close(ack) => {
                if let Err(err) = send.finish() {
                    state.fail(transport_error("finishing stream", err));
                } else {
                    let _ = tokio::time::timeout(close_timeout, done.wait_for(|done| *done)).await;
                    state
                        .connection
                        .close(VarInt::from_u32(CLOSE_DONE), b"done");
                }
                let _ = ack.send(());
                return;
            }
        }
    }
}

async fn write_frame(
    send: &mut SendStream,
    stream: StreamId,
    frame: &[u8],
) -> Result<(), NetError> {
    send.write_all(&stream.0)
        .await
        .map_err(|e| transport_error("writing session id", e))?;
    send.write_all(&(frame.len() as u64).to_le_bytes())
        .await
        .map_err(|e| transport_error("writing length", e))?;
    send.write_all(frame)
        .await
        .map_err(|e| transport_error("writing payload", e))
}

async fn read_connection(state: Arc<LinkState>) {
    let result = match state.connection.accept_uni().await {
        Ok(recv) => read_frames(recv, &state).await,
        Err(err) => Err(close_error(err, state.peer)),
    };
    match result {
        Ok(()) => {}
        // A graceful close by the peer keeps the frames we already queued, like the
        // connection watcher does, only other failures discard them.
        Err(err @ NetError::Disconnected(_)) => {
            state.inbox.close_sender(err);
            state.done.send_replace(true);
        }
        Err(err) => state.fail(err),
    }
}

async fn read_frames(mut recv: RecvStream, state: &LinkState) -> Result<(), NetError> {
    loop {
        let mut header = [0u8; 24];
        match recv.read_exact(&mut header).await {
            Ok(()) => {}
            Err(ReadExactError::FinishedEarly(0)) => {
                state.inbox.close_sender(NetError::Disconnected(state.peer));
                state.done.send_replace(true);
                return Ok(());
            }
            Err(err) => return Err(read_error(err, state.peer)),
        }
        let stream = StreamId(header[..16].try_into().unwrap());
        let len = u64::from_le_bytes(header[16..].try_into().unwrap());
        if len > state.max_frame_len as u64 {
            return Err(NetError::Malformed {
                party: state.peer,
                reason: "frame too long".into(),
            });
        }
        // One reservation accounts for the payload throughout reading and queuing.
        let permit = state.inbox.reserve(len as usize)?;
        let frame = read_frame(&mut recv, len as usize, state.peer).await?;
        state
            .inbox
            .push_reserved(stream, Instant::now(), frame, permit)?;
    }
}

/// Grow only as bytes arrive; announcing a long frame does not allocate its payload.
async fn read_frame(recv: &mut RecvStream, len: usize, peer: PartyId) -> Result<Vec<u8>, NetError> {
    const CHUNK: usize = 1 << 20;
    let mut frame = Vec::new();
    while frame.len() < len {
        let chunk = CHUNK.min(len - frame.len());
        let start = frame.len();
        frame.reserve_exact(chunk);
        frame.resize(start + chunk, 0);
        recv.read_exact(&mut frame[start..])
            .await
            .map_err(|err| read_error(err, peer))?;
    }
    Ok(frame)
}

impl PeerLink for QuicLink {
    fn send(&self, stream: StreamId, frame: Vec<u8>) -> Result<(), NetError> {
        if let Some(err) = self.local_closed.lock().unwrap().clone() {
            return Err(err);
        }
        if let Some(err) = self.state.inbox.sender_error() {
            return Err(err);
        }
        if frame.len() > self.state.max_frame_len {
            return Err(NetError::Config("frame exceeds the transport limit".into()));
        }
        // the budget reports the peer as the culprit, but this is our own queue
        let permit = self
            .outbound_budget
            .reserve(frame.capacity())
            .map_err(|_| NetError::SendQueueFull(self.state.peer))?;
        self.commands
            .send(Command::Send(stream, frame, permit))
            .map_err(|_| NetError::Disconnected(self.state.peer))
    }

    fn recv(&self, stream: StreamId, deadline: Instant) -> Result<Vec<u8>, NetError> {
        self.state.inbox.pop(stream, deadline)
    }

    fn abort(&self, reason: &str) {
        self.local_closed
            .lock()
            .unwrap()
            .get_or_insert(NetError::Closed(format!("aborted: {reason}")));
        self.state
            .connection
            .close(VarInt::from_u32(CLOSE_ABORT), reason_prefix(reason));
        self.state
            .inbox
            .fail(NetError::Closed(format!("aborted: {reason}")));
        self.state.done.send_replace(true);
    }

    fn close(&self) {
        self.local_closed
            .lock()
            .unwrap()
            .get_or_insert(NetError::Closed("link closed".into()));
        let (ack, acked) = std::sync::mpsc::channel();
        if self.commands.send(Command::Close(ack)).is_ok()
            && acked
                .recv_timeout(self.close_timeout + Duration::from_secs(1))
                .is_err()
        {
            // The writer may be stalled on flow control before it reaches Close.
            // Bound shutdown even when the peer stops reading queued payloads.
            self.state
                .connection
                .close(VarInt::from_u32(CLOSE_DONE), b"close timeout");
        }
        self.state.inbox.close_receiver(NetError::Closed(format!(
            "party {} closed the link to {}",
            self.me, self.state.peer
        )));
    }
}

#[cfg(test)]
mod tests;
