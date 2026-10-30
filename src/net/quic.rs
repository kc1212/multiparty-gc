//! QUIC transport: one QUIC connection per pair of parties, authenticated with mutual
//! TLS 1.3 and certificates that are pinned per party.
//!
//! Every [StreamId] is carried on its own unidirectional QUIC stream: the sender opens
//! the stream on the first frame and writes the stream ID, followed by length-prefixed
//! frames. A receiver task per QUIC stream reads the frames into an [Inbox].
//!
//! Party `i` connects to every party `j > i` and accepts connections from every
//! party `j < i`. Both sides check that the peer presents exactly the pinned certificate
//! of the expected party, and TLS checks that the peer holds the corresponding key.
//!
//! A graceful close must not lose frames that the peer has not read yet, since closing
//! a QUIC connection discards buffered data. On close, a party finishes its streams,
//! sends a "done" signal with the number of streams it opened on a control stream, and
//! only closes the connection once the peer has also sent "done" (i.e., the peer no
//! longer reads), the peer closed the connection, or a timeout passed. A receiver that
//! got "done" and read all announced streams to the end knows that no more frames
//! will arrive.

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use quinn::{
    Connection, ConnectionError, Endpoint, IdleTimeout, ReadExactError, RecvStream, SendStream,
    TransportConfig, VarInt,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use rustls::{
    DigitallySignedStruct, DistinguishedName, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};
use tokio::{
    runtime::Runtime,
    sync::{mpsc, watch},
};

use super::{NetError, Network, NetworkConfig, PartyId, PeerLink, StreamId, inbox::Inbox};

const ALPN: &[u8] = b"multiparty-gc/1";
/// The certificates are pinned, so the server name is not used for authentication.
const SERVER_NAME: &str = "multiparty-gc";
/// Stream ID of the control stream that signals a graceful close.
/// It cannot collide with a session stream except with negligible probability.
const CONTROL_STREAM: StreamId = StreamId([0xff; 16]);

const CLOSE_DONE: u32 = 0;
const CLOSE_ABORT: u32 = 1;
const CLOSE_VIOLATION: u32 = 2;
/// Abort reasons are truncated to fit into a single packet.
const MAX_REASON_LEN: usize = 512;
/// Upper bound on the streams a peer may open, honest parties use one per session.
const MAX_STREAMS: usize = 1 << 16;

fn transport_error(context: &str, err: impl std::fmt::Display) -> NetError {
    NetError::Transport(format!("{context}: {err}"))
}

/// The certificate and private key of a party.
pub struct Identity {
    certificate: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

impl Identity {
    /// Generate a self-signed certificate and key, returned as (certificate, key) PEM.
    pub fn generate_pem() -> Result<(String, String), NetError> {
        let certified = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_string()])
            .map_err(|e| transport_error("generating certificate", e))?;
        Ok((certified.cert.pem(), certified.key_pair.serialize_pem()))
    }

    /// Generate a fresh identity with a self-signed certificate.
    pub fn generate() -> Result<Self, NetError> {
        let (cert, key) = Self::generate_pem()?;
        Self::from_pem(cert.as_bytes(), key.as_bytes())
    }

    pub fn from_pem(certificate_pem: &[u8], key_pem: &[u8]) -> Result<Self, NetError> {
        Self::from_certificate_and_key_pem(certificate_from_pem(certificate_pem)?, key_pem)
    }

    pub fn from_certificate_and_key_pem(
        certificate: CertificateDer<'static>,
        key_pem: &[u8],
    ) -> Result<Self, NetError> {
        Ok(Self {
            certificate,
            key: PrivateKeyDer::from_pem_slice(key_pem)
                .map_err(|e| NetError::Config(format!("invalid private key: {e}")))?,
        })
    }

    pub fn certificate(&self) -> &CertificateDer<'static> {
        &self.certificate
    }
}

pub fn certificate_from_pem(pem: &[u8]) -> Result<CertificateDer<'static>, NetError> {
    CertificateDer::from_pem_slice(pem)
        .map_err(|e| NetError::Config(format!("invalid certificate: {e}")))
}

/// Configuration of the QUIC transport.
#[derive(Clone, Copy, Debug)]
pub struct QuicConfig {
    pub network: NetworkConfig,
    /// How long to keep trying to connect to all peers.
    pub connect_timeout: Duration,
    /// A connection is closed if the peer is silent for this long.
    pub idle_timeout: Duration,
    /// Interval of keep-alive packets, must be shorter than `idle_timeout`.
    pub keep_alive: Duration,
    /// How long a graceful close waits for the peer to finish.
    pub close_timeout: Duration,
    /// Largest frame a peer may send.
    pub max_frame_len: usize,
    /// Upper bound on the bytes buffered from one peer.
    pub max_buffered: usize,
    /// QUIC flow control window per stream and per connection.
    pub receive_window: u32,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            network: NetworkConfig::default(),
            connect_timeout: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(30),
            keep_alive: Duration::from_secs(5),
            close_timeout: Duration::from_secs(60),
            max_frame_len: 1 << 30,
            max_buffered: 1 << 32,
            receive_window: 64 << 20,
        }
    }
}

/// A bound QUIC endpoint of one party, see [QuicEndpoint::connect].
pub struct QuicEndpoint {
    runtime: Arc<Runtime>,
    endpoint: Endpoint,
    party_id: PartyId,
    certificates: Vec<CertificateDer<'static>>,
    identity: Identity,
    config: QuicConfig,
    transport: Arc<TransportConfig>,
    provider: Arc<CryptoProvider>,
}

impl QuicEndpoint {
    /// Bind the endpoint of `party_id` to `addr`.
    ///
    /// `certificates[j]` is the certificate of party `j`, ours must match `identity`.
    /// The endpoint accepts connections from parties with a smaller ID right away,
    /// they are processed once [Self::connect] is called.
    pub fn bind(
        addr: SocketAddr,
        party_id: PartyId,
        identity: Identity,
        certificates: Vec<CertificateDer<'static>>,
        config: QuicConfig,
    ) -> Result<Self, NetError> {
        let n = certificates.len();
        if n < 2 || party_id as usize >= n {
            return Err(NetError::Config(format!(
                "invalid party {party_id} for {n} parties"
            )));
        }
        if certificates[party_id as usize] != identity.certificate {
            return Err(NetError::Config(
                "our certificate does not match our identity".into(),
            ));
        }
        if certificates.iter().collect::<HashSet<_>>().len() != n {
            return Err(NetError::Config("certificates must be distinct".into()));
        }
        if config.keep_alive >= config.idle_timeout {
            return Err(NetError::Config(
                "keep-alive must be shorter than the idle timeout".into(),
            ));
        }

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| transport_error("starting runtime", e))?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());

        let mut transport = TransportConfig::default();
        transport
            .max_idle_timeout(Some(
                IdleTimeout::try_from(config.idle_timeout)
                    .map_err(|e| NetError::Config(format!("invalid idle timeout: {e}")))?,
            ))
            .keep_alive_interval(Some(config.keep_alive))
            .stream_receive_window(VarInt::from_u32(config.receive_window))
            .receive_window(VarInt::from_u32(config.receive_window))
            .send_window(config.receive_window as u64)
            .max_concurrent_uni_streams(VarInt::from_u32(256))
            .max_concurrent_bidi_streams(VarInt::from_u32(0));
        let transport = Arc::new(transport);

        // only parties with a smaller ID connect to us
        let clients = certificates[..party_id as usize].to_vec();
        let mut server_crypto = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| transport_error("server config", e))?
            .with_client_cert_verifier(Arc::new(PinnedClients {
                certificates: clients,
                provider: provider.clone(),
            }))
            .with_single_cert(vec![identity.certificate.clone()], identity.key.clone_key())
            .map_err(|e| NetError::Config(format!("invalid identity: {e}")))?;
        server_crypto.alpn_protocols = vec![ALPN.to_vec()];
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(server_crypto)
                .map_err(|e| transport_error("server config", e))?,
        ));
        server_config.transport_config(transport.clone());

        let endpoint = {
            let _guard = runtime.enter();
            let endpoint =
                Endpoint::client(addr).map_err(|e| transport_error("binding endpoint", e))?;
            endpoint.set_server_config(Some(server_config));
            endpoint
        };
        Ok(Self {
            runtime: Arc::new(runtime),
            endpoint,
            party_id,
            certificates,
            identity,
            config,
            transport,
            provider,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, NetError> {
        self.endpoint
            .local_addr()
            .map_err(|e| transport_error("local address", e))
    }

    /// Connect to all parties, `addresses[j]` is the address of party `j`.
    pub fn connect(self, addresses: &[SocketAddr]) -> Result<Network, NetError> {
        let n = self.certificates.len();
        let me = self.party_id as usize;
        if addresses.len() != n {
            return Err(NetError::Config("one address per party expected".into()));
        }

        let mut client_configs = HashMap::new();
        for j in me + 1..n {
            let mut client_crypto =
                rustls::ClientConfig::builder_with_provider(self.provider.clone())
                    .with_protocol_versions(&[&rustls::version::TLS13])
                    .map_err(|e| transport_error("client config", e))?
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(PinnedServer {
                        certificate: self.certificates[j].clone(),
                        provider: self.provider.clone(),
                    }))
                    .with_client_auth_cert(
                        vec![self.identity.certificate.clone()],
                        self.identity.key.clone_key(),
                    )
                    .map_err(|e| NetError::Config(format!("invalid identity: {e}")))?;
            client_crypto.alpn_protocols = vec![ALPN.to_vec()];
            let mut client_config = quinn::ClientConfig::new(Arc::new(
                QuicClientConfig::try_from(client_crypto)
                    .map_err(|e| transport_error("client config", e))?,
            ));
            client_config.transport_config(self.transport.clone());
            client_configs.insert(j, client_config);
        }

        let endpoint = self.endpoint.clone();
        let certificates = self.certificates.clone();
        let config = self.config;
        let connections = self.runtime.block_on(async move {
            tokio::time::timeout(
                config.connect_timeout,
                establish(endpoint, me, certificates, addresses, client_configs),
            )
            .await
            .map_err(|_| NetError::Transport("timed out connecting to all parties".into()))?
        })?;

        let links = connections
            .into_iter()
            .enumerate()
            .map(|(j, connection)| {
                connection.map(|connection| {
                    Box::new(QuicLink::new(
                        self.runtime.clone(),
                        self.endpoint.clone(),
                        self.party_id,
                        j as PartyId,
                        connection,
                        &config,
                    )) as Box<dyn PeerLink>
                })
            })
            .collect();
        Network::new(self.party_id, links, config.network)
    }
}

/// Bind and connect in one step, `peers[j]` is the address and certificate of party `j`.
pub fn connect(
    party_id: PartyId,
    identity: Identity,
    peers: &[(SocketAddr, CertificateDer<'static>)],
    config: QuicConfig,
) -> Result<Network, NetError> {
    let addr = peers
        .get(party_id as usize)
        .ok_or_else(|| NetError::Config(format!("no address for party {party_id}")))?
        .0;
    let certificates = peers.iter().map(|(_, c)| c.clone()).collect();
    let addresses = peers.iter().map(|(a, _)| *a).collect::<Vec<_>>();
    QuicEndpoint::bind(addr, party_id, identity, certificates, config)?.connect(&addresses)
}

/// Connect to every party with a larger ID and accept a connection from every party with
/// a smaller ID. The output is indexed by party.
async fn establish(
    endpoint: Endpoint,
    me: usize,
    certificates: Vec<CertificateDer<'static>>,
    addresses: &[SocketAddr],
    client_configs: HashMap<usize, quinn::ClientConfig>,
) -> Result<Vec<Option<Connection>>, NetError> {
    let n = certificates.len();
    let dials = (me + 1..n)
        .map(|j| {
            let endpoint = endpoint.clone();
            let client_config = client_configs[&j].clone();
            let addr = addresses[j];
            tokio::spawn(async move {
                // the peer may not be listening yet, so we retry
                loop {
                    let connecting = endpoint
                        .connect_with(client_config.clone(), addr, SERVER_NAME)
                        .map_err(|e| transport_error(&format!("connecting to party {j}"), e))?;
                    match connecting.await {
                        Ok(connection) => return Ok::<_, NetError>((j, connection)),
                        Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
                    }
                }
            })
        })
        .collect::<Vec<_>>();

    let mut connections: Vec<Option<Connection>> = (0..n).map(|_| None).collect();
    let mut accepted = 0;
    while accepted < me {
        let incoming = endpoint
            .accept()
            .await
            .ok_or_else(|| NetError::Transport("endpoint closed".into()))?;
        // a failed handshake (e.g., an unknown certificate) is not fatal
        let Ok(connection) = incoming.await else {
            continue;
        };
        match identify(&connection, &certificates[..me]) {
            Some(j) if connections[j].is_none() => {
                connections[j] = Some(connection);
                accepted += 1;
            }
            _ => connection.close(VarInt::from_u32(CLOSE_VIOLATION), b"unexpected party"),
        }
    }
    for dial in dials {
        let (j, connection) = dial.await.map_err(|e| transport_error("connecting", e))??;
        connections[j] = Some(connection);
    }
    Ok(connections)
}

/// The index of the pinned certificate the peer presented.
fn identify(connection: &Connection, certificates: &[CertificateDer<'static>]) -> Option<usize> {
    let chain = connection
        .peer_identity()?
        .downcast::<Vec<CertificateDer<'static>>>()
        .ok()?;
    let presented = chain.first()?;
    certificates.iter().position(|c| c == presented)
}

/// Accepts exactly one pinned server certificate.
#[derive(Debug)]
struct PinnedServer {
    certificate: CertificateDer<'static>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedServer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if intermediates.is_empty() && end_entity.as_ref() == self.certificate.as_ref() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Accepts the client certificates of a set of pinned parties.
#[derive(Debug)]
struct PinnedClients {
    certificates: Vec<CertificateDer<'static>>,
    provider: Arc<CryptoProvider>,
}

impl ClientCertVerifier for PinnedClients {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        if intermediates.is_empty()
            && self
                .certificates
                .iter()
                .any(|c| c.as_ref() == end_entity.as_ref())
        {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

enum Command {
    Send(StreamId, Vec<u8>),
    /// Close gracefully and signal on the channel when done.
    Close(std::sync::mpsc::Sender<()>),
}

/// What we know about the streams of the peer, to detect when it sent everything.
#[derive(Default)]
struct ReadState {
    /// Data streams that were read to the end.
    finished: u64,
    /// Number of data streams the peer announced when it closed.
    announced: Option<u64>,
}

/// Shared by the tasks that read from one peer.
struct Reader {
    connection: Connection,
    inbox: Arc<Inbox>,
    /// Set when the peer is done or the connection is closed.
    done: watch::Sender<bool>,
    state: Mutex<ReadState>,
    seen: Mutex<HashSet<StreamId>>,
    peer: PartyId,
    max_frame_len: usize,
    /// Bytes of frames that are partially read, they count towards `max_buffered`.
    in_flight: AtomicUsize,
    max_buffered: usize,
}

impl Reader {
    /// Once the peer announced it is done and all its streams ended, no frame will arrive.
    fn check_finished(&self) {
        let state = self.state.lock().unwrap();
        if state.announced == Some(state.finished) {
            self.inbox.close_sender(NetError::Disconnected(self.peer));
            let _ = self.done.send(true);
        }
    }

    /// The peer broke the protocol, close the connection.
    fn violation(&self, reason: &str) {
        self.inbox.close_sender(NetError::Transport(format!(
            "protocol violation by party {}: {reason}",
            self.peer
        )));
        self.connection
            .close(VarInt::from_u32(CLOSE_VIOLATION), reason.as_bytes());
    }
}

struct QuicLink {
    peer: PartyId,
    me: PartyId,
    connection: Connection,
    commands: mpsc::UnboundedSender<Command>,
    inbox: Arc<Inbox>,
    local_closed: Mutex<Option<NetError>>,
    close_timeout: Duration,
    // the runtime and the endpoint must outlive the connection
    endpoint: Endpoint,
    runtime: Arc<Runtime>,
}

impl Drop for QuicLink {
    fn drop(&mut self) {
        // give the endpoint time to send the close of our connection before the runtime
        // stops, otherwise the peer would only notice through a timeout
        let endpoint = self.endpoint.clone();
        let _ = self.runtime.block_on(async move {
            tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle()).await
        });
    }
}

impl QuicLink {
    fn new(
        runtime: Arc<Runtime>,
        endpoint: Endpoint,
        me: PartyId,
        peer: PartyId,
        connection: Connection,
        config: &QuicConfig,
    ) -> Self {
        let inbox = Arc::new(Inbox::new(peer, config.max_buffered));
        let (commands, command_rx) = mpsc::unbounded_channel();
        let (done_tx, done_rx) = watch::channel(false);
        let reader = Arc::new(Reader {
            connection: connection.clone(),
            inbox: inbox.clone(),
            done: done_tx,
            state: Mutex::new(ReadState::default()),
            seen: Mutex::new(HashSet::new()),
            peer,
            max_frame_len: config.max_frame_len,
            in_flight: AtomicUsize::new(0),
            max_buffered: config.max_buffered,
        });

        runtime.spawn(write_frames(
            connection.clone(),
            command_rx,
            done_rx,
            config.close_timeout,
        ));
        runtime.spawn(accept_streams(reader.clone()));
        runtime.spawn(async move {
            let err = reader.connection.closed().await;
            reader.inbox.close_sender(close_error(err, reader.peer));
            let _ = reader.done.send(true);
        });

        Self {
            peer,
            me,
            connection,
            commands,
            inbox,
            local_closed: Mutex::new(None),
            close_timeout: config.close_timeout,
            endpoint,
            runtime,
        }
    }
}

/// The error receivers observe after the connection is closed.
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

/// Write the frames of all streams to the peer in the order they are sent.
async fn write_frames(
    connection: Connection,
    mut commands: mpsc::UnboundedReceiver<Command>,
    mut done: watch::Receiver<bool>,
    close_timeout: Duration,
) {
    let mut streams: HashMap<StreamId, SendStream> = HashMap::new();
    while let Some(command) = commands.recv().await {
        match command {
            Command::Send(stream, frame) => {
                // a failed write means the connection is gone or the peer reset our
                // stream, in both cases the link cannot be used anymore
                if let Err(err) = write_frame(&connection, &mut streams, stream, &frame).await {
                    connection.close(
                        VarInt::from_u32(CLOSE_VIOLATION),
                        err.to_string().as_bytes(),
                    );
                }
            }
            Command::Close(ack) => {
                for stream in streams.values_mut() {
                    let _ = stream.finish();
                }
                if let Ok(mut control) = connection.open_uni().await {
                    let _ = control.write_all(&CONTROL_STREAM.0).await;
                    let _ = control
                        .write_all(&(streams.len() as u64).to_le_bytes())
                        .await;
                    let _ = control.finish();
                }
                // wait until the peer does not read anymore before discarding our data
                let _ = tokio::time::timeout(close_timeout, done.wait_for(|done| *done)).await;
                connection.close(VarInt::from_u32(CLOSE_DONE), b"done");
                let _ = ack.send(());
                return;
            }
        }
    }
}

async fn write_frame(
    connection: &Connection,
    streams: &mut HashMap<StreamId, SendStream>,
    stream: StreamId,
    frame: &[u8],
) -> Result<(), NetError> {
    let send = match streams.entry(stream) {
        std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
        std::collections::hash_map::Entry::Vacant(entry) => {
            let mut send = connection
                .open_uni()
                .await
                .map_err(|e| transport_error("opening stream", e))?;
            send.write_all(&stream.0)
                .await
                .map_err(|e| transport_error("writing", e))?;
            entry.insert(send)
        }
    };
    send.write_all(&(frame.len() as u64).to_le_bytes())
        .await
        .map_err(|e| transport_error("writing", e))?;
    send.write_all(frame)
        .await
        .map_err(|e| transport_error("writing", e))
}

/// Accept the streams of the peer and read their frames into the inbox.
async fn accept_streams(reader: Arc<Reader>) {
    while let Ok(recv) = reader.connection.accept_uni().await {
        tokio::spawn(read_frames(recv, reader.clone()));
    }
}

async fn read_frames(mut recv: RecvStream, reader: Arc<Reader>) {
    let mut header = [0u8; 16];
    if recv.read_exact(&mut header).await.is_err() {
        return;
    }
    let stream = StreamId(header);
    if stream == CONTROL_STREAM {
        let mut count = [0u8; 8];
        if recv.read_exact(&mut count).await.is_ok() {
            let mut state = reader.state.lock().unwrap();
            if state.announced.is_some() {
                drop(state);
                reader.violation("done twice");
                return;
            }
            state.announced = Some(u64::from_le_bytes(count));
        }
        reader.check_finished();
        return;
    }
    // frames of one stream must arrive in order, so every stream ID is used once
    {
        let mut seen = reader.seen.lock().unwrap();
        if seen.len() >= MAX_STREAMS || !seen.insert(stream) {
            drop(seen);
            reader.violation("stream used twice or too many streams");
            return;
        }
    }
    loop {
        let mut len = [0u8; 8];
        match recv.read_exact(&mut len).await {
            Ok(()) => {}
            // the stream ended between two frames
            Err(ReadExactError::FinishedEarly(0)) => {
                reader.state.lock().unwrap().finished += 1;
                reader.check_finished();
                return;
            }
            Err(_) => return,
        }
        let len = u64::from_le_bytes(len);
        if len > reader.max_frame_len as u64 {
            reader.violation("frame too long");
            return;
        }
        let Some(frame) = read_frame(&mut recv, &reader, len as usize).await else {
            return;
        };
        if reader.inbox.push(stream, Instant::now(), frame).is_err() {
            // the inbox reports the buffer limit (or a frame after "done") to the receiver
            reader.violation("unexpected frame");
            return;
        }
    }
}

/// Read a frame of `len` bytes, the buffer only grows as data arrives so that a peer
/// cannot make us allocate memory by announcing long frames.
async fn read_frame(recv: &mut RecvStream, reader: &Reader, len: usize) -> Option<Vec<u8>> {
    const CHUNK: usize = 1 << 20;
    let mut frame = Vec::new();
    // bytes of this frame that we added to `in_flight`
    let mut reserved = 0;
    let complete = loop {
        if frame.len() == len {
            break true;
        }
        let chunk = CHUNK.min(len - frame.len());
        reserved += chunk;
        if reader.in_flight.fetch_add(chunk, Ordering::SeqCst) + chunk > reader.max_buffered {
            reader.violation("too much data in flight");
            break false;
        }
        let start = frame.len();
        frame.resize(start + chunk, 0);
        if recv.read_exact(&mut frame[start..]).await.is_err() {
            break false;
        }
    };
    reader.in_flight.fetch_sub(reserved, Ordering::SeqCst);
    complete.then_some(frame)
}

impl PeerLink for QuicLink {
    fn send(&self, stream: StreamId, frame: Vec<u8>) -> Result<(), NetError> {
        if let Some(err) = self.local_closed.lock().unwrap().clone() {
            return Err(err);
        }
        if let Some(err) = self.inbox.sender_error() {
            // the connection is gone
            return Err(err);
        }
        self.commands
            .send(Command::Send(stream, frame))
            .map_err(|_| NetError::Disconnected(self.peer))
    }

    fn recv(&self, stream: StreamId, deadline: Instant) -> Result<Vec<u8>, NetError> {
        self.inbox.pop(stream, deadline)
    }

    fn abort(&self, reason: &str) {
        self.local_closed
            .lock()
            .unwrap()
            .get_or_insert(NetError::Closed(format!("aborted: {reason}")));
        let mut end = reason.len().min(MAX_REASON_LEN);
        while !reason.is_char_boundary(end) {
            end -= 1;
        }
        self.connection
            .close(VarInt::from_u32(CLOSE_ABORT), &reason.as_bytes()[..end]);
        self.inbox
            .close_receiver(NetError::Closed(format!("aborted: {reason}")));
    }

    fn close(&self) {
        self.local_closed
            .lock()
            .unwrap()
            .get_or_insert(NetError::Closed("link closed".into()));
        let (ack, acked) = std::sync::mpsc::channel();
        if self.commands.send(Command::Close(ack)).is_ok() {
            let _ = acked.recv_timeout(self.close_timeout + Duration::from_secs(1));
        }
        self.inbox.close_receiver(NetError::Closed(format!(
            "party {} closed the link to {}",
            self.me, self.peer
        )));
    }
}
