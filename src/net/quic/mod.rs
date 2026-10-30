//! QUIC transport: one QUIC connection per pair of parties, authenticated with mutual
//! TLS 1.3 and certificates that are pinned per party.
//!
//! Logical sessions are multiplexed over one unidirectional QUIC stream per direction.
//! Each frame carries its session's [StreamId], a length and the payload. The physical
//! streams live for the connection, so completed sessions consume no QUIC stream credit.
//!
//! Party `i` connects to every party `j > i` and accepts connections from every
//! party `j < i`. Both sides check that the peer presents exactly the pinned certificate
//! of the expected party, and TLS checks that the peer holds the corresponding key.
//!
//! A graceful close finishes our byte stream and waits for the peer to finish its own
//! before closing the connection. EOF between frames signals a graceful close; partial
//! frames and stream resets fail the link and wake waiting sessions immediately.

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use quinn::{
    Connection, Endpoint, IdleTimeout, TransportConfig, VarInt,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use rustls::{
    DigitallySignedStruct, DistinguishedName, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};
use tokio::runtime::Runtime;

mod transport;
use transport::QuicLink;

use super::{NetError, Network, NetworkConfig, PartyId, PeerLink};

const ALPN: &[u8] = b"multiparty-gc/2";
/// The certificates are pinned, so the server name is not used for authentication.
const SERVER_NAME: &str = "multiparty-gc";
const CLOSE_DONE: u32 = 0;
const CLOSE_ABORT: u32 = 1;
const CLOSE_VIOLATION: u32 = 2;
/// Abort reasons are truncated to fit into a single packet.
const MAX_REASON_LEN: usize = 512;

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
    /// Allocation budget per peer in each direction, including frame overhead.
    /// Incoming queued and partial frames share one budget; pending writes use another.
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
            .max_concurrent_uni_streams(VarInt::from_u32(1))
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
