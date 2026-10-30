//! Malformed peers exercise the same reader used by authenticated connections.

use super::*;
use crate::net::{
    buffer::FRAME_OVERHEAD,
    quic::{Identity, certificate_from_pem},
};
use rustls::pki_types::{PrivateKeyDer, pem::PemObject};

struct Pair {
    _client: Endpoint,
    _server: Endpoint,
    connection: Connection,
    state: Arc<LinkState>,
}

async fn pair(budget: usize) -> Pair {
    let (cert, key) = Identity::generate_pem().unwrap();
    let cert = certificate_from_pem(cert.as_bytes()).unwrap();
    let key = PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap();
    let mut server_config = quinn::ServerConfig::with_single_cert(vec![cert.clone()], key).unwrap();
    let mut transport = quinn::TransportConfig::default();
    transport.send_window(1024);
    server_config.transport_config(Arc::new(transport));
    let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let client_config = quinn::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
    let mut client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(client_config);
    let (outgoing, incoming) = tokio::join!(
        client
            .connect(server.local_addr().unwrap(), "multiparty-gc")
            .unwrap(),
        async { server.accept().await.unwrap().await.unwrap() }
    );
    let (done, _) = watch::channel(false);
    Pair {
        _client: client,
        _server: server,
        connection: outgoing.unwrap(),
        state: Arc::new(LinkState {
            connection: incoming,
            inbox: Arc::new(Inbox::new(0, budget)),
            done,
            peer: 0,
            max_frame_len: 1024,
        }),
    }
}

async fn read_to_failure(pair: &Pair) -> NetError {
    tokio::time::timeout(Duration::from_secs(2), read_connection(pair.state.clone()))
        .await
        .expect("a terminal stream error must be handled promptly");
    pair.state
        .inbox
        .pop(StreamId([0; 16]), Instant::now())
        .unwrap_err()
}

#[tokio::test]
async fn truncated_headers_and_payloads_fail_the_link() {
    for bytes in [
        vec![0; 10],
        [vec![0; 16], 5u64.to_le_bytes().to_vec(), vec![1; 2]].concat(),
    ] {
        let pair = pair(10 * FRAME_OVERHEAD).await;
        let mut send = pair.connection.open_uni().await.unwrap();
        send.write_all(&bytes).await.unwrap();
        send.finish().unwrap();
        let err = read_to_failure(&pair).await;
        assert!(matches!(err, NetError::Transport(_)), "{err:?}");
        assert!(pair.state.connection.close_reason().is_some());
    }
}

#[tokio::test]
async fn resetting_a_stream_fails_the_link() {
    let pair = pair(10 * FRAME_OVERHEAD).await;
    let mut send = pair.connection.open_uni().await.unwrap();
    send.write_all(&[0; 24]).await.unwrap();
    send.reset(VarInt::from_u32(7)).unwrap();
    assert!(matches!(
        read_to_failure(&pair).await,
        NetError::Transport(_)
    ));
}

#[tokio::test]
async fn empty_frame_flood_exhausts_receive_budget() {
    let pair = pair(2 * FRAME_OVERHEAD).await;
    let mut send = pair.connection.open_uni().await.unwrap();
    send.write_all(&[0; 24 * 3]).await.unwrap();
    send.finish().unwrap();
    assert!(matches!(
        read_to_failure(&pair).await,
        NetError::BufferLimit(0)
    ));
}

#[tokio::test]
async fn oversized_frame_is_rejected_from_its_header() {
    let pair = pair(10 * FRAME_OVERHEAD).await;
    let mut send = pair.connection.open_uni().await.unwrap();
    send.write_all(&[0; 16]).await.unwrap();
    send.write_all(&u64::MAX.to_le_bytes()).await.unwrap();
    // Keep the stream open without a payload: validation must not wait for it.
    assert!(matches!(
        read_to_failure(&pair).await,
        NetError::Malformed { party: 0, .. }
    ));
}

#[tokio::test]
async fn close_interrupts_a_writer_stalled_on_flow_control() {
    let pair = pair(10 * FRAME_OVERHEAD).await;
    let connection = pair.state.connection.clone();
    let endpoint = pair._server.clone();
    let closing = tokio::task::spawn_blocking(move || {
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .unwrap(),
        );
        let config = QuicConfig {
            close_timeout: Duration::from_millis(50),
            ..Default::default()
        };
        let link = QuicLink::new(runtime, endpoint, 1, 0, connection, &config);
        // The raw peer never accepts this stream; the 1 KiB send window fills.
        link.send(StreamId([0; 16]), vec![0; 1 << 20]).unwrap();
        link.close();
        assert!(link.state.connection.close_reason().is_some());
    });
    tokio::time::timeout(Duration::from_secs(6), closing)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn graceful_close_mid_stream_keeps_queued_frames() {
    let pair = pair(10 * FRAME_OVERHEAD).await;
    let reader = tokio::spawn(read_connection(pair.state.clone()));
    let stream = StreamId([0; 16]);
    let mut send = pair.connection.open_uni().await.unwrap();
    send.write_all(&[stream.0.as_slice(), &3u64.to_le_bytes(), &[1, 2, 3]].concat())
        .await
        .unwrap();
    // let the reader queue the frame, then close gracefully without finishing the stream
    tokio::time::sleep(Duration::from_millis(200)).await;
    pair.connection.close(VarInt::from_u32(CLOSE_DONE), b"done");
    tokio::time::timeout(Duration::from_secs(2), reader)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        pair.state.inbox.pop(stream, Instant::now()).unwrap(),
        vec![1, 2, 3]
    );
    assert!(matches!(
        pair.state.inbox.pop(stream, Instant::now()),
        Err(NetError::Disconnected(0))
    ));
}

#[tokio::test]
async fn full_send_queue_is_reported_as_ours() {
    let pair = pair(10 * FRAME_OVERHEAD).await;
    let connection = pair.state.connection.clone();
    let endpoint = pair._server.clone();
    let sending = tokio::task::spawn_blocking(move || {
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .unwrap(),
        );
        let config = QuicConfig {
            close_timeout: Duration::from_millis(50),
            max_buffered: (1 << 20) + FRAME_OVERHEAD + 100,
            ..Default::default()
        };
        let link = QuicLink::new(runtime, endpoint, 1, 0, connection, &config);
        // The raw peer never reads, so the first frame stays queued behind flow control.
        link.send(StreamId([0; 16]), vec![0; 1 << 20]).unwrap();
        let err = link.send(StreamId([0; 16]), vec![0; 1 << 20]).unwrap_err();
        link.close();
        err
    });
    let err = tokio::time::timeout(Duration::from_secs(6), sending)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(err, NetError::SendQueueFull(0)), "{err:?}");
}
