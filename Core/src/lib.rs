use bale_signaling::auth::{AuthOutcome, BaleAuth};
use bale_signaling::BaleSignaling;
use lk_signaling::{PeerId, Signaling, TokenStore};
use lktunnel::manager::{ActivationDriver, ClientTunnelManager, SessionEvent};
use lktunnel::quic_identity::{self, PeerIdentity};
use lktunnel::socks5_quic::Socks5Error;
use lktunnel::LkTunnel;
use serde_json::{json, Value};
use std::ffi::{c_char, CStr, CString};
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;

type StateCallback = extern "C" fn(u64, i32, u16, i32);
type Failure = (i32, i32);

const CONNECTED: i32 = 1;
const CLOSED: i32 = 2;
const DIALING: i32 = 10;
const WAITING_FOR_ROOM: i32 = 11;
const STARTING_PROXY: i32 = 12;
const SIGNALING_FAILED: i32 = -1;
const CALL_FAILED: i32 = -2;
const ROOM_FAILED: i32 = -3;
const PROXY_BIND_FAILED: i32 = -4;
const PROXY_TRANSPORT_FAILED: i32 = -5;

struct MemoryToken(Mutex<Option<Vec<u8>>>);

impl TokenStore for MemoryToken {
    fn load(&self) -> Option<Vec<u8>> {
        self.0.lock().unwrap().clone()
    }
    fn save(&self, bytes: &[u8]) {
        *self.0.lock().unwrap() = Some(bytes.to_vec());
    }
    fn clear(&self) {
        *self.0.lock().unwrap() = None;
    }
}

struct Session {
    id: u64,
    stop: watch::Sender<bool>,
}

static SESSION: Mutex<Option<Session>> = Mutex::new(None);

unsafe fn input(pointer: *const c_char) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(pointer) }
        .to_str()
        .ok()
        .map(str::to_owned)
}

fn result(value: Value) -> *mut c_char {
    CString::new(value.to_string())
        .map(CString::into_raw)
        .unwrap_or(ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn bale_free_string(value: *mut c_char) {
    if !value.is_null() {
        drop(unsafe { CString::from_raw(value) });
    }
}

#[no_mangle]
pub unsafe extern "C" fn bale_request_code(phone: *const c_char) -> *mut c_char {
    let Some(phone) = (unsafe { input(phone) }) else {
        return result(json!({"error":"invalid_phone"}));
    };
    if !(8..=15).contains(&phone.len()) || !phone.bytes().all(|b| b.is_ascii_digit()) {
        return result(json!({"error":"invalid_phone"}));
    }
    result(lktunnel::runtime().block_on(async {
        let auth = BaleAuth::new();
        match timeout(Duration::from_secs(25), auth.start_phone_auth(&phone)).await {
            Ok(Ok(start)) => json!({"transaction":start.transaction_hash}),
            _ => json!({"error":"code_request_failed"}),
        }
    }))
}

#[no_mangle]
pub unsafe extern "C" fn bale_verify_code(
    transaction: *const c_char,
    code: *const c_char,
) -> *mut c_char {
    let (Some(transaction), Some(code)) = (unsafe { input(transaction) }, unsafe { input(code) })
    else {
        return result(json!({"error":"invalid_code"}));
    };
    if transaction.is_empty()
        || !(3..=12).contains(&code.len())
        || !code.bytes().all(|b| b.is_ascii_digit())
    {
        return result(json!({"error":"invalid_code"}));
    }
    result(lktunnel::runtime().block_on(async {
        let auth = BaleAuth::new();
        match timeout(
            Duration::from_secs(25),
            auth.submit_otp(&transaction, &code),
        )
        .await
        {
            Ok(Ok(AuthOutcome::Authenticated { access_token })) => json!({"token":access_token}),
            Ok(Ok(AuthOutcome::NeedsSignupName { .. })) => {
                json!({"error":"existing_account_required"})
            }
            _ => json!({"error":"code_verification_failed"}),
        }
    }))
}

async fn connect(
    id: u64,
    signaling: Arc<BaleSignaling>,
    peer_id: &str,
    port: u16,
    allow_port_fallback: bool,
    state: StateCallback,
) -> Failure {
    signaling.auto_load_token();
    let driver = ActivationDriver::new(signaling.clone());
    let manager = ClientTunnelManager::new(signaling.clone(), driver);
    let mut events = manager.events();
    if timeout(Duration::from_secs(18), signaling.wait_until_ready())
        .await
        .is_err()
    {
        return (SIGNALING_FAILED, 0);
    }
    let Some(peer) = signaling.resolve_peer(peer_id).await else {
        return (CALL_FAILED, 0);
    };
    state(id, DIALING, 0, 0);
    if !matches!(
        timeout(Duration::from_secs(25), manager.place_call(peer.clone())).await,
        Ok(Ok(()))
    ) {
        return (CALL_FAILED, 0);
    }
    state(id, WAITING_FOR_ROOM, 0, 0);
    let established = timeout(Duration::from_secs(35), async {
        while let Some(event) = events.recv().await {
            match event {
                SessionEvent::Connected { peer_id, tunnel } if peer_id == peer => {
                    return Some(tunnel)
                }
                SessionEvent::Failed { peer_id } | SessionEvent::Disconnected { peer_id }
                    if peer_id == peer =>
                {
                    return None
                }
                _ => {}
            }
        }
        None
    })
    .await;
    let Ok(Some(tunnel)) = established else {
        return (ROOM_FAILED, 0);
    };
    state(id, STARTING_PROXY, 0, 0);
    let proxy = tokio::select! {
        biased;
        _ = wait_for_session_end(&mut events, &peer) => return (PROXY_TRANSPORT_FAILED, 0),
        result = start_proxy(&tunnel, port, allow_port_fallback) => result,
    };
    let (address, port_conflict) = match proxy {
        Ok(proxy) => proxy,
        Err(failure) => return failure,
    };
    state(id, CONNECTED, address.port(), port_conflict);
    wait_for_session_end(&mut events, &peer).await;
    (CLOSED, 0)
}

async fn wait_for_session_end(events: &mut mpsc::UnboundedReceiver<SessionEvent>, peer: &PeerId) {
    while let Some(event) = events.recv().await {
        if matches!(
            event,
            SessionEvent::Failed { peer_id } | SessionEvent::Disconnected { peer_id } if &peer_id == peer
        ) {
            return;
        }
    }
}

async fn start_proxy(
    tunnel: &Arc<LkTunnel>,
    port: u16,
    allow_port_fallback: bool,
) -> Result<(SocketAddr, i32), Failure> {
    if !matches!(
        timeout(Duration::from_secs(20), tunnel.ensure_quic_client()).await,
        Ok(Ok(()))
    ) {
        return Err((PROXY_TRANSPORT_FAILED, 0));
    }
    let (address, port_conflict) = match tunnel.enable_socks5_server(port).await {
        Ok(address) => (address, 0),
        Err(Socks5Error::Bind(error))
            if allow_port_fallback && port != 0 && error.kind() == ErrorKind::AddrInUse =>
        {
            let address = tunnel.enable_socks5_server(0).await.map_err(bind_failure)?;
            (address, error.raw_os_error().unwrap_or(0))
        }
        Err(error) => return Err(bind_failure(error)),
    };
    if !address.ip().is_loopback() {
        tunnel.disable_socks5_server();
        return Err((PROXY_BIND_FAILED, 0));
    }
    Ok((address, port_conflict))
}

fn bind_failure(error: Socks5Error) -> Failure {
    let errno = match error {
        Socks5Error::Bind(error) => error.raw_os_error().unwrap_or(0),
        _ => 0,
    };
    (PROXY_BIND_FAILED, errno)
}

#[no_mangle]
pub unsafe extern "C" fn bale_validate_tls_profile(profile: *const c_char) -> bool {
    (unsafe { input(profile) }).is_some_and(|profile| {
        PeerIdentity::from_json(&profile)
            .and_then(PeerIdentity::client_config)
            .is_ok()
    })
}

#[no_mangle]
pub unsafe extern "C" fn bale_start_socks(
    token: *const c_char,
    peer: *const c_char,
    port: u16,
    allow_port_fallback: bool,
    tls_profile: *const c_char,
    state: StateCallback,
) -> u64 {
    let (Some(token), Some(peer)) = (unsafe { input(token) }, unsafe { input(peer) }) else {
        return 0;
    };
    if token.is_empty() || port == 0 || !peer.parse::<i32>().is_ok_and(|id| id > 0) {
        return 0;
    }
    let mut session = SESSION.lock().unwrap();
    if session.is_some() {
        return 0;
    }
    let Some(profile) = (unsafe { input(tls_profile) }) else {
        return 0;
    };
    if quic_identity::set_client_profile(Some(&profile)).is_err() {
        return 0;
    }
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let (stop, mut stopped) = watch::channel(false);
    *session = Some(Session { id, stop });
    lktunnel::runtime().spawn(async move {
        lktunnel::dispatcher::init();
        let signing =
            BaleSignaling::new(Arc::new(MemoryToken(Mutex::new(Some(token.into_bytes())))));
        let (outcome, errno) = tokio::select! {
            result = connect(id, signing.clone(), &peer, port, allow_port_fallback, state) => result,
            _ = stopped.changed() => (CLOSED, 0),
        };
        signing.disconnect().await;
        let _ = quic_identity::set_client_profile(None);
        *SESSION.lock().unwrap() = None;
        state(id, outcome, 0, errno);
    });
    id
}

#[no_mangle]
pub extern "C" fn bale_stop(id: u64) {
    let session = SESSION.lock().unwrap();
    if let Some(session) = session.as_ref().filter(|session| session.id == id) {
        let _ = session.stop.send(true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn mutual_tls_accepts_the_pair_and_rejects_unknown_issuers() {
        use rcgen::{
            BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa,
            KeyPair, KeyUsagePurpose,
        };

        fn authority() -> (Certificate, KeyPair) {
            let mut params = CertificateParams::default();
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
            let key = KeyPair::generate().unwrap();
            (params.self_signed(&key).unwrap(), key)
        }
        fn identity(
            issuer: &(Certificate, KeyPair),
            trusted: &Certificate,
            server: bool,
        ) -> PeerIdentity {
            let key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::new(vec!["lktunnel".to_owned()]).unwrap();
            params.extended_key_usages = vec![if server {
                ExtendedKeyUsagePurpose::ServerAuth
            } else {
                ExtendedKeyUsagePurpose::ClientAuth
            }];
            let cert = params.signed_by(&key, &issuer.0, &issuer.1).unwrap();
            PeerIdentity::from_json(
                &json!({
                    "certificate": cert.pem(),
                    "private_key": key.serialize_pem(),
                    "ca_certificate": trusted.pem()
                })
                .to_string(),
            )
            .unwrap()
        }
        async fn exchange(server: quinn::ServerConfig, client: quinn::ClientConfig) -> bool {
            let loopback = "127.0.0.1:0".parse().unwrap();
            let server = quinn::Endpoint::server(server, loopback).unwrap();
            let mut client_endpoint = quinn::Endpoint::client(loopback).unwrap();
            client_endpoint.set_default_client_config(client);
            let address = server.local_addr().unwrap();
            let server_io = async {
                let connection = server.accept().await?.await.ok()?;
                let (mut send, mut recv) = connection.accept_bi().await.ok()?;
                let mut request = [0; 4];
                recv.read_exact(&mut request).await.ok()?;
                if &request != b"ping" {
                    return None;
                }
                send.write_all(b"pong").await.ok()?;
                send.finish().ok()?;
                let _ = send.stopped().await;
                Some(())
            };
            let client_io = async {
                let connection = client_endpoint
                    .connect(address, "lktunnel")
                    .ok()?
                    .await
                    .ok()?;
                let (mut send, mut recv) = connection.open_bi().await.ok()?;
                send.write_all(b"ping").await.ok()?;
                send.finish().ok()?;
                let mut response = [0; 4];
                recv.read_exact(&mut response).await.ok()?;
                (&response == b"pong").then_some(())
            };
            timeout(Duration::from_secs(5), async {
                tokio::join!(server_io, client_io)
            })
            .await
            .is_ok_and(|(server, client)| server.is_some() && client.is_some())
        }

        let paired = authority();
        let stranger = authority();
        let server = || identity(&paired, &paired.0, true).server_config().unwrap();
        assert!(
            exchange(
                server(),
                identity(&paired, &paired.0, false).client_config().unwrap()
            )
            .await
        );
        assert!(
            !exchange(
                server(),
                identity(&stranger, &paired.0, false)
                    .client_config()
                    .unwrap()
            )
            .await
        );
        assert!(
            !exchange(
                server(),
                identity(&paired, &stranger.0, false)
                    .client_config()
                    .unwrap()
            )
            .await
        );
    }

    #[tokio::test]
    async fn session_end_ignores_events_for_other_peers() {
        struct TestPeer(&'static str);
        impl lk_signaling::PeerRef for TestPeer {
            fn id_str(&self) -> &str {
                self.0
            }
        }

        let peer = PeerId::new(TestPeer("current"));
        let other = PeerId::new(TestPeer("other"));
        let (sender, mut events) = mpsc::unbounded_channel();
        sender
            .send(SessionEvent::Failed { peer_id: other })
            .unwrap();
        sender
            .send(SessionEvent::Disconnected {
                peer_id: peer.clone(),
            })
            .unwrap();

        timeout(
            Duration::from_secs(1),
            wait_for_session_end(&mut events, &peer),
        )
        .await
        .expect("session close should interrupt the pending proxy start");
        assert!(matches!(
            events.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn socks_client_waits_for_quic_without_closing_the_socket() {
        timeout(Duration::from_secs(12), async {
            let (client, server) = lktunnel::connect_loopback();
            let proxy = client.enable_socks5_server(0).await.unwrap();
            let mut socket = TcpStream::connect(proxy).await.unwrap();
            socket.write_all(&[5, 1, 0]).await.unwrap();
            let mut reply = [0; 2];
            assert!(timeout(Duration::from_millis(150), socket.readable())
                .await
                .is_err());
            server.start_server().unwrap();
            socket.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, [5, 0]);
            client.disconnect();
            server.disconnect();
        })
        .await
        .expect("waiting SOCKS5 client did not wake when QUIC became ready");
    }

    #[tokio::test]
    async fn socks_proxy_binds_to_loopback_and_forwards_tcp() {
        timeout(Duration::from_secs(30), async {
            let (client, server) = lktunnel::connect_loopback();
            // Permit the local echo fixture in this test process only.
            lktunnel::socks5_quic::set_ssrf_filter_enabled(false);
            server.start_server().unwrap();
            let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let preferred = occupied.local_addr().unwrap().port();
            let (state, errno) = start_proxy(&client, preferred, false).await.unwrap_err();
            assert_eq!(state, PROXY_BIND_FAILED);
            assert_eq!(
                std::io::Error::from_raw_os_error(errno).kind(),
                ErrorKind::AddrInUse
            );
            let (proxy, conflict) = start_proxy(&client, preferred, true).await.unwrap();
            assert_eq!(proxy.ip(), std::net::Ipv4Addr::LOCALHOST);
            assert_ne!(proxy.port(), preferred);
            assert_eq!(
                std::io::Error::from_raw_os_error(conflict).kind(),
                ErrorKind::AddrInUse
            );
            let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let echo_port = echo.local_addr().unwrap().port();
            let echo_task = tokio::spawn(async move {
                let (mut socket, _) = echo.accept().await.unwrap();
                let mut payload = [0; 4];
                socket.read_exact(&mut payload).await.unwrap();
                socket.write_all(&payload).await.unwrap();
            });

            let mut socket = TcpStream::connect(proxy).await.unwrap();
            socket.write_all(&[5, 1, 0]).await.unwrap();
            let mut method = [0; 2];
            socket.read_exact(&mut method).await.unwrap();
            assert_eq!(method, [5, 0]);
            let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
            request.extend_from_slice(&echo_port.to_be_bytes());
            socket.write_all(&request).await.unwrap();
            let mut reply = [0; 10];
            socket.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply[..4], &[5, 0, 0, 1]);
            socket.write_all(b"bale").await.unwrap();
            let mut echoed = [0; 4];
            socket.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, b"bale");
            echo_task.await.unwrap();
            client.disconnect();
            server.disconnect();
        })
        .await
        .expect("SOCKS5 round trip timed out");
    }
}
