//! Synthetic credentials only. These test the additive wire contract, not a
//! physical UI or the server's authorization action gates.
use hbb_common::{bytes::Bytes, lan::*, message_proto::*, protobuf::{Message as _, MessageField}, Stream};
use hbb_common::tokio::{self, net::{TcpListener, TcpStream}};
use sodiumoxide::crypto::secretbox;

#[test]
fn password_mode_preserves_legacy_wire_bytes_and_defaults() {
    // Original three-field LanLoginRequest fixture (username u/password p).
    let legacy = [0x0a, 1, b'u', 0x12, 1, b'p', 0x18, 9];
    let parsed = LanLoginRequest::parse_from_bytes(&legacy).unwrap();
    assert_eq!(parsed.access_method, ACCESS_PASSWORD);
    assert!(parsed.temporary_code.is_empty());
    assert_eq!(parsed.write_to_bytes().unwrap(), legacy);
    let new = LanLoginRequest { access_username: "u".into(), access_password: Bytes::from_static(b"p"), credential_revision_hint: 9, ..Default::default() };
    assert_eq!(new.write_to_bytes().unwrap(), legacy);
    assert_eq!(PROTOCOL_VERSION, 1);
}

#[test]
fn optional_methods_roundtrip_without_password_or_code_leak_in_capabilities() {
    for method in [ACCESS_CODE, ACCESS_MANUAL] {
        let mut msg = Message::new();
        msg.set_login_request(LoginRequest { lan_login: MessageField::some(LanLoginRequest {
            access_method: method, temporary_code: if method == ACCESS_CODE { "012345".into() } else { String::new() },
            ..Default::default() }), ..Default::default() });
        let parsed = Message::parse_from_bytes(&msg.write_to_bytes().unwrap()).unwrap();
        let login = parsed.login_request().lan_login.as_ref().unwrap();
        assert_eq!(login.access_method, method);
        assert!(login.access_password.is_empty()); assert!(login.access_username.is_empty());
        assert!(parsed.login_request().password.is_empty());
    }
    let mut reply = Message::new();
    reply.set_lan_access_capabilities(LanAccessCapabilities { version: ACCESS_VERSION, code_enabled: true, manual_enabled: true, ..Default::default() });
    // Exactly version and boolean fields; no code/nonce/credentials.
    assert_eq!(reply.lan_access_capabilities().write_to_bytes().unwrap(), [8, 1, 16, 1, 24, 1]);
}

async fn encrypted_pair() -> (Stream, Stream) {
    sodiumoxide::init().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let client = TcpStream::connect(address).await.unwrap();
    let (server, peer) = listener.accept().await.unwrap();
    let key = secretbox::gen_key();
    let mut client = Stream::from(client, address); let mut server = Stream::from(server, peer);
    client.set_key(key.clone()); server.set_key(key);
    (client, server)
}

#[tokio::test]
async fn probe_capabilities_request_and_pending_cross_encrypted_stream() {
    let (mut client, mut server) = encrypted_pair().await;
    assert!(client.is_secured() && server.is_secured());
    let mut probe = Message::new(); probe.set_lan_access_probe(LanAccessProbe { version: ACCESS_VERSION, ..Default::default() });
    client.send(&probe).await.unwrap();
    let received = server.next_timeout(2000).await.unwrap().unwrap();
    assert_eq!(Message::parse_from_bytes(&received).unwrap().lan_access_probe().version, ACCESS_VERSION);
    let mut reply = Message::new(); reply.set_lan_access_capabilities(LanAccessCapabilities { version: ACCESS_VERSION, manual_enabled: true, ..Default::default() });
    server.send(&reply).await.unwrap();
    let received = client.next_timeout(2000).await.unwrap().unwrap();
    assert!(Message::parse_from_bytes(&received).unwrap().lan_access_capabilities().manual_enabled);
    let mut login = Message::new(); login.set_login_request(LoginRequest { lan_login: MessageField::some(LanLoginRequest { access_method: ACCESS_MANUAL, ..Default::default() }), ..Default::default() });
    client.send(&login).await.unwrap();
    let received = server.next_timeout(2000).await.unwrap().unwrap();
    assert_eq!(Message::parse_from_bytes(&received).unwrap().login_request().lan_login.access_method, ACCESS_MANUAL);
    let mut pending = Message::new(); pending.set_lan_access_pending(LanAccessPending { version: ACCESS_VERSION, timeout_seconds: 60, ..Default::default() });
    server.send(&pending).await.unwrap();
    let received = client.next_timeout(2000).await.unwrap().unwrap();
    assert_eq!(Message::parse_from_bytes(&received).unwrap().lan_access_pending().timeout_seconds, 60);
}
