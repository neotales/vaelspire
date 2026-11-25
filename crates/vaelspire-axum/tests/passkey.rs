//! A software authenticator registers and signs in through the passkey routes.
//!
//! No browser. The authenticator is a P-256 key that builds the same attestation and
//! assertion bytes `webauthn-rs` accepts for a `none` attestation.

#![cfg(all(feature = "passkey", feature = "password", feature = "session"))]

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode, header};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::sync::Arc;
use tower::ServiceExt;
use vaelspire_axum::AuthRouter;
use vaelspire_core::{AuthStore, Id, Timestamp};
use vaelspire_store_sqlite::{SqliteStore, open};

const PASSWORD: &str = "correct horse battery staple";
const RP_ID: &str = "localhost";
const ORIGIN: &str = "http://localhost:8080";

struct SoftPasskey {
    key: SigningKey,
    credential_id: Vec<u8>,
}

impl SoftPasskey {
    fn generate() -> Self {
        let mut seed = [0u8; 32];
        std::fs::File::open("/dev/urandom")
            .expect("urandom")
            .read_exact(&mut seed)
            .expect("urandom");
        let mut credential_id = [0u8; 16];
        std::fs::File::open("/dev/urandom")
            .expect("urandom")
            .read_exact(&mut credential_id)
            .expect("urandom");
        Self {
            key: SigningKey::from_bytes(&seed.into()).expect("signing key"),
            credential_id: credential_id.to_vec(),
        }
    }

    fn register(&self, challenge_b64: &str) -> Value {
        let client_data = client_data("webauthn.create", challenge_b64);
        let auth_data = registration_auth_data(RP_ID, &self.credential_id, &self.public_cose());
        let attestation = attestation_none(&auth_data);
        json!({
            "id": b64url(&self.credential_id),
            "rawId": b64url(&self.credential_id),
            "type": "public-key",
            "response": {
                "attestationObject": b64url(&attestation),
                "clientDataJSON": b64url(&client_data),
            }
        })
    }

    fn login(&self, challenge_b64: &str) -> Value {
        let client_data = client_data("webauthn.get", challenge_b64);
        let auth_data = assertion_auth_data(RP_ID, 1);
        let mut signed = auth_data.clone();
        signed.extend(Sha256::digest(&client_data));
        let signature: Signature = self.key.sign(&signed);
        json!({
            "id": b64url(&self.credential_id),
            "rawId": b64url(&self.credential_id),
            "type": "public-key",
            "response": {
                "authenticatorData": b64url(&auth_data),
                "clientDataJSON": b64url(&client_data),
                "signature": b64url(&der_signature(&signature)),
            }
        })
    }

    fn public_cose(&self) -> Vec<u8> {
        let point = self.key.verifying_key().to_sec1_point(false);
        let bytes = point.as_ref();
        assert_eq!(bytes.len(), 65);
        assert_eq!(bytes[0], 0x04);
        cose_es256(&bytes[1..33], &bytes[33..65])
    }
}

fn client_data(kind: &str, challenge_b64: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "type": kind,
        "challenge": challenge_b64,
        "origin": ORIGIN,
    }))
    .expect("client data")
}

fn rp_id_hash(rp_id: &str) -> [u8; 32] {
    Sha256::digest(rp_id.as_bytes()).into()
}

fn registration_auth_data(rp_id: &str, credential_id: &[u8], cose: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend(rp_id_hash(rp_id));
    data.push(0x45); // UP | UV | AT
    data.extend(0u32.to_be_bytes());
    data.extend([0u8; 16]);
    data.extend(u16::try_from(credential_id.len()).unwrap().to_be_bytes());
    data.extend(credential_id);
    data.extend(cose);
    data
}

fn assertion_auth_data(rp_id: &str, counter: u32) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend(rp_id_hash(rp_id));
    data.push(0x05); // UP | UV
    data.extend(counter.to_be_bytes());
    data
}

fn cose_es256(x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut key = vec![0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
    key.extend(x);
    key.extend([0x22, 0x58, 0x20]);
    key.extend(y);
    key
}

fn attestation_none(auth_data: &[u8]) -> Vec<u8> {
    let mut object = vec![
        0xA3,
        0x63,
        b'f',
        b'm',
        b't',
        0x64,
        b'n',
        b'o',
        b'n',
        b'e',
        0x67,
        b'a',
        b't',
        b't',
        b'S',
        b't',
        b'm',
        b't',
        0xA0,
        0x68,
        b'a',
        b'u',
        b't',
        b'h',
        b'D',
        b'a',
        b't',
        b'a',
        0x58,
        u8::try_from(auth_data.len()).expect("authData fits in one byte"),
    ];
    object.extend(auth_data);
    object
}

fn der_signature(signature: &Signature) -> Vec<u8> {
    let (r, s) = signature.split_bytes();
    let mut body = der_int(r.as_slice());
    body.extend(der_int(s.as_slice()));
    let mut out = vec![0x30, u8::try_from(body.len()).expect("der length")];
    out.extend(body);
    out
}

fn der_int(bytes: &[u8]) -> Vec<u8> {
    let mut value = bytes.to_vec();
    while value.len() > 1 && value[0] == 0 && value[1] & 0x80 == 0 {
        value.remove(0);
    }
    if value[0] & 0x80 != 0 {
        value.insert(0, 0);
    }
    let mut out = vec![0x02, u8::try_from(value.len()).expect("int length")];
    out.extend(value);
    out
}

fn b64url(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let n =
            (u32::from(bytes[i]) << 16) | (u32::from(bytes[i + 1]) << 8) | u32::from(bytes[i + 2]);
        out.push(char::from(TABLE[((n >> 18) & 63) as usize]));
        out.push(char::from(TABLE[((n >> 12) & 63) as usize]));
        out.push(char::from(TABLE[((n >> 6) & 63) as usize]));
        out.push(char::from(TABLE[(n & 63) as usize]));
        i += 3;
    }
    if i < bytes.len() {
        let mut n = u32::from(bytes[i]) << 16;
        out.push(char::from(TABLE[((n >> 18) & 63) as usize]));
        if i + 1 < bytes.len() {
            n |= u32::from(bytes[i + 1]) << 8;
            out.push(char::from(TABLE[((n >> 12) & 63) as usize]));
            out.push(char::from(TABLE[((n >> 6) & 63) as usize]));
        } else {
            out.push(char::from(TABLE[((n >> 12) & 63) as usize]));
        }
    }
    out
}

struct Database {
    _file: tempfile::NamedTempFile,
    pool: sqlx::SqlitePool,
    store: Arc<SqliteStore>,
}

async fn database() -> Database {
    let file = tempfile::NamedTempFile::new().expect("temporary database");
    let path = file.path().to_str().expect("UTF-8 path");
    let store = Arc::new(open(path).await.expect("schema"));
    let pool = sqlx::SqlitePool::connect(path)
        .await
        .expect("inspection pool");
    Database {
        _file: file,
        pool,
        store,
    }
}

fn router(database: &Database, tenant: Id) -> Router {
    AuthRouter::new(Arc::clone(&database.store), tenant, [9; 32], false).into_router()
}

fn get(path: &str, cookie: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().method("GET").uri(path);
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(Body::empty()).expect("request")
}

fn post(path: &str, body: &Value, cookie: Option<&str>, csrf: &str) -> Request<Body> {
    let mut cookies = format!("neotales.csrf={csrf}");
    if let Some(cookie) = cookie {
        cookies = format!("neotales.session={cookie}; {cookies}");
    }
    Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ORIGIN, "http://localhost")
        .header(header::COOKIE, cookies)
        .header("x-csrf-token", csrf)
        .body(Body::from(body.to_string()))
        .expect("request")
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
    let response = app.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, headers, bytes.to_vec())
}

fn set_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|text| {
            let (key, value) = text.split(';').next()?.split_once('=')?;
            (key == name).then(|| value.to_owned())
        })
}

fn expect_status(status: StatusCode, body: &[u8], expected: StatusCode) {
    assert_eq!(status, expected, "{}", String::from_utf8_lossy(body));
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One registration, login, replay, and migration scenario.
async fn passkey_register_and_login() {
    let database = database().await;
    let tenant = Id::now_v7();
    database
        .store
        .create_tenant(tenant, "passkey", Timestamp::now_utc())
        .await
        .expect("tenant");
    let app = router(&database, tenant);
    let (_, headers, _) = send(&app, get("/session", None)).await;
    let csrf = set_cookie(&headers, "neotales.csrf").expect("csrf cookie");

    let refused = Request::builder()
        .method("POST")
        .uri("/passkey/login/begin")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("neotales.csrf={csrf}"))
        .header("x-csrf-token", &csrf)
        .body(Body::from(
            json!({"rp_id": RP_ID, "origin": ORIGIN, "email": "ada@example.test"}).to_string(),
        ))
        .expect("request");
    let (status, _, body) = send(&app, refused).await;
    expect_status(status, &body, StatusCode::FORBIDDEN);

    let email = "ada@example.test";
    let credentials = json!({"email": email, "password": PASSWORD});
    let (status, _, body) = send(&app, post("/sign-up", &credentials, None, &csrf)).await;
    expect_status(status, &body, StatusCode::CREATED);
    let (status, headers, body) = send(&app, post("/sign-in", &credentials, None, &csrf)).await;
    expect_status(status, &body, StatusCode::OK);
    let session = set_cookie(&headers, "neotales.session").expect("session cookie");

    let party = json!({"rp_id": RP_ID, "origin": ORIGIN});
    let (status, _, body) = send(
        &app,
        post("/passkey/register/begin", &party, Some(&session), &csrf),
    )
    .await;
    expect_status(status, &body, StatusCode::OK);
    let started: Value = serde_json::from_slice(&body).expect("challenge json");
    assert_eq!(started["publicKey"]["rp"]["id"], RP_ID);
    let challenge = started["publicKey"]["challenge"]
        .as_str()
        .expect("challenge")
        .to_owned();

    let authenticator = SoftPasskey::generate();
    let (status, _, body) = send(
        &app,
        post(
            "/passkey/register/finish",
            &json!({
                "rp_id": RP_ID,
                "origin": ORIGIN,
                "credential": authenticator.register(&challenge),
            }),
            Some(&session),
            &csrf,
        ),
    )
    .await;
    expect_status(status, &body, StatusCode::NO_CONTENT);

    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_passkey")
        .fetch_one(&database.pool)
        .await
        .expect("passkey row");
    assert_eq!(stored, 1);
    let ceremony: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_webauthn_challenge WHERE kind='passkey_register'",
    )
    .fetch_one(&database.pool)
    .await
    .expect("ceremony");
    assert_eq!(ceremony, 0, "finish deletes the registration ceremony");

    let (status, _, body) = send(
        &app,
        post(
            "/passkey/login/begin",
            &json!({"rp_id": RP_ID, "origin": ORIGIN, "email": email}),
            None,
            &csrf,
        ),
    )
    .await;
    expect_status(status, &body, StatusCode::OK);
    let started: Value = serde_json::from_slice(&body).expect("login challenge");
    let challenge = started["publicKey"]["challenge"]
        .as_str()
        .expect("login challenge")
        .to_owned();

    let (status, headers, body) = send(
        &app,
        post(
            "/passkey/login/finish",
            &json!({
                "rp_id": RP_ID,
                "origin": ORIGIN,
                "credential": authenticator.login(&challenge),
            }),
            None,
            &csrf,
        ),
    )
    .await;
    expect_status(status, &body, StatusCode::OK);
    let passkey_session = set_cookie(&headers, "neotales.session").expect("passkey session");
    assert_ne!(passkey_session, session);

    let (status, _, _) = send(
        &app,
        get(
            "/session",
            Some(&format!("neotales.session={passkey_session}")),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let login_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_webauthn_challenge WHERE kind='passkey_login'",
    )
    .fetch_one(&database.pool)
    .await
    .expect("login ceremony");
    assert_eq!(login_rows, 0, "finish deletes the login ceremony");
}
