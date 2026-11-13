use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use serde_json::Value;
use std::sync::{Arc, Mutex, OnceLock};

pub struct PeerIdentity {
    certificate: CertificateDer<'static>,
    private_key: PrivateKeyDer<'static>,
    roots: Arc<RootCertStore>,
}

impl PeerIdentity {
    pub fn from_json(profile: &str) -> Result<Self, String> {
        if profile.len() > 65_536 {
            return Err("identity profile too large".into());
        }
        let value: Value = serde_json::from_str(profile).map_err(|_| "invalid identity profile")?;
        let field = |name| value[name].as_str().ok_or("missing identity field");
        let certificate = CertificateDer::from_pem_slice(field("certificate")?.as_bytes())
            .map_err(|_| "invalid certificate")?;
        let private_key = PrivateKeyDer::from_pem_slice(field("private_key")?.as_bytes())
            .map_err(|_| "invalid private key")?;
        let ca = CertificateDer::from_pem_slice(field("ca_certificate")?.as_bytes())
            .map_err(|_| "invalid CA certificate")?;
        let mut roots = RootCertStore::empty();
        roots.add(ca).map_err(|_| "invalid trust anchor")?;
        Ok(Self {
            certificate,
            private_key,
            roots: Arc::new(roots),
        })
    }

    pub fn client_config(self) -> Result<quinn::ClientConfig, String> {
        let tls = ClientConfig::builder()
            .with_root_certificates(self.roots)
            .with_client_auth_cert(vec![self.certificate], self.private_key)
            .map_err(|_| "invalid client identity")?;
        let crypto =
            QuicClientConfig::try_from(tls).map_err(|_| "invalid client TLS configuration")?;
        Ok(quinn::ClientConfig::new(Arc::new(crypto)))
    }

    pub fn server_config(self) -> Result<quinn::ServerConfig, String> {
        let verifier = WebPkiClientVerifier::builder(self.roots)
            .build()
            .map_err(|_| "invalid client trust store")?;
        let tls = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![self.certificate], self.private_key)
            .map_err(|_| "invalid server identity")?;
        let crypto =
            QuicServerConfig::try_from(tls).map_err(|_| "invalid server TLS configuration")?;
        Ok(quinn::ServerConfig::with_crypto(Arc::new(crypto)))
    }
}

static CLIENT: Mutex<Option<quinn::ClientConfig>> = Mutex::new(None);

pub fn set_client_profile(profile: Option<&str>) -> Result<(), String> {
    let config = profile
        .map(|profile| PeerIdentity::from_json(profile)?.client_config())
        .transpose()?;
    *CLIENT.lock().unwrap() = config;
    Ok(())
}

pub(crate) fn client() -> Option<quinn::ClientConfig> {
    CLIENT.lock().unwrap().clone()
}

pub(crate) fn server() -> Result<Option<quinn::ServerConfig>, String> {
    server_settings().clone()
}

pub(crate) fn requires_authenticated_server() -> bool {
    !matches!(server_settings(), Ok(None))
}

fn server_settings() -> &'static Result<Option<quinn::ServerConfig>, String> {
    static SERVER: OnceLock<Result<Option<quinn::ServerConfig>, String>> = OnceLock::new();
    SERVER.get_or_init(|| {
        let Some(path) = std::env::var_os("BALEVPN_QUIC_TLS_PROFILE") else {
            return Ok(None);
        };
        let profile =
            std::fs::read_to_string(path).map_err(|_| "cannot read server identity profile")?;
        PeerIdentity::from_json(&profile)?.server_config().map(Some)
    })
}
