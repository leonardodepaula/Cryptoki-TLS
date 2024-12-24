//#![allow(dead_code, unused, unused_variables)]
use cryptoki::{
    context::{CInitializeArgs, Pkcs11},
    mechanism::{
        Mechanism, MechanismType,
        rsa::{PkcsMgfType, PkcsPssParams}
    },
    object::{Attribute, AttributeType, CertificateType, KeyType, ObjectClass},
    session::{UserType, Session},
    types::AuthPin,
};
use hyper_rustls::ConfigBuilderExt;
use reqwest;
use rustls::{
    self, Error as RusTLSError, SignatureAlgorithm, SignatureScheme,
    client::ResolvesClientCert,
    pki_types::CertificateDer,
    sign::{CertifiedKey, Signer, SigningKey},
};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
struct PKCS11 {
    session: Arc<Mutex<Session>>,
}

#[derive(Debug)]
struct MySigner {
    pkcs11: PKCS11,
    scheme: SignatureScheme
}

impl MySigner {
    fn get_mechanism(&self) -> anyhow::Result<Mechanism, RusTLSError> {
        match self.scheme {
            SignatureScheme::RSA_PKCS1_SHA256 => Ok(Mechanism::Sha256RsaPkcs),
            SignatureScheme::RSA_PKCS1_SHA384 => Ok(Mechanism::Sha384RsaPkcs),
            SignatureScheme::RSA_PKCS1_SHA512 => Ok(Mechanism::Sha512RsaPkcs),
            SignatureScheme::RSA_PSS_SHA256 => {
                let params = PkcsPssParams {
                    hash_alg: MechanismType::SHA256_RSA_PKCS,
                    mgf: PkcsMgfType::MGF1_SHA256,
                    s_len: 32.into()
                };
                Ok(Mechanism::Sha256RsaPkcsPss(params))
            },
            SignatureScheme::RSA_PSS_SHA384 => {
                let params = PkcsPssParams {
                    hash_alg: MechanismType::SHA384_RSA_PKCS,
                    mgf: PkcsMgfType::MGF1_SHA384,
                    s_len: 48.into()
                };
                Ok(Mechanism::Sha384RsaPkcsPss(params))
            },
            SignatureScheme::RSA_PSS_SHA512 => {
                let params = PkcsPssParams {
                    hash_alg: MechanismType::SHA512_RSA_PKCS,
                    mgf: PkcsMgfType::MGF1_SHA512,
                    s_len: 64.into()
                };
                Ok(Mechanism::Sha512RsaPkcsPss(params))
            },
            _ => Err(RusTLSError::General("Unsupported signature scheme".to_owned())),
        }
    }
}

impl Signer for MySigner {
    fn sign(&self, message: &[u8]) -> anyhow::Result<Vec<u8>, RusTLSError> {

        let session = self.pkcs11.session.lock().unwrap();

        let key_template = vec![
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sign(true),
            Attribute::KeyType(KeyType::RSA),
        ];
    
        let key = session
            .find_objects(&key_template).unwrap()
            .into_iter()
            .next()
            .unwrap();

        let mechanism = self.get_mechanism().unwrap();
        let signed_message = session.sign(&mechanism, key, message).unwrap();
        Ok(signed_message)
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

#[derive(Debug)]
struct MySigningKey {
    pkcs11: PKCS11

}

impl MySigningKey {
    fn supported_schemes(&self) -> &[SignatureScheme] {
        &[
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

impl SigningKey for MySigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let supported = self.supported_schemes();
        for scheme in offered {
            if supported.contains(scheme) {
                return Some(Box::new(MySigner { pkcs11: self.pkcs11.clone(), scheme: *scheme }));
            }
        }
        None
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}

#[derive(Debug)]
struct ClientCertResolver {
    chain: Vec<CertificateDer<'static>>,
    signing_key: Arc<MySigningKey>,
}

impl ResolvesClientCert for ClientCertResolver {
    fn resolve(&self, _acceptable_issuers: &[&[u8]], _sigschemes: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        Some(Arc::new(CertifiedKey {cert: self.chain.clone(), key: self.signing_key.clone(), ocsp: None}))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

fn get_certificate_der(pkcs11: PKCS11) -> anyhow::Result<Vec<CertificateDer<'static>>, anyhow::Error> {
    let session = pkcs11.session.lock().unwrap();
    let search_template = vec![Attribute::Class(ObjectClass::CERTIFICATE), Attribute::CertificateType(CertificateType::X_509)];
    let handle = session.find_objects(&search_template)?.remove(0);
    let value = session.get_attributes(handle, &[AttributeType::Value])?.remove(0);

    match value {
        Attribute::Value(cert) => {
            let certificate_der = CertificateDer::from_slice(&cert).into_owned();
            Ok(vec![certificate_der])
        },
        _ => {
            anyhow::bail!("Couldn't find X509 certificate.")
        },
    }
}

//#[allow(dead_code, unused)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {

    let _ = rustls::crypto::ring::default_provider().install_default();

    let pkcs11client = Pkcs11::new(std::env::var("PKCS11_SOFTHSM2_MODULE")?)?;
    // Example: let pkcs11client = Pkcs11::new("C:/Windows/System32/eTPKCS11.dll")?;
    pkcs11client.initialize(CInitializeArgs::OsThreads)?;

    let slot = pkcs11client.get_slots_with_token()?.remove(0);
    let session = pkcs11client.open_ro_session(slot)?;
    //session.login(UserType::User, None)?;
    session.login(UserType::User, Some(&AuthPin::new("YOUR_PIN".into()))).unwrap();

    let pkcs11 = PKCS11 { session: Arc::new(Mutex::new(session)) };
    let chain = get_certificate_der(pkcs11.clone())?;
    let my_signing_key = Arc::new(MySigningKey { pkcs11 });

    let tls = rustls::ClientConfig::builder()
        .with_native_roots()?
        .with_client_cert_resolver(Arc::new(ClientCertResolver {chain: chain, signing_key: my_signing_key}));

    let client = reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .build()?;

    let response = client.get("https://certauth.cryptomix.com/json/")
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await?
        .text()
        .await?;

    println!("{:?}", response);

    Ok(())

}