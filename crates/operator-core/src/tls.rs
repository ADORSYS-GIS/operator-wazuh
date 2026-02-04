//! TLS certificate management for the Wazuh operator

use crate::error::Result;
use rcgen::{CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair, SanType};

pub struct TlsManager;

impl TlsManager {
    /// Generate a self-signed CA certificate and key
    pub fn generate_ca() -> Result<(String, String)> {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "Wazuh Operator CA");
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::CrlSign,
        ];

        let key_pair = KeyPair::generate()?;
        let cert = params.self_signed(&key_pair)?;

        Ok((cert.pem(), key_pair.serialize_pem()))
    }

    /// Generate a server certificate signed by a CA
    pub fn generate_server_cert(
        ca_cert_pem: &str,
        ca_key_pem: &str,
        common_name: &str,
        alt_names: Vec<String>,
    ) -> Result<(String, String)> {
        let ca_key_pair = KeyPair::from_pem(ca_key_pem)?;
        let issuer = Issuer::from_ca_cert_pem(ca_cert_pem, ca_key_pair)?;

        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);

        for name in alt_names {
            params
                .subject_alt_names
                .push(SanType::DnsName(name.try_into().map_err(|e| {
                    crate::error::Error::ConfigError(format!("Invalid SAN: {}", e))
                })?));
        }

        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        ];

        let key_pair = KeyPair::generate()?;
        let cert = params.signed_by(&key_pair, &issuer)?;

        Ok((cert.pem(), key_pair.serialize_pem()))
    }
}
