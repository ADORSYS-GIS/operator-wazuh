//! TLS certificate management for the Wazuh operator

use crate::error::Result;
use rcgen::{CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair, SanType};

pub struct TlsManager;

#[derive(Clone, Debug)]
pub struct CertificateSubject {
    pub common_name: String,
    pub country: String,
    pub state_or_province: String,
    pub locality: String,
    pub organization: String,
    pub organizational_unit: String,
}

impl Default for CertificateSubject {
    fn default() -> Self {
        Self {
            common_name: "Wazuh Operator CA".to_string(),
            country: "US".to_string(),
            state_or_province: "California".to_string(),
            locality: "California".to_string(),
            organization: "Wazuh".to_string(),
            organizational_unit: "Wazuh".to_string(),
        }
    }
}

impl TlsManager {
    /// Generate a self-signed CA certificate and key
    pub fn generate_ca(subject: Option<&CertificateSubject>) -> Result<(String, String)> {
        let subject = subject.cloned().unwrap_or_default();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, subject.common_name);
        params
            .distinguished_name
            .push(DnType::OrganizationalUnitName, subject.organizational_unit);
        params
            .distinguished_name
            .push(DnType::OrganizationName, subject.organization);
        params
            .distinguished_name
            .push(DnType::LocalityName, subject.locality);
        params
            .distinguished_name
            .push(DnType::StateOrProvinceName, subject.state_or_province);
        params
            .distinguished_name
            .push(DnType::CountryName, subject.country);
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
        params
            .distinguished_name
            .push(DnType::OrganizationalUnitName, "Wazuh");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Wazuh");
        params
            .distinguished_name
            .push(DnType::LocalityName, "California");
        params.distinguished_name.push(DnType::CountryName, "US");

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
