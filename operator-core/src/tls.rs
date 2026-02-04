//! TLS certificate management for the Wazuh operator

use rcgen::{CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, SanType};
use crate::error::Result;

pub struct TlsManager;

impl TlsManager {
    /// Generate a self-signed CA certificate and key
    pub fn generate_ca() -> Result<(String, String)> {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, "Wazuh Operator CA");
        
        let key_pair = KeyPair::generate()?;
        let cert = params.self_signed(&key_pair)?;
        
        Ok((cert.pem(), key_pair.serialize_pem()))
    }

    /// Generate a server certificate signed by a CA
    pub fn generate_server_cert(_ca_cert_pem: &str, _ca_key_pem: &str, common_name: &str, alt_names: Vec<String>) -> Result<(String, String)> {
        // TODO: Implement proper signing with CA
        // For now, generate a simple self-signed cert as a placeholder
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, common_name);
        
        for name in alt_names {
            params.subject_alt_names.push(SanType::DnsName(name.try_into().unwrap()));
        }

        let key_pair = KeyPair::generate()?;
        let cert = params.self_signed(&key_pair)?;
        
        Ok((cert.pem(), key_pair.serialize_pem()))
    }
}
