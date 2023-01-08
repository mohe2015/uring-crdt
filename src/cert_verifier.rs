use std::{sync::RwLock, time::SystemTime};

use rustls::{
    client::{ServerCertVerified, ServerCertVerifier, WebPkiVerifier},
    server::{AllowAnyAuthenticatedClient, ClientCertVerifier},
    Certificate, Error, RootCertStore, ServerName,
};

pub struct MutableWebPkiVerifier {
    pub roots: RwLock<RootCertStore>,
}

impl ServerCertVerifier for MutableWebPkiVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        server_name: &ServerName,
        scts: &mut dyn Iterator<Item = &[u8]>,
        ocsp_response: &[u8],
        now: SystemTime,
    ) -> Result<ServerCertVerified, Error> {
        WebPkiVerifier::new(self.roots.read().unwrap().to_owned(), None).verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            scts,
            ocsp_response,
            now,
        )
    }
}

pub struct MutableClientCertVerifier {
    pub roots: RwLock<RootCertStore>,
}

impl ClientCertVerifier for MutableClientCertVerifier {
    fn client_auth_root_subjects(&self) -> Option<rustls::DistinguishedNames> {
        AllowAnyAuthenticatedClient::new(self.roots.read().unwrap().to_owned())
            .client_auth_root_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        now: SystemTime,
    ) -> Result<rustls::server::ClientCertVerified, Error> {
        AllowAnyAuthenticatedClient::new(self.roots.read().unwrap().to_owned()).verify_client_cert(
            end_entity,
            intermediates,
            now,
        )
    }
}
