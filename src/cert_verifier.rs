use std::time::SystemTime;

use rustls::{
    client::{ResolvesClientCert, ServerCertVerified, ServerCertVerifier, WebPkiVerifier},
    Certificate, Error, RootCertStore, ServerName,
};

pub struct MutableWebPkiVerifier {
    roots: RootCertStore,
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
        WebPkiVerifier::new(self.roots.to_owned(), None).verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            scts,
            ocsp_response,
            now,
        )
    }
}
