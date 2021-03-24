import x509 from 'x509.js';

function san(r) {
    var pem_cert = r.variables.ssl_client_raw_cert;
    if (!pem_cert) {
        return '{"error": "no client certificate"}';
    }

    var cert = x509.parse_pem_cert(pem_cert);

    // subjectAltName oid 2.5.29.17
    return JSON.stringify(x509.get_oid_value(cert, "2.5.29.17")[0]);
}

export default {san};
