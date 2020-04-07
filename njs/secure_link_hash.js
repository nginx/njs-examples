function version(r) {
    r.return(200, njs.version);
}

function create_secure_link(r) {
    return require('crypto').createHash('md5')
                            .update(r.uri).update(process.env.JWT_GEN_KEY)
                            .digest('base64url');
}
