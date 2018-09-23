function version(r) {
    r.return(200, njs.version);
}

function create_secure_link(r) {
    return require('crypto').createHash('md5')
                            .update(r.uri).update(" mykey")
                            .digest('base64url');
}
