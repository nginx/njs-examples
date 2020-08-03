function secret_key(r) {
    return process.env.SECRET_KEY;
}

function create_secure_link(r) {
    return require('crypto').createHash('md5')
                            .update(r.uri).update(process.env.SECRET_KEY)
                            .digest('base64url');
}

export default {secret_key, create_secure_link}
